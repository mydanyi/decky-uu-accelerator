"""UU package metadata handling, download and safe payload extraction.

Everything here is stdlib-only and deliberately conservative: downloads must
come from official UU CDN hosts, archives must fully validate before a single
byte is written, and executables are never run during extraction.
"""

import hashlib
import os
import re
import ssl
import tarfile
import tempfile
import urllib.error
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from .platform import elf_machine

_METADATA_API = "https://router.uu.163.com/api/plugin?type={}"
_PACKAGE_TYPES = ("steam-deck-plugin-x86_64",)

# Official UU CDN suffixes; a URL host must equal one of these or be a
# subdomain of it (so "gdl.netease.com.evil.example" is rejected).
_TRUSTED_HOST_SUFFIXES = ("gdl.netease.com", "gdl.nieapps.com")

_MD5_RE = re.compile(r"[0-9a-f]{32}")
_VERSION_RE = re.compile(r"-v?(\d[0-9A-Za-z._-]*)\.tar\.")

_ALLOWED_MEMBERS = {
    "uuplugin": 0o755,
    "xuplugin-guardian": 0o755,
    "uu.conf": 0o644,
}
_EXECUTABLE_MEMBERS = ("uuplugin", "xuplugin-guardian")
_REQUIRED_MEMBERS = ("uuplugin", "xuplugin-guardian", "uu.conf")

_CHUNK_SIZE = 64 * 1024

# Host trust bundles, most-preferred first. The Fedora/RHEL extracted bundle is
# listed ahead of the Debian paths because a translated FEX Decky runtime ships
# its own (guest) CA set; pointing OpenSSL at the host's real bundle matches what
# native Python/curl already validate against.
_CA_BUNDLE_CANDIDATES = (
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ssl/cert.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
)


def _ssl_context():
    """Return a verifying TLS context, preferring the host's real trust bundle.

    The first existing common bundle is handed to ``create_default_context`` as
    an explicit ``cafile``. When none exists we still return the secure default
    context (certificate *and* hostname verification); we never fall back to an
    unverified context, HTTP, or by mutating global SSL environment.
    """
    for candidate in _CA_BUNDLE_CANDIDATES:
        if Path(candidate).is_file():
            return ssl.create_default_context(cafile=candidate)
    return ssl.create_default_context()



def parse_metadata(text):
    """Parse the ``url,md5[,alternate_url]`` CSV returned by the UU API."""
    if isinstance(text, (bytes, bytearray, memoryview)):
        try:
            text = bytes(text).decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("下载元数据不是有效的 UTF-8 文本")
    if not isinstance(text, str):
        raise ValueError("下载元数据格式无效")

    fields = None
    for line in text.splitlines():
        if line.strip():
            fields = [field.strip() for field in line.strip().split(",")]
            break
    if not fields or len(fields) < 2:
        raise ValueError("下载元数据为空或字段不足")

    url, md5 = fields[0], fields[1].lower()
    if not url:
        raise ValueError("下载元数据缺少下载地址")
    if not _MD5_RE.fullmatch(md5):
        raise ValueError("下载元数据校验值无效")

    _check_url(url)
    alternate_url = fields[2] if len(fields) > 2 else ""
    if alternate_url:
        _check_url(alternate_url)
    else:
        alternate_url = None

    return {
        "url": url,
        "md5": md5,
        "alternate_url": alternate_url,
        "version": _version_from_url(url),
    }


def fetch_metadata(package_type, timeout=15):
    """Fetch and parse the official metadata for a supported package type."""
    if package_type not in _PACKAGE_TYPES:
        raise ValueError("不支持的安装包类型: {}".format(package_type))
    request = Request(
        _METADATA_API.format(package_type),
        headers={"Accept": "text/plain"},
    )
    context = _ssl_context()
    with urlopen(request, timeout=timeout, context=context) as response:
        body = response.read()
    return parse_metadata(body)


def download_archive(metadata, target, progress=None, timeout=30):
    """Download a package to ``target``, verifying the official MD5.

    Streaming goes to a temporary file in the target directory and is only
    promoted with an atomic replace after the checksum matches. Any failure
    leaves the previous target untouched and removes only that temporary file.
    """
    target = Path(target)
    expected_md5 = str(metadata.get("md5") or "").lower()
    if not _MD5_RE.fullmatch(expected_md5):
        raise ValueError("下载元数据校验值无效")

    candidates = _candidate_urls(metadata)
    temp_path = None
    last_error = None
    try:
        for url in candidates:
            try:
                temp_path, digest = _stream_to_temp(url, target, progress, timeout)
            except (OSError, urllib.error.URLError) as exc:
                last_error = exc
                temp_path = None
                continue
            if digest != expected_md5:
                raise ValueError(
                    "安装包 MD5 校验失败: 期望 {}，实际 {}".format(expected_md5, digest)
                )
            os.replace(temp_path, target)
            temp_path = None
            return target
        raise ValueError("安装包下载失败: {}".format(last_error))
    finally:
        if temp_path is not None:
            _remove_temp(temp_path)


def extract_payload(archive, dest, expected_arch):
    """Validate a package archive and extract it into ``dest``.

    The whole archive is validated in memory first; nothing is written unless
    every member, ELF architecture and ``uu.conf`` version is acceptable.
    """
    archive = Path(archive)
    dest = Path(dest)
    if expected_arch != "x86_64":
        raise ValueError("不支持的架构: {}".format(expected_arch))

    if dest.exists():
        if not dest.is_dir():
            raise ValueError("目标路径不是目录: {}".format(dest))
        if any(dest.iterdir()):
            raise ValueError("目标目录非空，拒绝覆盖: {}".format(dest))

    members, version = _read_payload(archive, expected_arch)

    files = []
    dest.mkdir(parents=True, exist_ok=True)
    for name, data in members:
        path = dest / name
        with open(path, "wb") as handle:
            handle.write(data)
        # Windows-mediated transfers drop the executable bit; restore it here.
        os.chmod(path, _ALLOWED_MEMBERS[name])
        files.append(str(path))

    return {"version": version, "files": files}


def _read_payload(archive, expected_arch):
    """Validate the entire archive and return ``([(name, data)], version)``."""
    if not archive.is_file():
        raise ValueError("安装包不存在: {}".format(archive))

    collected = {}
    order = []
    with tarfile.open(archive, "r:gz") as tar:
        for info in tar:
            name = _safe_basename(info.name)
            if name is None:
                raise ValueError("安装包包含不安全的路径: {}".format(info.name))
            if name not in _ALLOWED_MEMBERS:
                raise ValueError("安装包包含未知文件: {}".format(info.name))
            if name in collected:
                raise ValueError("安装包包含重复文件: {}".format(name))
            if not info.isreg():
                raise ValueError("安装包包含非普通文件: {}".format(info.name))
            handle = tar.extractfile(info)
            if handle is None:
                raise ValueError("无法读取安装包成员: {}".format(info.name))
            collected[name] = handle.read()
            order.append(name)

    missing = [name for name in _REQUIRED_MEMBERS if name not in collected]
    if missing:
        raise ValueError("安装包缺少必需文件: {}".format(", ".join(missing)))

    for name in _EXECUTABLE_MEMBERS:
        data = collected.get(name)
        if data is None:
            continue
        try:
            actual = elf_machine(data)
        except ValueError as exc:
            raise ValueError("{} 不是有效的 ELF 可执行文件: {}".format(name, exc))
        if actual != expected_arch:
            raise ValueError(
                "{} 架构不匹配: 期望 {}，实际 {}".format(name, expected_arch, actual)
            )

    version = _parse_uu_conf(collected["uu.conf"])
    return [(name, collected[name]) for name in order], version


def read_release_version(release_dir):
    """Return the version recorded in an extracted release's ``uu.conf``.

    Reuses the same parser as archive extraction (no second implementation) so a
    cached candidate records its authoritative ``uu.conf`` version instead of an
    unreliable metadata hint. Reads only ``uu.conf``; the archive is not
    re-audited.
    """
    conf = Path(release_dir) / "uu.conf"
    try:
        data = conf.read_bytes()
    except OSError as exc:
        raise ValueError("无法读取 uu.conf: {}".format(exc))
    return _parse_uu_conf(data)


def _parse_uu_conf(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("uu.conf 不是有效的 UTF-8 文本")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep and key.strip().lower() == "version":
            value = value.strip().strip('"').strip("'")
            if value:
                return value
    raise ValueError("uu.conf 缺少 version 字段")


def _safe_basename(name):
    """Flatten a tar member name to its basename, or ``None`` if unsafe."""
    if not isinstance(name, str) or not name or "\x00" in name:
        return None
    cleaned = name.replace("\\", "/").strip()
    if not cleaned or cleaned.startswith("/") or cleaned.startswith("~"):
        return None
    parts = [part for part in cleaned.split("/") if part not in ("", ".")]
    if not parts:
        return None
    for part in parts:
        if part == ".." or ":" in part:
            return None
    return parts[-1]


def _candidate_urls(metadata):
    """Primary URL then the official alternate, preferring HTTPS."""
    urls = []
    for key in ("url", "alternate_url"):
        url = metadata.get(key)
        if not url:
            continue
        _check_url(url)
        for candidate in (_https_variant(url), url):
            if candidate and candidate not in urls:
                urls.append(candidate)
    if not urls:
        raise ValueError("下载元数据缺少下载地址")
    return urls


def _https_variant(url):
    parts = urlsplit(url)
    if parts.scheme != "http":
        return None
    return urlunsplit(("https", parts.netloc, parts.path, parts.query, parts.fragment))


def _check_url(url):
    """Reject anything that is not an official HTTP(S) UU CDN URL."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("不支持的下载协议: {}".format(url))
    try:
        host = (parts.hostname or "").lower()
    except ValueError:
        raise ValueError("下载地址无效: {}".format(url))
    if not host:
        raise ValueError("下载地址缺少主机名: {}".format(url))
    trusted = any(
        host == suffix or host.endswith("." + suffix)
        for suffix in _TRUSTED_HOST_SUFFIXES
    )
    if not trusted:
        raise ValueError("非官方 UU 下载地址: {}".format(url))
    return parts


def _stream_to_temp(url, target, progress, timeout):
    """Stream ``url`` into a temporary sibling file; return (path, md5 hex)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=target.name + ".", suffix=".part", dir=str(target.parent)
    )
    temp_path = Path(temp_name)
    downloaded = 0
    digest = hashlib.md5()
    context = _ssl_context()
    try:
        with os.fdopen(fd, "wb") as handle:
            with urlopen(url, timeout=timeout, context=context) as response:
                _check_url(response.geturl())
                total = _content_length(response)
                if progress is not None:
                    progress(downloaded, total)
                while True:
                    chunk = response.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    handle.write(chunk)
                    digest.update(chunk)
                    downloaded += len(chunk)
                    if progress is not None:
                        progress(downloaded, total)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        _remove_temp(temp_path)
        raise
    return temp_path, digest.hexdigest()


def _content_length(response):
    raw = response.headers.get("Content-Length")
    if not raw:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _remove_temp(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _version_from_url(url):
    name = urlsplit(url).path.rsplit("/", 1)[-1]
    match = _VERSION_RE.search(name)
    return match.group(1) if match else None
