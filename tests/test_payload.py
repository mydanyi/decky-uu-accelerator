"""Contract tests for py_modules/uu_accelerator/payload.py.

These tests are written before the production module exists and define the
agreed API. They are expected to be red until payload.py is implemented.
No downloaded executables are used: every package is a tiny in-memory tar.gz.

Run with:
    PYTHONPATH=py_modules python3 -m unittest discover -s tests -v
"""

import contextlib
import hashlib
import io
import os
import shutil
import ssl
import struct
import tarfile
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from uu_accelerator.payload import (
    download_archive,
    extract_payload,
    fetch_metadata,
    parse_metadata,
)

ELF_X86_64 = 62
ELF_AARCH64 = 183

UU = "https://gdl.netease.com/uu/uuplugin-v14.9.4.tar.gz?sign=abc&t=1700000000"
UU_ALT = "https://gdl.nieapps.com/uu/uuplugin-v14.9.4.tar.gz?sign=def"
MD5 = "0123456789abcdef0123456789abcdef"

# The Fedora/RHEL trust bundle the plugin must prefer, ahead of the Debian
# paths, when validating HTTPS downloads.
FEDORA_CA_BUNDLE = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
DEBIAN_CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ssl/cert.pem",
)
CA_BUNDLE_CANDIDATES = (FEDORA_CA_BUNDLE,) + DEBIAN_CA_BUNDLES

PACKAGE_TYPE = "steam-deck-plugin-x86_64"


@contextlib.contextmanager
def fake_ca_filesystem(existing):
    """Pretend exactly ``existing`` CA bundles are present on disk.

    Production resolves a system trust bundle through ``Path.is_file``. The
    check is mocked so it is deterministic everywhere: a Debian-style host
    really does have ``/etc/ssl/certs/ca-certificates.crt``, which would
    otherwise mask the Fedora preference under test.
    """
    real_is_file = Path.is_file
    present = {str(path) for path in existing}

    def fake_is_file(self):
        text = str(self)
        if text in CA_BUNDLE_CANDIDATES:
            return text in present
        return real_is_file(self)

    with mock.patch.object(Path, "is_file", fake_is_file):
        yield


def assert_secure_context(case, context):
    """A usable context must validate certificates and check hostnames."""
    case.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
    case.assertTrue(context.check_hostname)


def elf_header(machine):
    """A syntactically valid 64-bit little-endian ELF header with e_machine set."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    body = struct.pack(
        "<HHIQQQIHHHHHH",
        2, machine, 1,
        0, 0, 0, 0,
        64, 56, 1, 64, 0, 0,
    )
    return ident + body


def core_members(machine, version="14.9.4", extra=()):
    """Required package payload; uu.conf carries the authoritative version."""
    members = [
        {"name": "uuplugin", "data": elf_header(machine)},
        {"name": "xuplugin-guardian", "data": elf_header(machine)},
        {"name": "uu.conf", "data": "version={}\n".format(version)},
    ]
    members.extend(extra)
    return members


def build_tar(path, members):
    with tarfile.open(path, "w:gz") as tar:
        for member in members:
            info = tarfile.TarInfo(member["name"])
            kind = member.get("type", "file")
            if kind in ("sym", "hard"):
                info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                info.linkname = member["link"]
                tar.addfile(info)
                continue
            data = member["data"]
            data = data.encode() if isinstance(data, str) else data
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def tar_bytes(members):
    """Same members as :func:`build_tar`, but returned as in-memory bytes."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for member in members:
            data = member["data"]
            data = data.encode() if isinstance(data, str) else data
            info = tarfile.TarInfo(member["name"])
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class FakeResponse(io.BytesIO):
    """Minimal stand-in for the urllib response subset that payload touches.

    BytesIO already provides the context-manager and streaming ``read`` API;
    we only add the redirect-aware ``geturl`` and a plain ``headers`` mapping.
    """

    def __init__(self, data, url, content_length=None):
        super().__init__(data)
        self._url = url
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def geturl(self):
        return self._url


class FetchMetadataPackageTypeTests(unittest.TestCase):
    def test_openwrt_aarch64_rejected_before_network(self):
        with mock.patch("uu_accelerator.payload.urlopen") as opener:
            with self.assertRaises(ValueError):
                fetch_metadata("openwrt-aarch64")
        opener.assert_not_called()

    def test_only_steam_deck_package_type_is_accepted(self):
        body = "{},{},{}\r\n".format(UU, MD5, UU_ALT).encode()
        with mock.patch("uu_accelerator.payload.urlopen",
                        return_value=FakeResponse(body, UU)) as opener:
            meta = fetch_metadata(PACKAGE_TYPE)
        self.assertEqual(meta["url"], UU)
        opener.assert_called_once()


class ParseMetadataTests(unittest.TestCase):
    def test_parses_signed_crlf_csv(self):
        meta = parse_metadata("{},{},{}\r\n".format(UU, MD5, UU_ALT))
        self.assertEqual(meta["url"], UU)
        self.assertEqual(meta["md5"], MD5)
        self.assertEqual(meta["alternate_url"], UU_ALT)
        self.assertIn("version", meta)

    def test_accepts_both_official_cdns(self):
        for host in ("http://gdl.netease.com", "https://gdl.nieapps.com",
                     "https://cdn.gdl.netease.com"):
            with self.subTest(host=host):
                url = host + "/pkg/uuplugin.tar.gz"
                meta = parse_metadata("{},{},{}".format(url, MD5, url))
                self.assertEqual(meta["url"], url)

    def test_rejects_empty_result_or_bad_checksum(self):
        for bad in ("", "   \r\n",
                    "{},not-a-checksum,{}".format(UU, UU_ALT),
                    "{},abc,{}".format(UU, UU_ALT)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_metadata(bad)

    def test_rejects_non_official_urls(self):
        for url in ("file:///tmp/uuplugin.tar.gz",
                    "https://evil.example.com/uuplugin.tar.gz",
                    "https://gdl.netease.com.evil.example/x.tar.gz"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                parse_metadata("{},{},{}".format(url, MD5, url))


class ExtractPayloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_valid_x86_package_reports_uu_conf_version(self):
        # Destination contains spaces on purpose (custom Decky user home).
        dest = Path(self.tmp) / "home with spaces" / "uu"
        archive = build_tar(Path(self.tmp) / "x86.tar.gz",
                            core_members(ELF_X86_64, version="14.9.4"))
        result = extract_payload(archive, dest, expected_arch="x86_64")
        self.assertEqual(result["version"], "14.9.4")
        names = {Path(f).name for f in result["files"]}
        self.assertTrue({"uuplugin", "xuplugin-guardian", "uu.conf"} <= names)
        for name in ("uuplugin", "xuplugin-guardian", "uu.conf"):
            self.assertTrue((dest / name).is_file())

    def test_rejects_aarch64_package_and_unsupported_arch_argument(self):
        dest = Path(self.tmp) / "dest-arm"
        extra = [{"name": "xtables-nft-multi", "data": elf_header(ELF_AARCH64)}]
        archive = build_tar(Path(self.tmp) / "arm.tar.gz",
                            core_members(ELF_AARCH64, version="14.9.4", extra=extra))
        for expected_arch in ("aarch64", "x86_64"):
            with self.subTest(expected_arch=expected_arch), self.assertRaises(ValueError):
                extract_payload(archive, dest, expected_arch=expected_arch)
        self.assertFalse(dest.exists())

    def test_rejects_optional_network_tool_even_when_x86(self):
        dest = Path(self.tmp) / "dest-xtables"
        extra = [{"name": "xtables-nft-multi", "data": elf_header(ELF_X86_64)}]
        archive = build_tar(Path(self.tmp) / "xtables.tar.gz",
                            core_members(ELF_X86_64, version="14.9.4", extra=extra))
        with self.assertRaises(ValueError):
            extract_payload(archive, dest, expected_arch="x86_64")
        self.assertFalse(dest.exists())

    def test_rejects_invalid_core_binaries(self):
        cases = {
            "arch-mismatch": core_members(ELF_AARCH64),  # package is ARM, host expects x86
            "malformed-elf": [
                {"name": "uuplugin", "data": b"not-an-elf"},
                {"name": "xuplugin-guardian", "data": elf_header(ELF_X86_64)},
                {"name": "uu.conf", "data": "version=14.9.4\n"},
            ],
            "missing-required": [m for m in core_members(ELF_X86_64)
                                 if m["name"] != "uu.conf"],
        }
        for case, members in cases.items():
            with self.subTest(case=case), self.assertRaises(ValueError):
                archive = build_tar(Path(self.tmp) / (case + ".tar.gz"), members)
                extract_payload(archive, Path(self.tmp) / ("out-" + case),
                                expected_arch="x86_64")

    def test_rejects_unsafe_archives_without_side_effects(self):
        base = core_members(ELF_X86_64)
        cases = {
            "traversal": base + [{"name": "../evil", "data": b"x"}],
            "symlink": base + [{"name": "evil-link", "type": "sym", "link": "/etc/passwd"}],
            "hardlink": base + [{"name": "evil-hard", "type": "hard", "link": "uuplugin"}],
            "unexpected": base + [{"name": "README.txt", "data": b"hi"}],
        }
        for case, members in cases.items():
            with self.subTest(case=case):
                archive = build_tar(Path(self.tmp) / (case + ".tar.gz"), members)
                with self.assertRaises(ValueError):
                    extract_payload(archive, Path(self.tmp) / ("safe-" + case),
                                    expected_arch="x86_64")
                # nothing may be written outside the requested destination
                self.assertFalse((Path(self.tmp) / "evil").exists())


class DownloadArchiveTests(unittest.TestCase):
    """download_archive against a mocked urllib, no real HTTP involved."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    @staticmethod
    def _metadata(data, url=UU, alternate=None, md5=None):
        return {
            "url": url,
            "md5": md5 or hashlib.md5(data).hexdigest(),
            "alternate_url": alternate,
        }

    def test_matching_md5_is_promoted_and_extracts_executables(self):
        archive = tar_bytes(core_members(ELF_X86_64, version="14.9.4"))
        metadata = self._metadata(archive)
        # Parent contains a space on purpose (custom Decky user home).
        target = Path(self.tmp) / "downloads with spaces" / "uuplugin.tar.gz"

        with mock.patch("uu_accelerator.payload.urlopen",
                        return_value=FakeResponse(archive, UU, len(archive))):
            result = download_archive(metadata, target)

        self.assertEqual(result, target)
        self.assertEqual(target.read_bytes(), archive)
        # the temporary .part sibling is promoted away, not left behind
        self.assertEqual(sorted(p.name for p in target.parent.iterdir()),
                         ["uuplugin.tar.gz"])

        dest = Path(self.tmp) / "extracted x86"
        outcome = extract_payload(target, dest, expected_arch="x86_64")
        self.assertEqual(outcome["version"], "14.9.4")
        for name in ("uuplugin", "xuplugin-guardian"):
            self.assertTrue(os.stat(dest / name).st_mode & 0o111, name)
        self.assertFalse(os.stat(dest / "uu.conf").st_mode & 0o111)

    def test_checksum_mismatch_keeps_old_target_and_drops_part(self):
        target = Path(self.tmp) / "uuplugin.tar.gz"
        target.write_bytes(b"previous good archive")
        metadata = self._metadata(b"unexpected bytes", md5="0" * 32)

        with mock.patch("uu_accelerator.payload.urlopen",
                        return_value=FakeResponse(b"unexpected bytes", UU)):
            with self.assertRaises(ValueError):
                download_archive(metadata, target)

        self.assertEqual(target.read_bytes(), b"previous good archive")
        self.assertEqual(list(target.parent.glob("*.part")), [])

    def test_transport_failure_uses_official_alternate(self):
        data = b"alternate mirror payload"
        calls = []

        def fake_urlopen(url, timeout=None, context=None):
            calls.append(url)
            if url == UU:
                raise urllib.error.URLError("primary mirror down")
            return FakeResponse(data, UU_ALT, len(data))

        metadata = self._metadata(data, alternate=UU_ALT)
        target = Path(self.tmp) / "alternate.tar.gz"
        with mock.patch("uu_accelerator.payload.urlopen", side_effect=fake_urlopen):
            result = download_archive(metadata, target)

        self.assertEqual(result, target)
        self.assertEqual(target.read_bytes(), data)
        self.assertEqual(calls, [UU, UU_ALT])
        self.assertEqual(list(target.parent.glob("*.part")), [])

    def test_non_official_final_redirect_is_rejected(self):
        target = Path(self.tmp) / "uuplugin.tar.gz"
        target.write_bytes(b"previous good archive")
        data = b"redirected payload"
        evil = "https://evil.example.com/uuplugin.tar.gz"

        with mock.patch("uu_accelerator.payload.urlopen",
                        return_value=FakeResponse(data, evil, len(data))):
            with self.assertRaises(ValueError):
                download_archive(self._metadata(data), target)

        self.assertEqual(target.read_bytes(), b"previous good archive")
        self.assertEqual(list(target.parent.glob("*.part")), [])


class SecureTransportTests(unittest.TestCase):
    """Every HTTPS request must use an explicit verified SSL context.

    The live FEX Decky backend failed with ``CERTIFICATE_VERIFY_FAILED`` because
    ``urlopen`` was called without a context, so it picked the wrong bundled CA.
    These regressions pin the desired behaviour: an explicit
    ``ssl.create_default_context`` (never an unverified one), preferring the
    Fedora trust bundle that native Python and curl validate against.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    @staticmethod
    def _metadata(data, url=UU, alternate=None, md5=None):
        return {
            "url": url,
            "md5": md5 or hashlib.md5(data).hexdigest(),
            "alternate_url": alternate,
        }

    def test_fetch_metadata_uses_fedora_bundle_with_verified_context(self):
        real_context = ssl.create_default_context()
        body = "{},{},{}\r\n".format(UU, MD5, UU_ALT).encode()
        response = FakeResponse(body, UU)
        factory = mock.Mock(return_value=real_context)

        with mock.patch("ssl.create_default_context", factory), \
                fake_ca_filesystem([FEDORA_CA_BUNDLE]), \
                mock.patch("uu_accelerator.payload.urlopen",
                           return_value=response) as opener:
            meta = fetch_metadata(PACKAGE_TYPE)

        self.assertEqual(meta["url"], UU)
        self.assertEqual(meta["md5"], MD5)
        # The factory must be handed the readable Fedora bundle explicitly.
        factory.assert_called_once()
        self.assertEqual(str(factory.call_args[1].get("cafile")), FEDORA_CA_BUNDLE)
        assert_secure_context(self, real_context)
        # The metadata request must reuse that exact verified context.
        opener.assert_called_once()
        self.assertIs(opener.call_args[1].get("context"), real_context)

    def test_download_archive_uses_fedora_bundle_with_verified_context(self):
        archive = tar_bytes(core_members(ELF_X86_64, version="14.9.4"))
        metadata = self._metadata(archive)
        target = Path(self.tmp) / "secure with spaces" / "uuplugin.tar.gz"
        real_context = ssl.create_default_context()
        response = FakeResponse(archive, UU, len(archive))
        factory = mock.Mock(return_value=real_context)

        with mock.patch("ssl.create_default_context", factory), \
                fake_ca_filesystem([FEDORA_CA_BUNDLE]), \
                mock.patch("uu_accelerator.payload.urlopen",
                           return_value=response) as opener:
            result = download_archive(metadata, target)

        self.assertEqual(result, target)
        self.assertEqual(target.read_bytes(), archive)
        factory.assert_called_once()
        self.assertEqual(str(factory.call_args[1].get("cafile")), FEDORA_CA_BUNDLE)
        assert_secure_context(self, real_context)
        # The streaming HTTPS request must reuse that exact verified context.
        opener.assert_called_once()
        self.assertIs(opener.call_args[1].get("context"), real_context)
        self.assertEqual(list(target.parent.glob("*.part")), [])

    def test_missing_system_bundle_still_uses_verified_default_context(self):
        real_context = ssl.create_default_context()
        body = "{},{},{}\r\n".format(UU, MD5, UU_ALT).encode()
        response = FakeResponse(body, UU)
        factory = mock.Mock(return_value=real_context)
        unverified = mock.Mock(
            side_effect=AssertionError("unverified SSL context must not be used"))

        with mock.patch("ssl.create_default_context", factory), \
                mock.patch("ssl._create_unverified_context", unverified), \
                fake_ca_filesystem([]), \
                mock.patch("uu_accelerator.payload.urlopen",
                           return_value=response) as opener:
            meta = fetch_metadata(PACKAGE_TYPE)

        self.assertEqual(meta["url"], UU)
        # No system bundle exists: still build a secure default, no cafile.
        factory.assert_called_once_with()
        unverified.assert_not_called()
        assert_secure_context(self, real_context)
        opener.assert_called_once()
        self.assertIs(opener.call_args[1].get("context"), real_context)
