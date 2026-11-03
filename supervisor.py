#!/usr/bin/env python3
"""Standalone UU core supervisor.

``python3 supervisor.py launch.json`` spawns the configured core, records the
core's own PID, appends the core's stdout/stderr to the configured log,
forwards SIGTERM/SIGINT to the direct core first, and escalates within the
process group it created for that core only. It never touches unrelated
processes or a global FEX server, and it never infers network restoration from
a process exit.

The module is import-safe: the contract test imports it for ``build_command``.
"""

import gzip
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

# How long the direct core must stay alive before we tell systemd it is ready.
# Only startup/process survival is confirmed here; this is not a claim that the
# core is paired with UU or that acceleration/network is actually ready.
READY_STABILIZE_SECONDS = 1.0

DEFAULT_SHUTDOWN_TIMEOUT = 30.0
SYSTEM_PATH_DIRS = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
OFFICIAL_PID_FILE = "/run/uuplugin.pid"

# A refused kernel-compat preflight is a *configuration* refusal, not a crash:
# the unit lists this status in ``RestartPreventExitStatus`` so an unsupported
# kernel produces one clear error instead of a restart storm.
PREFLIGHT_REFUSED_EXIT = 78

# Owned diagnosis file, written beside our PID file and read by the manager.
STARTUP_ERROR_NAME = "startup-error.txt"

REQUIRED_STRING_KEYS = ("engine", "executable", "config_path", "cwd", "pid_file", "log_file")


class ConfigError(Exception):
    """Raised when the launch config is unreadable or malformed."""


def build_command(config):
    """Return argv as a list: launch_prefix + [executable, config_path].

    Tokens are kept intact so paths containing spaces stay literal; the argv
    is handed to a shell-free exec and never string-concatenated.
    """
    prefix = config["launch_prefix"]
    return list(prefix) + [config["executable"], config["config_path"]]


def load_config(path):
    """Read and validate the launch config, returning a normalized dict."""
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ConfigError("cannot read launch config {!r}: {}".format(path, exc))

    if not isinstance(raw, dict):
        raise ConfigError("launch config must be a JSON object")

    if "launch_prefix" not in raw:
        raise ConfigError("missing required key: launch_prefix")
    prefix = raw["launch_prefix"]
    if not isinstance(prefix, list) or not all(isinstance(item, str) for item in prefix):
        raise ConfigError("launch_prefix must be a list of strings")

    for key in REQUIRED_STRING_KEYS:
        if key not in raw:
            raise ConfigError("missing required key: {}".format(key))
        if not isinstance(raw[key], str):
            raise ConfigError("{} must be a string".format(key))

    if raw["engine"] != "fex":
        raise ConfigError("engine must be 'fex', got: {!r}".format(raw["engine"]))

    timeout = raw.get("shutdown_timeout", DEFAULT_SHUTDOWN_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0:
        raise ConfigError("shutdown_timeout must be a non-negative number")

    config = dict(raw)
    config["shutdown_timeout"] = float(timeout)
    return config


def _child_env(config):
    """Child environment: this core's run dir first, then native system dirs.

    Only the child's copy is edited; the supervisor's own environment and any
    global config are left untouched.
    """
    env = dict(os.environ)
    run_dir = config["cwd"]
    if run_dir:
        env["PATH"] = os.pathsep.join([run_dir, SYSTEM_PATH_DIRS])
    else:
        env["PATH"] = SYSTEM_PATH_DIRS
    return env


class NoExactKernelProfile(RuntimeError):
    """No exact kernel identity profile matches the running kernel.

    Raised only when the three-field identity tuple (release, machine,
    normalized config digest) matches no accepted entry, or when
    ``proc/config.gz`` cannot be read -- i.e. the exact identity simply cannot
    be proven here. A malformed manifest, a missing file or a digest mismatch
    are tamper conditions and are never reported through this subclass, so a
    manifest problem can never fall through to the portable profile.
    """


# -- kernel cgroup compatibility preflight --------------------------------
#
# The FEX/x86 route needs ``xt_cgroup`` loaded before the core starts. We try
# the system ``modprobe`` first and only fall back to a locally bundled module
# when the host ships none; that bundled module is trusted only after it is
# proven to match this exact kernel and its bytes match the recorded digest.

_PREFLIGHT_TIMEOUT = 5


def _system_tool(name):
    """Resolve ``name`` against the native system PATH, else ``/usr/sbin``."""
    found = shutil.which(name, path=SYSTEM_PATH_DIRS)
    if found:
        return found
    return "/usr/sbin/" + name


def _invoke(runner, argv, action):
    """Run one shell-free command, turning runner faults into RuntimeError."""
    try:
        return runner(
            list(argv), capture_output=True, text=True, timeout=_PREFLIGHT_TIMEOUT
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("{}命令超时: {}".format(action, exc))
    except OSError as exc:
        raise RuntimeError("{}命令无法执行: {}".format(action, exc))


def _rc(result):
    return getattr(result, "returncode", 1)


def _stderr_text(result):
    return getattr(result, "stderr", "") or ""


def _invoke_checked(runner, argv, action, diagnostics):
    """Run one command, returning the result only when it succeeded.

    Every failure -- a non-zero rc, a timeout or an exec error -- is appended
    to ``diagnostics`` with the exact action, rc and stderr/exception so the
    caller's final error keeps the real reason instead of a bare bool.
    """
    try:
        result = _invoke(runner, argv, action)
    except RuntimeError as exc:
        diagnostics.append("{} 失败: {}".format(action, exc))
        return None
    if _rc(result) != 0:
        diagnostics.append(
            "{} 失败: rc={}, stderr={!r}".format(action, _rc(result), _stderr_text(result))
        )
        return None
    return result


def _diagnostic_text(entries, fallback):
    text = "; ".join(item for item in entries if item)
    return text or fallback


def _bundled_load_error(module_name, probe_text, system_text, bundled_text):
    """One terminal error that keeps every earlier failure visible."""
    capability = "cgroup" if module_name == "xt_cgroup" else "DNS DNAT"
    return RuntimeError(
        (
            "{}能力 (系统模块 {}) 加载失败:\n"
            "  iptables 探测: {}\n"
            "  系统 modprobe: {}\n"
            "  自带模块: {}"
        ).format(capability, module_name, probe_text, system_text, bundled_text)
    )


# One real iptables rule per feature, run in a throwaway unhooked chain.
_IPTABLES_PROBES = {
    "xt_cgroup": (
        "mangle",
        ["-m", "cgroup", "--path", "/", "-j", "MARK", "--set-mark", "0"],
    ),
    "xt_nat": (
        "nat",
        ["-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "127.0.0.1:9"],
    ),
}


def _probe_network_feature(module_name, runner=None, diagnostics=None):
    """Probe actual native iptables support for a feature module.

    A uniquely named, unhooked chain is created, the feature rule is appended
    to that chain only, and the chain is always flushed and deleted again.
    No built-in chain (OUTPUT/PREROUTING/INPUT/...) is ever touched, no policy
    or global flush happens, and the probe only reports success when the rule
    was accepted *and* the owned chain was cleaned up. Any failure (including
    unsupported backends, timeouts and cleanup errors) returns ``False`` so
    the existing modprobe/fallback path continues; there are no retries.

    ``diagnostics`` is an optional list that receives the failed action, rc and
    stderr/exception of every failed command, cleanup included. The boolean
    result and the unhooked-chain-only semantics are unchanged, and a failed
    probe is evidence about *this* run only, never proof the kernel lacks the
    feature.
    """
    if diagnostics is None:
        diagnostics = []
    spec = _IPTABLES_PROBES.get(module_name)
    if spec is None:
        diagnostics.append("未知探测目标: {}".format(module_name))
        return False
    table, rule = spec
    runner = subprocess.run if runner is None else runner
    ipt = _system_tool("iptables")
    chain = "UUProbe" + uuid.uuid4().hex[:16]  # 23 chars, collision-safe
    available = False
    created = False
    cleanup_ok = True
    try:
        result = _invoke_checked(
            runner, [ipt, "-t", table, "-N", chain], "iptables -N", diagnostics
        )
        if result is not None:
            created = True
            result = _invoke_checked(
                runner, [ipt, "-t", table, "-A", chain] + rule, "iptables -A", diagnostics
            )
            if result is not None:
                available = True
    finally:
        if created:
            if (
                _invoke_checked(
                    runner, [ipt, "-t", table, "-F", chain], "iptables -F", diagnostics
                )
                is None
            ):
                cleanup_ok = False
            if (
                _invoke_checked(
                    runner, [ipt, "-t", table, "-X", chain], "iptables -X", diagnostics
                )
                is None
            ):
                cleanup_ok = False
    return available and cleanup_ok


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalized_config_sha256(config_gz):
    """SHA-256 of the kernel config, normalized the same way on both ends.

    Only ``CONFIG_`` / ``# CONFIG_`` lines are kept, sorted, newline-joined and
    terminated with a final newline, so build-host ordering never matters.
    """
    try:
        with open(config_gz, "rb") as handle:
            raw = gzip.decompress(handle.read())
    except (OSError, EOFError) as exc:
        raise RuntimeError("无法读取或解压内核配置 {}: {}".format(config_gz, exc))
    text = raw.decode("utf-8", errors="replace")
    kept = [
        line
        for line in text.split("\n")
        if line.startswith("CONFIG_") or line.startswith("# CONFIG_")
    ]
    normalized = ("\n".join(sorted(kept)) + "\n").encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


_KERNEL_IDENTITY_FIELDS = ("kernel_release", "machine", "config_sha256")
# Module-ABI fields compared when selecting a bundled module candidate.
# ``kernel_version`` (the build-date string) is provenance metadata only:
# two builds of the same release/arch/config differ in it without any ABI
# change, so it must never gate the fallback match.
_MATCH_FIELDS = ("kernel_release", "machine", "config_sha256")


def _compat_entries(manifest):
    """Return every accepted kernel identity, baseline included.

    The shipped top-level ``kernel_release``/``machine``/``config_sha256``
    (plus the optional, purely provenance ``kernel_version``) stay one
    supported entry, so an already working install keeps loading exactly as
    before. ``compatible_kernels`` may only *add* entries, and each of them
    must carry the three ABI identity fields (``kernel_version`` is optional
    provenance): a malformed list is a hard error rather than a silently
    widened allow-list, because every accepted entry permits loading our
    bundled module bytes.

    A profile may additionally carry ``module_dir`` to point at its own
    independent module directory; when present, both ``module_sha256`` and
    ``nat_module_sha256`` are required valid 64-hex digests for that profile.
    The baseline and profiles without ``module_dir`` keep using the top-level
    module digests.
    """
    entries = [{key: manifest.get(key) for key in _KERNEL_IDENTITY_FIELDS}]
    profiles = manifest.get("compatible_kernels")
    if profiles is None:
        return entries
    if not isinstance(profiles, list):
        raise RuntimeError("内核兼容清单 compatible_kernels 必须是列表")
    for index, profile in enumerate(profiles, start=1):
        if not isinstance(profile, dict):
            raise RuntimeError(
                "内核兼容清单 compatible_kernels 第 {} 项不是对象".format(index)
            )
        entry = {}
        for key in _KERNEL_IDENTITY_FIELDS:
            value = profile.get(key)
            if not isinstance(value, str) or not value:
                raise RuntimeError(
                    "内核兼容清单 compatible_kernels 第 {} 项字段 {} 缺失或无效".format(
                        index, key
                    )
                )
            entry[key] = value
        if "module_dir" in profile:
            module_dir = profile.get("module_dir")
            if (
                not isinstance(module_dir, str)
                or not module_dir
                or module_dir in (".", "..")
                or "/" in module_dir
                or "\\" in module_dir
            ):
                raise RuntimeError(
                    "内核兼容清单 compatible_kernels 第 {} 项 module_dir 缺失或无效".format(
                        index
                    )
                )
            entry["module_dir"] = module_dir
            for digest_key in ("module_sha256", "nat_module_sha256"):
                digest = profile.get(digest_key)
                if (
                    not isinstance(digest, str)
                    or len(digest) != 64
                    or any(ch not in "0123456789abcdefABCDEF" for ch in digest)
                ):
                    raise RuntimeError(
                        "内核兼容清单 compatible_kernels 第 {} 项字段 {} 缺失或无效".format(
                            index, digest_key
                        )
                    )
                entry[digest_key] = digest.lower()
        entries.append(entry)
    return entries


def _validate_kernel_compat(compat, root, module_name="xt_cgroup", digest_key="module_sha256"):
    """Prove the bundled module belongs to this running kernel, or raise.

    The runtime identity is the three-field ABI tuple (release, machine,
    normalized kernel-config digest); it must equal *one* accepted entry --
    the legacy top-level baseline or an exact ``compatible_kernels`` profile. The
    matched entry decides where the module comes from: the baseline and
    profiles without ``module_dir`` use the top-level ``module_name.ko`` and
    the top-level ``digest_key``; a profile with ``module_dir`` uses that
    profile's own ``<module_dir>/<module_name>.ko`` and its own ``digest_key``.
    The exact module bytes are always proven against the digest of the matched
    entry, never a parent digest, so a profile never excuses a tampered module.
    Everything is checked *before* any dependency/insmod attempt; the validated
    module path is returned so the caller insmods exactly the hashed file.
    Being an exact match only, this neither parses ``vermagic`` nor force-loads,
    and an unlisted kernel is refused with its own release/version/arch and a
    hint to update the plugin or the system kernel modules.
    """
    if not isinstance(compat, str) or not compat:
        raise RuntimeError("缺少 kernel_compat 配置，无法为 FEX 引擎加载内核模块")

    compat_dir = Path(compat)
    manifest_path = compat_dir / "manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError("内核兼容清单缺失: {}".format(manifest_path))

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("内核兼容清单无法解析: {}".format(exc))
    if not isinstance(manifest, dict):
        raise RuntimeError("内核兼容清单格式无效")

    entries = _compat_entries(manifest)

    uname = os.uname()
    try:
        config_sha256 = _normalized_config_sha256(Path(root) / "proc" / "config.gz")
    except RuntimeError as exc:
        # An unreadable config.gz means the exact identity cannot be proven at
        # all, which is a no-match -- never a tamper verdict on the manifest.
        raise NoExactKernelProfile(str(exc))
    actual = {
        "kernel_release": uname.release,
        "kernel_version": uname.version,
        "machine": uname.machine,
        "config_sha256": config_sha256,
    }
    matched = None
    for entry in entries:
        if all(entry[key] == actual[key] for key in _MATCH_FIELDS):
            matched = entry
            break
    if matched is None:
        if module_name == "xt_nat":
            capability = "DNS DNAT (nat) 规则能力"
            hint = "xt_nat"
        else:
            capability = "cgroup 网络规则能力"
            hint = "xt_cgroup"
        raise NoExactKernelProfile(
            (
                "缺少{}: release={}，架构={}，配置={}；"
                "iptables 原生规则不支持且系统未加载 {} 模块，"
                "请安装适配当前内核 {} 的系统 {} 模块或更新加速器插件"
            ).format(
                capability,
                uname.release,
                uname.machine,
                actual["config_sha256"],
                hint,
                uname.release,
                hint,
            )
        )

    module_dir = matched.get("module_dir")
    if module_dir is None:
        module_path = compat_dir / (module_name + ".ko")
        expected_module = manifest.get(digest_key)
    else:
        module_path = compat_dir / module_dir / (module_name + ".ko")
        expected_module = matched.get(digest_key)

    if not module_path.is_file():
        raise RuntimeError("内核模块缺失: {}".format(module_path))

    actual_module = _sha256_file(module_path)
    if expected_module != actual_module:
        raise RuntimeError(
            "内核模块 {} 校验失败: 期望 {}，实际 {}".format(
                module_name, expected_module, actual_module
            )
        )
    return str(module_path)


# -- portable (BTF-verified) bundled module profile -----------------------
#
# A portable profile covers kernels we have no exact build for. Its module is
# trusted only after the bytes and their ABI manifest are proven against the
# recorded digests, the running release/arch, the compile-time config branches
# the real source uses, and the host's own BTF -- the last step is what makes
# one .ko valid across otherwise unrelated builds of the same kernel.

_PORTABLE_DIR = "portable"
_BTF_SUBDIR = ("sys", "kernel", "btf")
_KERNEL_ABI_NAME = "kernel_abi.py"
# KNOWN dependency BTF files that carry types the portable module needs; a
# built-in dependency simply has no file of its own and its types arrive via
# vmlinux, so a genuinely missing type fails the ABI check below.
_PORTABLE_BTF_DEPENDENCIES = {
    "xt_cgroup": ("x_tables",),
    "xt_nat": ("x_tables", "nf_conntrack", "nf_nat"),
}
# Compile-time branches the real xt_cgroup source selects on. A missing or
# "not set" symbol reads as "n", exactly like the kernel's own .config.
_PORTABLE_XT_CGROUP_CONFIG = (
    ("CONFIG_CGROUPS", "y"),
    ("CONFIG_SOCK_CGROUP_DATA", "y"),
    ("CONFIG_CGROUP_NET_CLASSID", "n"),
)


def _is_hex64(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdefABCDEF" for ch in value)
    )


def _kernel_config_values(config_gz):
    """Map ``CONFIG_*`` symbols to their literal value; unset reads as ``n``."""
    try:
        with open(config_gz, "rb") as handle:
            raw = gzip.decompress(handle.read())
    except (OSError, EOFError) as exc:
        raise RuntimeError("无法读取或解压内核配置 {}: {}".format(config_gz, exc))
    values = {}
    suffix = " is not set"
    for line in raw.decode("utf-8", errors="replace").split("\n"):
        line = line.strip()
        if line.startswith("# CONFIG_") and line.endswith(suffix):
            values[line[2 : -len(suffix)]] = "n"
        elif line.startswith("CONFIG_") and "=" in line:
            key, _, value = line.partition("=")
            values[key] = value.strip()
    return values


def _load_kernel_abi():
    """Import the standalone ABI helper that ships beside this supervisor."""
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        from kernel_abi import AbiError, validate_abi
    except ImportError as exc:
        raise RuntimeError(
            "缺少内核 ABI 校验辅助模块 {!r}: {}".format(_KERNEL_ABI_NAME, exc)
        )
    return validate_abi, AbiError


def _portable_entry(manifest, module_name):
    """Return the validated portable entry for *module_name*, or ``None``."""
    portable = manifest.get("portable_modules")
    if portable is None:
        return None
    if not isinstance(portable, dict):
        raise RuntimeError("内核兼容清单 portable_modules 必须是对象")
    entry = portable.get(module_name)
    if entry is None:
        return None
    if not isinstance(entry, dict):
        raise RuntimeError("内核兼容清单 portable_modules.{} 不是对象".format(module_name))
    for key in ("module_sha256", "abi_sha256"):
        if not _is_hex64(entry.get(key)):
            raise RuntimeError(
                "内核兼容清单 portable_modules.{}.{} 缺失或不是 64 位十六进制".format(
                    module_name, key
                )
            )
        entry[key] = entry[key].lower()
    return entry


def _validate_portable_kernel_compat(
    compat, root, module_name, dependency_args, runner, diagnostics
):
    """Prove the portable module fits this kernel, or raise.

    Order matters and is deliberate: every local, offline proof (manifest
    shape, file presence, module digest, ABI-manifest digest, release/arch, and
    the compile-time branches xt_cgroup actually uses) happens *before* a
    single dependency ``modprobe``. Only then are the dependencies loaded --
    which is also what publishes ``/sys/kernel/btf/x_tables`` -- and the host
    BTF read for :func:`kernel_abi.validate_abi`.

    Returns the validated module path and never force-loads anything; a
    ``None`` result means the manifest carries no portable profile for this
    module, so the caller keeps the original exact-profile refusal.
    """
    if not isinstance(compat, str) or not compat:
        raise RuntimeError("缺少 kernel_compat 配置，无法使用便携式模块")
    compat_dir = Path(compat)
    manifest_path = compat_dir / "manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError("内核兼容清单缺失: {}".format(manifest_path))
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("内核兼容清单无法解析: {}".format(exc))
    if not isinstance(manifest, dict):
        raise RuntimeError("内核兼容清单格式无效")

    entry = _portable_entry(manifest, module_name)
    if entry is None:
        return None

    portable_dir = compat_dir / _PORTABLE_DIR
    module_path = portable_dir / (module_name + ".ko")
    metadata_path = portable_dir / (module_name + ".abi.json")
    for path in (module_path, metadata_path):
        if not path.is_file():
            raise RuntimeError("便携式模块文件缺失: {}".format(path))

    module_digest = _sha256_file(module_path)
    if module_digest != entry["module_sha256"]:
        raise RuntimeError(
            "便携式模块 {} 校验失败: 期望 {}，实际 {}".format(
                module_name, entry["module_sha256"], module_digest
            )
        )
    metadata_digest = _sha256_file(metadata_path)
    if metadata_digest != entry["abi_sha256"]:
        raise RuntimeError(
            "便携式模块 {} 的 ABI 清单校验失败: 期望 {}，实际 {}".format(
                module_name, entry["abi_sha256"], metadata_digest
            )
        )

    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "便携式模块 {} 的 ABI 清单无法解析: {}".format(module_name, exc)
        )
    if not isinstance(metadata, dict):
        raise RuntimeError("便携式模块 {} 的 ABI 清单格式无效".format(module_name))

    uname = os.uname()
    if metadata.get("kernel_release") != uname.release:
        raise RuntimeError(
            "便携式模块 {} 的内核版本不匹配: 清单 {}，当前 {}".format(
                module_name, metadata.get("kernel_release"), uname.release
            )
        )
    if metadata.get("machine") != uname.machine:
        raise RuntimeError(
            "便携式模块 {} 的架构不匹配: 清单 {}，当前 {}".format(
                module_name, metadata.get("machine"), uname.machine
            )
        )
    if metadata.get("module_sha256") != module_digest:
        raise RuntimeError(
            "便携式模块 {} 的 ABI 清单记录的模块摘要与实际文件不符".format(module_name)
        )

    if module_name == "xt_cgroup":
        values = _kernel_config_values(Path(root) / "proc" / "config.gz")
        for symbol, expected in _PORTABLE_XT_CGROUP_CONFIG:
            actual_value = values.get(symbol, "n")
            if actual_value != expected:
                raise RuntimeError(
                    "便携式 xt_cgroup 不适用: {} 期望 {}，当前 {}".format(
                        symbol, expected, actual_value
                    )
                )

    # Dependencies last among the pre-flight steps: they are what makes the
    # dependency BTF files appear, and nothing above needed them.
    dependency = _invoke(
        runner,
        [_system_tool("modprobe")] + list(dependency_args),
        "modprobe {}".format(" ".join(dependency_args)),
    )
    if _rc(dependency) != 0:
        diagnostics.append(
            "modprobe {} 失败: rc={}, stderr={!r}".format(
                " ".join(dependency_args), _rc(dependency), _stderr_text(dependency)
            )
        )
        raise RuntimeError(
            "加载 {} 依赖模块失败: {} (rc={}, stderr={!r})".format(
                module_name,
                " ".join(dependency_args),
                _rc(dependency),
                _stderr_text(dependency),
            )
        )

    btf_dir = Path(root).joinpath(*_BTF_SUBDIR)
    base_path = btf_dir / "vmlinux"
    if not base_path.is_file():
        raise RuntimeError("宿主机内核 BTF 缺失: {}".format(base_path))
    try:
        base_btf = base_path.read_bytes()
    except OSError as exc:
        raise RuntimeError("无法读取宿主机内核 BTF {}: {}".format(base_path, exc))
    kernel_btf = [base_btf]
    for dependency_name in _PORTABLE_BTF_DEPENDENCIES.get(module_name, ()):
        split_path = btf_dir / dependency_name
        if not split_path.is_file():
            # Built-in dependency: its types live in vmlinux, and a genuinely
            # missing type is reported by the ABI validation below.
            continue
        try:
            kernel_btf.append(split_path.read_bytes())
        except OSError as exc:
            raise RuntimeError("无法读取依赖模块 BTF {}: {}".format(split_path, exc))
    if len(kernel_btf) == 1:
        kernel_btf = base_btf

    validate_abi, abi_error = _load_kernel_abi()
    try:
        validate_abi(
            metadata, kernel_btf, module_digest, uname.release, uname.machine
        )
    except abi_error as exc:
        raise RuntimeError(
            "便携式模块 {} 的 ABI 校验失败: {}".format(module_name, exc)
        )

    return str(module_path)


def _ensure_module(
    config, root, module_name, digest_key, dependency_args, runner=None, diagnostics=None
):
    """Make ``module_name`` available, sharing the loader for xt_cgroup/xt_nat.

    Route, in order: an already-present ``sys/module/<module_name>``; native
    iptables that already implements the feature; the system ``modprobe``; the
    exact-kernel bundled module; and, only when *no exact profile matches this
    kernel*, the portable bundled module, which is proven against the host BTF
    before ``insmod``. A concurrent load that wins the race is accepted.

    Every terminal failure carries the probe, system-modprobe and bundled
    reasons together, with rc and stderr where the OS provided them.
    """
    if diagnostics is None:
        diagnostics = []
    root = Path(root)
    module_dir = root / "sys" / "module" / module_name
    if module_dir.exists():
        return

    runner = subprocess.run if runner is None else runner

    # Native iptables may already implement the feature (built-in or nft
    # backend) even when the module is not loadable and no bundled candidate
    # matches this kernel; that capability is enough on its own and must
    # return before any modprobe, manifest, config or uname access.
    probe_start = len(diagnostics)
    if _probe_network_feature(module_name, runner=runner, diagnostics=diagnostics):
        return
    probe_text = _diagnostic_text(
        diagnostics[probe_start:], "iptables 原生探测未通过"
    )

    modprobe_start = len(diagnostics)
    try:
        probe = _invoke(
            runner,
            [_system_tool("modprobe"), module_name],
            "modprobe {}".format(module_name),
        )
        if _rc(probe) == 0:
            return
        diagnostics.append(
            "modprobe {} 失败: rc={}, stderr={!r}".format(
                module_name, _rc(probe), _stderr_text(probe)
            )
        )
    except RuntimeError as exc:
        diagnostics.append(str(exc))
    system_text = _diagnostic_text(
        diagnostics[modprobe_start:], "modprobe 未提供详细信息"
    )

    compat = config.get("kernel_compat")
    bundled_start = len(diagnostics)
    module_path = None
    via_portable = False
    try:
        module_path = _validate_kernel_compat(
            compat, root, module_name=module_name, digest_key=digest_key
        )
    except NoExactKernelProfile as no_exact:
        # The exact identity is the first bundled route and stays untouched;
        # only this no-match verdict may continue to the portable profile.
        diagnostics.append(str(no_exact))
        try:
            module_path = _validate_portable_kernel_compat(
                compat, root, module_name, dependency_args, runner, diagnostics
            )
        except RuntimeError as exc:
            diagnostics.append(str(exc))
            raise _bundled_load_error(
                module_name, probe_text, system_text, str(exc)
            )
        if module_path is None:
            raise _bundled_load_error(
                module_name,
                probe_text,
                system_text,
                _diagnostic_text(diagnostics[bundled_start:], str(no_exact)),
            )
        via_portable = True
    except RuntimeError as exc:
        # Tampered bytes, a malformed manifest or an unreadable file: refuse,
        # never reinterpret as a no-match.
        diagnostics.append(str(exc))
        raise _bundled_load_error(module_name, probe_text, system_text, str(exc))

    if not via_portable:
        # The portable route already loaded these dependencies exactly once, so
        # loading them again here would double-modprobe.
        try:
            dependency = _invoke(
                runner,
                [_system_tool("modprobe")] + list(dependency_args),
                "modprobe {}".format(" ".join(dependency_args)),
            )
        except RuntimeError as exc:
            raise _bundled_load_error(
                module_name, probe_text, system_text, str(exc)
            ) from exc
        if _rc(dependency) != 0:
            raise _bundled_load_error(
                module_name,
                probe_text,
                system_text,
                "加载 {} 依赖模块失败: {} (rc={}, stderr={!r})".format(
                    module_name,
                    " ".join(dependency_args),
                    _rc(dependency),
                    _stderr_text(dependency),
                ),
            )

    try:
        load = _invoke(
            runner, [_system_tool("insmod"), module_path], "insmod {}".format(module_name)
        )
    except RuntimeError as exc:
        diagnostics.append(str(exc))
        raise _bundled_load_error(
            module_name,
            probe_text,
            system_text,
            "加载本地 {} 模块失败: {}".format(module_name, exc),
        ) from exc
    if _rc(load) == 0:
        return
    if module_dir.exists():
        # Another loader raced us and won; the module is available regardless.
        return
    diagnostics.append(
        "insmod {} 失败: rc={}, stderr={!r}".format(
            module_name, _rc(load), _stderr_text(load)
        )
    )
    raise _bundled_load_error(
        module_name,
        probe_text,
        system_text,
        "加载本地 {} 模块失败: rc={}, stderr={!r}".format(
            module_name, _rc(load), _stderr_text(load)
        ),
    )


def ensure_cgroup_support(config, root="/", runner=None, diagnostics=None):
    """Make ``xt_cgroup`` available before the FEX core is launched.

    Only ``engine == "fex"`` is accepted; anything else is a configuration
    error. For ``fex`` an already-present ``sys/module/xt_cgroup`` is enough;
    otherwise the system ``modprobe`` is tried and, only when that fails, a
    locally bundled module is validated against the running kernel and the
    recorded ``module_sha256`` digest before ``x_tables`` and ``insmod`` are
    used. A concurrent load that wins the race is accepted.
    """
    if config.get("engine") != "fex":
        raise RuntimeError("unsupported engine: {!r}".format(config.get("engine")))
    _ensure_module(
        config,
        root,
        "xt_cgroup",
        "module_sha256",
        ["x_tables"],
        runner=runner,
        diagnostics=diagnostics,
    )


def ensure_nat_support(config, root="/", runner=None, diagnostics=None):
    """Make ``xt_nat`` available before the FEX core is launched.

    Only ``engine == "fex"`` is accepted; anything else is a configuration
    error. For ``fex`` an already-present ``sys/module/xt_nat`` is enough;
    otherwise the system ``modprobe`` is tried and, only when that fails, a
    locally bundled module is validated against the running kernel and the
    recorded ``nat_module_sha256`` digest before its dependencies
    (``x_tables`` and ``nf_nat``, one ``modprobe -a``) and ``insmod`` are used.
    A concurrent load that wins the race is accepted.
    """
    if config.get("engine") != "fex":
        raise RuntimeError("unsupported engine: {!r}".format(config.get("engine")))
    _ensure_module(
        config,
        root,
        "xt_nat",
        "nat_module_sha256",
        ["-a", "x_tables", "nf_nat"],
        runner=runner,
        diagnostics=diagnostics,
    )


def _startup_error_path(config):
    """Our own diagnosis file, always beside the PID file we publish."""
    return Path(config["pid_file"]).with_name(STARTUP_ERROR_NAME)


def _write_startup_error(config, reason):
    """Persist the refusal reason for the manager; never mask the original.

    The write is best effort: a filesystem problem must not replace the real
    kernel-compat reason with an unrelated I/O error, so a failure here is
    swallowed (the reason is still logged and printed).
    """
    try:
        _startup_error_path(config).write_text(reason + "\n", encoding="utf-8")
    except OSError:
        pass


def _preflight(config, log):
    """Run the kernel-compat preflight, reporting a failure to log+stderr.

    Only invoked when the launch config actually carries ``kernel_compat``, so
    legacy standalone configs keep their previous behaviour. Returns ``True``
    when the run may proceed, ``False`` when the caller must abort before
    spawning the core; the raw Chinese reason is also left in our own
    ``startup-error.txt`` so the manager can show it instead of a generic
    "start failed".
    """
    if "kernel_compat" not in config:
        return True
    try:
        ensure_cgroup_support(config, root="/", runner=None)
        ensure_nat_support(config, root="/", runner=None)
    except RuntimeError as exc:
        message = "[network-preflight] {}".format(exc)
        _write_startup_error(config, str(exc))
        try:
            log.write((message + "\n").encode("utf-8"))
            log.flush()
        except OSError:
            pass
        sys.stderr.write(message + "\n")
        return False
    return True


class _Stop(object):
    """Records a forwarded shutdown request from a signal handler."""

    def __init__(self):
        self.requested = False
        self.signum = None


def _install_signal_handlers(stop):
    def _handle(signum, frame):
        stop.requested = True
        stop.signum = signum

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)


def _normalize_rc(rc):
    if rc is None:
        return 0
    if rc < 0:
        return 128 + (-rc)
    return rc


def _signal_child(child, signum):
    try:
        child.send_signal(signum)
    except (ProcessLookupError, OSError):
        pass


def _signal_group(pgid, signum):
    try:
        os.killpg(pgid, signum)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _probe_group(pgid):
    """Fallback membership probe when ``/proc`` cannot be listed."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _group_has_live_member(pgid):
    """Whether ``pgid`` still holds a live (non-zombie) process.

    Only ``/proc`` entries whose process-group id matches are considered. A
    zombie orphan (its parent already gone and PID 1 not reaping it) is not
    counted as live, so a bounded drain can finish once real work is done.
    """
    if pgid <= 0:
        return False
    try:
        entries = os.listdir("/proc")
    except OSError:
        return _probe_group(pgid)
    for name in entries:
        if not name.isdigit():
            continue
        try:
            with open("/proc/{}/stat".format(name), "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        end = data.rfind(b")")  # comm may contain ')'; fields follow it
        if end < 0:
            continue
        fields = data[end + 2:].split()  # state, ppid, pgrp, ...
        if len(fields) < 3 or fields[0] == b"Z":
            continue
        try:
            member_pgid = int(fields[2])
        except ValueError:
            continue
        if member_pgid == pgid:
            return True
    return False


def _drain(child, pgid, deadline):
    """Wait until the direct child is reaped and its whole group is quiet.

    Polling the child reaps it, which is what lets a same-group guardian notice
    that its parent is gone and finish its own cleanup.
    """
    while True:
        if child.poll() is not None and not _group_has_live_member(pgid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def _escalate_group(child, pgid):
    """After the grace deadline, signal/kill only this core's own group."""
    _signal_group(pgid, signal.SIGTERM)
    if _drain(child, pgid, time.monotonic() + 1.0):
        return
    _signal_group(pgid, signal.SIGKILL)
    _drain(child, pgid, time.monotonic() + 5.0)


def _stop_core(child, timeout):
    """Forward a stop to the direct core, then drain its own process group.

    One shared deadline bounds the graceful phase so the configured grace is
    never spent twice; escalation stays inside the group we created.
    """
    pgid = child.pid
    deadline = time.monotonic() + max(timeout, 0.0)
    _signal_child(child, signal.SIGTERM)
    if _drain(child, pgid, deadline):
        return
    _escalate_group(child, pgid)


def _cleanup_group(child, pgid, timeout):
    """Let same-group guardians finish after a natural core exit, then drain."""
    deadline = time.monotonic() + max(timeout, 0.0)
    if _drain(child, pgid, deadline):
        return
    _escalate_group(child, pgid)


def _reap_child(child):
    """Best-effort final reap so no exited child is left unreaped."""
    if child is None:
        return
    try:
        child.poll()
    except Exception:
        pass


def _write_pid(path, pid):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(str(pid))


def _remove_owned_pid(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _remove_official_pid(child):
    if child is None:
        return
    try:
        with open(OFFICIAL_PID_FILE, encoding="utf-8") as handle:
            content = handle.read().strip()
    except OSError:
        return
    if content.isdigit() and int(content) == child.pid:
        _remove_owned_pid(OFFICIAL_PID_FILE)


def _cleanup_pid_files(config, child):
    _remove_owned_pid(config["pid_file"])
    _remove_official_pid(child)


def _notify_address():
    """Return the systemd notify socket address, or ``None`` when unset.

    A leading ``@`` selects the Linux abstract AF_UNIX namespace, which is
    expressed as a leading NUL byte followed by the raw name. When
    ``NOTIFY_SOCKET`` is unset the handshake is skipped entirely, so manual and
    standalone runs behave exactly as before.
    """
    path = os.environ.get("NOTIFY_SOCKET")
    if not path:
        return None
    if path.startswith("@"):
        return b"\0" + path[1:].encode("utf-8")
    return path


def _send_ready(address):
    """Send a single ``READY=1`` datagram; a send failure propagates."""
    if address is None:
        return
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"READY=1", address)


def _supervise(child, config, stop):
    """Poll the core: forward a stop request, or drain the group on exit.

    When ``NOTIFY_SOCKET`` is set the direct core earns one ``READY=1`` only
    after it has stayed alive for the stabilization window. Every loop first
    honors a stop request or natural exit, so an early-failing core is reported
    by its own exit code and never notified as ready.
    """
    pgid = child.pid
    timeout = config["shutdown_timeout"]
    address = _notify_address()
    notified = False
    started = time.monotonic()
    while True:
        if stop.requested:
            _stop_core(child, timeout)
            return 0
        rc = child.poll()
        if rc is not None:
            # Natural exit: give any same-group guardian a bounded chance to
            # clean up after noticing the gone parent, then drain the group.
            _cleanup_group(child, pgid, timeout)
            return rc
        if (
            address is not None
            and not notified
            and time.monotonic() - started >= READY_STABILIZE_SECONDS
        ):
            # Raises on failure so the post-spawn handler stops/reaps our core.
            _send_ready(address)
            notified = True
        time.sleep(0.02)


def run(launch_path):
    try:
        config = load_config(launch_path)
    except ConfigError as exc:
        sys.stderr.write("supervisor: {}\n".format(exc))
        return PREFLIGHT_REFUSED_EXIT

    stop = _Stop()
    _install_signal_handlers(stop)

    argv = build_command(config)
    env = _child_env(config)

    child = None
    rc = None
    failed = False
    try:
        log = open(config["log_file"], "ab")
        try:
            if not _preflight(config, log):
                # A failed kernel-compat preflight aborts before the core is
                # spawned: no Popen, no PID publication, no READY=1. The exit
                # status is the preflight-refused one the unit maps to
                # RestartPreventExitStatus, so an unsupported kernel is a
                # configuration failure rather than a restart loop.
                return PREFLIGHT_REFUSED_EXIT
            try:
                child = subprocess.Popen(
                    argv,
                    shell=False,
                    cwd=config["cwd"],
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=log,
                    start_new_session=True,
                )
            except OSError as exc:
                sys.stderr.write("supervisor: cannot spawn core: {}\n".format(exc))
                return 127

            try:
                _write_pid(config["pid_file"], child.pid)
                rc = _supervise(child, config, stop)
            except BaseException as exc:
                # Any post-spawn failure (e.g. PID publication) must not leak
                # the core/group or leave a live child behind.
                sys.stderr.write("supervisor: {}\n".format(exc))
                failed = True
        finally:
            try:
                log.close()
            except OSError:
                pass
            if child is not None:
                if failed:
                    _stop_core(child, config["shutdown_timeout"])
                _reap_child(child)
    finally:
        _cleanup_pid_files(config, child)

    if failed:
        return 1
    return _normalize_rc(rc)


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: supervisor.py <launch-config.json>\n")
        return 2
    return run(argv[1])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
