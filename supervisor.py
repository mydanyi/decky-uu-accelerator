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


_KERNEL_IDENTITY_FIELDS = ("kernel_release", "kernel_version", "machine", "config_sha256")


def _compat_entries(manifest):
    """Return every accepted kernel identity, baseline included.

    The shipped top-level ``kernel_release``/``kernel_version``/``machine``/
    ``config_sha256`` stay one supported entry, so an already working install
    keeps loading exactly as before. ``compatible_kernels`` may only *add*
    entries, and each of them must be a complete four-field object: a malformed
    list is a hard error rather than a silently widened allow-list, because
    every accepted entry permits loading our bundled module bytes.

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

    The runtime identity is the four-field tuple (release, version, machine,
    normalized kernel-config digest); it must equal *one* accepted entry -- the
    legacy top-level baseline or an exact ``compatible_kernels`` profile. The
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
    actual = {
        "kernel_release": uname.release,
        "kernel_version": uname.version,
        "machine": uname.machine,
        "config_sha256": _normalized_config_sha256(Path(root) / "proc" / "config.gz"),
    }
    matched = None
    for entry in entries:
        if all(entry[key] == actual[key] for key in _KERNEL_IDENTITY_FIELDS):
            matched = entry
            break
    if matched is None:
        raise RuntimeError(
            (
                "当前内核不在兼容列表: release={}，version={}，架构={}，配置={}；"
                "该内核既未随插件构建，也未验证过本插件所带模块，"
                "请更新加速器插件或安装适配当前内核的系统模块"
            ).format(
                uname.release, uname.version, uname.machine, actual["config_sha256"]
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


def _ensure_module(config, root, module_name, digest_key, dependency_args, runner=None):
    """Make ``module_name`` available, sharing the loader for xt_cgroup/xt_nat.

    An already-present ``sys/module/<module_name>`` is enough; otherwise the
    system ``modprobe`` is tried and, only when that fails, a locally bundled
    module is validated against the running kernel and the recorded digest
    before ``dependency_args`` and ``insmod`` are used. A concurrent load that
    wins the race is accepted, and every error names the module actually being
    loaded.
    """
    root = Path(root)
    module_dir = root / "sys" / "module" / module_name
    if module_dir.exists():
        return

    runner = subprocess.run if runner is None else runner

    probe = _invoke(
        runner, [_system_tool("modprobe"), module_name], "modprobe {}".format(module_name)
    )
    if _rc(probe) == 0:
        return

    compat = config.get("kernel_compat")
    module_path = _validate_kernel_compat(
        compat, root, module_name=module_name, digest_key=digest_key
    )

    dependency = _invoke(
        runner,
        [_system_tool("modprobe")] + list(dependency_args),
        "modprobe {}".format(" ".join(dependency_args)),
    )
    if _rc(dependency) != 0:
        raise RuntimeError(
            "加载 {} 依赖模块失败: {}".format(module_name, " ".join(dependency_args))
        )

    load = _invoke(runner, [_system_tool("insmod"), module_path], "insmod {}".format(module_name))
    if _rc(load) == 0:
        return
    if module_dir.exists():
        # Another loader raced us and won; the module is available regardless.
        return
    raise RuntimeError("加载本地 {} 模块失败".format(module_name))


def ensure_cgroup_support(config, root="/", runner=None):
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
    _ensure_module(config, root, "xt_cgroup", "module_sha256", ["x_tables"], runner=runner)


def ensure_nat_support(config, root="/", runner=None):
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
