"""Platform detection and engine selection for the UU accelerator plugin.

The host architecture is taken from the real PID 1 binary (``/proc/1/exe``) so
that a translated Decky backend (which reports the emulated uname) can never
mislead us. ``uname`` is only a fallback when PID 1 cannot be inspected.
"""

import os
import re
import shutil
import stat
import struct
from pathlib import Path

_ELF_MAGIC = b"\x7fELF"
_ELFCLASS64 = 2
_ELFDATA2LSB = 1
_E_MACHINE_OFFSET = 18
_ELF_MACHINES = {62: "x86_64", 183: "aarch64"}
_SUPPORTED_ARCHES = ("x86_64", "aarch64")
_UNAME_MACHINES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
}
_OS_RELEASE_PATHS = ("etc/os-release", "usr/lib/os-release")
_ARMADA_MARKER = "usr/lib/armada/version"
_LEGACY_UNITS = (
    "etc/systemd/system/uuplugin.service",
    "usr/lib/systemd/system/uuplugin.service",
)
_FEX_INTERPRETER = "FEXInterpreter"
_FEX_BINARY = "FEX"
_ARMADA_FEX_PATH = "usr/bin/FEX"

_ENGINE_SPECS = {
    "fex": {"package_type": "steam-deck-plugin-x86_64", "expected_arch": "x86_64"},
}


def elf_machine(header):
    """Return ``"x86_64"`` or ``"aarch64"`` for a raw ELF header.

    Only 64-bit little-endian ELF files with a supported ``e_machine`` are
    accepted; everything else raises :class:`ValueError`.
    """
    if not isinstance(header, (bytes, bytearray, memoryview)):
        raise ValueError("ELF 文件头必须是字节串")
    header = bytes(header)
    if len(header) < 20 or header[:4] != _ELF_MAGIC:
        raise ValueError("无效的 ELF 文件头")
    if header[4] != _ELFCLASS64 or header[5] != _ELFDATA2LSB:
        raise ValueError("仅支持 64 位小端 ELF 文件")
    (machine,) = struct.unpack_from("<H", header, _E_MACHINE_OFFSET)
    arch = _ELF_MACHINES.get(machine)
    if arch is None:
        raise ValueError("不支持的 ELF 架构: e_machine={}".format(machine))
    return arch


def detect_platform(root, home, which=None):
    """Detect the host platform without mutating it.

    ``root`` is the filesystem root to inspect (allows tests to use a fixture
    tree), ``home`` is the real Decky home supplied by the caller and is
    returned unchanged.
    """
    root = Path(root)
    which = shutil.which if which is None else which

    arch = _arch_from_pid1(root)
    if arch is None:
        arch = _arch_from_uname()
    if arch not in _SUPPORTED_ARCHES:
        raise ValueError("不支持的主机架构: {}".format(arch))

    os_id = _read_os_id(root)
    is_armada = os_id == "armada" or (root / _ARMADA_MARKER).is_file()

    fex_path = None
    if arch == "aarch64":
        fex_path = which(_FEX_INTERPRETER) or which(_FEX_BINARY) or None
        if fex_path is None and is_armada:
            fex_path = _armada_fex_fallback(root)

    if arch == "aarch64" and fex_path:
        engines = ["fex"]
        recommended = "fex"
    else:
        engines = []
        recommended = None

    legacy_install = any((root / unit).is_file() for unit in _LEGACY_UNITS)

    return {
        "os_id": os_id,
        "is_armada": is_armada,
        "arch": arch,
        "home": home,
        "fex_path": fex_path,
        "legacy_install": legacy_install,
        "engines": engines,
        "recommended_engine": recommended,
    }


def select_engine(platform, request="auto"):
    """Resolve a requested engine to a concrete package choice.

    Only ``"auto"`` and ``"fex"`` are allowed; the plugin is FEX-only on an
    ARM64 host with a discovered FEX interpreter. An unavailable or unknown
    request always raises instead of silently switching to another engine. A
    preexisting legacy installation is refused on *every* route: our plugin
    never takes over or replaces a UU install it did not create, so an explicit
    engine must not become a loophole around the guard.
    """
    if platform.get("legacy_install"):
        raise ValueError("检测到已存在的 uuplugin 安装，本插件不会接管或替换它")

    if request not in ("auto", "fex"):
        raise ValueError("不支持的引擎: {}；本插件仅支持 fex".format(request))

    arch = platform.get("arch")
    if arch != "aarch64":
        raise ValueError("仅在 ARM64 主机上支持 fex 引擎，当前架构: {}".format(arch))

    fex_path = platform.get("fex_path")
    if not fex_path:
        raise ValueError("未找到 FEXInterpreter，无法使用 fex 引擎")

    engines = list(platform.get("engines") or ())
    if "fex" not in engines:
        raise ValueError("引擎 fex 在当前平台不可用")

    launch_prefix = [fex_path]

    spec = _ENGINE_SPECS["fex"]
    return {
        "engine": "fex",
        "package_type": spec["package_type"],
        "expected_arch": spec["expected_arch"],
        "launch_prefix": launch_prefix,
    }


def _arch_from_pid1(root):
    """Architecture of the real init binary, or ``None`` when unreadable.

    Only the first 64 bytes are read: that is exactly one ELF header, and it
    avoids slurping a potentially large init binary (or following a special
    ``/proc`` link further than needed). A PID 1 that *is* readable but is not
    a supported ELF raises instead of quietly falling back to the emulated
    ``uname`` — otherwise a translated backend could mask the real host.
    """
    try:
        with open(root / "proc/1/exe", "rb") as handle:
            header = handle.read(64)
    except OSError:
        return None
    return elf_machine(header)


def _arch_from_uname():
    uname = getattr(os, "uname", None)
    if uname is None:
        raise ValueError("无法读取 /proc/1/exe，且当前系统不支持 uname")
    machine = (getattr(uname(), "machine", "") or "").lower()
    arch = _UNAME_MACHINES.get(machine)
    if arch is None:
        raise ValueError("不支持的主机架构: {}".format(machine or "unknown"))
    return arch


def _read_os_id(root):
    for relative in _OS_RELEASE_PATHS:
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = re.search(r'^ID\s*=\s*"?([^"\n\r]*)"?\s*$', text, re.MULTILINE)
        if match and match.group(1):
            return match.group(1).strip()
    return ""


def _armada_fex_fallback(root):
    """Armada ships FEX at ``/usr/bin/FEX`` even when it is not on PATH."""
    candidate = Path(root) / _ARMADA_FEX_PATH
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None
