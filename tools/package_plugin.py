#!/usr/bin/env python3
"""Package the UU加速器 Decky plugin into a distributable ZIP.

Standard-library only (no third-party imports). Intended to be run on the build
host inside the project checkout, for example::

    python3 tools/package_plugin.py --output output

The result is written as ``<output>/uu-accelerator-v<version>.zip`` containing a
single top-level ``uu-accelerator/`` directory, so it can be installed through
Decky's "Install Plugin from ZIP" developer flow.

The archive is intentionally minimal and deterministic:

* only the listed root files are included;
* only regular ``.py`` files under ``py_modules/`` are included (recursively);
* the known ``compat/armada-7.2.6/`` kernel-module files are included from an
  explicit list (the prebuilt baseline and child-profile modules, their GPL
  sources, license, Makefile, manifest, README);
* tests, tooling, node_modules, caches and the official UU payload are excluded;
* entries are sorted and given fixed metadata + 0644 permissions.

Exactly eight ELF objects may be packaged: the two prebuilt baseline
``compat/armada-7.2.6/xt_cgroup.ko`` / ``compat/armada-7.2.6/xt_nat.ko``, the
two modules of each known child profile directory (``oct26`` and ``oct29``),
and the two portable modules ``compat/armada-7.2.6/portable/xt_cgroup.ko`` /
``compat/armada-7.2.6/portable/xt_nat.ko``. Each must be an ELF64 little-endian
``ET_REL`` AArch64 relocatable. Baseline and child modules must match the
digest keys recorded in the shipped ``manifest.json`` (child modules via the
unique ``compatible_kernels`` profile whose ``module_dir`` equals that child
directory); portable modules and their ``*.abi.json`` sidecars must match the
top-level ``portable_modules`` mapping. Any other ELF content makes packaging
fail. The official UU core is always downloaded at runtime and is never
packaged.

It never downloads anything and never touches the network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

# Top-level directory inside the ZIP (Decky installs it as the plugin folder).
PLUGIN_DIR = "uu-accelerator"

# Expected identity of the plugin being packaged.
EXPECTED_PACKAGE_NAME = "uu-accelerator"

# Exact name that plugin.json must declare.
EXPECTED_PLUGIN_NAME = "UU加速器"

# Python modules that must exist within the plugin package.
REQUIRED_PY_MODULES = (
    "__init__.py",
    "platform.py",
    "payload.py",
    "manager.py",
    "service.py",
    "binding.py",
)

# Root files that must exist and be included, in this order.
REQUIRED_ROOT_FILES = (
    "plugin.json",
    "package.json",
    "main.py",
    "supervisor.py",
    "kernel_abi.py",
    "dist/index.js",
    "LICENSE",
    "README.md",
)

# Python package that must exist and contain at least one module.
PY_MODULES_PACKAGE = Path("py_modules") / "uu_accelerator"

# Kernel-module compatibility payload. The four prebuilt modules are the only
# permitted ELF objects and must ship together with their GPL sources and the
# license.
COMPAT_DIR = Path("compat") / "armada-7.2.6"

# Known child profile directories (each holding xt_cgroup.ko / xt_nat.ko and
# bound to the unique ``compatible_kernels`` profile with that ``module_dir``).
COMPAT_CHILD_DIRS = ("oct26", "oct29")
COMPAT_OCT26_DIR = COMPAT_DIR / "oct26"
COMPAT_OCT29_DIR = COMPAT_DIR / "oct29"

# The only paths (below the plugin root) allowed to contain ELF bytes, each
# paired with the manifest key whose SHA-256 must match that module. Baseline
# modules use the top-level digest keys; child modules use the digests of the
# unique ``compatible_kernels`` profile whose ``module_dir`` matches the child
# directory (never the top-level digests).
COMPAT_MODULES = (
    ((COMPAT_DIR / "xt_cgroup.ko").as_posix(), "module_sha256"),
    ((COMPAT_DIR / "xt_nat.ko").as_posix(), "nat_module_sha256"),
) + tuple(
    ((COMPAT_DIR / child / name).as_posix(), key)
    for child in COMPAT_CHILD_DIRS
    for name, key in (
        ("xt_cgroup.ko", "module_sha256"),
        ("xt_nat.ko", "nat_module_sha256"),
    )
)

# The set of compat paths permitted to contain ELF bytes.
COMPAT_MODULE_PATHS = tuple(relative for relative, _key in COMPAT_MODULES)

# Compat files that must exist and be included, in this order.
REQUIRED_COMPAT_FILES = (
    "xt_cgroup.ko",
    "xt_cgroup.c",
    "xt_nat.ko",
    "xt_nat.c",
    "Makefile",
    "GPL-2.0.txt",
    "manifest.json",
    "README.md",
)

# Additional child-profile modules that must exist and be included.
REQUIRED_CHILD_FILES = (
    "xt_cgroup.ko",
    "xt_nat.ko",
)

# Portable kernel-module payload: one ELF module plus a JSON ABI descriptor for
# each portable module, bound to the top-level ``portable_modules`` mapping in
# ``manifest.json``.
PORTABLE_DIR = COMPAT_DIR / "portable"
PORTABLE_MODULE_NAMES = ("xt_cgroup", "xt_nat")

# (relative path, module name, manifest digest key) per portable module.
PORTABLE_MODULES = tuple(
    ((PORTABLE_DIR / f"{name}.ko").as_posix(), name, "module_sha256")
    for name in PORTABLE_MODULE_NAMES
)

# (relative path, module name) per portable ABI descriptor.
PORTABLE_ABI_FILES = tuple(
    ((PORTABLE_DIR / f"{name}.abi.json").as_posix(), name)
    for name in PORTABLE_MODULE_NAMES
)

PORTABLE_MODULE_PATHS = tuple(relative for relative, _name, _key in PORTABLE_MODULES)

# Every path permitted to contain ELF bytes (legacy compat + portable).
ELF_MODULE_PATHS = COMPAT_MODULE_PATHS + PORTABLE_MODULE_PATHS

# Required shape of a portable ABI descriptor.
PORTABLE_ABI_SCHEMA = 1
PORTABLE_ABI_KERNEL_RELEASE = "7.2.6"
PORTABLE_ABI_MACHINE = "aarch64"

# License the compat manifest must declare (matches the shipped GPL source).
EXPECTED_COMPAT_LICENSE = "GPL-2.0-only"

# Directory / file names that must never be packaged.
EXCLUDED_DIR_NAMES = {
    ".git",
    ".github",
    "node_modules",
    "output",
    "tests",
    "tools",
    "__pycache__",
    ".cache",
    ".rollup.cache",
    ".mypy_cache",
    ".pytest_cache",
}

# Fixed, reproducible ZIP member timestamp (the ZIP epoch).
_ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)
_LINUX_FILE_MODE = 0o644 << 16

# ELF header identity required of the permitted kernel modules.
_ELF_MAGIC = b"\x7fELF"
_ELF_CLASS_64 = 2
_ELF_DATA_LSB = 1
_ET_REL = 1
_EM_AARCH64 = 183

# Identity fields a ``compatible_kernels`` profile must declare non-empty.
_CHILD_IDENTITY_FIELDS = (
    "kernel_release",
    "kernel_version",
    "machine",
    "config_sha256",
)


def _fail(message: str) -> "None":
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        _fail(f"required file is missing: {path}")
    except json.JSONDecodeError as exc:
        _fail(f"invalid JSON in {path}: {exc}")
    if not isinstance(data, dict):
        _fail(f"expected a JSON object in {path}")
    return data


def _validate_metadata(root: Path) -> str:
    """Validate plugin/package metadata and return the plugin version."""
    plugin = _load_json(root / "plugin.json")
    package = _load_json(root / "package.json")

    plugin_name = plugin.get("name")
    if plugin_name != EXPECTED_PLUGIN_NAME:
        _fail(
            "plugin.json 'name' must be "
            f"{EXPECTED_PLUGIN_NAME!r}, got {plugin_name!r}"
        )

    api_version = plugin.get("api_version")
    if not isinstance(api_version, int) or isinstance(api_version, bool):
        _fail("plugin.json must define an integer 'api_version'")

    package_name = package.get("name")
    if package_name != EXPECTED_PACKAGE_NAME:
        _fail(
            "package.json 'name' must be "
            f"{EXPECTED_PACKAGE_NAME!r}, got {package_name!r}"
        )

    version = package.get("version")
    if not isinstance(version, str) or not version.strip():
        _fail("package.json must define a non-empty 'version'")
    if not re.fullmatch(r"[0-9A-Za-z._-]+", version):
        _fail(f"package.json 'version' has unsupported characters: {version!r}")

    return version


def _collect_root_files(root: Path) -> "list[tuple[Path, str]]":
    entries: "list[tuple[Path, str]]" = []
    for relative in REQUIRED_ROOT_FILES:
        path = root / relative
        if not path.is_file():
            _fail(f"required root file is missing: {relative}")
        entries.append((path, relative))
    return entries


def _collect_python_modules(root: Path) -> "list[tuple[Path, str]]":
    package_dir = root / PY_MODULES_PACKAGE
    if not package_dir.is_dir():
        _fail(f"required package directory is missing: {PY_MODULES_PACKAGE}")

    for module in REQUIRED_PY_MODULES:
        if not (package_dir / module).is_file():
            _fail(f"required module is missing: {PY_MODULES_PACKAGE / module}")

    collected: "list[tuple[Path, str]]" = []
    for path in sorted(package_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix != ".py":
            continue
        if any(part in EXCLUDED_DIR_NAMES for part in path.relative_to(root).parts):
            continue
        collected.append((path, path.relative_to(root).as_posix()))

    if not collected:
        _fail(f"no Python modules found under {PY_MODULES_PACKAGE}")
    return collected


def _is_compat_module_elf(data: bytes) -> bool:
    """True only for an ELF64 little-endian, AArch64 ``ET_REL`` relocatable."""
    if len(data) < 20 or data[:4] != _ELF_MAGIC:
        return False
    if data[4] != _ELF_CLASS_64 or data[5] != _ELF_DATA_LSB:
        return False
    e_type = int.from_bytes(data[16:18], "little")
    e_machine = int.from_bytes(data[18:20], "little")
    return e_type == _ET_REL and e_machine == _EM_AARCH64


def _child_profile(manifest: dict, module_dir: str) -> dict:
    """Return the unique ``compatible_kernels`` profile for ``module_dir``."""
    profiles = manifest.get("compatible_kernels")
    if not isinstance(profiles, list):
        _fail("compat manifest.json must define a 'compatible_kernels' list")

    matches = []
    for profile in profiles:
        if not isinstance(profile, dict):
            _fail("compat manifest.json 'compatible_kernels' entries must be objects")
        if profile.get("module_dir") == module_dir:
            matches.append(profile)

    if len(matches) != 1:
        _fail(
            "compat manifest.json must define exactly one compatible_kernels "
            f"profile with module_dir {module_dir!r}, got {len(matches)}"
        )

    profile = matches[0]
    for field in _CHILD_IDENTITY_FIELDS:
        value = profile.get(field)
        if not isinstance(value, str) or not value.strip():
            _fail(
                "compat manifest.json profile must define a non-empty "
                f"{module_dir!r} {field!r}"
            )
    for key in ("module_sha256", "nat_module_sha256"):
        value = profile.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            _fail(
                "compat manifest.json profile must define a hex "
                f"{module_dir!r} {key!r}"
            )
    return profile


def _validate_compat_module(root: Path, manifest: dict) -> None:
    """Reject unless each compat module is the expected, manifest-bound ELF.

    Baseline modules are bound to the top-level ``module_sha256`` /
    ``nat_module_sha256``; each child profile's modules are bound to the
    digests of the unique ``compatible_kernels`` profile whose ``module_dir``
    equals that child directory.
    """
    child_profiles = {
        child: _child_profile(manifest, child) for child in COMPAT_CHILD_DIRS
    }

    for relative, digest_key in COMPAT_MODULES:
        module_path = root / relative
        data = module_path.read_bytes()

        if not _is_compat_module_elf(data):
            _fail(
                "compat module must be an ELF64 little-endian AArch64 ET_REL "
                f"relocatable: {relative}"
            )

        child_dir = next(
            (
                child
                for child in COMPAT_CHILD_DIRS
                if relative.startswith((COMPAT_DIR / child).as_posix() + "/")
            ),
            None,
        )
        if child_dir is not None:
            expected_digest = child_profiles[child_dir].get(digest_key)
            source = f"{child_dir} profile {digest_key!r}"
        else:
            expected_digest = manifest.get(digest_key)
            source = f"manifest.json {digest_key!r}"

        if not isinstance(expected_digest, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", expected_digest
        ):
            _fail(f"compat {source} must be a hex digest")

        actual_digest = _sha256(module_path)
        if actual_digest.lower() != expected_digest.lower():
            _fail(
                f"compat module digest does not match {source}: "
                f"{actual_digest} != {expected_digest}"
            )

    license_name = manifest.get("license")
    if license_name != EXPECTED_COMPAT_LICENSE:
        _fail(
            "compat manifest.json 'license' must be "
            f"{EXPECTED_COMPAT_LICENSE!r}, got {license_name!r}"
        )


def _portable_digest(manifest: dict, name: str, key: str) -> str:
    """Return the hex ``portable_modules`` digest for ``name``/``key``."""
    portable = manifest.get("portable_modules")
    if not isinstance(portable, dict):
        _fail("compat manifest.json must define a 'portable_modules' object")
    entry = portable.get(name)
    if not isinstance(entry, dict):
        _fail(f"compat manifest.json 'portable_modules' must define {name!r}")
    value = entry.get(key)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        _fail(
            "compat manifest.json portable_modules must define a hex "
            f"{name!r} {key!r}"
        )
    return value


def _validate_portable_modules(root: Path, manifest: dict) -> None:
    """Reject unless each portable module is the manifest-bound ELF."""
    for relative, name, digest_key in PORTABLE_MODULES:
        module_path = root / relative
        if not module_path.is_file():
            _fail(f"required portable module is missing: {relative}")
        if not _is_compat_module_elf(module_path.read_bytes()):
            _fail(
                "portable module must be an ELF64 little-endian AArch64 ET_REL "
                f"relocatable: {relative}"
            )
        expected = _portable_digest(manifest, name, digest_key)
        actual = _sha256(module_path)
        if actual.lower() != expected.lower():
            _fail(
                "portable module digest does not match portable_modules "
                f"{name!r} {digest_key!r}: {actual} != {expected}"
            )


def _validate_portable_abi(root: Path, manifest: dict) -> None:
    """Reject unless each portable ABI descriptor matches module and schema."""
    for relative, name in PORTABLE_ABI_FILES:
        abi_path = root / relative
        if not abi_path.is_file():
            _fail(f"required portable ABI file is missing: {relative}")

        expected = _portable_digest(manifest, name, "abi_sha256")
        actual = _sha256(abi_path)
        if actual.lower() != expected.lower():
            _fail(
                "portable ABI digest does not match portable_modules "
                f"{name!r} 'abi_sha256': {actual} != {expected}"
            )

        abi = _load_json(abi_path)
        schema = abi.get("schema")
        if type(schema) is not int or schema != PORTABLE_ABI_SCHEMA:
            _fail(f"portable ABI {relative} must declare integer schema 1")
        if abi.get("kernel_release") != PORTABLE_ABI_KERNEL_RELEASE:
            _fail(
                f"portable ABI {relative} 'kernel_release' must be "
                f"{PORTABLE_ABI_KERNEL_RELEASE!r}"
            )
        if abi.get("machine") != PORTABLE_ABI_MACHINE:
            _fail(
                f"portable ABI {relative} 'machine' must be "
                f"{PORTABLE_ABI_MACHINE!r}"
            )

        module_relative = (PORTABLE_DIR / f"{name}.ko").as_posix()
        module_digest = _sha256(root / module_relative)
        recorded = abi.get("module_sha256")
        if not isinstance(recorded, str) or recorded.strip().lower() != module_digest:
            _fail(
                f"portable ABI {relative} 'module_sha256' must equal the module "
                f"digest {module_digest}"
            )

        records = abi.get("records")
        if not isinstance(records, list) or not records:
            _fail(f"portable ABI {relative} must define a non-empty 'records' list")
        record_names = set()
        for record in records:
            if not isinstance(record, dict):
                _fail(f"portable ABI {relative} 'records' entries must be objects")
            record_name = record.get("name")
            if not isinstance(record_name, str) or not record_name:
                _fail(
                    f"portable ABI {relative} 'records' entries must define a "
                    "non-empty 'name'"
                )
            record_names.add(record_name)

        for field in ("public_roots", "required_names"):
            values = abi.get(field)
            if not isinstance(values, list) or not values:
                _fail(
                    f"portable ABI {relative} must define a non-empty {field!r} list"
                )
            if not all(isinstance(item, str) and item for item in values):
                _fail(
                    f"portable ABI {relative} {field!r} must contain non-empty "
                    "strings"
                )
            uncovered = sorted(set(values) - record_names)
            if uncovered:
                _fail(
                    f"portable ABI {relative} {field!r} names are not covered by "
                    f"'records': {', '.join(uncovered)}"
                )


def _collect_compat_files(root: Path) -> "list[tuple[Path, str]]":
    compat_dir = root / COMPAT_DIR
    if not compat_dir.is_dir():
        _fail(f"required compat directory is missing: {COMPAT_DIR}")

    entries: "list[tuple[Path, str]]" = []
    for name in REQUIRED_COMPAT_FILES:
        relative = (COMPAT_DIR / name).as_posix()
        path = compat_dir / name
        if not path.is_file():
            _fail(f"required compat file is missing: {relative}")
        entries.append((path, relative))

    for child in COMPAT_CHILD_DIRS:
        child_root = root / COMPAT_DIR / child
        if not child_root.is_dir():
            _fail(f"required compat directory is missing: {COMPAT_DIR / child}")
        for name in REQUIRED_CHILD_FILES:
            relative = (COMPAT_DIR / child / name).as_posix()
            path = child_root / name
            if not path.is_file():
                _fail(f"required compat file is missing: {relative}")
            entries.append((path, relative))

    manifest = _load_json(root / COMPAT_DIR / "manifest.json")
    _validate_compat_module(root, manifest)
    _validate_portable_modules(root, manifest)
    _validate_portable_abi(root, manifest)

    for relative, _name, _key in PORTABLE_MODULES:
        entries.append((root / relative, relative))
    for relative, _name in PORTABLE_ABI_FILES:
        entries.append((root / relative, relative))
    return entries


def _entry_arcname(relative: str) -> str:
    return f"{PLUGIN_DIR}/{relative}"


def _write_zip(zip_path: Path, entries: "list[tuple[Path, str]]") -> int:
    """Write a deterministic ZIP; return the number of members written."""
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(entries, key=lambda item: item[1])

    with zipfile.ZipFile(
        zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for source, relative in ordered:
            data = source.read_bytes()
            if data[:4] == _ELF_MAGIC and relative not in ELF_MODULE_PATHS:
                _fail(f"refusing to package ELF binary: {relative}")
            info = zipfile.ZipInfo(_entry_arcname(relative), date_time=_ZIP_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = _LINUX_FILE_MODE
            archive.writestr(info, data)

    return len(ordered)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_args(argv: "list[str] | None") -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Package the UU加速器 Decky plugin into a distributable ZIP."
    )
    parser.add_argument(
        "--output",
        default="output",
        metavar="DIR",
        help="Directory to write the ZIP into (default: %(default)s).",
    )
    parser.add_argument(
        "--root",
        default=".",
        metavar="DIR",
        help="Project root containing plugin.json/package.json (default: %(default)s).",
    )
    return parser.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    root = Path(args.root).resolve()
    if not root.is_dir():
        _fail(f"project root is not a directory: {root}")

    version = _validate_metadata(root)
    entries = (
        _collect_root_files(root)
        + _collect_python_modules(root)
        + _collect_compat_files(root)
    )

    zip_path = (Path(args.output) / f"uu-accelerator-v{version}.zip").resolve()
    entry_count = _write_zip(zip_path, entries)

    summary = {
        "path": str(zip_path),
        "name": EXPECTED_PACKAGE_NAME,
        "version": version,
        "sha256": _sha256(zip_path),
        "size": zip_path.stat().st_size,
        "entries": entry_count,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
