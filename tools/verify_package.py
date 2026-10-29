#!/usr/bin/env python3
"""Verify a packaged UU加速器 Decky plugin ZIP (read-only).

Opens an already-built ``.zip`` produced by ``tools/package_plugin.py`` and
checks, without executing anything, that:

* the ZIP CRCs are intact (``ZipFile.testzip`` returns ``None``);
* it contains exactly the twenty-three expected members under a single
  top-level ``uu-accelerator/`` directory;
* ``plugin.json`` declares the exact display name ``UU加速器`` with
  ``api_version == 1`` and ``flags == ["root"]``;
* ``package.json`` declares name ``uu-accelerator`` and version
  ``0.1.0-preview.6``;
* no member path contains a vendor/cores/tests/tools/node_modules/cache
  segment;
* the only ELF members are the baseline ``compat/armada-7.2.6/xt_cgroup.ko``
  and ``compat/armada-7.2.6/xt_nat.ko`` plus the Oct 26 profile
  ``compat/armada-7.2.6/oct26/xt_cgroup.ko`` and
  ``compat/armada-7.2.6/oct26/xt_nat.ko``, each of which must be an ELF64
  little-endian ``ET_REL`` AArch64 relocatable whose SHA-256 equals the
  ``module_sha256`` (xt_cgroup) / ``nat_module_sha256`` (xt_nat) recorded in the
  shipped ``manifest.json``; the ``oct26`` modules must match the unique
  ``compatible_kernels`` profile whose ``module_dir`` is ``oct26``. Any other
  ELF member fails;
* the compat ``manifest.json`` declares the ``GPL-2.0-only`` license;
* every packaged ``.py`` file parses with :func:`ast.parse`;
* the built ``dist/index.js`` is non-empty.

Nothing is extracted to disk, no official binary is run and no ``systemctl``
command is invoked: the tool only reads the ZIP and prints a JSON report to
stdout.

Usage:
    python3 tools/verify_package.py <output/uu-accelerator-v*.zip>
"""

import argparse
import ast
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

# Top-level directory inside the ZIP.
PLUGIN_DIR = "uu-accelerator"

# Exact name plugin.json must declare.
EXPECTED_PLUGIN_NAME = "UU加速器"

# package.json identity.
EXPECTED_PACKAGE_NAME = "uu-accelerator"
EXPECTED_VERSION = "0.1.0-preview.8"

# plugin.json identity.
EXPECTED_API_VERSION = 1
EXPECTED_FLAGS = ("root",)

# Kernel-module compatibility payload (the only permitted ELF members), each
# paired with the manifest key whose SHA-256 must match that module. Baseline
# modules use the top-level digest keys; the ``oct26`` modules use the digests
# of the unique ``compatible_kernels`` profile whose ``module_dir`` is
# ``oct26``.
COMPAT_DIR = f"{PLUGIN_DIR}/compat/armada-7.2.6"
COMPAT_OCT26_DIR = f"{COMPAT_DIR}/oct26"
COMPAT_OCT26_MODULE_DIR = "oct26"
COMPAT_MODULE = f"{COMPAT_DIR}/xt_cgroup.ko"
COMPAT_NAT_MODULE = f"{COMPAT_DIR}/xt_nat.ko"
COMPAT_OCT29_DIR = f"{COMPAT_DIR}/oct29"
COMPAT_OCT29_MODULE_DIR = "oct29"
COMPAT_OCT26_MODULE = f"{COMPAT_OCT26_DIR}/xt_cgroup.ko"
COMPAT_OCT26_NAT_MODULE = f"{COMPAT_OCT26_DIR}/xt_nat.ko"
COMPAT_OCT29_MODULE = f"{COMPAT_OCT29_DIR}/xt_cgroup.ko"
COMPAT_OCT29_NAT_MODULE = f"{COMPAT_OCT29_DIR}/xt_nat.ko"
COMPAT_MODULES = (
    COMPAT_MODULE,
    COMPAT_NAT_MODULE,
    COMPAT_OCT26_MODULE,
    COMPAT_OCT26_NAT_MODULE,
    COMPAT_OCT29_MODULE,
    COMPAT_OCT29_NAT_MODULE,
)
CHILD_MODULE_DIRS = {
    COMPAT_OCT26_MODULE_DIR: COMPAT_OCT26_DIR,
    COMPAT_OCT29_MODULE_DIR: COMPAT_OCT29_DIR,
}
COMPAT_MODULE_SHA_KEYS = {
    COMPAT_MODULE: "module_sha256",
    COMPAT_NAT_MODULE: "nat_module_sha256",
    COMPAT_OCT26_MODULE: "module_sha256",
    COMPAT_OCT26_NAT_MODULE: "nat_module_sha256",
    COMPAT_OCT29_MODULE: "module_sha256",
    COMPAT_OCT29_NAT_MODULE: "nat_module_sha256",
}
COMPAT_MANIFEST = f"{COMPAT_DIR}/manifest.json"
EXPECTED_COMPAT_LICENSE = "GPL-2.0-only"

# Identity fields a ``compatible_kernels`` profile must declare non-empty.
CHILD_IDENTITY_FIELDS = (
    "kernel_release",
    "kernel_version",
    "machine",
    "config_sha256",
)

# The twenty-three members that must be present, and nothing else.
EXPECTED_ENTRIES = (
    f"{PLUGIN_DIR}/plugin.json",
    f"{PLUGIN_DIR}/package.json",
    f"{PLUGIN_DIR}/main.py",
    f"{PLUGIN_DIR}/supervisor.py",
    f"{PLUGIN_DIR}/dist/index.js",
    f"{PLUGIN_DIR}/LICENSE",
    f"{PLUGIN_DIR}/README.md",
    f"{PLUGIN_DIR}/py_modules/uu_accelerator/__init__.py",
    f"{PLUGIN_DIR}/py_modules/uu_accelerator/platform.py",
    f"{PLUGIN_DIR}/py_modules/uu_accelerator/payload.py",
    f"{PLUGIN_DIR}/py_modules/uu_accelerator/manager.py",
    f"{PLUGIN_DIR}/py_modules/uu_accelerator/service.py",
    f"{PLUGIN_DIR}/py_modules/uu_accelerator/binding.py",
    f"{COMPAT_DIR}/xt_cgroup.ko",
    f"{COMPAT_DIR}/xt_cgroup.c",
    f"{COMPAT_DIR}/xt_nat.ko",
    f"{COMPAT_DIR}/xt_nat.c",
    f"{COMPAT_DIR}/Makefile",
    f"{COMPAT_DIR}/GPL-2.0.txt",
    f"{COMPAT_DIR}/manifest.json",
    f"{COMPAT_DIR}/README.md",
    f"{COMPAT_OCT26_DIR}/xt_cgroup.ko",
    f"{COMPAT_OCT26_DIR}/xt_nat.ko",
    f"{COMPAT_OCT29_DIR}/xt_cgroup.ko",
    f"{COMPAT_OCT29_DIR}/xt_nat.ko",
)

# The eight parseable Python members: project-root main.py + supervisor.py plus
# the six uu_accelerator package modules.
EXPECTED_PY = tuple(name for name in EXPECTED_ENTRIES if name.endswith(".py"))

# Path segments that must never appear in a packaged member.
FORBIDDEN_SEGMENTS = frozenset(
    ("vendor", "cores", "tests", "tools", "node_modules", "cache")
)

# ELF header identity required of the permitted compat modules.
ELF_MAGIC = b"\x7fELF"
ELF_CLASS_64 = 2
ELF_DATA_LSB = 1
ET_REL = 1
EM_AARCH64 = 183

_INDEX_ENTRY = f"{PLUGIN_DIR}/dist/index.js"


def _fail(message: str) -> "None":
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _member_segments(name: str) -> "list[str]":
    return [part for part in name.split("/") if part]


def _elf_header_ok(data: bytes) -> bool:
    """True only for an ELF64 little-endian, AArch64 ``ET_REL`` relocatable."""
    if len(data) < 20 or data[:4] != ELF_MAGIC:
        return False
    if data[4] != ELF_CLASS_64 or data[5] != ELF_DATA_LSB:
        return False
    e_type = int.from_bytes(data[16:18], "little")
    e_machine = int.from_bytes(data[18:20], "little")
    return e_type == ET_REL and e_machine == EM_AARCH64


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
    for field in CHILD_IDENTITY_FIELDS:
        value = profile.get(field)
        if not isinstance(value, str) or not value.strip():
            _fail(
                f"compat manifest.json {module_dir} profile must define a non-empty "
                f"{field!r}"
            )
    for key in ("module_sha256", "nat_module_sha256"):
        value = profile.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            _fail(
                f"compat manifest.json {module_dir} profile must define a hex "
                f"{key!r}"
            )
    return profile


def _load_member_json(archive: zipfile.ZipFile, name: str) -> dict:
    try:
        raw = archive.read(name)
    except KeyError:
        _fail(f"required member is missing: {name}")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"invalid JSON in {name}: {exc}")
    if not isinstance(data, dict):
        _fail(f"expected a JSON object in {name}")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a packaged UU加速器 Decky plugin ZIP (read-only)."
    )
    parser.add_argument(
        "zip",
        metavar="ZIP",
        help="path to the packaged plugin ZIP to verify",
    )
    args = parser.parse_args(argv)

    zip_path = Path(args.zip)
    if not zip_path.is_file():
        _fail(f"ZIP not found: {zip_path}")

    checks = {}
    report = {
        "zip": str(zip_path),
        "sha256": _sha256(zip_path),
        "bytes": zip_path.stat().st_size,
        "entries": [],
        "checks": checks,
        "ok": False,
    }

    with zipfile.ZipFile(zip_path, "r") as archive:
        bad_member = archive.testzip()
        checks["crc_ok"] = bad_member is None
        if bad_member is not None:
            report["error"] = f"CRC failure in member: {bad_member}"

        names = archive.namelist()
        report["entries"] = names

        checks["entry_count_exact"] = len(names) == len(EXPECTED_ENTRIES)
        checks["entries_exact"] = sorted(names) == sorted(EXPECTED_ENTRIES)
        checks["single_top_level_prefix"] = all(
            name.startswith(PLUGIN_DIR + "/") for name in names
        )

        checks["no_forbidden_segments"] = not any(
            set(_member_segments(name)) & FORBIDDEN_SEGMENTS for name in names
        )

        elf_members = []
        parsed_py = []
        for name in names:
            if name.endswith("/"):
                continue
            data = archive.read(name)
            if data[:4] == ELF_MAGIC:
                elf_members.append(name)
            if name.endswith(".py"):
                try:
                    ast.parse(data.decode("utf-8"), filename=name)
                except (UnicodeDecodeError, SyntaxError) as exc:
                    checks["python_ast_ok"] = False
                    report["error"] = f"Python parse error in {name}: {exc}"
                    break
                parsed_py.append(name)
        else:
            checks["python_ast_ok"] = True

        checks["elf_members_exact"] = sorted(elf_members) == sorted(COMPAT_MODULES)
        if not checks["elf_members_exact"]:
            report["error"] = f"unexpected ELF members: {elf_members}"

        index_data = archive.read(_INDEX_ENTRY) if _INDEX_ENTRY in names else b""
        checks["dist_index_nonempty"] = len(index_data) > 0
        checks["python_modules_packaged"] = len(parsed_py) == 8
        checks["python_modules_exact"] = sorted(parsed_py) == sorted(EXPECTED_PY)

    # --- metadata ---------------------------------------------------------
    with zipfile.ZipFile(zip_path, "r") as archive:
        plugin = _load_member_json(archive, f"{PLUGIN_DIR}/plugin.json")
        package = _load_member_json(archive, f"{PLUGIN_DIR}/package.json")
        compat = _load_member_json(archive, COMPAT_MANIFEST)
        names = archive.namelist()
        compat_modules = {
            path: (archive.read(path) if path in names else None)
            for path in COMPAT_MODULES
        }

    child_profiles = {}
    for module_dir in CHILD_MODULE_DIRS:
        try:
            child_profiles[module_dir] = _child_profile(compat, module_dir)
        except SystemExit:
            child_profiles[module_dir] = None
            report.setdefault(
                "error",
                f"compat manifest.json must define one valid {module_dir} "
                "compatible_kernels profile",
            )

    checks["plugin_name_exact"] = plugin.get("name") == EXPECTED_PLUGIN_NAME
    checks["api_version_one"] = plugin.get("api_version") == EXPECTED_API_VERSION
    flags = plugin.get("flags")
    checks["flags_root"] = isinstance(flags, list) and tuple(
        sorted(flags)
    ) == tuple(sorted(EXPECTED_FLAGS))

    checks["package_name_exact"] = package.get("name") == EXPECTED_PACKAGE_NAME
    checks["version_exact"] = package.get("version") == EXPECTED_VERSION

    report["plugin"] = {
        "name": plugin.get("name"),
        "api_version": plugin.get("api_version"),
        "flags": plugin.get("flags"),
    }
    report["package"] = {
        "name": package.get("name"),
        "version": package.get("version"),
    }

    # --- compat kernel modules --------------------------------------------
    checks["compat_license_gpl"] = compat.get("license") == EXPECTED_COMPAT_LICENSE
    for module_dir, profile in child_profiles.items():
        checks[f"compat_{module_dir}_profile_valid"] = profile is not None
    present = []
    elf_ok = []
    sha_ok = []
    module_hashes = {}
    for path in COMPAT_MODULES:
        data = compat_modules.get(path)
        module_hashes[path] = None
        present.append(data is not None)
        if data is None:
            elf_ok.append(False)
            sha_ok.append(False)
            report["error"] = f"required member is missing: {path}"
            continue
        elf_ok.append(_elf_header_ok(data))
        child_module_dir = next(
            (
                module_dir
                for module_dir, child_dir in CHILD_MODULE_DIRS.items()
                if path.startswith(child_dir + "/")
            ),
            None,
        )
        if child_module_dir is not None:
            child_profile = child_profiles.get(child_module_dir)
            expected_sha = (
                child_profile.get(COMPAT_MODULE_SHA_KEYS[path])
                if child_profile is not None
                else None
            )
        else:
            expected_sha = compat.get(COMPAT_MODULE_SHA_KEYS[path])
        actual_sha = hashlib.sha256(data).hexdigest()
        module_hashes[path] = actual_sha
        sha_ok.append(
            isinstance(expected_sha, str)
            and expected_sha.strip().lower() == actual_sha
        )
    checks["compat_module_present"] = all(present)
    checks["compat_module_elf_header"] = all(elf_ok)
    checks["compat_module_sha256_matches"] = all(sha_ok)
    if not checks["compat_module_sha256_matches"] and "error" not in report:
        report["error"] = (
            "compat module SHA-256 does not match manifest "
            "module_sha256/nat_module_sha256 or oct26 profile digests"
        )
    report["compat"] = {
        "license": compat.get("license"),
        "module_sha256": compat.get("module_sha256"),
        "nat_module_sha256": compat.get("nat_module_sha256"),
        "oct26_profile": child_profiles.get("oct26"),
        "oct29_profile": child_profiles.get("oct29"),
        "modules": module_hashes,
    }

    report["ok"] = all(checks.values()) and "error" not in report

    text = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    print(text)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
