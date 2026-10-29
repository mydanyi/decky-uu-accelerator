#!/usr/bin/env python3
"""Statically verify the sole official UU payload used by the FEX preview.

Fetches the official metadata for the Steam Deck (x86_64) package, downloads
the archive, checks its MD5 against the advertised value, extracts it into a
fresh per-package directory under ``--output`` and reports the authoritative
version (from ``uu.conf``), archive and member sizes, and the decoded ELF
architecture of each executable.

This never executes a downloaded core and never touches systemd or any service.
Every artifact and the report are written under the caller-provided
``--output`` directory. The tool exits non-zero on a genuine download,
checksum or extraction error.

Real official metadata frequently carries ``version=None`` (the API URL has no
parseable version), so the reported ``version`` always comes from ``uu.conf``;
the raw metadata hint is kept separately as ``metadata.version``.

Run with (from the project root):
    python3 tools/verify_official_payloads.py --output <dir>
"""

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "py_modules"))

from uu_accelerator import payload  # noqa: E402
from uu_accelerator.platform import elf_machine  # noqa: E402

PACKAGES = (
    ("steam-deck-plugin-x86_64", "x86_64"),
)
_EXECUTABLES = ("uuplugin", "xuplugin-guardian")


def file_md5(path):
    digest = hashlib.md5()
    with open(path, "rb") as handle:
        chunk = handle.read(1 << 20)
        while chunk:
            digest.update(chunk)
            chunk = handle.read(1 << 20)
    return digest.hexdigest()


def elf_arches(dest):
    """Decode the ELF machine of each executable member present in ``dest``."""
    arches = {}
    for name in _EXECUTABLES:
        path = dest / name
        if not path.is_file():
            continue
        try:
            arches[name] = elf_machine(path.read_bytes())
        except ValueError as exc:
            arches[name] = "invalid:{}".format(exc)
    return arches


def verify_package(package_type, expected_arch, output_dir, timeout):
    record = {"package_type": package_type, "expected_arch": expected_arch}

    metadata = payload.fetch_metadata(package_type, timeout=timeout)
    record["metadata"] = {
        "url": metadata.get("url"),
        "md5": metadata.get("md5"),
        "version": metadata.get("version"),
    }

    package_dir = output_dir / package_type
    package_dir.mkdir(parents=True, exist_ok=True)

    archive = package_dir / "{}.tar.gz".format(package_type)
    payload.download_archive(metadata, archive, timeout=timeout)

    archive_md5 = file_md5(archive)
    expected_md5 = str(metadata.get("md5") or "").lower()
    record["archive"] = {
        "path": str(archive),
        "size": archive.stat().st_size,
        "md5": archive_md5,
        "md5_match": archive_md5 == expected_md5,
    }

    # Fresh extraction directory per package; never reuse a previous one.
    dest = package_dir / "extracted"
    if dest.exists():
        shutil.rmtree(dest)
    outcome = payload.extract_payload(archive, dest, expected_arch=expected_arch)

    record["version"] = outcome.get("version")  # authoritative, from uu.conf
    record["files"] = {
        Path(name).name: Path(name).stat().st_size
        for name in outcome.get("files", [])
    }
    record["elf_arch"] = elf_arches(dest)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description="verify official UU payloads")
    parser.add_argument("--output", required=True,
                        help="directory for downloaded archives, extraction and report")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args(argv)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    records = []
    failed = False
    for package_type, expected_arch in PACKAGES:
        try:
            records.append(
                verify_package(package_type, expected_arch, output_dir, args.timeout))
        except Exception as exc:  # genuine download/checksum/extract error
            failed = True
            records.append({
                "package_type": package_type,
                "expected_arch": expected_arch,
                "error": "{}: {}".format(exc.__class__.__name__, exc),
            })

    report = {"packages": records, "ok": not failed}
    text = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    (output_dir / "verify_official_payloads.json").write_text(
        text + "\n", encoding="utf-8")
    print(text)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
