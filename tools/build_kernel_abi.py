#!/usr/bin/env python3
"""Build-time kernel ABI tooling.

Subcommands:

    extract  Locate an embedded BTF blob inside a raw uncompressed ARM64
             kernel Image and write it to a standalone .btf file.
    build    Build kernel-ABI metadata JSON from module and kernel BTF,
             then self-validate it against the kernel BTF.
    check    Validate existing metadata against kernel BTF, module hash,
             kernel release and machine.

Kernel BTF for ``build`` and ``check`` is supplied as a base vmlinux BTF
plus a repeatable ``--kernel-module-btf`` split BTF argument. Every split
shares the same base; splits are never chained on one another.

Standard library only. The module imports ``kernel_abi`` from the repo root,
so run it from (or with sys.path including) the repository root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from typing import List, Optional, Tuple


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from kernel_abi import AbiError, Btf, build_abi, validate_abi  # noqa: E402


BTF_MAGIC = b"\x9f\xeb\x01\x00"
HEADER_FMT = "<HBBIIIII"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 24
MIN_TYPES = 1000
REQUIRED_RECORD_NAMES = (("sk_buff", "sock", "module"), (4, "sk_buff", 4, "sock", 4, "module"))
# Actually required: (kind, name) tuples; public structures are structs.
REQUIRED_RECORD_KEYS = ((4, "sk_buff"), (4, "sock"), (4, "module"))


class ExtractError(Exception):
    """Raised when BTF extraction cannot produce exactly one valid blob."""


class _Candidate:
    __slots__ = ("offset", "end", "blob", "types")

    def __init__(self, offset: int, end: int, blob: bytes, types: int) -> None:
        self.offset = offset
        self.end = end
        self.blob = blob
        self.types = types


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _find_magic(data: bytes) -> List[int]:
    offsets: List[int] = []
    start = 0
    while True:
        index = data.find(BTF_MAGIC, start)
        if index < 0:
            break
        offsets.append(index)
        start = index + 1
    return offsets


def _has_required_names(btf: Btf) -> bool:
    try:
        records = btf.named_records()
    except (AbiError, ValueError):
        return False
    return all(key in records for key in REQUIRED_RECORD_KEYS)


def _extract_candidates(data: bytes) -> List[_Candidate]:
    valid: List[_Candidate] = []

    for offset in _find_magic(data):
        header_end = offset + HEADER_SIZE
        if header_end > len(data):
            continue
        try:
            fields = struct.unpack_from(HEADER_FMT, data, offset)
        except struct.error:
            continue
        (magic, version, flags, header_len, type_off, type_len,
         str_off, str_len) = fields
        if magic != struct.unpack("<H", BTF_MAGIC[:2])[0]:
            continue
        if header_len < HEADER_SIZE or header_len > len(data) - offset:
            continue
        if flags != 0:
            continue
        if str_len <= 0:
            continue
        # Section offsets are relative to header_len. Bounds check each
        # independently and require they not overlap.
        type_start = header_len + type_off
        type_end = type_start + type_len
        str_start = header_len + str_off
        str_end = str_start + str_len
        section_extent = header_len + max(type_off + type_len,
                                         str_off + str_len)
        end = offset + section_extent
        if end > len(data):
            continue
        blob_len = section_extent
        if type_start > blob_len or type_end > blob_len:
            continue
        if str_start > blob_len or str_end > blob_len:
            continue
        if type_end < type_start or str_end < str_start:
            continue
        if type_end > str_start and str_end > type_start:
            continue

        blob = data[offset:end]
        try:
            btf = Btf(blob)
        except (AbiError, ValueError, struct.error):
            continue
        try:
            types = len(btf.types)
        except (TypeError, AttributeError):
            continue
        if types <= MIN_TYPES:
            continue
        if not _has_required_names(btf):
            continue

        valid.append(_Candidate(offset, end, blob, types))

    # Reject any overlap among candidates; do not silently drop.
    for i in range(len(valid)):
        for j in range(i + 1, len(valid)):
            a = valid[i]
            b = valid[j]
            if a.offset < b.end and b.offset < a.end:
                raise ExtractError(
                    "overlapping BTF candidates at offsets %d and %d"
                    % (a.offset, b.offset))

    return valid


def cmd_extract(args: argparse.Namespace) -> int:
    data = _read_bytes(args.image)
    candidates = _extract_candidates(data)
    if len(candidates) != 1:
        raise ExtractError(
            "expected exactly one valid BTF blob, found %d" % len(candidates)
        )
    chosen = candidates[0]
    with open(args.output, "wb") as handle:
        handle.write(chosen.blob)
    summary = {
        "path": args.output,
        "size": len(chosen.blob),
        "types": chosen.types,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


def _kernel_btf_arg(args: argparse.Namespace):
    base = _read_bytes(args.kernel_btf)
    splits = [_read_bytes(path) for path in args.kernel_module_btf]
    if not splits:
        return base
    return [base] + splits


def cmd_build(args: argparse.Namespace) -> int:
    module_bytes = _read_bytes(args.module)
    module_btf = _read_bytes(args.module_btf)
    kernel_btf = _kernel_btf_arg(args)

    required = list(args.required or [])
    module_sha = _sha256(module_bytes)
    metadata = build_abi(
        module_btf=module_btf,
        kernel_btf=kernel_btf,
        module_sha256=module_sha,
        kernel_release=args.release,
        machine=args.machine,
        required_names=required,
        public_roots=(args.public_root or None),
    )
    # Self-validate before writing any build output.
    validate_abi(
        metadata=metadata,
        kernel_btf=kernel_btf,
        module_sha256=module_sha,
        kernel_release=args.release,
        machine=args.machine,
    )

    text = json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(text)

    records = metadata.get("records")
    if isinstance(records, list):
        record_count = len(records)
    elif isinstance(records, dict):
        record_count = len(records)
    else:
        record_count = 0

    summary = {
        "path": args.output,
        "records": record_count,
        "sha256": _sha256(text.encode("utf-8")),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    try:
        with open(args.metadata, "r", encoding="utf-8") as handle:
            metadata = json.load(handle)
        module_bytes = _read_bytes(args.module)
        kernel_btf = _kernel_btf_arg(args)
        validate_abi(
            metadata=metadata,
            kernel_btf=kernel_btf,
            module_sha256=_sha256(module_bytes),
            kernel_release=args.release,
            machine=args.machine,
        )
    except (AbiError, OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    print("pass")
    return 0


def _add_common_build_check(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--module", required=True, help="module .ko path")
    parser.add_argument("--kernel-btf", required=True, help="kernel .btf path")
    parser.add_argument(
        "--kernel-module-btf",
        action="append",
        default=[],
        metavar="PATH",
        help="split kernel module .btf path (repeatable; same base)",
    )
    parser.add_argument("--release", required=True, help="kernel release")
    parser.add_argument("--machine", required=True, help="machine/arch string")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_kernel_abi.py",
        description="Kernel ABI build-time tooling.",
    )
    sub = parser.add_subparsers(dest="command")

    extract = sub.add_parser("extract", help="extract BTF from ARM64 Image")
    extract.add_argument("--image", required=True, help="raw kernel Image path")
    extract.add_argument("--output", required=True, help="output .btf path")
    extract.set_defaults(func=cmd_extract)

    build = sub.add_parser("build", help="build ABI metadata JSON")
    _add_common_build_check(build)
    build.add_argument("--module-btf", required=True, help="module .btf path")
    build.add_argument(
        "--required",
        action="append",
        default=[],
        metavar="NAME",
        help="required record name (repeatable)",
    )
    build.add_argument(
        "--public-root",
        action="append",
        default=[],
        metavar="NAME",
        help="public root record name (repeatable)",
    )
    build.add_argument("--output", required=True, help="output JSON path")
    build.set_defaults(func=cmd_build)

    check = sub.add_parser("check", help="validate ABI metadata JSON")
    _add_common_build_check(check)
    check.add_argument("--metadata", required=True, help="metadata JSON path")
    check.set_defaults(func=cmd_check)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help(sys.stderr)
        return 2
    try:
        return args.func(args)
    except (ExtractError, AbiError, OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
