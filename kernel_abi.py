"""Standard-library BTF ABI matcher for ArmadaOS out-of-tree kernel modules.

Parses raw BTF v1 little-endian data, produces canonical (ID-free) type
signatures, and builds/validates conservative ABI metadata for prebuilt
checksum-verified modules against a reference kernel BTF.

Split BTF is supported: a module BTF blob may be constructed with a base
Btf (kernel vmlinux) so its type IDs and string offsets are resolved
against the concatenation of base + local sections. The base must be the
kernel BTF; module BTF blobs are never chained on one another.
"""

from __future__ import annotations

import json
import re
import struct

__all__ = ["AbiError", "Btf", "build_abi", "validate_abi"]

_MAGIC = 0xEB9F
_MAX_DEPTH = 64
_RECORD_KINDS = {4: "STRUCT", 5: "UNION", 6: "ENUM", 19: "ENUM64"}
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")

# Payload size (bytes, after the 12-byte type header) per kind.
# None means the payload size depends on vlen and is computed separately.
_FIXED_PAYLOAD = {
    1: 4,    # INT
    2: 0,    # PTR
    3: 12,   # ARRAY
    4: None, # STRUCT
    5: None, # UNION
    6: None, # ENUM
    7: 0,    # FWD
    8: 0,    # TYPEDEF
    9: 0,    # VOLATILE
    10: 0,   # CONST
    11: 0,   # RESTRICT
    12: 0,   # FUNC
    13: None,  # FUNC_PROTO
    14: 4,   # VAR
    15: None,  # DATASEC
    16: 0,   # FLOAT
    17: 4,   # DECL_TAG
    18: 0,   # TYPE_TAG
    19: None,  # ENUM64
}
_KIND_NAMES = {
    1: "INT", 2: "PTR", 3: "ARRAY", 4: "STRUCT", 5: "UNION", 6: "ENUM",
    7: "FWD", 8: "TYPEDEF", 9: "VOLATILE", 10: "CONST", 11: "RESTRICT",
    12: "FUNC", 13: "FUNC_PROTO", 14: "VAR", 15: "DATASEC", 16: "FLOAT",
    17: "DECL_TAG", 18: "TYPE_TAG", 19: "ENUM64",
}
_UNWRAP_KINDS = {8, 9, 10, 11, 18}


def _vlen_payload(kind: int, vlen: int) -> int:
    if kind in (4, 5, 15):
        return 12 * vlen
    if kind == 6:
        return 8 * vlen
    if kind == 13:
        return 8 * vlen
    if kind == 19:
        return 12 * vlen
    raise AbiError("unknown BTF kind %d" % kind)


class AbiError(ValueError):
    """Raised when BTF data or ABI metadata is invalid or incompatible."""


class _Type:
    __slots__ = ("type_id", "name_off", "name", "info", "kind", "kflag",
                 "vlen", "size_or_type", "raw", "payload")

    def __init__(self):
        self.type_id = 0
        self.name_off = 0
        self.name = ""
        self.info = 0
        self.kind = 0
        self.kflag = 0
        self.vlen = 0
        self.size_or_type = 0
        self.raw = b""
        self.payload = None


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


class Btf:
    """A parsed and validated raw BTF v1 little-endian blob.

    When ``base`` is supplied the blob is a *split* BTF: its type IDs
    continue past the base's highest ID, and its string offsets refer to
    the concatenation of the base string section followed by this blob's
    local string section. ``base`` must be a standalone Btf (the kernel
    vmlinux BTF); split blobs are never used as a base.
    """

    def __init__(self, data: bytes, base: "Btf" = None):
        if not isinstance(data, (bytes, bytearray)):
            raise AbiError("BTF data must be bytes")
        if base is not None:
            if not isinstance(base, Btf):
                raise AbiError("BTF base must be a Btf instance")
            if base._base is not None:
                raise AbiError("BTF base must be the kernel (non-split) BTF")
        self._base = base
        self.data = bytes(data)
        # Local types only; base types are consulted via ``types`` view.
        self._local_types = {0: None}
        self._strtab = b""
        self._parse()
        # Public ``types`` view: base types copied first, then local.
        self.types = {0: None}
        self._last_local_id = 0
        if base is not None:
            for tid, t in base.types.items():
                if tid == 0:
                    continue
                self.types[tid] = t
        for tid, t in self._local_types.items():
            if tid == 0:
                continue
            self.types[tid] = t
        self._validate_references()

    # -- string / concatenated table ------------------------------------
    @property
    def string_size(self) -> int:
        """Total string section length, including any base prefix."""
        base_len = self._base.string_size if self._base is not None else 0
        return base_len + len(self._strtab)

    def _string(self, off: int) -> str:
        if off < 0:
            raise AbiError("negative string offset %d" % off)
        if self._base is not None:
            base_len = self._base.string_size
            if off < base_len:
                return self._base._string(off)
            local_off = off - base_len
        else:
            local_off = off
        strtab = self._strtab
        if local_off >= len(strtab):
            raise AbiError("string offset %d out of range" % off)
        nul = strtab.find(b"\x00", local_off)
        if nul < 0:
            raise AbiError("string offset %d not NUL terminated" % off)
        try:
            return strtab[local_off:nul].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise AbiError("string offset %d invalid UTF-8: %s"
                           % (off, exc)) from None

    # -- parsing ---------------------------------------------------------
    def _parse(self):
        data = self.data
        if len(data) < 24:
            raise AbiError("BTF header truncated")
        magic, version, flags, hdr_len = struct.unpack_from("<HBBI", data, 0)
        if magic != _MAGIC:
            raise AbiError("bad BTF magic 0x%04x" % magic)
        if version != 1:
            raise AbiError("unsupported BTF version %d" % version)
        if flags != 0:
            raise AbiError("unsupported BTF flags 0x%02x" % flags)
        if hdr_len < 24:
            raise AbiError("BTF hdr_len %d < 24" % hdr_len)
        if hdr_len > len(data):
            raise AbiError("BTF hdr_len exceeds data")
        type_off, type_len, str_off, str_len = struct.unpack_from(
            "<IIII", data, 8)
        total = len(data)

        t_start = hdr_len + type_off
        t_end = t_start + type_len
        s_start = hdr_len + str_off
        s_end = s_start + str_len
        for label, start, end in (("type", t_start, t_end),
                                  ("string", s_start, s_end)):
            if start > total or end > total:
                raise AbiError("BTF %s section out of bounds" % label)
            if end < start:
                raise AbiError("BTF %s section inverted" % label)
        if t_end > s_start and s_end > t_start:
            raise AbiError("BTF type/string sections overlap")

        strtab = data[s_start:s_end]
        if not strtab:
            raise AbiError("BTF string table empty")
        # Standalone BTF must start with NUL; split BTF local strings may
        # begin with a non-NUL byte (their first offset points into the base).
        if self._base is None and strtab[0] != 0:
            raise AbiError("BTF string table must begin with NUL")
        self._strtab = strtab

        types_bytes = data[t_start:t_end]
        pos = 0
        if self._base is not None:
            base_max = max(self._base.types.keys())
            next_id = base_max + 1
        else:
            next_id = 1
        n = len(types_bytes)
        while pos < n:
            if n - pos < 12:
                raise AbiError("truncated BTF type header at offset %d" % pos)
            name_off, info, size_or_type = struct.unpack_from(
                "<III", types_bytes, pos)
            vlen = info & 0xFFFF
            kind = (info >> 24) & 0x1F
            kflag = (info >> 31) & 1
            if kind not in _FIXED_PAYLOAD:
                raise AbiError("unknown BTF kind %d (type id %d)"
                               % (kind, next_id))
            fixed = _FIXED_PAYLOAD[kind]
            if fixed is None:
                plen = _vlen_payload(kind, vlen)
            else:
                plen = fixed
            end = pos + 12 + plen
            if end > n:
                raise AbiError("truncated BTF type id %d" % next_id)
            t = _Type()
            t.type_id = next_id
            t.name_off = name_off
            t.info = info
            t.kind = kind
            t.kflag = kflag
            t.vlen = vlen
            t.size_or_type = size_or_type
            t.payload = types_bytes[pos + 12:end]
            t.raw = types_bytes[pos:end]
            self._local_types[next_id] = t
            pos = end
            next_id += 1
        self._last_local_id = next_id - 1

        # Resolve names (validate every name_off, including unreachable).
        for tid, t in self._local_types.items():
            if tid == 0:
                continue
            t.name = self._string(t.name_off)

    # -- reference validation -------------------------------------------
    def _check_ref(self, tid: int, allow_void: bool, where: str):
        if tid == 0:
            if not allow_void:
                raise AbiError("%s references void where illegal" % where)
            return
        if tid not in self.types or self.types[tid] is None:
            raise AbiError("%s references invalid type id %d" % (where, tid))

    def _validate_references(self):
        types = self.types
        for tid, t in self._local_types.items():
            if tid == 0:
                continue
            kind = t.kind
            p = t.payload
            where = "type id %d (%s)" % (tid, _KIND_NAMES.get(kind, str(kind)))
            if kind == 3:  # ARRAY
                elem = _u32(p, 0)
                index = _u32(p, 4)
                _u32(p, 8)  # nelems, any value allowed
                self._check_ref(elem, False, where + " element")
                self._check_ref(index, False, where + " index")
                for label, ref in (("element", elem), ("index", index)):
                    rt = types.get(ref)
                    if rt is not None and rt.kind == 0:
                        raise AbiError("%s %s cannot be kind 0" % (where, label))
                if elem == 0:
                    raise AbiError("%s element type must be positive" % where)
                if index == 0:
                    raise AbiError("%s index type must be positive" % where)
            elif kind in (4, 5):
                for i in range(t.vlen):
                    base = 12 * i
                    m_name = _u32(p, base)
                    m_type = _u32(p, base + 4)
                    if m_type == 0:
                        raise AbiError("%s member %d illegal void type"
                                       % (where, i))
                    self._check_ref(m_type, False, where + " member %d" % i)
                    self._string(m_name)
            elif kind in (6, 19):
                step = 12 if kind == 19 else 8
                for i in range(t.vlen):
                    self._string(_u32(p, step * i))
            elif kind == 13:  # FUNC_PROTO
                ret = t.size_or_type
                self._check_ref(ret, True, where + " return")
                for i in range(t.vlen):
                    if 8 * i + 8 > len(p):
                        raise AbiError("truncated FUNC_PROTO")
                    a_name = _u32(p, 8 * i)
                    a_type = _u32(p, 8 * i + 4)
                    self._string(a_name)
                    self._check_ref(a_type, True, where + " arg %d" % i)
                    if a_type == 0 and (i != t.vlen - 1 or a_name != 0):
                        raise AbiError("%s arg %d illegal void type"
                                       % (where, i))
            elif kind == 2:  # PTR may point at void (void *).
                self._check_ref(t.size_or_type, True, where)
            elif kind == 17:  # DECL_TAG
                if t.size_or_type == 0:
                    raise AbiError("%s has illegal void type" % where)
                self._check_ref(t.size_or_type, False, where)
            elif kind in (8, 9, 10, 11, 18):  # TYPEDEF/quals/type_tag
                self._check_ref(t.size_or_type, True, where)
            elif kind == 14:  # VAR
                if t.size_or_type == 0:
                    raise AbiError("%s has illegal void type" % where)
                self._check_ref(t.size_or_type, False, where)
            elif kind == 12:  # FUNC
                if t.size_or_type == 0:
                    raise AbiError("%s has illegal void type" % where)
                self._check_ref(t.size_or_type, False, where)
                target = types.get(t.size_or_type)
                if target is not None and target.kind != 13:
                    raise AbiError("%s FUNC target is not FUNC_PROTO" % where)
            elif kind == 15:  # DATASEC payload: (type_id, offset, size)
                for i in range(t.vlen):
                    base = 12 * i
                    v_type = _u32(p, base)
                    _u32(p, base + 4)
                    _u32(p, base + 8)
                    self._check_ref(v_type, False, where + " var %d" % i)
                    vt = types.get(v_type)
                    if vt is not None and vt.kind != 14:
                        raise AbiError("%s var %d not a VAR" % (where, i))
            elif kind in (1, 16, 7):
                pass
            else:  # pragma: no cover - guarded at parse
                raise AbiError("unhandled kind %d" % kind)

    # -- public helpers --------------------------------------------------
    def named_records(self) -> dict:
        out = {}
        for tid, t in self.types.items():
            if tid == 0 or t is None:
                continue
            if t.kind in _RECORD_KINDS and t.name:
                out.setdefault((t.kind, t.name), []).append(tid)
        for key in out:
            out[key].sort()
        return out

    def record(self, type_id: int) -> dict:
        t = self.types.get(type_id)
        if t is None:
            raise AbiError("invalid type id %d" % type_id)
        if t.kind not in _RECORD_KINDS or not t.name:
            raise AbiError("type id %d is not a named record" % type_id)
        return {"kind": t.kind, "name": t.name,
                "signature": self.signature(type_id)}

    def signature(self, type_id: int) -> dict:
        return self._sig(type_id, 0, frozenset(), True)

    # -- canonical signatures -------------------------------------------
    def _sig(self, tid: int, depth: int, named_stack, top_level: bool):
        if depth > _MAX_DEPTH:
            raise AbiError("BTF signature recursion too deep")
        if tid == 0:
            return {"kind": "void"}
        t = self.types.get(tid)
        if t is None:
            raise AbiError("signature references invalid type id %d" % tid)
        kind = t.kind
        if kind in _UNWRAP_KINDS:
            # Unwrapping preserves top_level: a typedef to a named struct at
            # the top still expands that struct's shape.
            return self._sig(t.size_or_type, depth + 1, named_stack,
                             top_level)
        if kind == 1:  # INT
            encoded = _u32(t.payload, 0)
            return {"kind": "int", "size": t.size_or_type,
                    "encoding": (encoded >> 24) & 0x0F,
                    "bit_offset": (encoded >> 16) & 0xFF,
                    "bit_width": encoded & 0xFF}
        if kind == 2:  # PTR
            return {"kind": "ptr",
                    "pointee": self._sig(t.size_or_type, depth + 1,
                                         named_stack, False)}
        if kind == 3:  # ARRAY
            p = t.payload
            elem = _u32(p, 0)
            nelems = _u32(p, 8)
            return {"kind": "array", "nelems": nelems,
                    "element": self._sig(elem, depth + 1, named_stack,
                                         False)}
        if kind in (4, 5):
            return self._agg_sig(t, depth, named_stack, top_level)
        if kind in (6, 19):
            return self._enum_sig(t, depth, named_stack, top_level)
        if kind == 7:  # FWD
            kindname = "union" if t.kflag else "struct"
            if top_level:
                raise AbiError("FWD type id %d cannot be a top record" % tid)
            return {"kind": "ref", "ref_kind": kindname, "ref_name": t.name}
        if kind == 12:  # FUNC
            return self._sig(t.size_or_type, depth + 1, named_stack, False)
        if kind == 13:  # FUNC_PROTO
            p = t.payload
            args = []
            for i in range(t.vlen):
                a_type = _u32(p, 8 * i + 4)
                if a_type == 0:
                    # Only the final unnamed argument may be void -> variadic.
                    if i != t.vlen - 1 or _u32(p, 8 * i) != 0:
                        raise AbiError("FUNC_PROTO arg %d illegal void" % i)
                    args.append({"kind": "varargs"})
                else:
                    args.append(self._sig(a_type, depth + 1, named_stack,
                                          False))
            return {"kind": "proto",
                    "ret": self._sig(t.size_or_type, depth + 1,
                                     named_stack, False),
                    "args": args}
        if kind == 16:  # FLOAT
            return {"kind": "float", "size": t.size_or_type}
        raise AbiError("type id %d kind %s not allowed in signature"
                       % (tid, _KIND_NAMES.get(kind, str(kind))))

    def _agg_sig(self, t: _Type, depth: int, named_stack, top_level: bool):
        kindname = "struct" if t.kind == 4 else "union"
        if t.name:
            key = (t.kind, t.name)
            if not top_level:
                # Nested named aggregates are stable references; this also
                # terminates all recursive/forward/private graphs.
                return {"kind": "ref", "ref_kind": kindname,
                        "ref_name": t.name}
            members = self._members(t, depth, named_stack | {key})
            return {"kind": kindname, "name": t.name,
                    "size": t.size_or_type, "members": members}
        members = self._members(t, depth, named_stack)
        return {"kind": kindname, "anonymous": True,
                "size": t.size_or_type, "members": members}

    def _members(self, t: _Type, depth: int, named_stack):
        p = t.payload
        out = []
        kflag = t.kflag
        for i in range(t.vlen):
            base = 12 * i
            m_name = self._string(_u32(p, base))
            m_type = _u32(p, base + 4)
            raw = _u32(p, base + 8)
            if kflag:
                bit_offset = raw & 0xFFFFFF
                width = (raw >> 24) & 0xFF
            else:
                bit_offset = raw
                width = 0
            out.append({"name": m_name, "bit_offset": bit_offset,
                        "bit_width": width,
                        "type": self._sig(m_type, depth + 1, named_stack,
                                          False)})
        return out

    def _enum_sig(self, t: _Type, depth: int, named_stack, top_level: bool):
        p = t.payload
        is64 = t.kind == 19
        signed = bool(t.kflag)
        members = []
        for i in range(t.vlen):
            if is64:
                base = 12 * i
                lo = _u32(p, base + 4)
                hi = _u32(p, base + 8)
                raw = (hi << 32) | lo
                if signed and (hi & 0x80000000):
                    raw -= 1 << 64
            else:
                base = 8 * i
                raw32 = _u32(p, base + 4)
                if signed:
                    raw = struct.unpack_from("<i", struct.pack("<I", raw32),
                                             0)[0]
                else:
                    raw = raw32
            members.append({"name": self._string(_u32(p, base)),
                            "value": raw})
        kindname = "enum64" if is64 else "enum"
        if t.name and not top_level:
            return {"kind": "ref", "ref_kind": kindname, "ref_name": t.name}
        if t.name:
            return {"kind": kindname, "name": t.name,
                    "size": t.size_or_type, "signed": signed,
                    "members": members}
        return {"kind": kindname, "anonymous": True,
                "size": t.size_or_type, "signed": signed,
                "members": members}


def _canon_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _check_sha(sha: str, label: str) -> None:
    if not isinstance(sha, str) or not _HEX64.match(sha):
        raise AbiError("%s must be a 64-char hex digest" % label)


def _parse_kernel_btf_arg(kernel_btf):
    """Return (base Btf, list of split Btf) for the kernel_btf argument.

    Accepts either raw bytes (single standalone vmlinux BTF) or a nonempty
    list/tuple whose first element is the base BTF bytes and remaining
    elements are split module BTF bytes sharing the same base.
    """
    if isinstance(kernel_btf, (bytes, bytearray)):
        base = Btf(kernel_btf)
        return base, []
    if isinstance(kernel_btf, (list, tuple)):
        if not kernel_btf:
            raise AbiError("kernel_btf list must be nonempty")
        base_bytes = kernel_btf[0]
        if not isinstance(base_bytes, (bytes, bytearray)):
            raise AbiError("kernel_btf base must be bytes")
        base = Btf(base_bytes)
        splits = []
        for i, blob in enumerate(kernel_btf[1:], 1):
            if not isinstance(blob, (bytes, bytearray)):
                raise AbiError("kernel_btf split #%d must be bytes" % i)
            try:
                splits.append(Btf(blob, base=base))
            except AbiError as exc:
                raise AbiError("kernel_btf split #%d malformed: %s"
                               % (i, exc)) from None
        return base, splits
    raise AbiError("kernel_btf must be bytes or a list/tuple of bytes")


def _catalog_named_records(base: Btf, splits: list):
    """Return {key: [(sig_json, source_index), ...]} across all catalogs.

    Source index 0 is the base; splits are 1..N. Duplicate keys from
    different catalogs are kept distinct here; conflicts are detected by
    callers that compare against expected signatures.
    """
    catalog = {}
    for tid, t in base.types.items():
        if tid == 0 or t is None:
            continue
        if t.kind in _RECORD_KINDS and t.name:
            catalog.setdefault((t.kind, t.name), []).append((tid, 0, base))
    for idx, split in enumerate(splits, 1):
        for tid in split._local_types:
            if tid == 0:
                continue
            t = split._local_types[tid]
            if t.kind in _RECORD_KINDS and t.name:
                catalog.setdefault((t.kind, t.name), []).append(
                    (tid, idx, split))
    return catalog


def _catalog_signatures(catalog: dict, keys=None):
    """Return {key: {sig_json: canonical_json_dict}} for selected entries.

    ``keys`` limits work to the requested catalog entries; ``None`` keeps
    the original all-records behavior for callers that need it.
    """
    out = {}
    if keys is None:
        keys = catalog
    for key in keys:
        entries = catalog.get(key)
        if entries is None:
            continue
        sigs = {}
        for tid, _src, btf in entries:
            sig_json = _canon_json(btf.signature(tid))
            sigs[sig_json] = json.loads(sig_json)
        out[key] = sigs
    return out


def _public_closure(roots, signatures: dict) -> set:
    """Return root keys plus all named types reachable by value.

    ``signatures`` maps ``(kind, name)`` keys to canonical signatures.
    Pointer and function-prototype branches are opaque: a public root that
    merely points at another type does not require that type's layout.
    """
    ref_kinds = {"struct": 4, "union": 5, "enum": 6, "enum64": 19}
    seen = set()
    pending = list(roots)
    while pending:
        key = pending.pop()
        if key in seen:
            continue
        if key not in signatures:
            raise AbiError(
                "public root closure missing by-value type %s %r"
                % (_KIND_NAMES.get(key[0], str(key[0])), key[1]))
        seen.add(key)
        stack = [signatures[key]]
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            kind = node.get("kind")
            if kind in ("ptr", "proto"):
                continue
            if kind == "ref":
                ref_kind = ref_kinds.get(node.get("ref_kind"))
                ref_name = node.get("ref_name")
                if (ref_kind is None or not isinstance(ref_name, str)
                        or not ref_name):
                    raise AbiError("malformed named ref in public closure")
                ref_key = (ref_kind, ref_name)
                if ref_key not in signatures:
                    raise AbiError(
                        "public root closure missing by-value type %s %r"
                        % (_KIND_NAMES[ref_kind], ref_name))
                if ref_key not in seen:
                    pending.append(ref_key)
                continue
            for value in node.values():
                if isinstance(value, dict):
                    stack.append(value)
                elif isinstance(value, list):
                    stack.extend(item for item in value
                                 if isinstance(item, dict))
    return seen


def build_abi(module_btf: bytes, kernel_btf, module_sha256: str,
              kernel_release: str, machine: str,
              required_names: list, public_roots: list = None) -> dict:
    _check_sha(module_sha256, "module_sha256")
    if not isinstance(kernel_release, str) or not kernel_release:
        raise AbiError("kernel_release must be a nonempty string")
    if not isinstance(machine, str) or not machine:
        raise AbiError("machine must be a nonempty string")
    if not isinstance(required_names, (list, tuple)):
        raise AbiError("required_names must be a list")
    req = list(required_names)
    if not req:
        raise AbiError("required_names must be nonempty")
    seen = set()
    for name in req:
        if not isinstance(name, str) or not name:
            raise AbiError("required_names must be nonempty strings")
        if name in seen:
            raise AbiError("duplicate required name %r" % name)
        seen.add(name)

    roots = None
    if public_roots is not None:
        if not isinstance(public_roots, (list, tuple)):
            raise AbiError("public_roots must be a list")
        roots = list(public_roots)
        if not roots:
            raise AbiError("public_roots must be nonempty")
        seen_roots = set()
        for name in roots:
            if not isinstance(name, str) or not name:
                raise AbiError("public_roots must be nonempty strings")
            if name in seen_roots:
                raise AbiError("duplicate public root %r" % name)
            seen_roots.add(name)

    base, splits = _parse_kernel_btf_arg(kernel_btf)
    module = Btf(module_btf)
    mod_records = module.named_records()

    # Detect conflicting duplicates within module (differing signatures).
    mod_sigs = {}
    mod_sig_objs = {}
    for key, ids in mod_records.items():
        sigs = {}
        for tid in ids:
            sig_json = _canon_json(module.signature(tid))
            sigs.setdefault(sig_json, tid)
        if len(sigs) > 1:
            raise AbiError("conflicting duplicate module record %s %r"
                           % (_KIND_NAMES[key[0]], key[1]))
        mod_sigs[key] = sigs
        mod_sig_objs[key] = json.loads(next(iter(sigs)))

    catalog = _catalog_named_records(base, splits)

    records = []
    covered = set()
    if roots is not None:
        root_keys = set()
        for name in roots:
            matches = [key for key in mod_records if key[1] == name]
            if not matches:
                raise AbiError("public root %r absent from module" % name)
            if len(matches) > 1:
                raise AbiError("ambiguous public root %r" % name)
            root_keys.add(matches[0])
        selected = _public_closure(root_keys, mod_sig_objs)
        catalog_sigs = _catalog_signatures(catalog, selected)
        for key in sorted(selected):
            sigs = mod_sigs[key]
            sig_json = next(iter(sigs))
            if key not in catalog_sigs:
                raise AbiError(
                    "public root closure type %s %r absent from kernel ABI"
                    % (_KIND_NAMES[key[0]], key[1]))
            if sig_json not in catalog_sigs[key]:
                raise AbiError("incompatible type %s %r"
                               % (_KIND_NAMES[key[0]], key[1]))
            records.append({"kind": key[0], "name": key[1],
                            "signature": json.loads(sig_json)})
            covered.add(key[1])
    else:
        selected = set(mod_records) & set(catalog)
        catalog_sigs = _catalog_signatures(catalog, selected)
        for key in sorted(mod_records):
            if key not in catalog_sigs:
                continue
            sigs = mod_sigs[key]
            if len(sigs) != 1:
                raise AbiError("conflicting duplicate module record %s %r"
                               % (_KIND_NAMES[key[0]], key[1]))
            sig_json = next(iter(sigs))
            if sig_json not in catalog_sigs[key]:
                raise AbiError("incompatible type %s %r"
                               % (_KIND_NAMES[key[0]], key[1]))
            records.append({"kind": key[0], "name": key[1],
                            "signature": json.loads(sig_json)})
            covered.add(key[1])

    records.sort(key=lambda r: (r["kind"], r["name"]))

    for name in req:
        if name not in covered:
            raise AbiError("required type %r absent from module/kernel ABI" % name)

    metadata = {
        "schema": 1,
        "module_sha256": module_sha256.lower(),
        "kernel_release": kernel_release,
        "machine": machine,
        "required_names": list(req),
        "records": records,
    }
    if roots is not None:
        metadata["public_roots"] = list(roots)
    return metadata


def validate_abi(metadata: dict, kernel_btf, module_sha256: str,
                 kernel_release: str, machine: str) -> None:
    if not isinstance(metadata, dict):
        raise AbiError("metadata must be a dict")
    schema = metadata.get("schema")
    if type(schema) is not int or schema != 1:
        raise AbiError("unsupported metadata schema %r" % (schema,))
    _check_sha(module_sha256, "module_sha256")
    md_sha = metadata.get("module_sha256")
    if not isinstance(md_sha, str) or not _HEX64.match(md_sha):
        raise AbiError("metadata module_sha256 malformed")
    if md_sha.lower() != module_sha256.lower():
        raise AbiError("module_sha256 mismatch")
    if metadata.get("kernel_release") != kernel_release:
        raise AbiError("kernel_release mismatch")
    if metadata.get("machine") != machine:
        raise AbiError("machine mismatch")

    records = metadata.get("records")
    if not isinstance(records, list) or not records:
        raise AbiError("metadata records must be a nonempty list")
    req = metadata.get("required_names")
    if not isinstance(req, list) or not req:
        raise AbiError("required_names must be a nonempty list")
    seen = set()
    for name in req:
        if not isinstance(name, str) or not name:
            raise AbiError("required_names entries must be nonempty strings")
        if name in seen:
            raise AbiError("duplicate required name %r" % name)
        seen.add(name)

    public_roots = None
    if "public_roots" in metadata:
        raw_roots = metadata.get("public_roots")
        if not isinstance(raw_roots, list) or not raw_roots:
            raise AbiError("public_roots must be a nonempty list")
        public_roots = list(raw_roots)
        seen_roots = set()
        for name in public_roots:
            if not isinstance(name, str) or not name:
                raise AbiError("public_roots entries must be nonempty strings")
            if name in seen_roots:
                raise AbiError("duplicate public root %r" % name)
            seen_roots.add(name)

    base, splits = _parse_kernel_btf_arg(kernel_btf)
    catalog = _catalog_named_records(base, splits)

    covered = set()
    expected_keys = []
    record_sigs = {}
    for rec in records:
        if not isinstance(rec, dict):
            raise AbiError("metadata record must be a dict")
        kind = rec.get("kind")
        name = rec.get("name")
        sig = rec.get("signature")
        if not isinstance(kind, int) or isinstance(kind, bool) \
                or kind not in _RECORD_KINDS:
            raise AbiError("metadata record has invalid kind %r" % (kind,))
        if not isinstance(name, str) or not name:
            raise AbiError("metadata record missing name")
        if not isinstance(sig, dict):
            raise AbiError("metadata record %r missing signature" % name)
        key = (kind, name)
        expected_keys.append(key)
        if key not in catalog:
            raise AbiError("missing type %s %r" % (_KIND_NAMES[kind], name))
        # Compute signatures only for referenced metadata keys.
        sig_json = _canon_json(sig)
        expected_json = _canon_json(sig)
        k_sigs = set()
        for tid, _src, btf in catalog[key]:
            k_sigs.add(_canon_json(btf.signature(tid)))
        if expected_json not in k_sigs:
            raise AbiError("incompatible type %s %r"
                           % (_KIND_NAMES[kind], name))
        covered.add(name)
        record_sigs[key] = sig

    for name in req:
        if name not in covered:
            raise AbiError("required type %r not covered by records" % name)

    if public_roots is not None:
        meta_keys = set(expected_keys)
        root_keys = set()
        for name in public_roots:
            matches = [key for key in meta_keys if key[1] == name]
            if not matches:
                raise AbiError("public root %r not covered by records" % name)
            if len(matches) > 1:
                raise AbiError("ambiguous public root %r" % name)
            root_keys.add(matches[0])
        _public_closure(root_keys, record_sigs)

    if expected_keys != sorted(expected_keys):
        # Determinism is required for reproducibly built metadata.
        raise AbiError("metadata records not sorted by kind/name")
    if len(set(expected_keys)) != len(expected_keys):
        raise AbiError("duplicate metadata record")

