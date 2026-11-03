import hashlib
import json
import struct
import unittest

from kernel_abi import AbiError, Btf, build_abi, validate_abi


# ---- tiny BTF byte builder ---------------------------------------------

# Kinds and their fixed payload / vlen-driven payload sizes are mirrored here.
VARLEN = {4, 5, 6, 13, 15, 19}


class B:
    """Mutable BTF builder. Types are added in order; IDs start at 1."""

    def __init__(self):
        self.types = []  # list of (kind, kflag, name, extra)

    def add(self, kind, name, size_or_type, kflag=0, vlen=None):
        self.types.append([kind, kflag, name, size_or_type, vlen, None])
        return len(self.types)  # id

    # -- helpers ---------------------------------------------------------
    def int_t(self, name, size, enc=0, bits=0):
        tid = len(self.types) + 1
        self.types.append([1, 0, name, size, None, (enc, 0, bits)])
        return tid

    def int_full(self, name, size, enc, bits, offset=0):
        tid = len(self.types) + 1
        self.types.append([1, 0, name, size, None, (enc, offset, bits)])
        return tid

    def datasec(self, name, entries):
        # entries: list of (var_type_id, offset, size)
        tid = len(self.types) + 1
        self.types.append([15, 0, name, 0, None, list(entries)])
        return tid

    def ptr(self, name, target):
        return self.add(2, name, target)

    def array(self, name, elem, index, nelems):
        tid = len(self.types) + 1
        self.types.append([3, 0, name, elem, None, (elem, index, nelems)])
        return tid

    def struct(self, name, size, members, kflag=0):
        tid = len(self.types) + 1
        self.types.append([4, kflag, name, size, None, list(members)])
        return tid

    def union(self, name, size, members, kflag=0):
        tid = len(self.types) + 1
        self.types.append([5, kflag, name, size, None, list(members)])
        return tid

    def enum(self, name, size, members, signed=False):
        tid = len(self.types) + 1
        self.types.append([6, 1 if signed else 0, name, size, None, list(members)])
        return tid

    def fwd(self, name, struct_flag=1):
        return self.add(7, name, 0, kflag=struct_flag)

    def typedef(self, name, target):
        return self.add(8, name, target)

    def const(self, name, target):
        return self.add(10, name, target)

    def func(self, name, proto):
        return self.add(12, name, proto)

    def proto(self, ret, args):
        tid = len(self.types) + 1
        self.types.append([13, 0, "", ret, None, list(args)])
        return tid

    def var(self, name, target):
        return self.add(14, name, target)

    def enum64(self, name, size, members, signed=False):
        tid = len(self.types) + 1
        self.types.append([19, 1 if signed else 0, name, size, None, list(members)])
        return tid

    def float_t(self, name, size):
        return self.add(16, name, size)

    # -- serialization ---------------------------------------------------
    def _strtab(self):
        # Build offset map; index 0 is the empty string.
        blob = bytearray(b"\x00")
        offsets = {"": 0}
        for t in self.types:
            name = t[2]
            if name and name not in offsets:
                offsets[name] = len(blob)
                blob += name.encode("utf-8") + b"\x00"
            extra = t[5]
            if t[0] in (4, 5):
                for mname, _mtype, _moff in extra:
                    if mname and mname not in offsets:
                        offsets[mname] = len(blob)
                        blob += mname.encode("utf-8") + b"\x00"
            if t[0] in (6, 19):
                for ename, _eval in extra:
                    if ename and ename not in offsets:
                        offsets[ename] = len(blob)
                        blob += ename.encode("utf-8") + b"\x00"
            if t[0] == 13:
                for aname, _atype in extra:
                    if aname and aname not in offsets:
                        offsets[aname] = len(blob)
                        blob += aname.encode("utf-8") + b"\x00"
            if t[0] == 15:
                for _v, _off, _sz in extra:
                    pass
        return blob, offsets

    def serialize(self, kinds_override=None, bad_name_off=None,
                  corrupt_magic=None):
        strtab, offs = self._strtab()
        type_blob = bytearray()
        for idx, t in enumerate(self.types):
            kind, kflag, name, sot, vlen, extra = t
            if kinds_override is not None and idx == kinds_override[0]:
                kind = kinds_override[1]
            name_off = offs.get(name, 0)
            if bad_name_off is not None and idx == bad_name_off[0]:
                name_off = bad_name_off[1]
            if kind in VARLEN:
                v = len(extra) if vlen is None else vlen
            else:
                v = 0
            info = (kind << 24) | ((kflag & 1) << 31) | (v & 0xFFFF)
            type_blob += struct.pack("<III", name_off, info, sot)
            if kind == 1:
                enc, off, bits = extra
                type_blob += struct.pack(
                    "<I", (enc << 24) | (off << 16) | bits)
            elif kind == 3:
                e, i, n = extra
                type_blob += struct.pack("<III", e, i, n)
            elif kind in (4, 5):
                for mname, mtype, moff in extra:
                    type_blob += struct.pack("<III", offs.get(mname, 0), mtype, moff)
            elif kind == 6:
                for ename, eval_ in extra:
                    type_blob += struct.pack(
                        "<II", offs.get(ename, 0), eval_ & 0xFFFFFFFF)
            elif kind == 13:
                for aname, atype in extra:
                    type_blob += struct.pack("<II", offs.get(aname, 0), atype)
            elif kind == 14:
                type_blob += struct.pack("<I", sot)
            elif kind == 17:
                type_blob += struct.pack("<I", sot)
            elif kind == 19:
                for ename, eval_ in extra:
                    u = eval_ & 0xFFFFFFFFFFFFFFFF
                    type_blob += struct.pack("<III", offs.get(ename, 0),
                                             u & 0xFFFFFFFF, u >> 32)
            elif kind == 15:
                for var, off, sz in extra:
                    type_blob += struct.pack("<III", var, off, sz)

        magic = 0xEB9F if corrupt_magic is None else corrupt_magic
        header = struct.pack("<HBBIIIII", magic, 1, 0, 24, 0,
                             len(type_blob), len(type_blob), len(strtab))
        return header + bytes(type_blob) + bytes(strtab)


BASE = "a" * 64
REL = "6.6.0-armada"
MACH = "aarch64"


# ---- tests --------------------------------------------------------------


class BtfParsingTests(unittest.TestCase):
    def test_header_wire_format(self):
        b = B()
        b.struct("s", 4, [])
        data = b.serialize()
        self.assertEqual(struct.calcsize("<HBBIIIII"), 24)
        self.assertEqual(len(data), 24 + len(b.types) * 12
                        + len(b._strtab()[0]))
        self.assertEqual(data[:8].hex(), "9feb010018000000")

    def test_bad_magic(self):
        b = B()
        b.struct("s", 4, [])
        with self.assertRaises(AbiError):
            Btf(b.serialize(corrupt_magic=0x1234))

    def test_truncated(self):
        b = B()
        b.struct("s", 4, [])
        data = b.serialize()
        with self.assertRaises(AbiError):
            Btf(data[:20])
        with self.assertRaises(AbiError):
            Btf(data[:-3])

    def test_unknown_kind(self):
        b = B()
        b.struct("s", 4, [])
        with self.assertRaises(AbiError):
            Btf(b.serialize(kinds_override=(0, 31)))

    def test_bad_name_offset(self):
        b = B()
        b.struct("s", 4, [])
        with self.assertRaises(AbiError):
            Btf(b.serialize(bad_name_off=(0, 10000)))

    def test_bad_type_reference(self):
        b = B()
        b.ptr("p", 999)
        with self.assertRaises(AbiError):
            Btf(b.serialize())

    def test_unreachable_invalid_node_rejected(self):
        b = B()
        b.struct("s", 4, [])
        b.ptr("orphan", 4242)
        with self.assertRaises(AbiError):
            Btf(b.serialize())

    def test_array_requires_positive(self):
        b = B()
        b.int_t("i", 4)
        b.array("a", 0, 1, 2)
        with self.assertRaises(AbiError):
            Btf(b.serialize())

    def test_named_records(self):
        b = B()
        i = b.int_t("i", 4)
        b.struct("s", 4, [(None, i, 0)])
        btf = Btf(b.serialize())
        recs = btf.named_records()
        self.assertIn((4, "s"), recs)
        self.assertNotIn((1, "i"), recs)

    def test_void_pointer_and_const_void_named(self):
        b = B()
        b.ptr("p", 0)
        b.const("cvoid", 0)
        b.types.append([10, 0, "cvoid2", 0, None, None])
        btf = Btf(b.serialize())
        self.assertEqual(btf.signature(1), {
            "kind": "ptr", "pointee": {"kind": "void"}})

    def test_func_proto_variadic_last(self):
        b = B()
        a = b.add(9, "", 0) if False else None
        i = b.int_t("int", 4)
        p = b.proto(i, [("a", i), ("", 0)])
        b.func("f", p)
        sig = Btf(b.serialize()).signature(p)
        self.assertEqual(sig["args"][-1], {"kind": "varargs"})

    def test_func_proto_void_middle_rejected(self):
        b = B()
        i = b.int_t("int", 4)
        b.proto(i, [("", 0), ("a", i)])
        with self.assertRaises(AbiError):
            Btf(b.serialize())

    def test_func_proto_named_last_void_rejected(self):
        b = B()
        i = b.int_t("int", 4)
        b.proto(i, [("named_void", 0)])
        with self.assertRaises(AbiError):
            Btf(b.serialize())

    def test_func_target_must_be_proto(self):
        b = B()
        i = b.int_t("int", 4)
        b.func("f", i)
        with self.assertRaises(AbiError):
            Btf(b.serialize())

    def test_var_void_rejected(self):
        b = B()
        b.var("v", 0)
        with self.assertRaises(AbiError):
            Btf(b.serialize())

    def test_datasec_type_id_first(self):
        b = B()
        i = b.int_t("int", 4)
        v = b.var("v", i)
        b.datasec(".data", [(v, 64, 4)])
        btf = Btf(b.serialize())
        ds = btf.types[3]
        self.assertEqual(struct.unpack_from("<I", ds.payload, 0)[0], v)

    def test_bad_enum_name_rejected(self):
        b = B()
        b.enum("E", 4, [("X", 1)])
        data = bytearray(b.serialize())
        # corrupt the enum member's name_off to a huge value.
        type_start = 24
        member_off = type_start + 12
        struct.pack_into("<I", data, member_off, 999999)
        with self.assertRaises(AbiError):
            Btf(bytes(data))

    def test_typedef_cycle_rejected(self):
        b = B()
        b.types.append([8, 0, "a", 2, None, None])
        b.types.append([8, 0, "b", 1, None, None])
        with self.assertRaises(AbiError):
            Btf(b.serialize()).signature(1)

    def test_anonymous_struct_pointer_cycle_terminates(self):
        b = B()
        b.int_t("int", 4)
        sid = len(b.types) + 1
        b.types.append([4, 0, "", 0, None, []])
        p = b.ptr("selfp", sid)
        b.types[sid - 1][5].append(("next", p, 0))
        data = b.serialize()
        with self.assertRaises(AbiError):
            Btf(data).signature(sid)


class SignatureTests(unittest.TestCase):
    def _two_mods(self, build_a, build_b):
        a, b = B(), B()
        build_a(a)
        build_b(b)
        return a.serialize(), b.serialize()

    def test_equivalent_ids_and_typedef_aliases(self):
        def mod_a(b):
            i = b.int_t("u32", 4)
            b.typedef("my_u32", i)
            t = b.typedef("alias", i)
            b.struct("outer", 4, [("x", t, 0)])

        def mod_b(b):
            # extra filler shifts IDs
            b.ptr("filler", 1)
            i = b.int_t("unsigned int", 4)
            b.struct("outer", 4, [("x", i, 0)])

        da, db = self._two_mods(mod_a, mod_b)
        ba, bb = Btf(da), Btf(db)
        ra = ba.named_records()[(4, "outer")][0]
        rb = bb.named_records()[(4, "outer")][0]
        self.assertEqual(ba.signature(ra), bb.signature(rb))
        self.assertNotIn('"type_id":', json.dumps(ba.signature(ra)))

    def test_offset_size_mismatch(self):
        def mod_a(b):
            i = b.int_t("int", 4)
            b.struct("outer", 8, [("x", i, 0), ("y", i, 32)])
        def mod_b(b):
            i = b.int_t("int", 4)
            b.struct("outer", 8, [("x", i, 0), ("y", i, 64)])
        da, db = self._two_mods(mod_a, mod_b)
        a, bb = Btf(da), Btf(db)
        ra = a.named_records()[(4, "outer")][0]
        rb = bb.named_records()[(4, "outer")][0]
        self.assertNotEqual(a.signature(ra), bb.signature(rb))
        with self.assertRaises(AbiError):
            build_abi(da, db, BASE, REL, MACH, [])

    def test_bitfield_canonical(self):
        def mod_a(b):
            i = b.int_t("int", 4)
            b.struct("outer", 4, [("x", i, (3 << 24) | 2)], kflag=1)
        def mod_b(b):
            i = b.int_t("int", 4)
            b.struct("outer", 4, [("x", i, (3 << 24) | 2)], kflag=1)
        da, db = self._two_mods(mod_a, mod_b)
        a = Btf(da)
        sig = a.signature(a.named_records()[(4, "outer")][0])
        member = sig["members"][0]
        self.assertEqual(member["bit_offset"], 2)
        self.assertEqual(member["bit_width"], 3)

    def test_enum_signed_and_64(self):
        b = B()
        b.enum("E", 4, [("NEG", -1), ("A", 3)], signed=True)
        b.enum64("E64", 8, [("BIG", 2**40)], signed=False)
        b.enum64("S64", 8, [("MINUS", -5)], signed=True)
        btf = Btf(b.serialize())
        esig = btf.signature(btf.named_records()[(6, "E")][0])
        self.assertTrue(esig["signed"])
        self.assertEqual(esig["size"], 4)
        self.assertEqual(esig["members"], [{"name": "NEG", "value": -1},
                                           {"name": "A", "value": 3}])
        e64sig = btf.signature(btf.named_records()[(19, "E64")][0])
        self.assertEqual(e64sig["size"], 8)
        self.assertEqual(e64sig["members"], [{"name": "BIG", "value": 2**40}])
        s64sig = btf.signature(btf.named_records()[(19, "S64")][0])
        self.assertEqual(s64sig["members"], [{"name": "MINUS", "value": -5}])

    def test_size_mismatch_same_members(self):
        def mod(sz):
            b = B()
            i = b.int_t("int", 4)
            b.struct("outer", sz, [("x", i, 0), ("y", i, 32)])
            return b.serialize()
        a, bb = Btf(mod(8)), Btf(mod(16))
        sa = a.signature(a.named_records()[(4, "outer")][0])
        sb = bb.signature(bb.named_records()[(4, "outer")][0])
        self.assertNotEqual(sa, sb)
        with self.assertRaises(AbiError):
            build_abi(mod(8), mod(16), BASE, REL, MACH, ["outer"])

    def test_int_wire_format_payload_hex(self):
        b = B()
        b.int_full("int", 4, 1, 32)
        data = b.serialize()
        # INT payload follows the 12-byte type header at offset 24.
        self.assertEqual(data[24 + 12:24 + 16].hex(), "20000001")

    def test_int_width_signedness_mismatch(self):
        def mod(bits, enc):
            b = B()
            i = b.int_full("int", 4, enc=enc, bits=bits)
            b.struct("outer", 4, [("x", i, 0)])
            return b.serialize()
        a = Btf(mod(32, 0))
        c = Btf(mod(32, 1))
        sa = a.signature(a.named_records()[(4, "outer")][0])
        sc = c.signature(c.named_records()[(4, "outer")][0])
        self.assertNotEqual(sa, sc)
        with self.assertRaises(AbiError):
            build_abi(mod(32, 0), mod(32, 1), BASE, REL, MACH, ["outer"])

    def test_valid_void_ptr_constvoid_variadic(self):
        b = B()
        b.ptr("voidp", 0)
        b.types.append([10, 0, "constvoid", 0, None, None])
        i = b.int_t("int", 4)
        p = b.proto(i, [("x", 1), ("", 0)])
        b.func("f", p)
        btf = Btf(b.serialize())
        self.assertEqual(btf.signature(1)["pointee"], {"kind": "void"})
        sig = btf.signature(p)
        self.assertEqual(sig["args"][-1], {"kind": "varargs"})

    def test_nested_named_struct_immediate_ref(self):
        b = B()
        i = b.int_t("int", 4)
        inner = b.struct("inner", 4, [("a", i, 0)])
        b.struct("outer", 4, [("in", inner, 0)])
        btf = Btf(b.serialize())
        sig = btf.signature(btf.named_records()[(4, "outer")][0])
        self.assertEqual(sig["members"][0]["type"], {
            "kind": "ref", "ref_kind": "struct", "ref_name": "inner"})

    def test_top_fwd_rejected(self):
        b = B()
        b.fwd("fwdty", struct_flag=1)
        with self.assertRaises(AbiError):
            Btf(b.serialize()).signature(1)

    def test_nested_anonymous(self):
        def mod(b):
            i = b.int_t("int", 4)
            inner = b.struct(None, 4, [("a", i, 0)])
            b.struct("outer", 4, [("inner", inner, 0)])
        a, bb = B(), B()
        mod(a)
        mod(bb)
        da, db = a.serialize(), bb.serialize()
        sa = Btf(da).signature(Btf(da).named_records()[(4, "outer")][0])
        sb = Btf(db).signature(Btf(db).named_records()[(4, "outer")][0])
        self.assertEqual(sa, sb)
        self.assertTrue(sa["members"][0]["type"]["anonymous"])

    def test_function_pointer(self):
        def mod(b):
            v = b.add(2, "void", 0) if False else None
            i = b.int_t("int", 4)
            p = b.proto(i, [("a", i), ("b", b.ptr("p2", i))])
            b.ptr("fp", p)
            b.struct("outer", 8, [("cb", b.ptr("cbp", p), 0)])
        a, bb = B(), B()
        mod(a)
        mod(bb)
        da, db = a.serialize(), bb.serialize()
        sa = Btf(da).signature(Btf(da).named_records()[(4, "outer")][0])
        sb = Btf(db).signature(Btf(db).named_records()[(4, "outer")][0])
        self.assertEqual(sa, sb)
        self.assertEqual(sa["members"][0]["type"]["kind"], "ptr")

    def test_recursion_cycle_via_pointer_allowed(self):
        b = B()
        i = b.int_t("int", 4)
        tid = len(b.types) + 1  # captured index of the node struct
        b.types.append([4, 0, "node", 16, None, [("next", 0, 0)]])
        b.types[tid - 1][5][0] = ("next", b.ptr("nextp", tid), 0)
        b.types[tid - 1][5].append(("val", i, 64))
        data = b.serialize()
        btf = Btf(data)
        sig = btf.signature(btf.named_records()[(4, "node")][0])
        self.assertEqual(sig["members"][0]["type"]["kind"], "ptr")
        self.assertEqual(sig["members"][0]["type"]["pointee"], {
            "kind": "ref", "ref_kind": "struct", "ref_name": "node"})


class BuildAbiTests(unittest.TestCase):
    def _kernel(self):
        b = B()
        i = b.int_t("int", 4)
        b.struct("xt_cgroup_info", 8, [("a", i, 0), ("b", i, 32)])
        return b.serialize()

    def _module(self, offset=32):
        b = B()
        i = b.int_t("int", 4)
        b.struct("xt_cgroup_info", 8, [("a", i, 0), ("b", i, offset)])
        b.struct("module_private", 4, [("p", i, 0)])
        return b.serialize()

    def test_build_and_validate(self):
        md = build_abi(self._module(), self._kernel(), BASE, REL, MACH,
                       ["xt_cgroup_info"])
        self.assertEqual(md["schema"], 1)
        self.assertEqual([r["name"] for r in md["records"]], ["xt_cgroup_info"])
        validate_abi(md, self._kernel(), BASE, REL, MACH)
        self.assertNotIn("module_private", json.dumps(md))

    def test_incompatible_intersection_rejected(self):
        with self.assertRaises(AbiError):
            build_abi(self._module(offset=64), self._kernel(), BASE, REL, MACH,
                      ["xt_cgroup_info"])

    def test_empty_required_names_rejected(self):
        with self.assertRaises(AbiError):
            build_abi(self._module(), self._kernel(), BASE, REL, MACH, [])

    def test_missing_required(self):
        with self.assertRaises(AbiError):
            build_abi(self._module(), self._kernel(), BASE, REL, MACH,
                      ["not_there"])

    def test_private_omitted(self):
        md = build_abi(self._module(), self._kernel(), BASE, REL, MACH,
                       ["xt_cgroup_info"])
        self.assertFalse(any(r["name"] == "module_private" for r in md["records"]))

    def test_conflicting_duplicate_module_record_rejected(self):
        k = B()
        i = k.int_t("int", 4)
        k.struct("dup", 4, [("a", i, 0)])
        ker = k.serialize()
        m = B()
        i = m.int_t("int", 4)
        m.struct("dup", 4, [("a", i, 0)])
        m.struct("dup", 8, [("a", i, 0), ("b", i, 32)])
        with self.assertRaises(AbiError):
            build_abi(m.serialize(), ker, BASE, REL, MACH, ["dup"])

    def test_empty_required_names_validate_rejected(self):
        md, k = ValidateAbiTests._setup(self)
        md["required_names"] = []
        with self.assertRaises(AbiError):
            validate_abi(md, k, BASE, REL, MACH)


class ValidateAbiTests(unittest.TestCase):
    def _setup(self):
        b = B()
        i = b.int_t("int", 4)
        b.struct("xt_cgroup_info", 8, [("a", i, 0), ("b", i, 32)])
        k = b.serialize()
        md = build_abi(k, k, BASE, REL, MACH, ["xt_cgroup_info"])
        return md, k

    def test_ok(self):
        md, k = self._setup()
        validate_abi(md, k, BASE, REL, MACH)

    def test_hash_mismatch(self):
        md, k = self._setup()
        with self.assertRaises(AbiError):
            validate_abi(md, k, "b" * 64, REL, MACH)

    def test_bad_digest(self):
        md, k = self._setup()
        md["module_sha256"] = "xyz"
        with self.assertRaises(AbiError):
            validate_abi(md, k, BASE, REL, MACH)

    def test_release_machine_mismatch(self):
        md, k = self._setup()
        with self.assertRaises(AbiError):
            validate_abi(md, k, BASE, REL + "x", MACH)
        with self.assertRaises(AbiError):
            validate_abi(md, k, BASE, REL, "x86")

    def test_schema_mismatch(self):
        md, k = self._setup()
        md["schema"] = 2
        with self.assertRaises(AbiError):
            validate_abi(md, k, BASE, REL, MACH)

    def test_schema_bool_rejected(self):
        md, k = self._setup()
        md["schema"] = True
        with self.assertRaises(AbiError):
            validate_abi(md, k, BASE, REL, MACH)

    def test_missing_required(self):
        md, k = self._setup()
        md["required_names"] = ["absent"]
        with self.assertRaises(AbiError):
            validate_abi(md, k, BASE, REL, MACH)

    def test_incompatible_record(self):
        md, k = self._setup()
        b = B()
        i = b.int_t("int", 4)
        b.struct("xt_cgroup_info", 16, [("a", i, 0), ("b", i, 32)])
        with self.assertRaises(AbiError):
            validate_abi(md, b.serialize(), BASE, REL, MACH)

    def test_nested_named_reference_mismatch_via_validate(self):
        # Kernel: outer.in is a ref to inner(a at 0).
        k = B()
        i = k.int_t("int", 4)
        inner = k.struct("inner", 4, [("a", i, 0)])
        k.struct("outer", 4, [("in", inner, 0)])
        ker = k.serialize()
        md = build_abi(ker, ker, BASE, REL, MACH, ["outer"])
        # Mutate metadata to claim a different nested type reference.
        md2 = json.loads(json.dumps(md))
        md2["records"][0]["signature"]["members"][0]["type"]["ref_name"] = "other"
        with self.assertRaises(AbiError):
            validate_abi(md2, ker, BASE, REL, MACH)

    def test_records_invalid_kind_no_leak(self):
        md, k = self._setup()
        md["records"][0]["kind"] = True
        with self.assertRaises(AbiError):
            validate_abi(md, k, BASE, REL, MACH)
        md, k = self._setup()
        del md["records"][0]["name"]
        with self.assertRaises(AbiError):
            validate_abi(md, k, BASE, REL, MACH)

    def test_duplicate_required(self):
        md, k = self._setup()
        md["required_names"] = ["xt_cgroup_info", "xt_cgroup_info"]
        with self.assertRaises(AbiError):
            validate_abi(md, k, BASE, REL, MACH)


if __name__ == "__main__":
    unittest.main()

