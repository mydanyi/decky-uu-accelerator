"""Portable unit tests for kernel_abi. No external tools, no devices."""

import importlib.util
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from kernel_abi import AbiError, Btf, build_abi, validate_abi
from test_kernel_abi import B

SHA = "b" * 64
REL = "6.6.0-armada"
MACH = "aarch64"
MAGIC = 0xEB9F
HDR = struct.Struct("<HBBIIIII")


def btf_bytes(tsec, strtab, gap=b""):
    """Assemble a legacy 24-byte-header BTF blob (type_off == 0)."""
    return (HDR.pack(MAGIC, 1, 0, 24, 0, len(tsec), len(tsec) + len(gap), len(strtab))
            + tsec + gap + strtab)


def local_strtab(*names):
    """Split-BTF local string table: NO leading NUL, offsets are local."""
    blob = bytearray()
    offs = {}
    for name in names:
        if name not in offs:
            offs[name] = len(blob)
            blob += name.encode("utf-8") + b"\x00"
    return bytes(blob), offs


def record_blob(name_off, size, members):
    out = struct.pack("<III", name_off, (4 << 24) | len(members), size)
    for mname_off, mtype, moff in members:
        out += struct.pack("<III", mname_off, mtype, moff)
    return out


def record_names(meta):
    return {rec["name"] for rec in meta["records"]}


def kernel_image(unrelated_size=8, root_by_value=False, root_off=0):
    b = B()
    b.int_t("int", 4, enc=1, bits=32)                       # 1
    b.struct("unrelated", unrelated_size, [("a", 1, 0)])    # 2
    b.ptr("p_unrelated", 2)                                  # 3
    target = 2 if root_by_value else 3
    b.struct("root", 8, [("link", target, root_off)])       # 4
    return b.serialize()


def closure_image():
    b = B()
    b.int_t("int", 4, enc=1, bits=32)                        # 1
    b.int_t("unsigned int", 4, bits=32)                      # 2 array index
    b.union("", 4, [("u", 1, 0)])                            # 3 anonymous union
    b.array("cells", 3, 2, 3)                                # 4 [3] of union
    b.struct("inner", 12, [("cells", 4, 0)])                 # 5
    b.enum("mode", 4, [("MODE_A", 0)])                       # 6
    b.struct("outer", 16, [("in", 5, 0), ("m", 6, 96)])      # 7
    return b.serialize()


class SplitBtfTests(unittest.TestCase):
    def setUp(self):
        base = B()
        base.int_t("int", 4, enc=1, bits=32)                     # 1
        base.int_t("unsigned int", 4, bits=32)                   # 2
        base.struct("base_tag", 4, [("v", 2, 0)])               # 3
        self.base_bytes = base.serialize()
        self.base = Btf(self.base_bytes)
        self.base_max = max(self.base.types)

    def _split_bytes(self, name):
        local, offs = local_strtab(name, "x")
        bs = self.base.string_size
        blob = record_blob(bs + offs[name], 4, [(bs + offs["x"], 2, 0)])
        return btf_bytes(blob, local), local

    def test_standalone_and_split_signatures_match(self):
        standalone = B()
        standalone.int_t("int", 4, enc=1, bits=32)
        standalone.int_t("unsigned int", 4, bits=32)
        standalone.struct("base_tag", 4, [("v", 2, 0)])
        standalone.struct("mod_rec", 8, [("tag", 3, 0), ("count", 2, 32)])
        ref = Btf(standalone.serialize())

        local, offs = local_strtab("mod_rec", "tag", "count")
        bs = self.base.string_size
        blob = record_blob(bs + offs["mod_rec"], 8,
                           [(bs + offs["tag"], 3, 0), (bs + offs["count"], 2, 32)])
        split = Btf(btf_bytes(blob, local), base=self.base)

        self.assertEqual(local[:1], b"m")  # local strtab has no leading NUL
        ref_id = ref.named_records()[(4, "mod_rec")][0]
        split_id = split.named_records()[(4, "mod_rec")][0]
        self.assertEqual(split.signature(split_id), ref.signature(ref_id))
        self.assertEqual(min(set(split.types) - set(self.base.types)), self.base_max + 1)

    def test_two_splits_share_id_range_and_merge_catalog(self):
        alpha_bytes, _ = self._split_bytes("alpha_rec")
        beta_bytes, _ = self._split_bytes("beta_rec")
        alpha = Btf(alpha_bytes, base=self.base)
        beta = Btf(beta_bytes, base=self.base)
        self.assertEqual(min(set(alpha.types) - set(self.base.types)), self.base_max + 1)
        self.assertEqual(min(set(beta.types) - set(self.base.types)), self.base_max + 1)
        self.assertIn((4, "alpha_rec"), alpha.named_records())
        self.assertIn((4, "beta_rec"), beta.named_records())

        module = B()
        module.int_t("int", 4, enc=1, bits=32)
        module.int_t("unsigned int", 4, bits=32)
        module.struct("base_tag", 4, [("v", 2, 0)])
        module.struct("alpha_rec", 4, [("x", 2, 0)])
        module.struct("beta_rec", 4, [("x", 2, 0)])
        module_bytes = module.serialize()
        image = [self.base_bytes, alpha_bytes, beta_bytes]

        meta = build_abi(module_bytes, image, SHA, REL, MACH,
                         required_names=["alpha_rec", "beta_rec"],
                         public_roots=["alpha_rec", "beta_rec"])
        validate_abi(meta, image, SHA, REL, MACH)
        self.assertEqual(record_names(meta), {"alpha_rec", "beta_rec"})

    def test_dangling_base_type_rejected(self):
        local, offs = local_strtab("bad_rec")
        blob = record_blob(self.base.string_size + offs["bad_rec"], 4, [(0, 99, 0)])
        with self.assertRaises((ValueError, AbiError)):
            Btf(btf_bytes(blob, local), base=self.base)

    def test_malformed_split_rejected(self):
        local, offs = local_strtab("bad_rec")
        blob = record_blob(self.base.string_size + offs["bad_rec"], 4, [(0, 2, 0)])
        with self.assertRaises((ValueError, AbiError)):
            Btf(btf_bytes(blob, local)[:-4], base=self.base)

    def test_nested_base_chaining_rejected(self):
        local, offs = local_strtab("bad_rec")
        blob = btf_bytes(record_blob(self.base.string_size + offs["bad_rec"], 4, [(0, 2, 0)]), local)
        inner = Btf(blob, base=self.base)
        with self.assertRaises((ValueError, AbiError)):
            Btf(blob, base=inner)


class AbiAlignmentTests(unittest.TestCase):
    def test_pointer_only_layout_change_passes_with_roots(self):
        reference = kernel_image(unrelated_size=8)
        module = kernel_image(unrelated_size=16)
        meta = build_abi(module, module, SHA, REL, MACH,
                         required_names=["root"], public_roots=["root"])
        validate_abi(meta, reference, SHA, REL, MACH)
        build_abi(module, reference, SHA, REL, MACH,
                  required_names=["root"], public_roots=["root"])

    def test_by_value_change_rejected_at_build(self):
        reference = kernel_image(unrelated_size=8, root_by_value=True)
        module = kernel_image(unrelated_size=16, root_by_value=True)
        with self.assertRaises(AbiError):
            build_abi(module, reference, SHA, REL, MACH,
                      required_names=["root"], public_roots=["root"])

    def test_by_value_change_rejected_at_validate(self):
        reference = kernel_image(unrelated_size=8, root_by_value=True)
        module = kernel_image(unrelated_size=16, root_by_value=True)
        meta = build_abi(module, module, SHA, REL, MACH,
                         required_names=["root"], public_roots=["root"])
        with self.assertRaises(AbiError):
            validate_abi(meta, reference, SHA, REL, MACH)

    def test_root_offset_change_fails(self):
        reference = kernel_image(root_off=0)
        module = kernel_image(root_off=32)
        with self.assertRaises(AbiError):
            build_abi(module, reference, SHA, REL, MACH,
                      required_names=["root"], public_roots=["root"])

    def test_explicit_pointee_root_catches_pointee_change(self):
        reference = kernel_image(unrelated_size=8)
        module = kernel_image(unrelated_size=16)
        meta = build_abi(module, module, SHA, REL, MACH,
                         required_names=["root", "unrelated"],
                         public_roots=["root", "unrelated"])
        with self.assertRaises(AbiError):
            validate_abi(meta, reference, SHA, REL, MACH)


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.img = closure_image()

    def test_nested_by_value_closure_included(self):
        meta = build_abi(self.img, self.img, SHA, REL, MACH,
                         required_names=["outer"], public_roots=["outer"])
        validate_abi(meta, self.img, SHA, REL, MACH)
        self.assertLessEqual({"outer", "inner", "mode"}, record_names(meta))

    def test_missing_closure_record_refused(self):
        meta = build_abi(self.img, self.img, SHA, REL, MACH,
                         required_names=["outer"], public_roots=["outer"])
        validate_abi(meta, self.img, SHA, REL, MACH)
        meta["records"] = [rec for rec in meta["records"] if rec["name"] != "inner"]
        self.assertNotIn("inner", record_names(meta))
        with self.assertRaises(AbiError):
            validate_abi(meta, self.img, SHA, REL, MACH)


class RootValidationTests(unittest.TestCase):
    def setUp(self):
        self.img = closure_image()

    def test_public_roots_empty_list_rejected(self):
        with self.assertRaises(AbiError):
            build_abi(self.img, self.img, SHA, REL, MACH,
                      required_names=["outer"], public_roots=[])

    def test_public_roots_empty_string_rejected(self):
        with self.assertRaises(AbiError):
            build_abi(self.img, self.img, SHA, REL, MACH,
                      required_names=["outer"], public_roots=[""])

    def test_public_roots_duplicate_rejected(self):
        with self.assertRaises(AbiError):
            build_abi(self.img, self.img, SHA, REL, MACH,
                      required_names=["outer"], public_roots=["outer", "outer"])

    def test_public_roots_missing_rejected(self):
        with self.assertRaises(AbiError):
            build_abi(self.img, self.img, SHA, REL, MACH,
                      required_names=["outer"], public_roots=["missing"])

    def test_public_roots_bare_string_rejected(self):
        with self.assertRaises((AbiError, TypeError)):
            build_abi(self.img, self.img, SHA, REL, MACH,
                      required_names=["outer"], public_roots="outer")

    def test_ambiguous_root_rejected(self):
        b = B()
        b.int_t("int", 4, enc=1, bits=32)
        b.struct("dup", 4, [("a", 1, 0)])
        b.union("dup", 4, [("b", 1, 0)])
        b.struct("outer", 4, [("v", 1, 0)])
        img = b.serialize()
        with self.assertRaises(AbiError):
            build_abi(img, img, SHA, REL, MACH,
                      required_names=["outer"], public_roots=["dup"])

    def test_default_public_roots_none_valid(self):
        meta = build_abi(self.img, self.img, SHA, REL, MACH, required_names=["outer"])
        validate_abi(meta, self.img, SHA, REL, MACH)
        self.assertIn("outer", record_names(meta))


class BuildToolExtractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = HERE.parent / "tools" / "build_kernel_abi.py"
        spec = importlib.util.spec_from_file_location("build_kernel_abi_ut", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cls.mod = mod

    def test_extract_extended_header_with_gap(self):
        b = B()
        b.int_t("int", 4, enc=1, bits=32)
        b.struct("root", 4, [("a", 1, 0)])
        core = b.serialize()
        tlen = HDR.unpack_from(core, 0)[5]
        slen = HDR.unpack_from(core, 0)[7]
        tsec = core[24:24 + tlen]
        strtab = core[24 + tlen:24 + tlen + slen]
        gap = b"\x00" * 8
        raw = (HDR.pack(MAGIC, 1, 0, 32, 0, len(tsec), len(tsec) + len(gap), len(strtab))
               + b"\x00" * 8 + tsec + gap + strtab)
        data = b"\xde\xad\xbe\xef" + raw
        with mock.patch.object(self.mod, "MIN_TYPES", 0), \
                mock.patch.object(self.mod, "REQUIRED_RECORD_KEYS", ((4, "root"),)):
            candidates = self.mod._extract_candidates(data)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].blob, raw)


if __name__ == "__main__":
    unittest.main()
