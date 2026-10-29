"""Contract tests for py_modules/uu_accelerator/platform.py.

These tests are written before the production module exists and define the
agreed API. They are expected to be red until platform.py is implemented.

Run with:
    PYTHONPATH=py_modules python3 -m unittest discover -s tests -v
"""

import os
import shutil
import struct
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from uu_accelerator.platform import elf_machine, detect_platform, select_engine

ELF_X86_64 = 62
ELF_AARCH64 = 183


def elf_header(machine):
    """A syntactically valid 64-bit little-endian ELF header with e_machine set."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    body = struct.pack(
        "<HHIQQQIHHHHHH",
        2, machine, 1,        # e_type, e_machine, e_version
        0, 0, 0, 0,           # e_entry, e_phoff, e_shoff, e_flags
        64, 56, 1, 64, 0, 0,  # e_ehsize .. e_shstrndx
    )
    return ident + body


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    return path


def platform_dict(**overrides):
    base = dict(
        os_id="armada",
        is_armada=True,
        arch="aarch64",
        home="/home/deck",
        fex_path=None,
        legacy_install=False,
        engines=["native"],
        recommended_engine="native",
    )
    base.update(overrides)
    return base


class ElfMachineTests(unittest.TestCase):
    def test_identifies_official_architectures(self):
        for machine, expected in ((ELF_X86_64, "x86_64"), (ELF_AARCH64, "aarch64")):
            with self.subTest(machine=machine):
                self.assertEqual(elf_machine(elf_header(machine)), expected)

    def test_rejects_non_elf_header(self):
        for bad in (b"", b"not-an-elf", b"\x7fELF\x02\x01\x01\x00"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                elf_machine(bad)


class DetectPlatformTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = Path(self.tmp) / "root"

    # -- fixture helpers -------------------------------------------------
    def os_release(self, os_id):
        write(self.root / "etc/os-release",
              'ID={}\nNAME="Test"\nVERSION_ID="1"\n'.format(os_id))

    def pid1(self, machine):
        target = write(self.root / "usr/bin/init", elf_header(machine))
        link = self.root / "proc/1/exe"
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(str(target), str(link))

    def armada_marker(self):
        write(self.root / "usr/lib/armada/version", "1.0.0\n")

    def legacy_service(self):
        write(self.root / "etc/systemd/system/uuplugin.service", "[Unit]\n")

    @staticmethod
    def no_which(name):
        return None

    @staticmethod
    def fex_which(path):
        return lambda name: str(path) if name == "FEXInterpreter" else None

    @staticmethod
    def fex_bin_which(path):
        return lambda name: str(path) if name == "FEX" else None

    def snapshot(self):
        return {
            str(p.relative_to(self.root)): p.read_bytes()
            for p in sorted(self.root.rglob("*"))
            if p.is_file()
        }

    # -- tests -----------------------------------------------------------
    def test_prefers_pid1_elf_over_translated_uname(self):
        # Host PID1 is a real AArch64 binary, but the translated Decky backend
        # reports x86_64 through uname. PID1 must win.
        self.pid1(ELF_AARCH64)
        self.os_release("armada")
        self.armada_marker()
        fex = write(self.root / "usr/bin/FEXInterpreter", elf_header(ELF_X86_64))
        home = "/home/Decky User/uu"  # must not assume /home/deck
        translated = types.SimpleNamespace(machine="x86_64")
        with mock.patch("os.uname", return_value=translated):
            info = detect_platform(self.root, home, which=self.fex_which(fex))
        self.assertEqual(info["arch"], "aarch64")
        self.assertTrue(info["is_armada"])
        self.assertEqual(info["os_id"], "armada")
        self.assertEqual(info["home"], home)
        self.assertEqual(info["fex_path"], str(fex))
        self.assertEqual(info["engines"], ["fex"])
        self.assertEqual(info["recommended_engine"], "fex")
        self.assertFalse(info["legacy_install"])

    def test_detects_armada_fex_binary_when_not_on_path(self):
        # Armada ships FEX at /usr/bin/FEX; FEXInterpreter may not be on PATH.
        # The real host arch still comes from PID1, not the translated uname.
        self.pid1(ELF_AARCH64)
        self.os_release("arch")
        self.armada_marker()
        fex = write(self.root / "usr/bin/FEX", elf_header(ELF_X86_64))
        fex.chmod(0o755)
        home = "/home/Decky User/uu"  # must not assume /home/deck
        translated = types.SimpleNamespace(machine="x86_64")
        with mock.patch("os.uname", return_value=translated):
            info = detect_platform(self.root, home, which=self.no_which)
        self.assertEqual(info["arch"], "aarch64")
        self.assertEqual(info["os_id"], "arch")
        self.assertTrue(info["is_armada"])  # armada marker, not the os_id
        self.assertEqual(info["home"], home)
        self.assertEqual(info["fex_path"], str(fex))
        self.assertEqual(info["engines"], ["fex"])
        self.assertEqual(info["recommended_engine"], "fex")

    def test_prefers_fex_interpreter_over_usr_bin_fex(self):
        # When both entry points exist, the PATH-resolved FEXInterpreter wins.
        self.pid1(ELF_AARCH64)
        self.os_release("armada")
        self.armada_marker()
        fallback = write(self.root / "usr/bin/FEX", elf_header(ELF_X86_64))
        interpreter = write(self.root / "usr/bin/FEXInterpreter",
                            elf_header(ELF_X86_64))
        info = detect_platform(self.root, "/home/deck",
                               which=self.fex_which(interpreter))
        self.assertEqual(info["arch"], "aarch64")
        self.assertEqual(info["fex_path"], str(interpreter))
        self.assertNotEqual(info["fex_path"], str(fallback))
        self.assertEqual(info["engines"], ["fex"])
        self.assertEqual(info["recommended_engine"], "fex")

    def test_armada_fex_regression_from_usr_bin_fex(self):
        # Armada marker + translated guest uname (x86_64) + FEX present at
        # /usr/bin/FEX. The translated guest must not leak into the host arch,
        # and FEX still has to be reported as an available engine.
        self.pid1(ELF_AARCH64)
        self.os_release("arch")
        self.armada_marker()
        fex = write(self.root / "usr/bin/FEX", elf_header(ELF_X86_64))
        translated = types.SimpleNamespace(machine="x86_64")
        which = type(self).fex_bin_which(fex)  # FEX -> path, FEXInterpreter -> None
        with mock.patch("os.uname", return_value=translated):
            info = detect_platform(self.root, "/home/deck", which=which)
        self.assertTrue(info["is_armada"])
        self.assertEqual(info["arch"], "aarch64")
        self.assertEqual(info["fex_path"], str(fex))
        self.assertEqual(info["engines"], ["fex"])
        self.assertEqual(info["recommended_engine"], "fex")

    def test_prefers_interpreter_when_both_fex_names_available(self):
        # Both /usr/bin/FEX and a PATH-resolved FEXInterpreter exist; the
        # interpreter entry point must win.
        self.pid1(ELF_AARCH64)
        self.os_release("armada")
        self.armada_marker()
        fallback = write(self.root / "usr/bin/FEX", elf_header(ELF_X86_64))
        interpreter = write(self.root / "usr/bin/FEXInterpreter",
                            elf_header(ELF_X86_64))
        which = lambda name: (
            str(interpreter) if name == "FEXInterpreter"
            else str(fallback) if name == "FEX" else None
        )
        info = detect_platform(self.root, "/home/deck", which=which)
        self.assertEqual(info["fex_path"], str(interpreter))
        self.assertNotEqual(info["fex_path"], str(fallback))

    def test_arm_host_without_fex_has_no_engine(self):
        self.pid1(ELF_AARCH64)
        self.os_release("armada")
        self.armada_marker()
        info = detect_platform(self.root, "/home/deck", which=self.no_which)
        self.assertEqual(info["arch"], "aarch64")
        self.assertEqual(info["engines"], [])
        self.assertIsNone(info["fex_path"])
        self.assertIsNone(info["recommended_engine"])

    def test_x86_64_host_has_no_engine(self):
        self.pid1(ELF_X86_64)
        self.os_release("steamos")
        info = detect_platform(self.root, "/home/deck", which=self.no_which)
        self.assertEqual(info["arch"], "x86_64")
        self.assertFalse(info["is_armada"])
        self.assertEqual(info["engines"], [])
        self.assertIsNone(info["recommended_engine"])

    def test_falls_back_to_uname_when_pid1_unreadable(self):
        # No /proc/1/exe fixture -> uname is the only remaining source.
        self.os_release("armada")
        self.armada_marker()
        uname = types.SimpleNamespace(machine="aarch64")
        with mock.patch("os.uname", return_value=uname):
            info = detect_platform(self.root, "/home/deck", which=self.no_which)
        self.assertEqual(info["arch"], "aarch64")

    def test_reports_legacy_service_install(self):
        self.pid1(ELF_X86_64)
        self.os_release("steamos")
        self.legacy_service()
        info = detect_platform(self.root, "/home/deck", which=self.no_which)
        self.assertTrue(info["legacy_install"])

    def test_does_not_mutate_fixture_tree(self):
        self.pid1(ELF_AARCH64)
        self.os_release("armada")
        self.armada_marker()
        self.legacy_service()
        before = self.snapshot()
        detect_platform(self.root, "/home/deck", which=self.no_which)
        self.assertEqual(self.snapshot(), before)

    def test_rejects_unknown_architecture(self):
        self.os_release("someos")
        uname = types.SimpleNamespace(machine="riscv64")
        with mock.patch("os.uname", return_value=uname), self.assertRaises(ValueError):
            detect_platform(self.root, "/home/deck", which=self.no_which)

    def test_readable_pid1_with_unsupported_machine_is_rejected(self):
        # PID1 is readable but not a supported architecture. The translated
        # backend uname (x86_64) must NOT be used as a fallback here: uname is
        # only a fallback when PID1 is genuinely unreadable.
        self.pid1(243)  # RISC-V e_machine, not in the supported set
        self.os_release("armada")
        translated = types.SimpleNamespace(machine="x86_64")
        with mock.patch("os.uname", return_value=translated), self.assertRaises(ValueError):
            detect_platform(self.root, "/home/deck", which=self.no_which)


class SelectEngineTests(unittest.TestCase):
    def test_auto_picks_fex_on_arm64_with_fex(self):
        platform = platform_dict(engines=["fex"], recommended_engine="fex",
                                 fex_path="/usr/bin/FEXInterpreter")
        chosen = select_engine(platform, "auto")
        self.assertEqual(chosen["engine"], "fex")
        self.assertEqual(chosen["package_type"], "steam-deck-plugin-x86_64")
        self.assertEqual(chosen["expected_arch"], "x86_64")
        self.assertEqual(chosen["launch_prefix"], ["/usr/bin/FEXInterpreter"])

    def test_fex_uses_interpreter_launch_prefix(self):
        platform = platform_dict(engines=["fex"], recommended_engine="fex",
                                 fex_path="/usr/bin/FEXInterpreter")
        chosen = select_engine(platform, "fex")
        self.assertEqual(chosen["engine"], "fex")
        self.assertEqual(chosen["package_type"], "steam-deck-plugin-x86_64")
        self.assertEqual(chosen["expected_arch"], "x86_64")
        self.assertEqual(chosen["launch_prefix"], ["/usr/bin/FEXInterpreter"])

    def test_rejects_unavailable_requests(self):
        pc = platform_dict(os_id="steamos", is_armada=False, arch="x86_64",
                           engines=["x86"], recommended_engine="x86")
        for request in ("fex", "x86", "native", "bogus"):
            with self.subTest(request=request), self.assertRaises(ValueError):
                select_engine(pc, request)
        with self.subTest(request="auto-on-x86"), self.assertRaises(ValueError):
            select_engine(pc, "auto")
        arm_no_fex = platform_dict(engines=[], recommended_engine=None, fex_path=None)
        for request in ("fex", "native", "auto"):
            with self.subTest(request=request), self.assertRaises(ValueError):
                select_engine(arm_no_fex, request)

    def test_rejects_removed_routes_even_with_forged_lists(self):
        # Forged advertised lists must never re-enable removed native/x86
        # routes; only their own requests are rejected, fex stays valid.
        forged_native = platform_dict(engines=["fex", "native"],
                                      recommended_engine="native",
                                      fex_path="/usr/bin/FEXInterpreter")
        forged_x86 = platform_dict(engines=["fex", "x86"], recommended_engine="x86",
                                   fex_path="/usr/bin/FEXInterpreter")
        for request in ("native", "x86"):
            with self.subTest(request=request), self.assertRaises(ValueError):
                select_engine(forged_native, request)
            with self.subTest(request=request), self.assertRaises(ValueError):
                select_engine(forged_x86, request)

    def test_stale_recommended_does_not_block_explicit_or_auto_fex(self):
        stale = platform_dict(engines=["fex"], recommended_engine="x86",
                              fex_path="/usr/bin/FEXInterpreter")
        for request in ("fex", "auto"):
            with self.subTest(request=request):
                chosen = select_engine(stale, request)
                self.assertEqual(chosen["engine"], "fex")
                self.assertEqual(chosen["launch_prefix"], ["/usr/bin/FEXInterpreter"])

    def test_rejects_fex_without_confirmed_arch_or_path(self):
        no_path = platform_dict(engines=["fex"], recommended_engine="fex", fex_path=None)
        wrong_arch = platform_dict(arch="x86_64", engines=["fex"],
                                   recommended_engine="fex",
                                   fex_path="/usr/bin/FEXInterpreter")
        for platform in (no_path, wrong_arch):
            for request in ("fex", "auto"):
                with self.subTest(request=request, platform=platform), self.assertRaises(ValueError):
                    select_engine(platform, request)

    def test_refuses_automatic_takeover_when_legacy(self):
        legacy = platform_dict(engines=["fex"], recommended_engine="fex",
                               fex_path="/usr/bin/FEXInterpreter",
                               legacy_install=True)
        with self.assertRaises(ValueError):
            select_engine(legacy, "auto")

    def test_refuses_explicit_engines_when_legacy(self):
        # An explicit route must not be a loophole around the legacy guard:
        # our plugin never takes over a preexisting UU installation.
        arm = platform_dict(engines=["fex"], recommended_engine="fex",
                            fex_path="/usr/bin/FEXInterpreter",
                            legacy_install=True)
        pc = platform_dict(os_id="steamos", is_armada=False, arch="x86_64",
                           engines=[], recommended_engine=None,
                           legacy_install=True)
        for platform, request in ((arm, "auto"), (arm, "fex"),
                                  (arm, "native"), (pc, "x86")):
            with self.subTest(request=request), self.assertRaises(ValueError):
                select_engine(platform, request)
