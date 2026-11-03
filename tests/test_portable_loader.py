import gzip
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import kernel_abi
import supervisor


INT_ENC = 0x01000020  # signed int, 32 bits


def _btf(member_offset=0):
    strings = b"\x00int\x00fixture\x00x\x00"
    types = bytearray()
    # id 1: INT, size 4
    types += struct.pack("<III", 1, 1 << 24, 4)
    types += struct.pack("<I", INT_ENC)
    # id 2: STRUCT "fixture", member "x" at member_offset bytes
    types += struct.pack(
        "<III", strings.index(b"fixture"), 1 | (4 << 24), 4 + member_offset
    )
    types += struct.pack("<III", strings.index(b"x\x00"), 1, member_offset * 8)
    return (
        struct.pack(
            "<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(types), len(types), len(strings)
        )
        + bytes(types)
        + strings
    )


class _Completed(object):
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _FakeRunner(object):
    """Records calls; only the loader paths are modelled."""

    def __init__(self, root):
        self.root = root
        self.calls = []
        self.insmod_calls = []
        self.dependency_calls = []
        self.insmod_rc = 0

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        args = list(argv[1:])
        if tool == "iptables":
            if "-A" in args:
                return _Completed(1, stderr="native-probe-error")
            return _Completed(0)
        if tool == "modprobe":
            module = args[-1]
            if module in ("xt_cgroup", "xt_nat"):
                return _Completed(1, stderr="system-module-not-found")
            self.dependency_calls.append(module)
            return _Completed(0)
        if tool == "insmod":
            path = Path(args[-1])
            self.insmod_calls.append(path)
            if self.insmod_rc:
                return _Completed(self.insmod_rc, stderr="insmod-error")
            (self.root / "sys" / "module" / path.stem).mkdir(
                parents=True, exist_ok=True
            )
            return _Completed(0)
        return _Completed(0)


class PortableLoaderTest(unittest.TestCase):
    RELEASE = "7.2.6"
    MACHINE = "aarch64"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for rel in ("sys/kernel/btf", "sys/module", "proc", "plugin/portable"):
            (self.root / rel).mkdir(parents=True)
        self.compat = self.root / "plugin"
        self.btf = _btf()
        (self.root / "sys/kernel/btf/vmlinux").write_bytes(self.btf)
        (self.root / "proc/config.gz").write_bytes(
            gzip.compress(
                b"CONFIG_CGROUPS=y\n"
                b"CONFIG_SOCK_CGROUP_DATA=y\n"
                b"CONFIG_UNRELATED=m\n"
            )
        )
        self.config = {"engine": "fex", "kernel_compat": str(self.compat)}
        self.manifest = {
            "kernel_release": self.RELEASE,
            "machine": self.MACHINE,
            "config_sha256": "0" * 64,
            "portable_modules": {},
        }
        for name in ("xt_cgroup", "xt_nat"):
            data = ("fake-" + name).encode("ascii")
            (self.compat / "portable" / (name + ".ko")).write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            meta = kernel_abi.build_abi(
                self.btf,
                self.btf,
                digest,
                self.RELEASE,
                self.MACHINE,
                ["fixture"],
                public_roots=["fixture"],
            )
            blob = json.dumps(meta, sort_keys=True).encode()
            (self.compat / "portable" / (name + ".abi.json")).write_bytes(blob)
            self.manifest["portable_modules"][name] = {
                "module_sha256": digest,
                "abi_sha256": hashlib.sha256(blob).hexdigest(),
            }
        self._write_manifest()

    def _write_manifest(self):
        (self.compat / "manifest.json").write_text(
            json.dumps(self.manifest), encoding="utf-8"
        )

    def _uname(self):
        info = mock.Mock()
        info.release = self.RELEASE
        info.machine = self.MACHINE
        info.version = "test"
        return mock.patch.object(supervisor.os, "uname", return_value=info)

    def _ensure_cgroup(self, fake, config=None):
        diagnostics = []
        with self._uname():
            supervisor.ensure_cgroup_support(
                config or self.config,
                root=str(self.root),
                diagnostics=diagnostics,
                runner=fake,
            )
        return diagnostics

    def test_loaded_once_then_skipped_then_reloaded_after_reboot(self):
        fake = _FakeRunner(self.root)
        self._ensure_cgroup(fake)
        self.assertEqual(len(fake.insmod_calls), 1)
        self._ensure_cgroup(fake)
        self.assertEqual(len(fake.insmod_calls), 1)
        (self.root / "sys/module/xt_cgroup").rmdir()
        self._ensure_cgroup(fake)
        self.assertEqual(len(fake.insmod_calls), 2)

    def test_unrelated_config_change_still_loads(self):
        (self.root / "proc/config.gz").write_bytes(
            gzip.compress(
                b"CONFIG_CGROUPS=y\n"
                b"CONFIG_SOCK_CGROUP_DATA=y\n"
                b"CONFIG_UNRELATED=y\n"
            )
        )
        fake = _FakeRunner(self.root)
        self._ensure_cgroup(fake)
        self.assertEqual(len(fake.insmod_calls), 1)

    def test_portable_nat_loads(self):
        fake = _FakeRunner(self.root)
        with self._uname():
            supervisor.ensure_nat_support(
                self.config, root=str(self.root), diagnostics=[], runner=fake
            )
        self.assertTrue(any(p.stem == "xt_nat" for p in fake.insmod_calls))

    def test_bad_module_hash_rejected_before_dependency_and_insmod(self):
        (self.compat / "portable/xt_cgroup.ko").write_bytes(b"tampered")
        fake = _FakeRunner(self.root)
        with self.assertRaises(RuntimeError):
            self._ensure_cgroup(fake)
        self.assertEqual(fake.dependency_calls, [])
        self.assertEqual(fake.insmod_calls, [])

    def test_bad_abi_hash_rejected_before_dependency_and_insmod(self):
        self.manifest["portable_modules"]["xt_cgroup"]["abi_sha256"] = "1" * 64
        self._write_manifest()
        fake = _FakeRunner(self.root)
        with self.assertRaises(RuntimeError):
            self._ensure_cgroup(fake)
        self.assertEqual(fake.dependency_calls, [])
        self.assertEqual(fake.insmod_calls, [])

    def test_changed_host_btf_rejected_before_insmod(self):
        (self.root / "sys/kernel/btf/vmlinux").write_bytes(_btf(member_offset=4))
        fake = _FakeRunner(self.root)
        with self.assertRaises(RuntimeError):
            self._ensure_cgroup(fake)
        self.assertEqual(fake.insmod_calls, [])

    def test_classid_enabled_rejected(self):
        (self.root / "proc/config.gz").write_bytes(
            gzip.compress(
                b"CONFIG_CGROUPS=y\n"
                b"CONFIG_SOCK_CGROUP_DATA=y\n"
                b"CONFIG_CGROUP_NET_CLASSID=y\n"
            )
        )
        fake = _FakeRunner(self.root)
        with self.assertRaises(RuntimeError):
            self._ensure_cgroup(fake)
        self.assertEqual(fake.insmod_calls, [])

    def test_critical_config_branch_missing_rejected(self):
        (self.root / "proc/config.gz").write_bytes(
            gzip.compress(b"CONFIG_CGROUPS=y\nCONFIG_SOCK_CGROUP_DATA=n\n")
        )
        fake = _FakeRunner(self.root)
        with self.assertRaises(RuntimeError):
            self._ensure_cgroup(fake)
        self.assertEqual(fake.insmod_calls, [])

    def test_exact_profile_tampered_module_never_falls_back_to_portable(self):
        self.manifest["config_sha256"] = supervisor._normalized_config_sha256(
            self.root / "proc/config.gz"
        )
        self.manifest["module_sha256"] = "2" * 64
        (self.compat / "xt_cgroup.ko").write_bytes(b"tampered-exact")
        self._write_manifest()
        fake = _FakeRunner(self.root)
        with self.assertRaises(RuntimeError):
            self._ensure_cgroup(fake)
        self.assertEqual(fake.dependency_calls, [])
        self.assertEqual(fake.insmod_calls, [])

    def test_final_failure_message_keeps_every_cause(self):
        (self.root / "sys/kernel/btf/vmlinux").write_bytes(_btf(member_offset=4))
        fake = _FakeRunner(self.root)
        with self.assertRaises(RuntimeError) as caught:
            self._ensure_cgroup(fake)
        message = str(caught.exception)
        self.assertIn("native-probe-error", message)
        self.assertIn("system-module-not-found", message)
        self.assertIn("ABI", message)


if __name__ == "__main__":
    unittest.main()
