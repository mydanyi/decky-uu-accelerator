"""Regression tests for Manager.acceleration_status (STA001)."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from uu_accelerator.manager import Manager


def fake_platform(*args, **kwargs):
    return {"arch": "x86_64", "is_armada": True, "engines": ["fex"], "legacy_install": False, "recommended_engine": "fex", "fex_path": None}


def safe_runner(argv, **kwargs):
    return subprocess.CompletedProcess(argv, 0, "", "")


class AccelerationStatusTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.runtime = base / "run"
        self.settings = base / "settings"
        self.logs = base / "logs"
        self.plugin = base / "plugin"
        self.fake_root = base / "fakeroot"
        for d in (self.runtime, self.settings, self.logs, self.plugin, self.fake_root):
            d.mkdir(parents=True, exist_ok=True)
        self.mgr = Manager(
            self.runtime,
            self.settings,
            self.logs,
            self.plugin,
            root=str(self.fake_root),
            command_runner=safe_runner,
            platform_provider=fake_platform,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def write_pid(self, pid=1688):
        run_dir = self.runtime / "run"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "core.pid").write_text(f"{pid}\n", encoding="utf-8")

    def fake_proc(self, pid=1688, iff=True):
        fdinfo = self.fake_root / "proc" / str(pid) / "fdinfo"
        fdinfo.mkdir(parents=True, exist_ok=True)
        body = "" if not iff else "iff:\ttun163\n"
        (fdinfo / "38").write_text(body, encoding="utf-8")

    def write_flags(self, up=True):
        net = self.fake_root / "sys" / "class" / "net" / "tun163"
        net.mkdir(parents=True, exist_ok=True)
        (net / "flags").write_text("0x1003\n" if up else "0x902\n", encoding="utf-8")

    def probe(self):
        return self.mgr._acceleration_status(True, True)

    def test_stopped_short_circuit_no_commands(self):
        with mock.patch("subprocess.run") as run:
            self.assertEqual(self.mgr._acceleration_status(False, True), "stopped")
            self.assertEqual(self.mgr._acceleration_status(True, False), "stopped")
            self.assertEqual(self.mgr._acceleration_status(False, False), "stopped")
            run.assert_not_called()

    def test_ready_to_accelerating_to_ready(self):
        self.write_pid()
        self.fake_proc()

        def rules(argv, **kw):
            self.assertEqual(argv, ["ip", "-j", "-4", "rule", "show"])
            self.assertFalse(kw.get("shell", False))
            self.assertTrue(kw.get("capture_output"))
            self.assertTrue(kw.get("text"))
            self.assertEqual(kw.get("timeout"), 1)
            return subprocess.CompletedProcess(argv, 0, json.dumps([{"table": "179"}]), "")

        def ipt(argv, **kw):
            self.assertEqual(
                argv,
                ["iptables", "-w", "1", "-t", "nat", "-C", "OUTPUT", "-p", "udp",
                 "--dport", "53", "-m", "mark", "!", "--mark", "0x164", "-j", "DNAT",
                 "--to-destination", "172.19.163.1:53"],
            )
            self.assertFalse(kw.get("shell", False))
            self.assertTrue(kw.get("capture_output"))
            self.assertTrue(kw.get("text"))
            self.assertEqual(kw.get("timeout"), 2)
            return subprocess.CompletedProcess(argv, 0, "", "")

        # before flags exist: ready, no commands
        with mock.patch("subprocess.run") as run:
            self.assertEqual(self.probe(), "ready")
            run.assert_not_called()

        # flags UP -> dispatcher on actual argv/kwargs
        self.write_flags(True)

        def disp(argv, **kw):
            return ipt(argv, **kw) if argv[0] == "iptables" else rules(argv, **kw)

        with mock.patch("subprocess.run", side_effect=disp):
            self.assertEqual(self.probe(), "accelerating")

        # stop accelerating: interface gone -> ready
        (self.fake_root / "sys" / "class" / "net" / "tun163" / "flags").unlink()
        with mock.patch("subprocess.run") as run:
            self.assertEqual(self.probe(), "ready")
            run.assert_not_called()

    def test_zero_traffic_still_accelerating(self):
        self.write_pid()
        self.fake_proc()
        self.write_flags(True)
        for table in ("179", 179):
            with self.subTest(table=table):
                rules = subprocess.CompletedProcess([], 0, json.dumps([{"table": table}]), "")
                ipt = subprocess.CompletedProcess([], 0, "", "")
                with mock.patch("subprocess.run", side_effect=[rules, ipt]):
                    self.assertEqual(self.probe(), "accelerating")

    def test_unrelated_process_tunnel_not_counted(self):
        self.write_pid(pid=2000)
        self.fake_proc(pid=2000, iff=False)
        self.write_flags(True)
        # tunnel FD exists under another pid only
        other = self.fake_root / "proc" / "1688" / "fdinfo"
        other.mkdir(parents=True, exist_ok=True)
        (other / "38").write_text("iff:\ttun163\n", encoding="utf-8")
        with mock.patch("subprocess.run") as run:
            self.assertEqual(self.probe(), "ready")
            run.assert_not_called()

    def test_interface_down_ready(self):
        self.write_pid()
        self.fake_proc()
        self.write_flags(False)
        with mock.patch("subprocess.run") as run:
            self.assertEqual(self.probe(), "ready")
            run.assert_not_called()

    def test_missing_rule_dnat_exit1_ready(self):
        self.write_pid()
        self.fake_proc()
        self.write_flags(True)
        rules = subprocess.CompletedProcess([], 0, json.dumps([{"table": "179"}]), "")
        ipt = subprocess.CompletedProcess([], 1, "", "No such rule")
        with mock.patch("subprocess.run", side_effect=[rules, ipt]):
            self.assertEqual(self.probe(), "ready")

    def test_rule179_with_fwmark_not_enough(self):
        self.write_pid()
        self.fake_proc()
        self.write_flags(True)
        rules = subprocess.CompletedProcess([], 0, json.dumps([{"table": "179", "fwmark": "0x164"}]), "")
        with mock.patch("subprocess.run", side_effect=[rules]):
            self.assertEqual(self.probe(), "ready")

    def test_invalid_json_unknown(self):
        self.write_pid()
        self.fake_proc()
        self.write_flags(True)
        rules = subprocess.CompletedProcess([], 0, "not json", "")
        with mock.patch("subprocess.run", side_effect=[rules]):
            self.assertEqual(self.probe(), "unknown")

    def test_tool_missing_unknown(self):
        self.write_pid()
        self.fake_proc()
        self.write_flags(True)
        with mock.patch("subprocess.run", side_effect=FileNotFoundError("ip")):
            self.assertEqual(self.probe(), "unknown")

    def test_timeout_unknown(self):
        self.write_pid()
        self.fake_proc()
        self.write_flags(True)
        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired([], 1)):
            self.assertEqual(self.probe(), "unknown")

    def test_nonzero_rules_unknown(self):
        self.write_pid()
        self.fake_proc()
        self.write_flags(True)
        rules = subprocess.CompletedProcess([], 3, "", "err")
        with mock.patch("subprocess.run", side_effect=[rules]):
            self.assertEqual(self.probe(), "unknown")

    def test_fdinfo_permission_denied_unknown(self):
        self.write_pid()
        fdinfo = self.fake_root / "proc" / "1688" / "fdinfo"
        fdinfo.mkdir(parents=True, exist_ok=True)
        f = fdinfo / "38"
        f.write_text("iff:\ttun163\n", encoding="utf-8")
        self.write_flags(True)
        original = Path.read_text

        def guarded(path_self, *args, **kwargs):
            if str(path_self) == str(f):
                raise PermissionError(13, "Permission denied")
            return original(path_self, *args, **kwargs)

        with mock.patch("pathlib.Path.read_text", side_effect=guarded, autospec=True), \
                mock.patch("subprocess.run") as run:
            self.assertEqual(self.probe(), "unknown")
            run.assert_not_called()

    def test_timeouts_and_read_only_argv(self):
        self.write_pid()
        self.fake_proc()
        self.write_flags(True)
        seen = []

        def rec(argv, **kw):
            seen.append((list(argv), kw))
            if argv[0] == "ip":
                return subprocess.CompletedProcess(argv, 0, json.dumps([{"table": "179"}]), "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with mock.patch("subprocess.run", side_effect=rec):
            self.assertEqual(self.probe(), "accelerating")
        self.assertEqual(len(seen), 2)
        for argv, kw in seen:
            self.assertFalse(kw.get("shell", False))
            self.assertTrue(kw.get("capture_output"))
            self.assertTrue(kw.get("text"))
            if argv[0] == "ip":
                self.assertEqual(kw.get("timeout"), 1)
            else:
                self.assertEqual(kw.get("timeout"), 2)

    def test_status_carries_acceleration_status_phase_idle(self):
        self.write_pid()
        self.fake_proc()
        self.write_flags(True)
        rules = subprocess.CompletedProcess([], 0, json.dumps([{"table": "179"}]), "")
        ipt = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(self.mgr, "_is_active", return_value=True), \
             mock.patch.object(self.mgr, "_core_running", return_value=True), \
             mock.patch.object(self.mgr, "_platform", return_value=fake_platform()), \
             mock.patch("subprocess.run", side_effect=[rules, ipt]):
            st = self.mgr.status()
        self.assertEqual(st["acceleration_status"], "accelerating")
        self.assertEqual(st["phase"], "idle")

    def test_repeated_probe_never_mutates_systemctl(self):
        self.write_pid()
        self.fake_proc()
        self.write_flags(True)
        rules = subprocess.CompletedProcess([], 0, json.dumps([{"table": "179"}]), "")
        ipt = subprocess.CompletedProcess([], 0, "", "")
        calls = []

        def rec(argv, **kw):
            calls.append(list(argv))
            if argv[0] == "ip":
                return rules
            return ipt

        with mock.patch("subprocess.run", side_effect=rec):
            for _ in range(3):
                self.assertEqual(self.probe(), "accelerating")
        mutating = [c for c in calls if c[0] == "systemctl"]
        self.assertEqual(mutating, [])


if __name__ == "__main__":
    unittest.main()
