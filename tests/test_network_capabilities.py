"""Network capability tests: real iptables probes bypass version allowlists.

These tests exercise ``supervisor._probe_network_feature`` and the fallback
bypass purely through fake runners; no real firewall is ever touched.
"""

import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR_PATH = PROJECT_ROOT / "supervisor.py"


def load_supervisor():
    spec = importlib.util.spec_from_file_location("uu_supervisor_caps", SUPERVISOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def completed(rc):
    return subprocess.CompletedProcess([], rc, "", "")


class FakeRunner:
    """Records argv calls and returns scripted results/side effects."""

    def __init__(self, results=None, side_effect=None):
        self.calls = []
        self._results = list(results or [])
        self._side_effect = side_effect

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append(argv)
        if self._side_effect is not None:
            result = self._side_effect(argv, kwargs)
            if result is not None:
                return result
        if self._results:
            return self._results.pop(0)
        return completed(0)


GLOBAL_CHAINS = {"OUTPUT", "PREROUTING", "INPUT", "FORWARD", "POSTROUTING"}


class NetworkCapabilityTestCase(unittest.TestCase):
    def setUp(self):
        self.supervisor = load_supervisor()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(self.tmp), ignore_errors=True)

    # -- probe argv behaviour ---------------------------------------------
    def test_cgroup_probe_uses_unhooked_mangle_chain_argv(self):
        runner = FakeRunner([completed(0), completed(0), completed(0), completed(0)])
        self.assertTrue(self.supervisor._probe_network_feature("xt_cgroup", runner=runner))

        self.assertEqual(len(runner.calls), 4)
        create, append, flush, delete = runner.calls
        self.assertTrue(all(isinstance(c, list) for c in runner.calls))
        for call in runner.calls:
            self.assertEqual(call[0].endswith("iptables"), True)
            self.assertEqual(call[1], "-t")
            self.assertEqual(call[2], "mangle")
        self.assertEqual(create[3], "-N")
        chain = create[4]
        self.assertLessEqual(len(chain), 28)
        self.assertNotIn(chain, GLOBAL_CHAINS)
        self.assertEqual(append[3], "-A")
        self.assertEqual(append[4], chain)
        self.assertEqual(
            append[5:],
            ["-m", "cgroup", "--path", "/", "-j", "MARK", "--set-mark", "0"],
        )
        self.assertEqual(flush[3], "-F")
        self.assertEqual(flush[4], chain)
        self.assertEqual(delete[3], "-X")
        self.assertEqual(delete[4], chain)

    def test_nat_probe_uses_unhooked_nat_chain_argv(self):
        runner = FakeRunner([completed(0)] * 4)
        self.assertTrue(self.supervisor._probe_network_feature("xt_nat", runner=runner))

        create, append, flush, delete = runner.calls
        self.assertEqual(create[2], "nat")
        chain = create[4]
        self.assertNotIn(chain, GLOBAL_CHAINS)
        self.assertEqual(
            append[5:],
            ["-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "127.0.0.1:9"],
        )
        self.assertEqual(flush[4], chain)
        self.assertEqual(delete[4], chain)

    def test_probe_never_targets_global_chains(self):
        for module in ("xt_cgroup", "xt_nat"):
            runner = FakeRunner([completed(0)] * 4)
            self.supervisor._probe_network_feature(module, runner=runner)
            for call in runner.calls:
                target = call[4]
                self.assertNotIn(target, GLOBAL_CHAINS)

    def test_append_failure_still_cleans_owned_chain(self):
        runner = FakeRunner([completed(0), completed(1), completed(0), completed(0)])
        self.assertFalse(self.supervisor._probe_network_feature("xt_cgroup", runner=runner))
        actions = [call[3] for call in runner.calls]
        self.assertIn("-F", actions)
        self.assertIn("-X", actions)

    def test_creation_failure_never_cleans_someone_elses_chain(self):
        runner = FakeRunner([completed(1)])
        self.assertFalse(self.supervisor._probe_network_feature("xt_nat", runner=runner))
        self.assertEqual(len(runner.calls), 1)  # only -N; no -F/-X issued

    def test_timeout_during_append_still_cleans_owned_chain(self):
        def side_effect(argv, kwargs):
            if "-A" in argv:
                raise subprocess.TimeoutExpired(argv, 5)
            return completed(0)

        runner = FakeRunner(side_effect=side_effect)
        self.assertFalse(self.supervisor._probe_network_feature("xt_cgroup", runner=runner))
        actions = [call[3] for call in runner.calls]
        self.assertIn("-F", actions)
        self.assertIn("-X", actions)

    def test_timeout_during_cleanup_flush_still_tries_delete(self):
        def side_effect(argv, kwargs):
            if "-F" in argv:
                raise subprocess.TimeoutExpired(argv, 5)
            return completed(0)

        runner = FakeRunner(side_effect=side_effect)
        self.assertFalse(self.supervisor._probe_network_feature("xt_cgroup", runner=runner))
        actions = [call[3] for call in runner.calls]
        self.assertIn("-F", actions)
        self.assertIn("-X", actions)  # delete attempted despite flush timeout

    def test_cleanup_failure_means_no_success(self):
        runner = FakeRunner([completed(0), completed(0), completed(1), completed(0)])
        self.assertFalse(self.supervisor._probe_network_feature("xt_nat", runner=runner))

    def test_unknown_module_returns_false_without_running(self):
        runner = FakeRunner()
        self.assertFalse(self.supervisor._probe_network_feature("bogus_mod", runner=runner))
        self.assertEqual(runner.calls, [])

    # -- fallback bypass on unknown kernels -------------------------------
    def make_barren_root(self):
        root = self.tmp / "root"
        (root / "sys" / "module").mkdir(parents=True, exist_ok=True)
        # no proc/config.gz, no kernel_compat manifest anywhere
        return root

    def fex_config(self):
        return {"engine": "fex"}

    def uname_patch(self, version="9.9.9-unknown"):
        return mock.patch(
            "os.uname",
            return_value=SimpleNamespace(
                release="9.9.9-unknown", version=version, machine="x86_64"
            ),
        )

    def test_native_cgroup_capability_works_on_unknown_kernel(self):
        # Probe-first: a native capability short-circuits before modprobe.
        root = self.make_barren_root()
        runner = FakeRunner()
        with mock.patch.object(self.supervisor, "_probe_network_feature", return_value=True):
            with self.uname_patch():
                self.supervisor.ensure_cgroup_support(
                    self.fex_config(), root=str(root), runner=runner)
        self.assertEqual(len(runner.calls), 0)  # no modprobe attempts

    def test_native_nat_capability_works_on_unknown_kernel(self):
        root = self.make_barren_root()
        runner = FakeRunner()
        with mock.patch.object(self.supervisor, "_probe_network_feature", return_value=True):
            with self.uname_patch():
                self.supervisor.ensure_nat_support(
                    self.fex_config(), root=str(root), runner=runner)
        self.assertEqual(len(runner.calls), 0)

    def test_native_capability_bypasses_unreadable_config_and_missing_manifest(self):
        root = self.make_barren_root()
        compat = self.tmp / "compat"  # no manifest.json inside
        compat.mkdir()
        config = {"engine": "fex", "kernel_compat": str(compat)}
        runner = FakeRunner()
        with mock.patch.object(self.supervisor, "_probe_network_feature", return_value=True):
            with self.uname_patch():
                self.supervisor.ensure_cgroup_support(config, root=str(root), runner=runner)
                self.supervisor.ensure_nat_support(config, root=str(root), runner=runner)
        self.assertEqual(len(runner.calls), 0)  # native probes succeed first

    def test_modprobe_success_on_unknown_kernel_still_works(self):
        root = self.make_barren_root()
        runner = FakeRunner([completed(0), completed(0)])
        with mock.patch.object(self.supervisor, "_probe_network_feature", return_value=False):
            pass
        with mock.patch.object(
            self.supervisor, "_probe_network_feature", return_value=False
        ), self.uname_patch():
            self.supervisor.ensure_cgroup_support(self.fex_config(), root=str(root), runner=runner)
            self.supervisor.ensure_nat_support(self.fex_config(), root=str(root), runner=runner)
        self.assertEqual(len(runner.calls), 2)

    def test_probe_failure_then_missing_manifest_reports_capability_error(self):
        root = self.make_barren_root()
        compat = self.tmp / "compat"
        compat.mkdir()
        config = {"engine": "fex", "kernel_compat": str(compat)}
        runner = FakeRunner([completed(1), completed(1)])  # modprobe + probe both fail
        with self.uname_patch():
            with self.assertRaises(RuntimeError) as ctx:
                self.supervisor.ensure_cgroup_support(config, root=str(root), runner=runner)
        message = str(ctx.exception)
        self.assertNotIn("当前内核不在兼容列表", message)
        self.assertIn("cgroup", message)


if __name__ == "__main__":
    unittest.main()
