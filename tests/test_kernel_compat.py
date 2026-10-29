"""Contract tests for supervisor.ensure_cgroup_support and ensure_nat_support."""

import gzip
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR_PATH = PROJECT_ROOT / "supervisor.py"

KRELEASE = "7.2.6"
KVERSION = "#1 SMP PREEMPT Sun Oct 11 14:17:59 UTC 2026"
KMACHINE = "aarch64"

# The second profile actually verified in the field report: same release and
# arch as the shipped baseline, a different build timestamp and a different
# kernel configuration. It is only ever accepted as an exact four-field match.
KVERSION_OCT16 = "#1 SMP PREEMPT Fri Oct 16 22:33:25 UTC 2026"

# A third synthetic build matched by an exact ``compatible_kernels`` entry that
# carries its own ``module_dir`` subtree and per-entry module digests. The
# build timestamp is deliberately distinct from both other profiles.
KVERSION_OCT26 = "#1 SMP PREEMPT Mon Oct 26 11:51:41 UTC 2026"

CONFIG_LINES = [
    "CONFIG_CGROUP_SCHED=y",
    "# CONFIG_CFS_BANDWIDTH is not set",
    "CONFIG_FAIR_GROUP_SCHED=y",
    "CONFIG_IKCONFIG_PROC=y",
    "# a plain comment that is ignored",
    "CONFIG_NET=y",
]

CONFIG_LINES_OCT26 = [
    "CONFIG_CGROUP_SCHED=y",
    "CONFIG_CFS_BANDWIDTH=y",
    "CONFIG_FAIR_GROUP_SCHED=y",
    "CONFIG_IKCONFIG_PROC=y",
    "# a plain comment that is ignored",
    "CONFIG_NET=y",
    "CONFIG_NF_NAT=y",
    "CONFIG_NF_CONNTRACK=y",
]

CONFIG_LINES_OCT16 = [
    "CONFIG_CGROUP_SCHED=y",
    "CONFIG_CFS_BANDWIDTH=y",
    "CONFIG_FAIR_GROUP_SCHED=y",
    "CONFIG_IKCONFIG_PROC=y",
    "# a plain comment that is ignored",
    "CONFIG_NET=y",
    "CONFIG_NF_NAT=y",
]

MODULE_BYTES = b"\x7fELF xt_cgroup module bytes\n"
NAT_MODULE_BYTES = b"\x7fELF xt_nat module bytes\n"

CHILD_MODULE_BYTES = b"\x7fELF xt_cgroup oct26 child module bytes\n"
CHILD_NAT_MODULE_BYTES = b"\x7fELF xt_nat oct26 child module bytes\n"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def normalize_config(lines):
    """Sort CONFIG_/# CONFIG_ lines, newline-join, add a final newline."""
    kept = [ln for ln in lines if ln.startswith("CONFIG_") or ln.startswith("# CONFIG_")]
    return ("\n".join(sorted(kept)) + "\n").encode("utf-8")


def completed(rc):
    return subprocess.CompletedProcess([], rc, "", "")


def load_supervisor():
    spec = importlib.util.spec_from_file_location("uu_supervisor_compat", SUPERVISOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeRunner:
    """Records runner invocations and returns scripted return codes."""

    def __init__(self, results=None, side_effect=None):
        self.calls = []
        self._results = list(results or [])
        self._side_effect = side_effect

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append((argv, kwargs))
        if self._side_effect is not None:
            result = self._side_effect(argv, kwargs)
            if result is not None:
                return result
        if self._results:
            return self._results.pop(0)
        return completed(0)


class KernelCompatTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(self.tmp), ignore_errors=True)
        self.supervisor = load_supervisor()
        # Isolate the legacy module-loader tests from the real iptables rule
        # probe introduced with network capability detection.
        probe_patch = mock.patch.object(
            self.supervisor, "_probe_network_feature", create=True, return_value=False
        )
        probe_patch.start()
        self.addCleanup(probe_patch.stop)

    # -- helpers ---------------------------------------------------------
    def ensure(self, config, root, runner):
        func = getattr(self.supervisor, "ensure_cgroup_support", None)
        if func is None:
            self.fail("supervisor.ensure_cgroup_support is missing")
        return func(config, root=str(root), runner=runner)

    def ensure_nat(self, config, root, runner):
        func = getattr(self.supervisor, "ensure_nat_support", None)
        if func is None:
            self.fail("supervisor.ensure_nat_support is missing")
        return func(config, root=str(root), runner=runner)

    def make_root(self, with_xt_cgroup=False, with_xt_nat=False):
        root = self.tmp / "root"
        (root / "sys" / "module").mkdir(parents=True, exist_ok=True)
        (root / "proc").mkdir(parents=True, exist_ok=True)
        if with_xt_cgroup:
            (root / "sys" / "module" / "xt_cgroup").mkdir()
        if with_xt_nat:
            (root / "sys" / "module" / "xt_nat").mkdir()
        return root

    def build_env(self, overrides=None, config_lines=None, module_bytes=MODULE_BYTES):
        root = self.make_root()
        lines = CONFIG_LINES if config_lines is None else config_lines
        raw = "\n".join(lines) + "\n"
        (root / "proc" / "config.gz").write_bytes(gzip.compress(raw.encode("utf-8")))
        compat = self.tmp / "compat"
        compat.mkdir(parents=True, exist_ok=True)
        (compat / "xt_cgroup.ko").write_bytes(module_bytes)
        (compat / "xt_nat.ko").write_bytes(NAT_MODULE_BYTES)
        manifest = {
            "kernel_release": KRELEASE,
            "kernel_version": KVERSION,
            "machine": KMACHINE,
            "config_sha256": sha256(normalize_config(lines)),
            "module_sha256": sha256(module_bytes),
            "nat_module_sha256": sha256(NAT_MODULE_BYTES),
        }
        if overrides:
            manifest.update(overrides)
        (compat / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return root, compat

    def verified_profile(self, **overrides):
        """One exact four-field entry for the manifest's ``compatible_kernels``."""
        entry = {
            "kernel_release": KRELEASE,
            "kernel_version": KVERSION_OCT16,
            "machine": KMACHINE,
            "config_sha256": sha256(normalize_config(CONFIG_LINES_OCT16)),
        }
        entry.update(overrides)
        return entry

    def write_child_modules(self, compat, module_dir, module_bytes=None, nat_bytes=None):
        """Materialize a per-profile ``module_dir`` leaf holding both modules."""
        child = compat / module_dir
        child.mkdir(parents=True, exist_ok=True)
        (child / "xt_cgroup.ko").write_bytes(
            CHILD_MODULE_BYTES if module_bytes is None else module_bytes)
        (child / "xt_nat.ko").write_bytes(
            CHILD_NAT_MODULE_BYTES if nat_bytes is None else nat_bytes)
        return child

    def verified_oct26_profile(self, **overrides):
        """One exact four-field entry for the Oct-26 ``module_dir`` profile."""
        entry = {
            "kernel_release": KRELEASE,
            "kernel_version": KVERSION_OCT26,
            "machine": KMACHINE,
            "config_sha256": sha256(normalize_config(CONFIG_LINES_OCT26)),
        }
        entry.update(overrides)
        return entry

    def build_oct26_env(self, profile_overrides=None, module_dir="oct26"):
        """Oct-11 baseline plus one Oct-26 profile that owns its module subtree.

        The parent ``compat`` tree deliberately keeps *only* the baseline
        modules: any load from ``compat/xt_cgroup.ko`` or ``compat/xt_nat.ko``
        proves the child profile fell back to parent binaries. The child leaf
        is written independently and the running kernel is the Oct-26 one.
        """
        root, compat = self.build_env(config_lines=CONFIG_LINES_OCT26)
        child = self.write_child_modules(compat, module_dir)
        entry = self.verified_oct26_profile(
            module_dir=module_dir,
            module_sha256=sha256((child / "xt_cgroup.ko").read_bytes()),
            nat_module_sha256=sha256((child / "xt_nat.ko").read_bytes()),
        )
        entry.update(profile_overrides or {})
        manifest = self.read_manifest(compat)
        manifest["config_sha256"] = sha256(normalize_config(CONFIG_LINES))
        manifest["compatible_kernels"] = [entry]
        self.write_manifest(compat, manifest)
        return root, compat, entry

    def write_manifest(self, compat, manifest):
        (compat / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return compat

    def read_manifest(self, compat):
        return json.loads((compat / "manifest.json").read_text(encoding="utf-8"))

    def build_verified_env(self, profile_overrides=None, module_overrides=None):
        """Oct-11 baseline manifest plus one Oct-16 reported profile.

        The *running* kernel/config is the Oct-16 one (it is what
        ``proc/config.gz`` holds), while the manifest keeps the shipped
        top-level baseline untouched, so only an exact ``compatible_kernels``
        entry can match.
        """
        root, compat = self.build_env(config_lines=CONFIG_LINES_OCT16)
        manifest = self.read_manifest(compat)
        manifest["config_sha256"] = sha256(normalize_config(CONFIG_LINES))
        manifest["compatible_kernels"] = [
            self.verified_profile(**(profile_overrides or {}))
        ]
        if module_overrides:
            manifest.update(module_overrides)
        self.write_manifest(compat, manifest)
        return root, compat

    def uname_patch(self, release=KRELEASE, version=KVERSION, machine=KMACHINE):
        return mock.patch(
            "os.uname",
            return_value=SimpleNamespace(release=release, version=version, machine=machine),
        )

    def fex_config(self, compat):
        config = {"engine": "fex"}
        if compat is not None:
            config["kernel_compat"] = str(compat)
        return config

    # -- tests -----------------------------------------------------------
    def test_non_fex_engines_are_rejected_without_runner(self):
        for engine in ("native", "x86", "bogus"):
            with self.subTest(engine=engine):
                runner = FakeRunner()
                with self.assertRaises(RuntimeError):
                    self.ensure({"engine": engine}, self.tmp, runner)
                self.assertEqual(runner.calls, [])

    def test_loaded_module_skips_for_fex(self):
        root = self.make_root(with_xt_cgroup=True)
        runner = FakeRunner()
        self.ensure({"engine": "fex"}, root, runner)
        self.assertEqual(runner.calls, [])

    def test_modprobe_success_skips_fallback(self):
        root = self.make_root()
        config = self.fex_config(self.tmp / "missing")
        runner = FakeRunner([completed(0)])
        self.ensure(config, root, runner)

        self.assertEqual(len(runner.calls), 1)
        argv, kwargs = runner.calls[0]
        self.assertEqual(os.path.basename(argv[0]), "modprobe")
        self.assertEqual(argv[1], "xt_cgroup")
        self.assertIs(kwargs.get("capture_output"), True)
        self.assertIs(kwargs.get("text"), True)
        self.assertEqual(kwargs.get("timeout"), 5)

    def test_fallback_success_loads_local_module(self):
        root, compat = self.build_env()
        config = self.fex_config(compat)
        runner = FakeRunner([completed(1), completed(0), completed(0)])

        with self.uname_patch():
            self.ensure(config, root, runner)

        self.assertEqual(len(runner.calls), 3)
        first, second, third = (call[0] for call in runner.calls)
        self.assertEqual(os.path.basename(first[0]), "modprobe")
        self.assertEqual(first[1], "xt_cgroup")
        self.assertEqual(os.path.basename(second[0]), "modprobe")
        self.assertEqual(second[1], "x_tables")
        self.assertEqual(os.path.basename(third[0]), "insmod")
        self.assertTrue(os.path.isabs(third[1]))
        self.assertEqual(third[1], str(compat / "xt_cgroup.ko"))
        for argv, _ in runner.calls:
            self.assertIsInstance(argv, list)

    def test_identity_mismatch_rejected_before_insmod(self):
        # kernel_version (build date) is no longer an ABI gate; only a
        # release or architecture mismatch may still reject the candidate.
        for field, wrong in (("release", "0.0.0"), ("machine", "x86_64")):
            with self.subTest(field=field):
                root, compat = self.build_env()
                config = self.fex_config(compat)
                runner = FakeRunner([completed(1), completed(0), completed(0)])

                with self.uname_patch(**{field: wrong}):
                    with self.assertRaises(RuntimeError):
                        self.ensure(config, root, runner)

                self.assertEqual(len(runner.calls), 1)  # only the initial modprobe

    def test_config_hash_mismatch_rejected_before_insmod(self):
        root, compat = self.build_env(overrides={"config_sha256": "0" * 64})
        config = self.fex_config(compat)
        runner = FakeRunner([completed(1), completed(0), completed(0)])

        with self.uname_patch():
            with self.assertRaises(RuntimeError):
                self.ensure(config, root, runner)

        self.assertEqual(len(runner.calls), 1)

    def test_corrupt_module_hash_rejected_before_insmod(self):
        root, compat = self.build_env(overrides={"module_sha256": "0" * 64})
        config = self.fex_config(compat)
        runner = FakeRunner([completed(1), completed(0), completed(0)])

        with self.uname_patch():
            with self.assertRaises(RuntimeError):
                self.ensure(config, root, runner)

        self.assertEqual(len(runner.calls), 1)

    def test_dependency_modprobe_failure_raises(self):
        root, compat = self.build_env()
        config = self.fex_config(compat)
        runner = FakeRunner([completed(1), completed(1)])

        with self.uname_patch():
            with self.assertRaises(RuntimeError):
                self.ensure(config, root, runner)

        self.assertEqual(len(runner.calls), 2)  # modprobe xt_cgroup, modprobe x_tables

    def test_insmod_failure_raises_when_module_absent(self):
        root, compat = self.build_env()
        config = self.fex_config(compat)
        runner = FakeRunner([completed(1), completed(0), completed(1)])

        with self.uname_patch():
            with self.assertRaises(RuntimeError):
                self.ensure(config, root, runner)

        self.assertEqual(len(runner.calls), 3)

    def test_insmod_failure_accepts_concurrent_load(self):
        root, compat = self.build_env()
        config = self.fex_config(compat)

        def side_effect(argv, kwargs):
            if os.path.basename(argv[0]) == "insmod":
                (root / "sys" / "module" / "xt_cgroup").mkdir()
                return completed(1)
            return None

        runner = FakeRunner([completed(1), completed(0)], side_effect=side_effect)
        with self.uname_patch():
            self.ensure(config, root, runner)

        self.assertEqual(len(runner.calls), 3)  # no endless retries

    # -- xt_nat ----------------------------------------------------------
    def test_nat_non_fex_engines_are_rejected_without_runner(self):
        for engine in ("native", "x86", "bogus"):
            with self.subTest(engine=engine):
                runner = FakeRunner()
                with self.assertRaises(RuntimeError):
                    self.ensure_nat({"engine": engine}, self.tmp, runner)
                self.assertEqual(runner.calls, [])

    def test_nat_loaded_module_skips_for_fex(self):
        root = self.make_root(with_xt_nat=True)
        runner = FakeRunner()
        self.ensure_nat({"engine": "fex"}, root, runner)
        self.assertEqual(runner.calls, [])

    def test_loaded_cgroup_does_not_mask_missing_nat(self):
        # xt_cgroup is present but xt_nat is absent: the NAT preflight must
        # still probe xt_nat rather than short-circuit on the loaded cgroup.
        root = self.make_root(with_xt_cgroup=True)
        config = self.fex_config(self.tmp / "missing")
        runner = FakeRunner([completed(0)])
        self.ensure_nat(config, root, runner)

        self.assertEqual(len(runner.calls), 1)
        argv, _ = runner.calls[0]
        self.assertEqual(os.path.basename(argv[0]), "modprobe")
        self.assertEqual(argv[1], "xt_nat")

    def test_nat_fallback_loads_exact_module_and_dependencies(self):
        root, compat = self.build_env()
        config = self.fex_config(compat)
        runner = FakeRunner([completed(1), completed(0), completed(0)])

        with self.uname_patch():
            self.ensure_nat(config, root, runner)

        self.assertEqual(len(runner.calls), 3)
        first, second, third = (call[0] for call in runner.calls)
        self.assertEqual(os.path.basename(first[0]), "modprobe")
        self.assertEqual(first[1], "xt_nat")
        self.assertEqual(os.path.basename(second[0]), "modprobe")
        self.assertEqual(second[1:], ["-a", "x_tables", "nf_nat"])
        self.assertEqual(os.path.basename(third[0]), "insmod")
        self.assertEqual(third[1], str(compat / "xt_nat.ko"))

    def test_nat_wrong_hash_prevents_insmod(self):
        root, compat = self.build_env(overrides={"nat_module_sha256": "0" * 64})
        config = self.fex_config(compat)
        runner = FakeRunner([completed(1), completed(0), completed(0)])

        with self.uname_patch():
            with self.assertRaises(RuntimeError):
                self.ensure_nat(config, root, runner)

        self.assertEqual(len(runner.calls), 1)  # only the initial modprobe

    def test_nat_kernel_mismatch_prevents_load(self):
        for field, wrong in (("release", "0.0.0"), ("machine", "x86_64")):
            with self.subTest(field=field):
                root, compat = self.build_env()
                config = self.fex_config(compat)
                runner = FakeRunner([completed(1), completed(0), completed(0)])

                with self.uname_patch(**{field: wrong}):
                    with self.assertRaises(RuntimeError):
                        self.ensure_nat(config, root, runner)

                self.assertEqual(len(runner.calls), 1)

    # -- compatible_kernels profiles --------------------------------------
    def test_legacy_baseline_still_matches_alongside_profiles(self):
        """The shipped top-level baseline keeps working when profiles are listed.

        Adding ``compatible_kernels`` must widen the manifest, not replace its
        original baseline: a host matching the Oct-11 release/version/arch and
        config still gets the fallback load even though the extra profile names
        a different build.
        """
        root, compat = self.build_env()
        manifest = self.read_manifest(compat)
        manifest["compatible_kernels"] = [self.verified_profile()]
        self.write_manifest(compat, manifest)

        runner = FakeRunner([completed(1), completed(0), completed(0)])
        with self.uname_patch():
            self.ensure(self.fex_config(compat), root, runner)

        self.assertEqual(len(runner.calls), 3)
        self.assertEqual(os.path.basename(runner.calls[2][0][0]), "insmod")
        self.assertEqual(runner.calls[2][0][1], str(compat / "xt_cgroup.ko"))

    def test_second_verified_profile_allows_cgroup_and_nat_fallback(self):
        """The reported Oct-16 profile is accepted for both bundled modules.

        Its build timestamp and kernel config both differ from the baseline, so
        a match can only come from an exact four-field ``compatible_kernels``
        entry; each module still loads only after its own digest is proven.
        """
        for name, ensure in (("xt_cgroup", self.ensure), ("xt_nat", self.ensure_nat)):
            with self.subTest(module=name):
                root, compat = self.build_verified_env()
                runner = FakeRunner([completed(1), completed(0), completed(0)])

                with self.uname_patch(version=KVERSION_OCT16):
                    ensure(self.fex_config(compat), root, runner)

                first, second, third = (call[0] for call in runner.calls)
                self.assertEqual(len(runner.calls), 3)
                self.assertEqual(os.path.basename(first[0]), "modprobe")
                self.assertEqual(first[1], name)
                self.assertEqual(os.path.basename(second[0]), "modprobe")
                self.assertEqual(os.path.basename(third[0]), "insmod")
                self.assertEqual(third[1], str(compat / (name + ".ko")))

    def test_unlisted_version_machine_or_config_profile_is_rejected(self):
        """Only exact matches pass: an unknown version/config or wrong arch fails.

        Every rejection happens before any dependency or ``insmod`` call, so an
        unlisted kernel can never reach a module load attempt.
        """
        cases = (
            # the verified profile's config differs from this host's
            ("unknown-config", {"config_sha256": "0" * 64}, {}),
            # a cross-arch profile entry can never be selected on this host
            ("cross-arch-profile", {"machine": "x86_64"}, {}),
            # this host is x86_64 while both baseline and profile are aarch64
            ("cross-arch-host", None, {"machine": "x86_64"}),
        )
        for label, profile_overrides, uname_overrides in cases:
            with self.subTest(case=label):
                root, compat = self.build_verified_env(
                    profile_overrides=profile_overrides)
                runner = FakeRunner([completed(1), completed(0), completed(0)])

                uname_values = {"version": KVERSION_OCT16}
                uname_values.update(uname_overrides)
                with self.uname_patch(**uname_values):
                    with self.assertRaises(RuntimeError):
                        self.ensure(self.fex_config(compat), root, runner)

                self.assertEqual(len(runner.calls), 1)  # rejected before insmod

    def test_differing_build_date_alone_is_accepted_for_both_modules(self):
        """A different kernel_version (build date) alone never rejects.

        Both the top-level baseline and the ``compatible_kernels`` profile are
        matched on release/architecture/config only, for xt_cgroup and xt_nat.
        """
        other_version = "#1 SMP PREEMPT Mon Oct 19 08:00:00 UTC 2026"
        for name, ensure in (("xt_cgroup", self.ensure), ("xt_nat", self.ensure_nat)):
            with self.subTest(module=name):
                # parent (baseline) candidate, host version differs from manifest
                root, compat = self.build_env()
                runner = FakeRunner([completed(1), completed(0), completed(0)])
                with self.uname_patch(version=other_version):
                    ensure(self.fex_config(compat), root, runner)
                self.assertEqual(len(runner.calls), 3)
                self.assertEqual(
                    runner.calls[2][0][1], str(compat / (name + ".ko")))

                # child (compatible_kernels profile) candidate, same idea
                root, compat = self.build_verified_env()
                runner = FakeRunner([completed(1), completed(0), completed(0)])
                with self.uname_patch(version="#9 SMP totally other build"):
                    ensure(self.fex_config(compat), root, runner)
                self.assertEqual(len(runner.calls), 3)
                self.assertEqual(
                    runner.calls[2][0][1], str(compat / (name + ".ko")))

    def test_child_profile_without_kernel_version_matches_for_both_modules(self):
        """A matching profile may omit ``kernel_version`` entirely.

        ``kernel_version`` is optional provenance, never a required ABI field:
        both xt modules must still select the child ``module_dir`` bytes.
        """
        for name, ensure in (("xt_cgroup", self.ensure), ("xt_nat", self.ensure_nat)):
            with self.subTest(module=name):
                root, compat, _entry = self.build_oct26_env()
                (compat / (name + ".ko")).unlink()
                manifest = self.read_manifest(compat)
                manifest["compatible_kernels"][0].pop("kernel_version", None)
                self.write_manifest(compat, manifest)
                runner = FakeRunner([completed(1), completed(0), completed(0)])

                with self.uname_patch(version=KVERSION_OCT26):
                    ensure(self.fex_config(compat), root, runner)

                self.assertEqual(len(runner.calls), 3)
                self.assertEqual(
                    runner.calls[2][0][1], str(compat / "oct26" / (name + ".ko")))

    def test_compatible_profile_cannot_bypass_module_digest(self):
        """A matching profile never excuses a tampered bundled module.

        The four identity fields only decide *which* kernel is allowed; the
        top-level module digests still gate the load for both modules.
        """
        for name, digest_key, ensure in (
            ("xt_cgroup", "module_sha256", self.ensure),
            ("xt_nat", "nat_module_sha256", self.ensure_nat),
        ):
            with self.subTest(module=name):
                root, compat = self.build_verified_env(
                    module_overrides={digest_key: "0" * 64})
                runner = FakeRunner([completed(1), completed(0), completed(0)])

                with self.uname_patch(version=KVERSION_OCT16):
                    with self.assertRaises(RuntimeError):
                        ensure(self.fex_config(compat), root, runner)

                self.assertEqual(len(runner.calls), 1)  # only the modprobe probe

    # -- module_dir profiles (Oct-26) -------------------------------------
    def test_oct26_module_dir_selects_child_bytes_for_both_modules(self):
        """A matched ``module_dir`` entry loads only the child subtree.

        Both modules must be hashed and ``insmod``-ed from
        ``compat/oct26/``; the parent ``compat`` files are left absent so any
        fallback to baseline binaries or baseline digests would fail loudly.
        """
        for name, digest_key, ensure in (
            ("xt_cgroup", "module_sha256", self.ensure),
            ("xt_nat", "nat_module_sha256", self.ensure_nat),
        ):
            with self.subTest(module=name):
                root, compat, entry = self.build_oct26_env()
                (compat / (name + ".ko")).unlink()
                runner = FakeRunner([completed(1), completed(0), completed(0)])

                with self.uname_patch(version=KVERSION_OCT26):
                    ensure(self.fex_config(compat), root, runner)

                self.assertEqual(len(runner.calls), 3)
                first, second, third = (call[0] for call in runner.calls)
                self.assertEqual(os.path.basename(first[0]), "modprobe")
                self.assertEqual(first[1], name)
                self.assertEqual(os.path.basename(second[0]), "modprobe")
                self.assertEqual(os.path.basename(third[0]), "insmod")
                self.assertEqual(
                    third[1], str(compat / "oct26" / (name + ".ko")))
                # the entry carries its own digest for this module
                self.assertEqual(
                    sha256((compat / "oct26" / (name + ".ko")).read_bytes()),
                    entry[digest_key],
                )

    def test_oct26_child_module_uppercase_digest_accepted_for_both_modules(self):
        for name, digest_key, ensure in (
            ("xt_cgroup", "module_sha256", self.ensure),
            ("xt_nat", "nat_module_sha256", self.ensure_nat),
        ):
            with self.subTest(module=name):
                root, compat, entry = self.build_oct26_env()
                (compat / (name + ".ko")).unlink()
                manifest = self.read_manifest(compat)
                profile = manifest["compatible_kernels"][0]
                profile[digest_key] = profile[digest_key].upper()
                self.write_manifest(compat, manifest)
                runner = FakeRunner([completed(1), completed(0), completed(0)])

                with self.uname_patch(version=KVERSION_OCT26):
                    ensure(self.fex_config(compat), root, runner)

                self.assertEqual(len(runner.calls), 3)
                first, second, third = (call[0] for call in runner.calls)
                self.assertEqual(os.path.basename(first[0]), "modprobe")
                self.assertEqual(first[1], name)
                self.assertEqual(os.path.basename(second[0]), "modprobe")
                self.assertEqual(os.path.basename(third[0]), "insmod")
                self.assertEqual(
                    third[1], str(compat / "oct26" / (name + ".ko")))

    def test_oct26_child_module_digest_tampered_rejects_before_insmod(self):
        """A bad per-entry digest fails before dependency or ``insmod`` calls."""
        for name, digest_key, ensure in (
            ("xt_cgroup", "module_sha256", self.ensure),
            ("xt_nat", "nat_module_sha256", self.ensure_nat),
        ):
            with self.subTest(module=name):
                root, compat, _ = self.build_oct26_env(
                    profile_overrides={digest_key: "0" * 64})
                runner = FakeRunner([completed(1), completed(0), completed(0)])

                with self.uname_patch(version=KVERSION_OCT26):
                    with self.assertRaises(RuntimeError):
                        ensure(self.fex_config(compat), root, runner)

                self.assertEqual(len(runner.calls), 1)  # only the modprobe probe

    def test_oct26_module_dir_without_digest_never_inherits_parent(self):
        """Missing or invalid entry digests must not fall back to top level."""
        for name, digest_key, ensure in (
            ("xt_cgroup", "module_sha256", self.ensure),
            ("xt_nat", "nat_module_sha256", self.ensure_nat),
        ):
            for label, bad in (("missing", None), ("invalid", "zz" * 32)):
                with self.subTest(module=name, case=label):
                    overrides = {digest_key: bad}
                    root, compat, _ = self.build_oct26_env(
                        profile_overrides=overrides)
                    manifest = self.read_manifest(compat)
                    entry = manifest["compatible_kernels"][0]
                    if bad is None:
                        entry.pop(digest_key, None)
                    else:
                        entry[digest_key] = bad
                    self.write_manifest(compat, manifest)
                    # Parent digests are valid for the parent files, so an
                    # inheritance bug would wrongly load the parent binary.
                    self.assertEqual(
                        self.read_manifest(compat)[digest_key],
                        sha256((compat / (name + ".ko")).read_bytes()),
                    )
                    runner = FakeRunner([completed(1), completed(0), completed(0)])

                    with self.uname_patch(version=KVERSION_OCT26):
                        with self.assertRaises(RuntimeError):
                            ensure(self.fex_config(compat), root, runner)

                    self.assertEqual(len(runner.calls), 1)

    def test_oct26_invalid_module_dir_rejected_before_dependencies(self):
        """Absolute or traversal ``module_dir`` values fail before any load."""
        for bad_dir in ("../oct26", "/oct26", "oct26/..", "a/b", "", ".", "..",
                        "oct26\\x"):
            with self.subTest(module_dir=bad_dir):
                root, compat, _ = self.build_oct26_env(module_dir="oct26")
                manifest = self.read_manifest(compat)
                manifest["compatible_kernels"][0]["module_dir"] = bad_dir
                self.write_manifest(compat, manifest)
                runner = FakeRunner([completed(1), completed(0), completed(0)])

                with self.uname_patch(version=KVERSION_OCT26):
                    with self.assertRaises(RuntimeError):
                        self.ensure(self.fex_config(compat), root, runner)

                self.assertEqual(len(runner.calls), 1)

    def test_oct26_child_with_differing_build_date_loads_child_bytes(self):
        """A profile whose build date differs from the host still matches.

        ``kernel_version`` is provenance metadata, not an ABI gate: the child
        ``module_dir`` entry is selected by release/architecture/config and
        its own digests still prove the loaded bytes.
        """
        root, compat, entry = self.build_oct26_env(
            profile_overrides={"kernel_version": "#1 SMP PREEMPT Tue Oct 27 11:51:41 UTC 2026"})
        (compat / "xt_cgroup.ko").unlink()
        runner = FakeRunner([completed(1), completed(0), completed(0)])

        with self.uname_patch(version=KVERSION_OCT26):
            self.ensure(self.fex_config(compat), root, runner)

        self.assertEqual(len(runner.calls), 3)
        self.assertEqual(os.path.basename(runner.calls[2][0][0]), "insmod")
        self.assertEqual(
            runner.calls[2][0][1], str(compat / "oct26" / "xt_cgroup.ko"))
        self.assertEqual(
            sha256((compat / "oct26" / "xt_cgroup.ko").read_bytes()),
            entry["module_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
