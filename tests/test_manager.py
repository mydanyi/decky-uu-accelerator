"""Contract tests for py_modules/uu_accelerator/manager.py.

manager.py does not exist yet, so this module is expected to be red until the
installer is implemented. The tests pin a small, dependency-free installer API:
every real integration boundary (subprocess, platform probing, metadata fetch,
download) is injected as a plain function hook, and systemd is faked with a
stateful stand-in. Nothing here touches the real /etc/systemd or the network.

All manager methods are synchronous; Decky wraps them off-thread later.

Run with:
    PYTHONPATH=py_modules python3 -m unittest discover -s tests -v
"""

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from uu_accelerator.manager import Manager

try:  # discover() imports test modules either package-qualified or flat
    from .test_payload import ELF_AARCH64, ELF_X86_64, core_members, elf_header
except ImportError:  # pragma: no cover - flat import path
    from test_payload import ELF_AARCH64, ELF_X86_64, core_members, elf_header

UNIT_ID = "uu-accelerator"
UNIT_FILE = "uu-accelerator.service"
OWNERSHIP_MARKER = "Managed by UU加速器"
IDENTITY_NAME = ".uuplugin_uuid"
PYTHON = "/usr/bin/python3"

# A synthetic Unicode QR marker (never a real device QR/SN). Each character
# encodes two vertical QR pixels; only the legal glyphs plus LF appear.
QR_MARKER_NAME = ".steam_deck_sn_qrcode"
QR_SAMPLE = "\u2580\u2584\u2588\u2580\n\u2588 \u2584\u2588\n\u2580\u2584 \u2588\n"

STATUS_FIELDS = (
    "installed", "running", "core_running", "busy", "phase", "progress",
    "error", "version", "engine", "engines", "autostart", "platform", "binding",
)

_VERBS = {
    "start", "stop", "restart", "enable", "disable",
    "is-active", "is-enabled", "daemon-reload",
}


def completed(args, code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args, code, stdout, stderr)


def payload_bytes(version, machine=ELF_X86_64, extra=()):
    """A tiny valid package (uu.conf carries the authoritative version).

    ``mtime=0`` keeps the gzip stream deterministic so repeated builds of the
    same fixture always hash to the same MD5 (they used to drift across a
    second boundary because the gzip header embeds the current time).
    """
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            for member in core_members(machine, version=version, extra=extra):
                data = member["data"]
                data = data.encode() if isinstance(data, str) else data
                info = tarfile.TarInfo(member["name"])
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class FakeSystemctl:
    """Stateful stand-in for systemctl; only tracks active/enabled state."""

    def __init__(self):
        self.active = set()
        self.enabled = set()
        self.calls = []
        self.fail_start_once = set()
        self.fail_stop_once = set()
        self.fail_enable_once = set()
        self.fail_disable_once = set()

    @staticmethod
    def _key(unit):
        if unit.endswith(".service"):
            unit = unit[: -len(".service")]
        return unit

    def __call__(self, args):
        args = list(args)
        self.calls.append(args)
        verb = next((token for token in args if token in _VERBS), "")
        unit = self._key(args[-1]) if len(args) > 1 else ""

        if verb == "daemon-reload":
            return completed(args, 0)
        if verb in ("start", "restart"):
            if unit in self.fail_start_once:
                self.fail_start_once.discard(unit)
                return completed(args, 1, stderr="start failed")
            self.active.add(unit)
            return completed(args, 0)
        if verb == "stop":
            if unit in self.fail_stop_once:
                self.fail_stop_once.discard(unit)
                return completed(args, 1, stderr="stop failed")
            self.active.discard(unit)
            return completed(args, 0)
        if verb == "enable":
            if unit in self.fail_enable_once:
                self.fail_enable_once.discard(unit)
                return completed(args, 1, stderr="enable failed")
            self.enabled.add(unit)
            return completed(args, 0)
        if verb == "disable":
            if unit in self.fail_disable_once:
                self.fail_disable_once.discard(unit)
                return completed(args, 1, stderr="disable failed")
            self.enabled.discard(unit)
            return completed(args, 0)
        if verb == "is-active":
            running = unit in self.active
            return completed(args, 0 if running else 3, "active" if running else "inactive")
        if verb == "is-enabled":
            on = unit in self.enabled
            return completed(args, 0 if on else 1, "enabled" if on else "disabled")
        return completed(args, 0)


class ManagerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(self.tmp), ignore_errors=True)

        self.runtime = self.tmp / "runtime"
        self.settings = self.tmp / "settings"
        self.logs = self.tmp / "logs"
        self.plugin = self.tmp / "plugin"
        self.system = self.tmp / "systemd"
        self.root = self.tmp / "root"
        self.home = self.tmp / "home" / "deck"
        for path in (self.plugin, self.system, self.root, self.home):
            path.mkdir(parents=True, exist_ok=True)
        (self.plugin / "supervisor.py").write_text(
            "# supervisor placeholder, copied never executed\n", encoding="utf-8")

        self.systemctl = FakeSystemctl()
        self.archives = {}          # md5 -> package bytes
        self.downloads = 0
        self.fetches = 0
        self.platform = self.platform_dict()
        self.metadata = {}

        self.metadata_fetcher = self._default_metadata_fetcher
        self.archive_downloader = self._default_archive_downloader
        self.platform_provider = lambda *a, **k: dict(self.platform)

    # -- hooks -----------------------------------------------------------
    def platform_dict(self, **overrides):
        base = dict(
            os_id="armada", is_armada=True, arch="aarch64", home=str(self.home),
            fex_path="/usr/bin/FEXInterpreter", legacy_install=False,
            engines=["fex"], recommended_engine="fex",
        )
        base.update(overrides)
        return base

    def configure_release(self, version, machine=ELF_X86_64, extra=()):
        data = payload_bytes(version, machine, extra)
        md5 = hashlib.md5(data).hexdigest()
        self.archives[md5] = data
        self.metadata = {
            "url": "https://gdl.netease.com/uu/uuplugin-v{}.tar.gz".format(version),
            "md5": md5,
            "alternate_url": None,
            "version": version,
        }
        return md5

    def _default_metadata_fetcher(self, package_type, **kwargs):
        self.fetches += 1
        return dict(self.metadata)

    def _default_archive_downloader(self, metadata, target, **kwargs):
        self.downloads += 1
        data = self.archives[metadata["md5"]]
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        Path(target).write_bytes(data)
        return Path(target)

    def make_manager(self, **overrides):
        kwargs = dict(
            system_dir=self.system,
            home=self.home,
            root=self.root,
            command_runner=self.systemctl,
            platform_provider=self.platform_provider,
            metadata_fetcher=self.metadata_fetcher,
            archive_downloader=self.archive_downloader,
        )
        kwargs.update(overrides)
        return Manager(self.runtime, self.settings, self.logs, self.plugin, **kwargs)

    # -- artifact readers -------------------------------------------------
    def unit_path(self):
        return self.system / UNIT_FILE

    def read_unit(self):
        return self.unit_path().read_text(encoding="utf-8")

    def install_json(self):
        return json.loads((self.runtime / "install.json").read_text(encoding="utf-8"))

    def manifest_fields(self):
        manifest = self.install_json()
        return {key: manifest[key] for key in ("engine", "version", "md5")}

    def identity_path(self):
        return self.settings / "identity" / IDENTITY_NAME

    def read_state(self):
        # A first install leaves autostart false *implicitly*: no state.json is
        # written until an intent is persisted, and a rejected first enable must
        # not create one. Treat an absent file as empty state.
        try:
            return json.loads((self.settings / "state.json").read_text(encoding="utf-8"))
        except OSError:
            return {}

    def unit_field(self, key):
        for line in self.read_unit().splitlines():
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
        return None

    def run_dir(self):
        raw = self.unit_field("WorkingDirectory")
        if not raw:
            return None
        return Path(raw.strip('"').replace("%%", "%"))

    def current_release_dir(self):
        # The live payload release the ``current`` symlink points at; the real
        # core writes its QR marker beside the executable *there*, not in run/.
        return Path(os.readlink(self.runtime / "current"))

    def start_count(self):
        return sum(1 for call in self.systemctl.calls if "start" in call)

    def strict_systemctl(self):
        """A fake that rejects stop/disable with no live state, like real systemctl.

        The lenient default stand-in happily clears absent active/enabled state,
        which would hide an uninstall (or rollback) that touches a unit the
        plugin never installed. Real ``systemctl stop``/``disable`` fail when the
        unit is neither loaded from an owned unit file nor currently
        active/enabled, so this wrapper delegates to the fake for the normal
        case but returns a nonzero status for that impossible transition.
        """
        base = self.systemctl
        own_unit = self.unit_path()

        def runner(args):
            args = list(args)
            verb = next((token for token in args if token in _VERBS), "")
            unit = base._key(args[-1]) if len(args) > 1 else ""
            if unit == UNIT_ID and not own_unit.is_file():
                if verb == "stop" and unit not in base.active:
                    base.calls.append(args)
                    return completed(
                        args, 5, stderr="Unit uu-accelerator.service not loaded.")
                if verb == "disable" and unit not in base.enabled:
                    base.calls.append(args)
                    return completed(
                        args, 1, stderr="Unit uu-accelerator.service not loaded.")
            return base(args)

        return runner

    def start_failure_runner(self, writer, diagnostic, seen):
        """A systemctl stand-in whose failed ``start`` writes a diagnosis.

        A real failing start is the supervisor exiting 78 after it wrote
        ``run/startup-error.txt``. This hook records whether the file was still
        present when the manager issued ``start`` and then emulates the
        supervisor's write, so both the fresh reason and the stale-file reset
        are observable.
        """
        base = self.systemctl

        def runner(args):
            args = list(args)
            verb = next((token for token in args if token in _VERBS), "")
            if verb == "start":
                seen.append(diagnostic.exists())
            result = base(args)
            if verb == "start" and getattr(result, "returncode", 0) != 0:
                writer()
            return result

        return runner

    # -- tests -----------------------------------------------------------
    def test_install_records_profile_and_starts_own_service(self):
        md5 = self.configure_release("14.9.4")
        manager = self.make_manager()

        manager.install(engine="fex")

        manifest = self.install_json()
        self.assertEqual(manifest["engine"], "fex")
        self.assertEqual(manifest["version"], "14.9.4")
        self.assertEqual(manifest["md5"], md5)

        self.assertTrue(self.unit_path().is_file())
        unit = self.read_unit()
        self.assertIn(OWNERSHIP_MARKER, unit)
        self.assertIn(PYTHON, unit)

        copied = list(self.runtime.rglob("supervisor.py"))
        self.assertEqual(len(copied), 1)
        self.assertIn(str(copied[0]), unit)

        run_dir = self.run_dir()
        if run_dir is not None:
            for name in ("uuplugin", "xuplugin-guardian", "uu.conf"):
                self.assertTrue((run_dir / name).is_file(), name)

        bindpaths = self.unit_field("BindPaths")
        self.assertIsNotNone(bindpaths)
        self.assertIn("/tmp/uu", bindpaths)
        self.assertIn(str(run_dir), bindpaths.replace("%%", "%"))

        self.assertIn(UNIT_ID, self.systemctl.active)

        status = manager.status()
        for field in STATUS_FIELDS:
            self.assertIn(field, status)
        self.assertTrue(status["installed"])
        self.assertTrue(status["running"])
        self.assertFalse(status["busy"])
        self.assertIsNone(status["error"])
        self.assertEqual(status["engine"], "fex")
        self.assertEqual(status["version"], "14.9.4")
        self.assertEqual(status["platform"]["arch"], "aarch64")
        self.assertIn("fex", status["engines"])
        self.assertIn("qr_text", status["binding"])
        self.assertIn("available", status["binding"])
        self.assertNotIn("bound", status["binding"])
        self.assertNotIn("accelerated", status["binding"])

    def test_install_supports_spaced_chinese_and_percent_paths(self):
        self.runtime = self.tmp / "数据 100% dir"
        self.settings = self.tmp / "设置 目录"
        self.logs = self.tmp / "日志"
        self.configure_release("14.9.4")
        manager = self.make_manager()

        manager.install(engine="fex")

        self.assertTrue((self.runtime / "install.json").is_file())
        raw_wd = self.unit_field("WorkingDirectory")
        self.assertIsNotNone(raw_wd)
        # systemd's config_parse_working_directory hands the raw rvalue straight
        # to unit_path_printf/path_simplify, so a leading double quote would be
        # parsed as part of the path. A scalar WorkingDirectory must therefore
        # be an *unquoted* absolute path with percent escaped as %%; internal
        # spaces and Chinese characters stay literal.
        self.assertEqual(raw_wd, str(self.runtime / "run").replace("%", "%%"))
        self.assertNotIn('"', raw_wd)
        self.assertIn("100%%", raw_wd)
        self.assertIn("数据 100% dir", str(self.run_dir()))
        self.assertTrue(self.identity_path().is_file())

    def test_install_failures_preserve_existing_installation(self):
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        unit_before = self.read_unit()
        manifest_before = self.manifest_fields()
        identity_before = self.identity_path().read_text(encoding="utf-8")

        def broken(*args, **kwargs):
            raise RuntimeError("boundary failed")

        def bad_checksum(*args, **kwargs):
            raise ValueError("安装包 MD5 校验失败")

        def garbage(metadata, target, **kwargs):
            Path(target).write_bytes(b"not-a-tar")
            return Path(target)

        cases = {
            "metadata-fetch": {"metadata_fetcher": broken},
            "download": {"archive_downloader": broken},
            "checksum": {"archive_downloader": bad_checksum},
            "payload": {"archive_downloader": garbage},
        }
        for case, overrides in cases.items():
            with self.subTest(case=case):
                self.configure_release("15.0.0")  # a genuine upgrade candidate
                failing = self.make_manager(**overrides)
                with self.assertRaises(Exception):
                    failing.install(engine="fex")

                self.assertEqual(self.read_unit(), unit_before)
                self.assertEqual(self.manifest_fields(), manifest_before)
                self.assertEqual(
                    self.identity_path().read_text(encoding="utf-8"), identity_before)
                self.assertIn(UNIT_ID, self.systemctl.active)

    def test_check_updates_reports_update_without_downloading(self):
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        downloads_before = self.downloads
        unit_before = self.read_unit()
        manifest_before = self.manifest_fields()

        self.configure_release("15.0.0")
        result = manager.check_updates()
        self.assertTrue(result["update_available"])
        self.assertEqual(result.get("version"), "15.0.0")

        self.assertEqual(self.downloads, downloads_before)
        self.assertEqual(self.read_unit(), unit_before)
        self.assertEqual(self.manifest_fields(), manifest_before)

        self.configure_release("14.9.4")  # back to the installed md5
        self.assertFalse(self.make_manager().check_updates()["update_available"])

    def test_reinstall_with_identical_md5_is_noop(self):
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        downloads_before = self.downloads
        starts_before = self.start_count()

        manager.install(engine="fex")

        self.assertEqual(self.downloads, downloads_before)
        self.assertEqual(self.start_count(), starts_before)

    def test_reinstall_and_start_refresh_stale_owned_unit(self):
        """An older owned unit is upgraded in place without disturbing service.

        An already-installed unit that lags the current release (here a stale
        ``TimeoutStartSec=15`` instead of the generated 45) must be rewritten to
        the fresh text by *both* an identical-engine/MD5 reinstall and a plain
        ``start()``, each followed by a ``daemon-reload`` before the service is
        (re)started. Neither path may download a payload or stop/restart an
        active service.
        """
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        def reload_count():
            return sum(1 for call in self.systemctl.calls if "daemon-reload" in call)

        def stop_count():
            return sum(1 for call in self.systemctl.calls if "stop" in call)

        # Pretend an older release installed this same (owned) unit with a
        # shorter start bound than the current build_unit emits.
        stale = self.read_unit().replace(
            "TimeoutStartSec=45", "TimeoutStartSec=15")
        self.unit_path().write_text(stale, encoding="utf-8")
        self.assertEqual(self.unit_field("TimeoutStartSec"), "15")

        downloads_before = self.downloads
        starts_before = self.start_count()
        reloads_before = reload_count()
        stops_before = stop_count()

        manager.install(engine="fex")  # identical engine + MD5

        self.assertEqual(self.unit_field("TimeoutStartSec"), "45")
        self.assertEqual(self.downloads, downloads_before)
        self.assertEqual(self.start_count(), starts_before)
        self.assertEqual(stop_count(), stops_before)
        self.assertGreater(reload_count(), reloads_before)
        self.assertIn(UNIT_ID, self.systemctl.active)

        # A plain start() must likewise refresh the stale unit, and must do so
        # before the service is started.
        self.unit_path().write_text(stale, encoding="utf-8")
        events = []
        base = self.systemctl

        def runner(args):
            args = list(args)
            verb = next((token for token in args if token in _VERBS), "")
            if verb in ("start", "daemon-reload"):
                events.append((verb, self.unit_field("TimeoutStartSec")))
            return base(args)

        started = self.make_manager(command_runner=runner)
        starts_before = self.start_count()
        started.start()

        self.assertEqual(self.unit_field("TimeoutStartSec"), "45")
        self.assertEqual(self.start_count(), starts_before + 1)
        reloads = [i for i, (verb, _) in enumerate(events) if verb == "daemon-reload"]
        starts = [i for i, (verb, _) in enumerate(events) if verb == "start"]
        self.assertTrue(reloads and starts)
        self.assertLess(reloads[0], starts[0])
        self.assertEqual(events[starts[0]][1], "45")

    def test_failed_new_start_rolls_back_to_previous_installation(self):
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")
        manager.set_autostart(True)

        unit_before = self.read_unit()
        manifest_before = self.manifest_fields()
        self.assertIn(UNIT_ID, self.systemctl.active)
        self.assertIn(UNIT_ID, self.systemctl.enabled)

        self.configure_release("15.0.0")
        self.systemctl.fail_start_once.add(UNIT_ID)
        with self.assertRaises(Exception):
            manager.install(engine="fex")

        self.assertEqual(self.manifest_fields(), manifest_before)
        self.assertEqual(self.read_unit(), unit_before)
        self.assertIn(UNIT_ID, self.systemctl.active)
        self.assertIn(UNIT_ID, self.systemctl.enabled)

    def test_autostart_persists_across_manager_instances(self):
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")
        manager.set_autostart(True)
        self.assertEqual(self.systemctl.enabled, {UNIT_ID})

        other = self.make_manager()
        self.assertTrue(other.status()["autostart"])
        other.set_autostart(False)
        self.assertEqual(self.systemctl.enabled, set())
        self.assertTrue(self.systemctl.active <= {UNIT_ID})

    def test_stop_and_uninstall_touch_only_own_unit(self):
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")
        run_dir = self.run_dir()

        manager.stop()
        self.assertNotIn(UNIT_ID, self.systemctl.active)
        self.assertTrue(manager.status()["installed"])
        manager.start()
        self.assertIn(UNIT_ID, self.systemctl.active)

        manager.uninstall()
        self.assertFalse(self.unit_path().exists())
        self.assertFalse((self.runtime / "install.json").exists())
        self.assertTrue(self.identity_path().is_file())
        if run_dir is not None:
            self.assertFalse(run_dir.exists())
        self.assertFalse(manager.status()["installed"])
        self.assertTrue(self.systemctl.active <= {UNIT_ID})
        self.assertTrue(self.systemctl.enabled <= {UNIT_ID})

        tokens = [token for call in self.systemctl.calls for token in call]
        for banned in ("pkill", "iptables", "nft", "ufw", "firewall-cmd"):
            self.assertNotIn(banned, tokens)

    def test_uninstall_reset_binding_removes_only_identity(self):
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")
        keep = self.settings / "keep.txt"
        keep.write_text("keep", encoding="utf-8")
        self.assertTrue(self.identity_path().is_file())

        manager.uninstall(reset_binding=True)

        self.assertFalse(self.identity_path().exists())
        self.assertTrue(keep.is_file())

    # -- binding reset ---------------------------------------------------
    def test_reset_binding_reissues_only_identity_and_restarts_core(self):
        """reset_binding() keeps the install and only renews the binding UUID.

        Manager.reset_binding() is not implemented yet, so this test is
        intentionally red: it pins that a reset re-issues exactly
        settings/identity/.uuplugin_uuid with a fresh UUID, leaves the payload,
        manifest, unit and unrelated settings untouched, and restarts the
        plugin's own core rather than leaving it down.
        """
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        identity_before = self.identity_path().read_text(encoding="utf-8")
        manifest_before = self.install_json()
        unit_before = self.read_unit()
        keep = self.settings / "keep.txt"
        keep.write_text("keep", encoding="utf-8")
        payload_before = sorted(p.name for p in manager.payload_dir.iterdir())
        starts_before = self.start_count()

        manager.reset_binding()

        identity_after = self.identity_path().read_text(encoding="utf-8")
        self.assertNotEqual(identity_after, identity_before)
        uuid.UUID(identity_after)  # a fresh, well-formed UUID

        # only the binding identity changes; everything else is retained
        self.assertEqual(self.install_json(), manifest_before)
        self.assertEqual(self.read_unit(), unit_before)
        self.assertEqual(keep.read_text(encoding="utf-8"), "keep")
        self.assertEqual(
            sorted(p.name for p in manager.payload_dir.iterdir()), payload_before)
        self.assertTrue((self.run_dir() / "uuplugin").is_file())

        # the plugin's own core is restarted, not left stopped
        self.assertGreater(self.start_count(), starts_before)
        self.assertIn(UNIT_ID, self.systemctl.active)

    def test_reset_binding_keeps_old_identity_when_stop_fails(self):
        """A failed stop must raise before the old identity is replaced."""
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        identity_before = self.identity_path().read_text(encoding="utf-8")
        self.systemctl.fail_stop_once.add(UNIT_ID)

        with self.assertRaises(Exception):
            manager.reset_binding()

        self.assertEqual(
            self.identity_path().read_text(encoding="utf-8"), identity_before)
        self.assertIn(UNIT_ID, self.systemctl.active)

    def test_refuses_foreign_unit_file(self):
        self.configure_release("14.9.4")
        self.make_manager().install(engine="fex")

        foreign = "[Unit]\nDescription=Somebody else\n"
        self.unit_path().write_text(foreign, encoding="utf-8")
        fresh = self.make_manager()

        with self.assertRaises(Exception):
            fresh.install(engine="fex")
        self.assertEqual(self.read_unit(), foreign)

        with self.assertRaises(Exception):
            fresh.uninstall()
        self.assertEqual(self.read_unit(), foreign)

    def test_refuses_legacy_installation_takeover(self):
        self.platform = self.platform_dict(legacy_install=True)
        self.configure_release("14.9.4")
        manager = self.make_manager()

        for engine in ("auto", "fex"):
            with self.subTest(engine=engine), self.assertRaises(ValueError):
                manager.install(engine=engine)

        self.assertFalse(self.unit_path().exists())

    # -- lifecycle regressions -------------------------------------------
    def test_successful_mutation_clears_stale_install_error(self):
        """A stale install error must not survive a later successful mutation.

        The manager records the last install failure in ``status()['error']``.
        Once a *different* mutation succeeds (start/stop/autostart/reset) that
        stale error must be cleared rather than lingering and misreporting the
        healthy install as broken.
        """
        state = {"broken": False}

        def fetcher(package_type, **kwargs):
            if state["broken"]:
                raise RuntimeError("boundary failed")
            return self._default_metadata_fetcher(package_type, **kwargs)

        self.configure_release("14.9.4")
        manager = self.make_manager(metadata_fetcher=fetcher)
        manager.install(engine="fex")
        self.assertIsNone(manager.status()["error"])

        def fail_update():
            self.configure_release("15.0.0")  # a genuine upgrade candidate
            state["broken"] = True
            try:
                with self.assertRaises(Exception):
                    manager.install(engine="fex")
            finally:
                state["broken"] = False
            self.assertTrue(manager.status()["error"])

        cases = (
            ("start", lambda: manager.start()),
            ("stop", lambda: manager.stop()),
            ("autostart", lambda: manager.set_autostart(True)),
            ("reset", lambda: manager.reset_binding()),
        )
        for name, action in cases:
            with self.subTest(action=name):
                fail_update()
                action()
                self.assertIsNone(manager.status()["error"], name)

    def test_stop_uninstall_and_upgrade_fail_loudly_without_switching(self):
        """A failed systemctl stop must raise and never tear down live state."""
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        unit_before = self.read_unit()
        manifest_before = self.manifest_fields()
        current_before = os.readlink(self.runtime / "current")
        run_before = os.readlink(self.run_dir() / "uuplugin")

        self.systemctl.fail_stop_once.add(UNIT_ID)
        with self.assertRaises(Exception):
            manager.stop()
        self.assertIn(UNIT_ID, self.systemctl.active)

        self.systemctl.fail_stop_once.add(UNIT_ID)
        with self.assertRaises(Exception):
            manager.uninstall()
        self.assertTrue(self.unit_path().is_file())

        self.systemctl.fail_stop_once.add(UNIT_ID)
        self.configure_release("15.0.0")
        with self.assertRaises(Exception):
            manager.install(engine="fex")

        self.assertEqual(self.read_unit(), unit_before)
        self.assertEqual(self.manifest_fields(), manifest_before)
        self.assertEqual(os.readlink(self.runtime / "current"), current_before)
        self.assertEqual(os.readlink(self.run_dir() / "uuplugin"), run_before)
        self.assertIn(UNIT_ID, self.systemctl.active)

    def test_set_autostart_rejects_foreign_unit_and_keeps_state_on_failure(self):
        """Ownership is guarded and a rejected enable/disable keeps old state."""
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        self.systemctl.fail_enable_once.add(UNIT_ID)
        with self.assertRaises(Exception):
            manager.set_autostart(True)
        self.assertFalse(self.read_state().get("autostart", False))
        self.assertNotIn(UNIT_ID, self.systemctl.enabled)

        manager.set_autostart(True)
        self.assertTrue(self.read_state()["autostart"])

        self.systemctl.fail_disable_once.add(UNIT_ID)
        with self.assertRaises(Exception):
            manager.set_autostart(False)
        self.assertTrue(self.read_state()["autostart"])
        self.assertIn(UNIT_ID, self.systemctl.enabled)

        foreign = "[Unit]\nDescription=Somebody else\n"
        self.unit_path().write_text(foreign, encoding="utf-8")
        with self.assertRaises(Exception):
            manager.set_autostart(False)
        self.assertEqual(self.read_unit(), foreign)

    def test_daemon_reload_publishes_own_unit_before_start(self):
        """The unit must be on disk and reloaded before the service starts."""
        self.configure_release("14.9.4")
        events = []
        unit = self.system / UNIT_FILE
        base = self.systemctl

        def runner(args):
            args = list(args)
            verb = next((token for token in args if token in _VERBS), "")
            published = unit.is_file() and OWNERSHIP_MARKER in unit.read_text(
                encoding="utf-8")
            events.append((verb, published))
            return base(args)

        manager = self.make_manager(command_runner=runner)
        manager.install(engine="fex")

        starts = [i for i, (verb, _) in enumerate(events) if verb == "start"]
        self.assertTrue(starts, "install must start the service")
        first_start = starts[0]
        reloads = [
            i for i, (verb, published) in enumerate(events)
            if verb == "daemon-reload" and published and i < first_start
        ]
        self.assertTrue(
            reloads,
            "daemon-reload must run after the unit is published and before start",
        )

    def test_cached_candidate_records_uuconf_version_without_api_hint(self):
        """A cached candidate must record the uu.conf version, not a None hint."""
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        # A real /v14.9.4/uu.tar.gz URL parses to no version at all.
        self.configure_release("15.0.0")
        self.metadata["version"] = None

        self.systemctl.fail_start_once.add(UNIT_ID)
        with self.assertRaises(Exception):
            manager.install(engine="fex")

        manager.install(engine="fex")  # retry: candidate is already cached

        self.assertEqual(self.install_json()["engine"], "fex")
        self.assertEqual(self.install_json()["version"], "15.0.0")

    def _seed_legacy_manifest(self, manager, engine):
        """Rewrite the persisted manifest to a legacy engine without starting it.

        Never call this on a manager whose platform lacks a FEX route: the
        caller must have installed valid FEX first (which the platform selects).
        """
        manifest = self.install_json()
        manifest["engine"] = engine
        manifest["package_type"] = engine
        (self.runtime / "install.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        return manifest

    def test_switch_native_to_fex_drops_stale_helper_and_records_prefix(self):
        """Legacy native manifest -> FEX migration drops the stale helper."""
        self.configure_release("14.9.4", machine=ELF_X86_64)
        manager = self.make_manager()
        manager.install(engine="fex")

        # Manually seed the legacy native manifest and a stale owned helper
        # symlink pointing into the cached payload; no install-native path exists.
        self._seed_legacy_manifest(manager, "native")
        release = Path(self.install_json()["release"])
        (release / "xtables-nft-multi").write_bytes(elf_header(ELF_X86_64))
        helper_source = release / "xtables-nft-multi"
        helper = self.run_dir() / "xtables-nft-multi"
        if helper.is_symlink() or helper.exists():
            helper.unlink()
        helper.symlink_to(str(helper_source))
        self.assertTrue(helper.is_symlink())
        identity_before = self.identity_path().read_text(encoding="utf-8")

        self.configure_release("14.9.5", machine=ELF_X86_64)  # FEX payload
        manager.install(engine="fex")

        self.assertFalse(helper.exists() or helper.is_symlink())
        self.assertEqual(
            self.identity_path().read_text(encoding="utf-8"), identity_before)
        self.assertEqual(self.install_json()["engine"], "fex")
        launch = json.loads(
            (self.runtime / "launch.json").read_text(encoding="utf-8"))
        self.assertEqual(launch["engine"], "fex")
        self.assertEqual(launch["launch_prefix"], ["/usr/bin/FEXInterpreter"])
        self.assertIn("kernel_compat", launch)

    # -- Task14a: lifecycle regressions ----------------------------------
    def test_uninstall_is_successful_and_repeatable_without_live_state(self):
        """uninstall must succeed before any install and stay repeatable.

        The strict stand-in rejects ``stop``/``disable`` when the plugin owns
        neither a unit file nor any active/enabled state, exactly like the real
        tool; an uninstall that blindly stops a unit it never installed must not
        fail, and a second uninstall after a real teardown must be a no-op.
        """
        fresh = self.make_manager(command_runner=self.strict_systemctl())
        fresh.uninstall()  # never installed: stop/disable would be nonzero
        fresh.uninstall()  # repeatable
        self.assertFalse(self.unit_path().exists())
        self.assertFalse((self.runtime / "install.json").exists())
        self.assertFalse(fresh.status()["installed"])

        self.configure_release("14.9.4")
        manager = self.make_manager(command_runner=self.strict_systemctl())
        manager.install(engine="fex")
        manager.uninstall()
        manager.uninstall()  # a second uninstall after teardown also succeeds

        self.assertFalse(self.unit_path().exists())
        self.assertFalse((self.runtime / "install.json").exists())
        self.assertFalse(manager.status()["installed"])

    def test_first_install_write_launch_failure_rolls_back_completely(self):
        """A failure before the unit is written leaves no first-install debris.

        ``_write_launch`` raises before the unit exists, so rollback must leave
        no unit, manifest, current symlink or run aliases behind, must unlink the
        copied launch/supervisor, and must surface the *original* error rather
        than masking it with a 回滚失败 caused by stopping a nonexistent unit.
        """
        self.configure_release("14.9.4")
        manager = self.make_manager(command_runner=self.strict_systemctl())

        with mock.patch.object(
            Manager,
            "_write_launch",
            side_effect=RuntimeError("write_launch exploded"),
        ):
            with self.assertRaises(RuntimeError) as caught:
                manager.install(engine="fex")

        self.assertIn("write_launch exploded", str(caught.exception))
        self.assertNotIn("回滚", str(caught.exception))

        self.assertFalse(self.unit_path().exists())
        self.assertFalse((self.runtime / "install.json").exists())
        self.assertFalse(os.path.lexists(self.runtime / "current"))
        run = self.runtime / "run"
        for name in ("uuplugin", "uu.conf"):
            self.assertFalse(os.path.lexists(run / name), name)
        self.assertFalse((self.runtime / "launch.json").exists())
        self.assertFalse((self.runtime / "supervisor.py").exists())
        self.assertFalse(manager.status()["installed"])

    def test_first_install_start_failure_rolls_back_to_absent(self):
        """A failed first start must roll all the way back to 'never installed'.

        The unit is published and its one-shot start fails; rollback must disable
        the unit *before* deleting it, leave no unit/manifest/current/run aliases
        and no active or enabled systemd state, and retain only the binding UUID
        and the downloaded payload cache.
        """
        self.configure_release("14.9.4")
        manager = self.make_manager(command_runner=self.strict_systemctl())
        self.systemctl.fail_start_once.add(UNIT_ID)

        with self.assertRaises(RuntimeError) as caught:
            manager.install(engine="fex")
        self.assertNotIn("回滚", str(caught.exception))

        self.assertFalse(self.unit_path().exists())
        self.assertFalse((self.runtime / "install.json").exists())
        self.assertFalse(os.path.lexists(self.runtime / "current"))
        run = self.runtime / "run"
        for name in ("uuplugin", "uu.conf"):
            self.assertFalse(os.path.lexists(run / name), name)

        self.assertEqual(self.systemctl.active, set())
        self.assertEqual(self.systemctl.enabled, set())

        self.assertTrue(self.identity_path().is_file())
        self.assertTrue(manager.payload_dir.is_dir())
        self.assertFalse(manager.status()["installed"])

    def test_generated_unit_is_notify_and_bounded(self):
        """The installed unit must be Type=notify with a finite start timeout."""
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        self.assertEqual(self.unit_field("Type"), "notify")
        self.assertEqual(self.unit_field("NotifyAccess"), "main")
        raw = self.unit_field("TimeoutStartSec")
        self.assertIsNotNone(raw)
        self.assertEqual(int(raw.strip().rstrip("s")), 45)

    # -- Task06: QR binding repair ---------------------------------------
    def test_status_binding_reads_qr_beside_release_executable(self):
        """The live QR marker sits beside the executable in the *current
        release*, not in the run directory.

        The real core writes ``.steam_deck_sn_qrcode`` next to the payload it
        was launched from, and ``current`` points at that release while the
        runtime CWD stays ``run/``. A stale ``run/`` copy (here a "Loading..."
        placeholder) must be ignored in favour of the release-side marker, and
        ``status()['binding']`` must expose a generated SVG.
        """
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        release = self.current_release_dir()
        self.assertTrue((release / "uuplugin").is_file())
        (release / QR_MARKER_NAME).write_text(QR_SAMPLE, encoding="utf-8")
        # A stale legacy run-side marker must lose to the release-side one.
        (self.run_dir() / QR_MARKER_NAME).write_text("Loading...", encoding="utf-8")

        binding = manager.status()["binding"]
        self.assertTrue(binding["available"])
        self.assertTrue(binding["qr_svg"].startswith("<svg"))
        self.assertIn("crispEdges", binding["qr_svg"])
        # Backwards-compatible fields survive; no invented bound/accelerated.
        self.assertIn("qr_text", binding)
        self.assertNotIn("bound", binding)
        self.assertNotIn("accelerated", binding)

    def test_status_binding_falls_back_to_legacy_run_qr(self):
        """A legacy run-side marker is still honored when no release one exists."""
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        release = self.current_release_dir()
        self.assertFalse((release / QR_MARKER_NAME).exists())
        (self.run_dir() / QR_MARKER_NAME).write_text(QR_SAMPLE, encoding="utf-8")

        binding = manager.status()["binding"]
        self.assertTrue(binding["available"])
        self.assertTrue(binding["qr_svg"].startswith("<svg"))
        self.assertIn("crispEdges", binding["qr_svg"])

    def test_reset_binding_clears_qr_marker_beside_release_and_run(self):
        """A reset must drop the QR marker wherever it lives.

        ``reset_binding`` renews the binding, so the stale QR marker is cleared
        both beside the release executable and in the legacy run directory,
        while the identity UUID is re-issued, the payload is untouched and the
        core is restarted (existing semantics).
        """
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        release = self.current_release_dir()
        release_marker = release / QR_MARKER_NAME
        run_marker = self.run_dir() / QR_MARKER_NAME
        release_marker.write_text(QR_SAMPLE, encoding="utf-8")
        run_marker.write_text(QR_SAMPLE, encoding="utf-8")

        identity_before = self.identity_path().read_text(encoding="utf-8")
        payload_before = sorted(p.name for p in manager.payload_dir.iterdir())
        starts_before = self.start_count()

        manager.reset_binding()

        self.assertFalse(release_marker.exists())
        self.assertFalse(run_marker.exists())

        identity_after = self.identity_path().read_text(encoding="utf-8")
        self.assertNotEqual(identity_after, identity_before)
        uuid.UUID(identity_after)  # a fresh, well-formed UUID

        self.assertEqual(
            sorted(p.name for p in manager.payload_dir.iterdir()), payload_before)
        self.assertTrue((release / "uuplugin").is_file())

        # the plugin's own core is restarted, not left stopped
        self.assertGreater(self.start_count(), starts_before)
        self.assertIn(UNIT_ID, self.systemctl.active)

        binding = manager.status()["binding"]
        self.assertFalse(binding["available"])

    # -- startup diagnostics ---------------------------------------------
    def test_start_failure_surfaces_fresh_supervisor_diagnosis(self):
        """A failed start must report the supervisor's *new* diagnosis.

        The supervisor leaves ``run/startup-error.txt`` when its kernel-compat
        preflight refuses the host, and the unit maps that exit status to a
        silent no-restart. The manager must clear the previous run's diagnosis
        before every ``systemctl start`` and, once this start failed, raise an
        error carrying the newly written reason -- not the old one.
        """
        for action in ("start", "install"):
            with self.subTest(action=action):
                self.configure_release("14.9.4")
                self.make_manager().install(engine="fex")

                diagnostic = self.run_dir() / "startup-error.txt"
                # A leftover from an older run must never be reused as the reason.
                diagnostic.write_text("旧内核错误", encoding="utf-8")
                seen = []

                def writer():
                    diagnostic.write_text(
                        "内核编译版本不匹配: 新原因", encoding="utf-8")

                failing = self.make_manager(
                    command_runner=self.start_failure_runner(
                        writer, diagnostic, seen))
                self.systemctl.fail_start_once.add(UNIT_ID)
                if action == "install":
                    self.configure_release("15.0.0")  # a genuine upgrade
                    call = lambda: failing.install(engine="fex")  # noqa: E731
                else:
                    call = failing.start

                with self.assertRaises(RuntimeError) as caught:
                    call()

                message = str(caught.exception)
                self.assertIn("内核编译版本不匹配: 新原因", message)
                self.assertNotIn("旧内核错误", message)
                self.assertTrue(seen, "manager never issued a start")
                self.assertNotIn(
                    True, seen, "the stale diagnosis survived into the start")

    def test_plain_start_failure_ignores_stale_startup_error(self):
        """A start failure without a diagnosis must not resurrect an old one.

        The stale file belongs to an earlier run: once this start fails without
        writing a diagnosis, the error stays generic and the leftover is gone,
        because the manager clears it before ``systemctl start``.
        """
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")

        diagnostic = self.run_dir() / "startup-error.txt"
        diagnostic.write_text("旧内核不匹配", encoding="utf-8")

        self.systemctl.fail_start_once.add(UNIT_ID)
        with self.assertRaises(RuntimeError) as caught:
            manager.start()

        self.assertNotIn("旧内核不匹配", str(caught.exception))
        self.assertFalse(
            diagnostic.exists(), "stale startup-error.txt survived the start")

    # -- F004: legacy native/x86 lifecycle regressions --------------------
    def _seed_legacy_stopped(self, engine):
        """Seed a legacy native/x86 manifest that is stopped and disabled."""
        self.configure_release("14.9.4")
        manager = self.make_manager()
        manager.install(engine="fex")
        manager.stop()
        self._seed_legacy_manifest(manager, engine)
        manager.set_autostart(False)
        return manager

    def test_legacy_engine_rejects_start_without_uuid_change(self):
        for engine in ("native", "x86"):
            with self.subTest(engine=engine):
                self.setUp()
                manager = self._seed_legacy_stopped(engine)
                identity_before = self.identity_path().read_text(encoding="utf-8")
                starts_before = self.start_count()
                with self.assertRaises(ValueError):
                    manager.start()
                self.assertEqual(self.start_count(), starts_before)
                self.assertEqual(
                    self.identity_path().read_text(encoding="utf-8"),
                    identity_before)
                self.assertNotIn(UNIT_ID, self.systemctl.active)

    def test_legacy_engine_reset_binding_rejects_without_changing_uuid(self):
        for engine in ("native", "x86"):
            with self.subTest(engine=engine):
                self.setUp()
                manager = self._seed_legacy_stopped(engine)
                identity_before = self.identity_path().read_text(encoding="utf-8")
                starts_before = self.start_count()
                with self.assertRaises(ValueError):
                    manager.reset_binding()
                self.assertEqual(self.start_count(), starts_before)
                self.assertEqual(
                    self.identity_path().read_text(encoding="utf-8"),
                    identity_before)

    def test_legacy_engine_enable_autostart_rejected_disable_allowed(self):
        for engine in ("native", "x86"):
            with self.subTest(engine=engine):
                self.setUp()
                manager = self._seed_legacy_stopped(engine)
                with self.assertRaises(ValueError):
                    manager.set_autostart(True)
                self.assertFalse(self.read_state().get("autostart", False))
                self.assertNotIn(UNIT_ID, self.systemctl.enabled)
                # Disable stays permitted for old unsupported installs.
                manager.set_autostart(False)
                self.assertFalse(self.read_state().get("autostart", False))

    def test_legacy_engine_stop_and_uninstall_allowed(self):
        for engine in ("native", "x86"):
            with self.subTest(engine=engine):
                self.setUp()
                manager = self._seed_legacy_stopped(engine)
                identity_before = self.identity_path().read_text(encoding="utf-8")
                manager.stop()
                manager.uninstall()
                self.assertFalse(self.unit_path().exists())
                self.assertFalse((self.runtime / "install.json").exists())
                self.assertEqual(
                    self.identity_path().read_text(encoding="utf-8"),
                    identity_before)

    def test_install_fex_from_seeded_legacy_preserves_uuid(self):
        for engine in ("native", "x86"):
            with self.subTest(engine=engine):
                self.setUp()
                manager = self._seed_legacy_stopped(engine)
                identity_before = self.identity_path().read_text(encoding="utf-8")
                self.configure_release("14.9.5")
                manager.install(engine="fex")
                self.assertEqual(self.install_json()["engine"], "fex")
                self.assertEqual(
                    self.identity_path().read_text(encoding="utf-8"),
                    identity_before)
                # The seeded legacy service was stopped, so the upgrade
                # preserves that prior state instead of starting FEX.
                self.assertNotIn(UNIT_ID, self.systemctl.active)
                # Explicit start verifies the new FEX engine can start.
                manager.start()
                self.assertIn(UNIT_ID, self.systemctl.active)

    def test_failed_migration_from_legacy_leaves_stopped_disabled(self):
        for engine in ("native", "x86"):
            with self.subTest(engine=engine):
                self.setUp()
                manager = self._seed_legacy_stopped(engine)
                identity_before = self.identity_path().read_text(encoding="utf-8")
                manifest_before = self.manifest_fields()
                # Model an existing running legacy service with autostart on.
                self.systemctl.active.add(UNIT_ID)
                self.systemctl.enabled.add(UNIT_ID)
                manager._write_state({"autostart": True})
                self.systemctl.calls.clear()
                self.configure_release("14.9.5")
                self.systemctl.fail_start_once.add(UNIT_ID)
                with self.assertRaises(Exception):
                    manager.install(engine="fex")
                self.assertEqual(self.install_json()["engine"], engine)
                self.assertEqual(self.manifest_fields(), manifest_before)
                self.assertNotIn(UNIT_ID, self.systemctl.active)
                self.assertNotIn(UNIT_ID, self.systemctl.enabled)
                self.assertFalse(self.read_state().get("autostart", False))
                self.assertEqual(
                    self.identity_path().read_text(encoding="utf-8"),
                    identity_before)
                # Rollback must not enable the legacy unit or start anything
                # beyond the single failed candidate FEX start.
                self.assertFalse(
                    any("enable" in call for call in self.systemctl.calls))
                self.assertEqual(self.start_count(), 1)

    def test_check_updates_from_legacy_native_fetches_fex_and_flags_engine(self):
        manager = self._seed_legacy_stopped("native")
        manifest_before = self.manifest_fields()
        fetches_before = self.fetches
        seen = []

        def fetcher(package_type, **kwargs):
            seen.append(package_type)
            return self._default_metadata_fetcher(package_type, **kwargs)

        other = self.make_manager(metadata_fetcher=fetcher)
        result = other.check_updates()
        self.assertGreater(self.fetches, fetches_before)
        self.assertTrue(result["update_available"])
        self.assertEqual(result["engine"], "fex")
        self.assertEqual(seen, ["steam-deck-plugin-x86_64"])
        self.assertEqual(self.manifest_fields(), manifest_before)

    def test_generated_unit_refuses_restart_on_preflight_exit(self):
        """Exit code 78 (preflight refused) must not trigger a restart.

        The supervisor exits 78 for a refused startup, so the unit keeps
        ``Restart=on-failure`` for genuine crash loops but lists 78 in
        ``RestartPreventExitStatus`` to avoid a restart storm on an
        incompatible kernel.
        """
        self.configure_release("14.9.4")
        self.make_manager().install(engine="fex")

        self.assertEqual(self.unit_field("Restart"), "on-failure")
        self.assertEqual(self.unit_field("RestartPreventExitStatus"), "78")
