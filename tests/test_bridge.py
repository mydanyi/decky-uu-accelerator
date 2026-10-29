"""Contract tests for the Decky bridge at the project root: ``main.py``.

``main.py`` does not exist yet, so this module is expected to be red until the
Decky RPC bridge is implemented. It pins a small, stdlib-only async API:

* ``Plugin._main`` builds a :class:`Manager` from the Decky constants
  (runtime/settings/log/plugin dirs plus the user home) and does **no** download,
  install, start or stop on load.
* ``Plugin.get_status`` returns ``Manager.status()`` merged with the bridge's own
  current-job busy/error state, so progress stays visible while a mutation runs.
* Async mutation RPCs (``install_core``, ``start_core``, ``stop_core``,
  ``set_autostart``, ``uninstall_core``, ``reset_binding``) run exactly one
  background ``asyncio.to_thread`` job and return ``{"accepted": True}``; a
  second overlapping mutation returns ``{"accepted": False, "error": ...}`` and
  does *not* queue another job.
* ``check_updates`` is a pure off-thread delegate with no install side effects.
* ``_unload`` waits for an owned pending job and never stops an installed core;
  ``_uninstall`` delegates ``Manager.uninstall(reset_binding=False)`` off-thread.

The real ``decky`` module and ``Manager`` are replaced by a fake module and a
small :class:`FakeManager`; nothing here touches the network, systemd, or a real
device. Blocking is simulated with a ``threading.Event`` and every wait is
bounded and released in a ``finally``.

Run with:
    PYTHONPATH=py_modules python3 -m unittest discover -s tests -v
"""

import asyncio
import importlib.util
import logging
import shutil
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAIN_PATH = PROJECT_ROOT / "main.py"
PY_MODULES = PROJECT_ROOT / "py_modules"

# The real Manager/py_modules are on PYTHONPATH in normal runs; be explicit so
# this module also imports cleanly when discovered from elsewhere.
if str(PY_MODULES) not in sys.path:
    sys.path.insert(0, str(PY_MODULES))

_DECKY_DIRS = (
    "DECKY_PLUGIN_RUNTIME_DIR",
    "DECKY_PLUGIN_SETTINGS_DIR",
    "DECKY_PLUGIN_LOG_DIR",
    "DECKY_PLUGIN_DIR",
)


def make_fake_decky(tmp):
    """A minimal stand-in for the ``decky`` module and its constants/logger."""
    decky = types.ModuleType("decky")
    decky.logger = logging.getLogger("decky.fake")
    for name in _DECKY_DIRS:
        path = tmp / name.lower().replace("decky_", "")
        path.mkdir(parents=True, exist_ok=True)
        setattr(decky, name, str(path))

    home = tmp / "home" / "deck"
    home.mkdir(parents=True, exist_ok=True)
    decky.DECKY_USER_HOME = str(home)
    decky.HOME = str(home)
    decky.DECKY_HOME = str(tmp / "homebrew")
    decky.USER = "deck"
    decky.DECKY_USER = "deck"
    decky.DECKY_VERSION = "v2.5.0"
    decky.DECKY_PLUGIN_NAME = "UU加速器"
    decky.__version__ = "1.0.0"

    async def emit(*args, **kwargs):  # pragma: no cover - placeholder
        return None

    decky.emit = emit
    return decky


def load_bridge():
    """Import the project-root ``main.py``, or fail loudly if it is absent."""
    if not MAIN_PATH.is_file():
        raise FileNotFoundError("missing project-root main.py at {}".format(MAIN_PATH))
    spec = importlib.util.spec_from_file_location("uu_accelerator_main", MAIN_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["uu_accelerator_main"] = module
    spec.loader.exec_module(module)
    return module


class FakeManager:
    """Records calls and blocks/fails on demand; no side effects on the host."""

    instances = []

    def __init__(self, *args, **kwargs):
        self.init_args = args
        self.init_kwargs = kwargs
        self.calls = []
        self.uninstall_calls = []
        # Test hooks: block ``install`` on this event; raise this exception.
        self.install_gate = None
        self.fail_install = None
        self.busy = False
        self.phase = "idle"
        self.progress = 0
        self.error = None
        FakeManager.instances.append(self)

    # -- recorders -------------------------------------------------------
    def _record(self, name, *args):
        self.calls.append((name, args))

    def install(self, engine="auto"):
        self._record("install", engine)
        self.busy = True
        self.phase = "installing"
        try:
            if self.install_gate is not None:
                self.install_gate.wait(10.0)
            if self.fail_install is not None:
                raise self.fail_install
            self.phase = "complete"
            self.progress = 100
            self.error = None
        except BaseException as exc:
            self.error = str(exc) or exc.__class__.__name__
            self.phase = "error"
            raise
        finally:
            self.busy = False

    def start(self):
        self._record("start")
        self.phase = "complete"

    def stop(self):
        self._record("stop")
        self.phase = "idle"

    def set_autostart(self, enabled):
        self._record("set_autostart", bool(enabled))

    def reset_binding(self):
        self._record("reset_binding")

    def uninstall(self, reset_binding=False):
        self._record("uninstall", bool(reset_binding))
        self.uninstall_calls.append(bool(reset_binding))

    def check_updates(self):
        self._record("check_updates")
        return {"update_available": False, "version": None, "md5": "", "engine": "fex"}

    def status(self):
        return {
            "installed": True,
            "running": True,
            "core_running": True,
            "busy": self.busy,
            "phase": self.phase,
            "progress": self.progress,
            "error": self.error,
            "version": "14.9.4",
            "engine": "fex",
            "engines": ["fex"],
            "autostart": False,
            "platform": {"arch": "aarch64", "fex_path": "/usr/bin/FEXInterpreter"},
            "binding": {"qr_text": "", "available": False},
        }


class BridgeTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        if not MAIN_PATH.is_file():
            self.fail("missing project-root main.py at {}".format(MAIN_PATH))
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(self.tmp), ignore_errors=True)

        self.decky = make_fake_decky(self.tmp)
        self._saved_decky = sys.modules.get("decky")
        sys.modules["decky"] = self.decky
        self.addCleanup(self._restore_decky)

        FakeManager.instances = []
        self.module = load_bridge()

    def _restore_decky(self):
        if self._saved_decky is None:
            sys.modules.pop("decky", None)
        else:
            sys.modules["decky"] = self._saved_decky

    # -- helpers ---------------------------------------------------------
    async def load_plugin(self):
        """Instantiate the bridge with a FakeManager and run ``_main``."""
        with mock.patch.object(self.module, "Manager", FakeManager):
            plugin = self.module.Plugin()
            await plugin._main()
        return plugin, FakeManager.instances[-1]

    @staticmethod
    def names(manager):
        return [name for name, _args in manager.calls]

    async def wait_status(self, plugin, predicate, timeout=5.0):
        """Bounded poll of ``get_status`` until ``predicate`` holds."""
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = await plugin.get_status()
            if predicate(last):
                return last
            await asyncio.sleep(0.02)
        return last

    # -- tests -----------------------------------------------------------
    async def test_load_initializes_manager_without_installing(self):
        plugin, manager = await self.load_plugin()

        provided = {str(value) for value in
                    list(manager.init_args) + list(manager.init_kwargs.values())}
        for expected in (
            self.decky.DECKY_PLUGIN_RUNTIME_DIR,
            self.decky.DECKY_PLUGIN_SETTINGS_DIR,
            self.decky.DECKY_PLUGIN_LOG_DIR,
            self.decky.DECKY_PLUGIN_DIR,
            self.decky.DECKY_USER_HOME,
        ):
            self.assertIn(str(expected), provided)

        # loading must never download, install, start or stop anything
        self.assertEqual(self.names(manager), [])

        # check_updates is a pure delegate and leaves no install side effects
        result = await asyncio.wait_for(plugin.check_updates(), timeout=2.0)
        self.assertIn("update_available", result)
        self.assertIn("check_updates", self.names(manager))
        self.assertNotIn("install", self.names(manager))
        self.assertNotIn("stop", self.names(manager))

    async def test_overlapping_mutation_is_refused_while_job_busy(self):
        plugin, manager = await self.load_plugin()
        gate = threading.Event()
        manager.install_gate = gate
        try:
            first = await asyncio.wait_for(plugin.install_core(), timeout=2.0)
            self.assertTrue(first.get("accepted"))

            # the worker is blocked, but status must still answer immediately
            status = await asyncio.wait_for(plugin.get_status(), timeout=2.0)
            self.assertTrue(status["busy"])

            # a second mutation is refused, not queued
            second = await asyncio.wait_for(plugin.stop_core(), timeout=2.0)
            self.assertFalse(second.get("accepted"))
            self.assertTrue(second.get("error"))
            self.assertNotIn("stop", self.names(manager))
        finally:
            gate.set()

        final = await self.wait_status(plugin, lambda s: not s["busy"])
        self.assertFalse(final["busy"])
        self.assertIn("install", self.names(manager))

    async def test_worker_failure_surfaces_in_status(self):
        plugin, manager = await self.load_plugin()
        manager.fail_install = RuntimeError("simulated download failure")

        accepted = await asyncio.wait_for(plugin.install_core(), timeout=2.0)
        self.assertTrue(accepted.get("accepted"))

        status = await self.wait_status(plugin, lambda s: not s["busy"])
        self.assertFalse(status["busy"])
        self.assertTrue(status["error"])
        self.assertIn("simulated download failure", status["error"])
        self.assertEqual(status["phase"], "error")

    async def test_unload_waits_and_uninstall_delegates(self):
        plugin, manager = await self.load_plugin()
        gate = threading.Event()
        manager.install_gate = gate
        released = threading.Event()

        def release():
            time.sleep(0.1)
            released.set()
            gate.set()

        releaser = threading.Thread(target=release, daemon=True)
        releaser.start()
        try:
            accepted = await asyncio.wait_for(plugin.install_core(), timeout=2.0)
            self.assertTrue(accepted.get("accepted"))
            # _unload must block until the owned job finishes, never stop it
            await asyncio.wait_for(plugin._unload(), timeout=5.0)
            self.assertTrue(released.is_set())
        finally:
            gate.set()

        self.assertNotIn("stop", self.names(manager))
        self.assertTrue((await plugin.get_status())["running"])

        await asyncio.wait_for(plugin._uninstall(), timeout=5.0)
        self.assertEqual(manager.uninstall_calls, [False])

    async def test_busy_status_prefers_live_manager_phase(self):
        """While a job runs, get_status keeps the manager's live phase/progress.

        A generic ``running`` phase would hide real progress, and a stale error
        from an earlier job must not leak into the middle of the current one.
        """
        plugin, manager = await self.load_plugin()
        gate = threading.Event()
        manager.install_gate = gate
        try:
            accepted = await asyncio.wait_for(plugin.install_core(), timeout=2.0)
            self.assertTrue(accepted.get("accepted"))

            # The blocked job's manager reports real download progress.
            manager.phase = "downloading"
            manager.progress = 37
            manager.error = "stale failure from a previous job"

            status = await asyncio.wait_for(plugin.get_status(), timeout=2.0)
            self.assertTrue(status["busy"])
            self.assertEqual(status["phase"], "downloading")
            self.assertEqual(status["progress"], 37)
            self.assertIsNone(status["error"])  # stale error cleared while busy
            self.assertTrue(status["running"])  # unrelated fields preserved
        finally:
            gate.set()

        # Drain the owned job so no task outlives the test.
        final = await self.wait_status(plugin, lambda s: not s["busy"])
        self.assertFalse(final["busy"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
