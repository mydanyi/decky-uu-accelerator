"""Decky RPC bridge for the UU加速器 plugin (project-root ``main.py``).

Decky loads this file and calls :meth:`Plugin._main`; the bridge owns exactly one
:class:`~uu_accelerator.manager.Manager` built from the Decky constants and does
**no** download, install, start or stop on load. Every mutating RPC runs in a
single background :func:`asyncio.to_thread` job and returns immediately; a second
overlapping mutation is refused rather than queued. :meth:`Plugin.get_status`
merges the live manager status with the bridge's own busy/phase/error state so
progress stays readable while a job runs, and a failed job stays visible as an
error instead of masquerading as a clean completion.

Standard library only; no servers, no framework, and no fake ``decky`` fallback.
"""

import asyncio
import logging
import sys
from pathlib import Path

import decky

# Decky normally publishes the unpacked package on ``sys.path``; keep the
# project-root bridge importable when it is loaded directly from this file.
_PY_MODULES = Path(__file__).resolve().parent / "py_modules"
if str(_PY_MODULES) not in sys.path:
    sys.path.insert(0, str(_PY_MODULES))

from uu_accelerator.manager import Manager  # noqa: E402  (path set above)

PLUGIN_NAME = "UU加速器"
_MUTATION_BUSY = "UU加速器正在执行其他操作，请稍候再试"
# Manager phases that carry no live progress; while a job runs, a real active
# manager phase (downloading/verifying/…) is preferred over a generic running.
_STALE_PHASES = frozenset(("idle", "complete", "error"))

_logger = getattr(decky, "logger", None) or logging.getLogger("uu_accelerator")


class Plugin:
    """Thin async façade over the synchronous :class:`Manager`.

    The manager is synchronous and never owns a long-lived process; the bridge
    only schedules that work off-thread and mirrors its progress for Decky.
    """

    def __init__(self):
        self._manager = None
        self._task = None
        self._busy = False
        self._job_error = None
        self._job_phase = None

    # -- lifecycle -------------------------------------------------------
    async def _main(self):
        _logger.info("%s: 初始化桥接", PLUGIN_NAME)
        self._manager = Manager(
            decky.DECKY_PLUGIN_RUNTIME_DIR,
            decky.DECKY_PLUGIN_SETTINGS_DIR,
            decky.DECKY_PLUGIN_LOG_DIR,
            decky.DECKY_PLUGIN_DIR,
            home=decky.DECKY_USER_HOME,
        )

    async def _unload(self):
        """Wait for the owned background job; never stop the installed core."""
        task = self._task
        if task is not None and not task.done():
            _logger.info("%s: 等待后台任务结束", PLUGIN_NAME)
            await task

    async def _uninstall(self):
        """Wait for pending work, then uninstall without touching the binding."""
        await self._unload()
        await asyncio.to_thread(self._manager.uninstall, reset_binding=False)

    # -- read-only RPCs --------------------------------------------------
    async def get_status(self):
        status = await asyncio.to_thread(self._manager.status)
        merged = dict(status)
        merged["busy"] = bool(self._busy or status.get("busy"))
        if self._busy:
            # While a job runs, prefer the manager's live phase (downloading,
            # verifying, …) so real progress stays visible; fall back to the
            # generic running phase only when the manager reports a stale one.
            live_phase = status.get("phase")
            if live_phase is None or live_phase in _STALE_PHASES:
                live_phase = "running"
            merged["phase"] = live_phase
            merged["error"] = None  # a previous failure must not leak mid-job
        elif self._job_phase is not None:
            # Job finished: surface its final phase/error until a new job starts.
            merged["phase"] = self._job_phase
            merged["error"] = self._job_error
        return merged

    async def check_updates(self):
        """Pure off-thread delegate: compares MD5s, installs nothing."""
        return await asyncio.to_thread(self._manager.check_updates)

    # -- mutating RPCs ---------------------------------------------------
    async def install_core(self, engine="auto"):
        return self._schedule(self._manager.install, engine)

    async def start_core(self):
        return self._schedule(self._manager.start)

    async def stop_core(self):
        return self._schedule(self._manager.stop)

    async def set_autostart(self, enabled):
        return self._schedule(self._manager.set_autostart, bool(enabled))

    async def uninstall_core(self, reset_binding=False):
        return self._schedule(self._manager.uninstall, bool(reset_binding))

    async def reset_binding(self):
        return self._schedule(self._manager.reset_binding)

    # -- job plumbing ----------------------------------------------------
    def _schedule(self, func, *args):
        """Start exactly one off-thread job, or refuse an overlapping mutation."""
        if self._busy:
            return {"accepted": False, "error": _MUTATION_BUSY}
        self._busy = True
        self._job_error = None
        self._job_phase = "running"
        self._task = asyncio.ensure_future(self._run_job(func, args))
        return {"accepted": True}

    async def _run_job(self, func, args):
        """Run ``func`` off-thread; record failures so get_status surfaces them."""
        try:
            await asyncio.to_thread(func, *args)
        except BaseException as exc:  # never turn a failure into clean completion
            self._job_error = str(exc) or exc.__class__.__name__
            self._job_phase = "error"
            _logger.error("%s: 后台操作失败: %s", PLUGIN_NAME, exc)
        else:
            self._job_error = None
            self._job_phase = "complete"
        finally:
            self._busy = False
            self._task = None
