"""Installation manager for the UU accelerator plugin.

This module owns the whole install lifecycle: detecting the host, refusing to
take over a legacy install, fetching official metadata, downloading and
verifying a package, extracting it into a task-owned release directory,
switching the live ``run/`` symlinks and unit, starting/stopping the plugin's
*own* systemd unit, and rolling back cleanly when anything fails.

Design rules baked in here (all pinned by ``tests/test_manager.py``):

* Real integration boundaries (``systemctl``, platform probing, metadata
  fetch, archive download) are plain, injectable function hooks so tests never
  touch the network or ``/etc/systemd``.
* Extraction/download happen into fresh candidates *before* the running
  installation is disturbed; a failed download or bad package leaves the old
  service completely untouched.
* Persistence: the installed identity lives in ``settings_dir/identity`` and
  the machine-readable install record in ``runtime_dir/install.json``.
* Operations serialize behind one lock plus a ``busy`` flag; :meth:`status`
  never takes the lock so progress stays readable while work runs.

The manager is synchronous; Decky calls it off-thread. It never creates a
long-lived process or server of its own.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import uuid
from pathlib import Path

from . import payload
from .binding import terminal_qr_svg
from .platform import detect_platform, select_engine
from .service import OWNERSHIP_MARKER, UNIT_NAME, build_unit

__all__ = ["Manager"]

PHASES = (
    "idle",
    "detecting",
    "metadata",
    "downloading",
    "verifying",
    "installing",
    "starting",
    "complete",
    "error",
)

_MANIFEST_NAME = "install.json"
_LAUNCH_NAME = "launch.json"
_SUPERVISOR_NAME = "supervisor.py"
_SUPERVISOR_SOURCE = "supervisor.py"
_STATE_NAME = "state.json"
_IDENTITY_DIR = "identity"
_IDENTITY_NAME = ".uuplugin_uuid"
_QRCODE_NAME = ".steam_deck_sn_qrcode"
_CORE_PID_NAME = "core.pid"
# Owned diagnosis file the supervisor writes beside its PID file when it refuses
# the kernel-compat preflight; it is cleared before every ``systemctl start``.
STARTUP_ERROR_NAME = "startup-error.txt"

# The bundled xt_cgroup kernel module release dir, always wired into the sole
# supported (FEX) launch route.
_KERNEL_COMPAT_DIR = "armada-7.2.6"

# Payload members exposed from ``run/`` as relative symlinks onto the current
# release; the network helper is optional and skipped when absent.
_PAYLOAD_LINKS = ("uuplugin", "xuplugin-guardian", "uu.conf", "xtables-nft-multi")

_ANSI_RE = re.compile(
    r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-Z\\-_])"
)

# Must exceed the unit's own TimeoutStopSec (45s) so a legitimate graceful stop
# is never cut short (and reported as a spurious failure) by our own subprocess.
_SYSTEMCTL_TIMEOUT = 60


def _run_systemctl(argv):
    """Default command hook: a bounded, shell-free ``systemctl`` invocation."""
    return subprocess.run(
        list(argv), capture_output=True, text=True, timeout=_SYSTEMCTL_TIMEOUT
    )


class Manager:
    """Install/start/stop/uninstall manager for the plugin's own unit."""

    def __init__(
        self,
        runtime_dir,
        settings_dir,
        logs_dir,
        plugin_dir,
        *,
        system_dir=None,
        home=None,
        root=None,
        command_runner=None,
        platform_provider=None,
        metadata_fetcher=None,
        archive_downloader=None,
    ):
        self.runtime_dir = Path(runtime_dir)
        self.settings_dir = Path(settings_dir)
        self.logs_dir = Path(logs_dir)
        self.plugin_dir = Path(plugin_dir)

        self.system_dir = (
            Path(system_dir) if system_dir is not None else Path("/etc/systemd/system")
        )
        self.home = home
        self.root = root if root is not None else "/"

        self._command_runner = command_runner or _run_systemctl
        self._platform_provider = platform_provider or (
            lambda *args, **kwargs: detect_platform(self.root, self.home)
        )
        self._metadata_fetcher = metadata_fetcher or payload.fetch_metadata
        self._archive_downloader = archive_downloader or payload.download_archive

        # One lock serializes operations; the busy flag is readable without it.
        self._lock = threading.RLock()
        self._busy = False
        self._phase = "idle"
        self._progress = 0
        self._error = None

    # -- paths -----------------------------------------------------------
    @property
    def unit_path(self):
        return self.system_dir / UNIT_NAME

    @property
    def run_dir(self):
        return self.runtime_dir / "run"

    @property
    def payload_dir(self):
        return self.runtime_dir / "payload"

    @property
    def downloads_dir(self):
        return self.runtime_dir / "downloads"

    @property
    def current_link(self):
        return self.runtime_dir / "current"

    @property
    def manifest_path(self):
        return self.runtime_dir / _MANIFEST_NAME

    @property
    def launch_path(self):
        return self.runtime_dir / _LAUNCH_NAME

    @property
    def supervisor_path(self):
        return self.runtime_dir / _SUPERVISOR_NAME

    @property
    def identity_path(self):
        return self.settings_dir / _IDENTITY_DIR / _IDENTITY_NAME

    @property
    def state_path(self):
        return self.settings_dir / _STATE_NAME

    # -- public API ------------------------------------------------------
    def install(self, engine="auto"):
        """Install (or upgrade to) the selected engine; returns the manifest."""
        with self._lock:
            self._busy = True
            self._error = None
            try:
                result = self._do_install(engine)
            except BaseException as exc:
                self._error = str(exc) or exc.__class__.__name__
                self._phase = "error"
                raise
            finally:
                self._busy = False
            self._progress = 100
            self._phase = "complete"
            return result

    def check_updates(self):
        """Compare the installed route's MD5 with official metadata only."""
        manifest = self._read_manifest()
        # Always resolve the sole FEX route, so an old native/x86 install can
        # still check the FEX package for an update.
        choice = select_engine(self._platform(), "auto")
        metadata = self._metadata_fetcher(choice["package_type"])
        md5 = str(metadata.get("md5") or "").lower()
        if manifest is None:
            update_available = False
        else:
            installed_md5 = str(manifest.get("md5") or "").lower()
            engine_changed = manifest.get("engine") != "fex"
            update_available = engine_changed or md5 != installed_md5
        return {
            "update_available": update_available,
            "version": metadata.get("version"),
            "md5": md5,
            "engine": choice["engine"],
        }

    def start(self):
        with self._lock:
            self._assert_own_unit()
            manifest = self._read_manifest()
            if manifest is None:
                raise ValueError("UU 加速器尚未安装，无法启动")
            # Refresh the runtime adapter from the installed plugin before the
            # unit starts, so a plugin upgrade takes effect without a download
            # or a stop/reset. The engine comes from the recorded manifest.
            choice = select_engine(self._platform(), manifest["engine"])
            self._write_supervisor()
            self._write_launch(choice)
            # Refresh the installed unit too, so a plugin-managed unit from an
            # older release (e.g. a shorter TimeoutStartSec) is upgraded before
            # the service starts -- without a download or a stop/restart.
            self._write_unit(build_unit(self.run_dir, self.supervisor_path, self.launch_path))
            self._systemctl("daemon-reload")
            if not self._start_unit():
                raise RuntimeError("UU 加速器服务启动失败")
            self._phase = "complete"
            self._error = None

    def stop(self):
        with self._lock:
            self._assert_own_unit()
            self._stop_unit()
            self._phase = "idle"
            self._error = None

    def set_autostart(self, enabled):
        enabled = bool(enabled)
        with self._lock:
            self._assert_own_unit()
            manifest = self._read_manifest()
            if manifest is None:
                raise ValueError("UU 加速器尚未安装，无法设置自启动")
            if enabled:
                # Enabling requires a currently supported engine+platform;
                # disabling stays permitted for old unsupported installs.
                select_engine(self._platform(), manifest["engine"])
            # Only persist the new intent once systemd accepted the change; a
            # rejected/foreign unit must not leave a half-applied setting.
            self._systemctl("enable" if enabled else "disable")
            self._write_state({"autostart": enabled})
            self._error = None

    def uninstall(self, reset_binding=False):
        with self._lock:
            self._assert_own_unit()
            if self.unit_path.is_file():
                # A unit we own is present: stop and disable it (checked, so a
                # real failure surfaces) before the file is unlinked.
                self._stop_unit()
                self._systemctl("disable")
                self._unlink_required(self.unit_path)
                self._systemctl("daemon-reload")
            else:
                # Never installed, or already torn down: a missing unit with no
                # active/enabled state is normal, so those verbs are skipped
                # rather than reported as failures (only possible live state is
                # touched). Owned partial runtime is still cleared below.
                if self._is_active():
                    self._stop_unit()
                if self._is_enabled():
                    self._systemctl("disable")
            self._remove_runtime_artifacts()
            if reset_binding:
                self._remove_file(self.identity_path)
            self._phase = "idle"
            self._progress = 0
            self._error = None

    def reset_binding(self):
        """Renew the binding identity for the installed core, restarting it.

        Only ``settings/identity/.uuplugin_uuid`` and the owned QR marker change;
        the payload, manifest, unit and unrelated settings are untouched, and the
        running core is restarted rather than left down.
        """
        with self._lock:
            self._assert_own_unit()
            manifest = self._read_manifest()
            if manifest is None:
                raise ValueError("UU 加速器尚未安装，无法重置绑定")
            # Reject remounted native/x86 before stopping or touching UUID/QR.
            select_engine(self._platform(), manifest["engine"])
            was_active = self._is_active()
            old_identity = self._read_identity()
            if was_active:
                # A failed stop must raise before the old identity is replaced.
                self._stop_unit()
            try:
                self._write_identity(str(uuid.uuid4()))
                self._clear_qr_marker()
                if was_active:
                    if not self._start_unit():
                        raise RuntimeError("重置绑定后服务启动失败")
                    if not self._is_active():
                        raise RuntimeError("重置绑定后服务未处于运行状态")
            except BaseException as exc:
                try:
                    self._restore_identity(old_identity)
                    if was_active and not self._is_active():
                        self._start_unit()
                except BaseException as rollback_exc:
                    raise RuntimeError(
                        "重置绑定失败: {}；恢复身份失败: {}".format(exc, rollback_exc)
                    ) from exc
                raise
            self._error = None
            self._phase = "complete"

    def status(self):
        try:
            platform = self._platform()
        except Exception:
            platform = {}
        manifest = self._read_manifest()
        return {
            "installed": manifest is not None,
            "running": self._is_active(),
            "core_running": self._core_running(),
            "busy": self._busy,
            "phase": self._phase,
            "progress": self._progress,
            "error": self._error,
            "version": manifest.get("version") if manifest else None,
            "engine": manifest.get("engine") if manifest else None,
            "engines": list(platform.get("engines") or []),
            "autostart": bool(self._read_state().get("autostart")),
            "platform": platform,
            "binding": self._binding_state(),
        }

    # -- install internals ----------------------------------------------
    def _do_install(self, engine):
        self._update("detecting", 5)
        platform = self._platform()
        choice = select_engine(platform, engine)  # refuses legacy on every route
        self._assert_own_unit()  # refuses a conflicting unit we do not own
        manifest = self._read_manifest()

        self._update("metadata", 10)
        metadata = self._metadata_fetcher(choice["package_type"])
        md5 = str(metadata.get("md5") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{32}", md5):
            raise ValueError("下载元数据校验值无效")

        if (
            manifest is not None
            and manifest.get("engine") == choice["engine"]
            and str(manifest.get("md5") or "").lower() == md5
        ):
            # Identical engine + MD5: no download and no restart, but refresh
            # the copied runtime adapter so a plugin upgrade actually takes
            # effect instead of retaining the old supervisor/launch.
            self._write_supervisor()
            self._write_launch(choice)
            # The copied runtime adapter is not the only artifact that can be
            # stale: upgrade the owned unit in place as well, so an older unit
            # (e.g. a shorter TimeoutStartSec) takes effect. No download and no
            # stop/restart happen here, so an active acceleration is untouched.
            self._write_unit(build_unit(self.run_dir, self.supervisor_path, self.launch_path))
            self._systemctl("daemon-reload")
            return manifest

        release, version = self._prepare_release(choice, metadata, md5)
        was_active = self._is_active()
        was_enabled = self._is_enabled()
        if was_active:
            # Stop the old unit *before* entering the candidate switch: an
            # unsuccessful stop leaves the old unit/manifest/current payload
            # untouched, with no implicit second stop/restart in rollback.
            self._stop_unit()
        self._switch_and_start(
            choice, version, md5, release, manifest, was_active, was_enabled
        )
        return self._read_manifest()

    def _prepare_release(self, choice, metadata, md5):
        """Download/verify/extract into a private candidate; return (dir, ver)."""
        key = "{}-{}".format(choice["engine"], md5)
        final = self.payload_dir / key
        if final.is_dir():
            # The cached candidate's version comes from its own uu.conf; the
            # metadata hint is often None and must never be recorded.
            return final, payload.read_release_version(final)

        staging = self.payload_dir / (key + ".tmp")
        self._remove_tree(staging)

        self._update("downloading", 15)
        archive = self.downloads_dir / (key + ".tar.gz")
        archive.parent.mkdir(parents=True, exist_ok=True)
        self._archive_downloader(
            metadata, archive, progress=self._download_progress()
        )

        self._update("verifying", 70)
        actual = self._file_md5(archive)
        if actual != md5:
            raise ValueError(
                "安装包 MD5 校验失败: 期望 {}，实际 {}".format(md5, actual)
            )

        self._update("installing", 80)
        try:
            outcome = payload.extract_payload(
                archive, staging, expected_arch=choice["expected_arch"]
            )
            if final.exists():
                self._remove_tree(final)
            os.replace(str(staging), str(final))
        except BaseException:
            self._remove_tree(staging)
            raise
        return final, outcome.get("version")

    def _switch_and_start(self, choice, version, md5, release, manifest,
                          was_active, was_enabled):
        """Flip the live state to a ready candidate, with rollback on failure."""
        snapshot = self._snapshot(manifest)
        first_install = manifest is None

        try:
            self._update("starting", 88)
            self._activate_release(choice, release)
            if first_install or was_active:
                if not self._start_unit():
                    raise RuntimeError("UU 加速器服务启动失败")
                if not self._is_active():
                    raise RuntimeError("UU 加速器服务未处于运行状态")
            if self._read_state().get("autostart"):
                # Honor the persisted autostart intent, not a one-off checkbox.
                self._systemctl("enable")
            self._write_manifest(
                self._make_manifest(choice, version, md5, release)
            )
        except BaseException as exc:
            try:
                self._rollback(snapshot, was_active, was_enabled)
            except BaseException as rollback_exc:
                raise RuntimeError(
                    "{}；回滚失败: {}".format(exc, rollback_exc)
                ) from exc
            raise

    def _activate_release(self, choice, release):
        self._ensure_identity()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._link_release(release)
        self._replace_symlink(self.current_link, release)
        self._write_supervisor()
        self._write_launch(choice)
        self._write_unit(build_unit(self.run_dir, self.supervisor_path, self.launch_path))
        # Publish the fresh unit before any start.
        self._systemctl("daemon-reload")

    def _rollback(self, snapshot, was_active, was_enabled):
        """Restore the previous owned state, verifying each step or failing loud.

        The first-install baseline legitimately has no unit, release or
        manifest: the rollback then removes only what this attempt created and
        never touches the shared payload/download cache, the binding identity or
        unrelated settings.
        """
        legacy = snapshot.get("engine") not in (None, "fex")
        candidate_unit = self.unit_path.is_file()
        # Stop the candidate only when a unit exists or is actually live; a
        # pre-unit failure must never stop a unit that was never written.
        if candidate_unit or self._is_active():
            self._stop_unit()

        if snapshot["unit_text"] is not None:
            # A previous owned unit existed: restore it and its enabled state.
            self._write_unit_text(snapshot["unit_text"])
            self._systemctl("daemon-reload")
            self._systemctl("enable" if was_enabled and not legacy else "disable")
        elif candidate_unit:
            # First install: disable the candidate while its file still exists
            # (a missing unit cannot be disabled), then drop it.
            self._systemctl("disable")
            self._remove_file(self.unit_path)
            self._systemctl("daemon-reload")

        for name, content in (
            (_LAUNCH_NAME, snapshot["launch"]),
            (_SUPERVISOR_NAME, snapshot["supervisor"]),
            (_MANIFEST_NAME, snapshot["manifest_bytes"]),
        ):
            path = self.runtime_dir / name
            if content is not None:
                self._write_bytes(path, content)
            else:
                self._remove_file(path)

        if snapshot["release"] is not None:
            self._link_release(snapshot["release"])
            self._replace_symlink(self.current_link, snapshot["release"])
        else:
            # No prior release: remove only the run dir/current link this
            # attempt created; keep the payload/download cache and identity.
            self._unlink_required(self.current_link)
            self._remove_tree_required(self.run_dir)

        legacy = snapshot.get("engine") not in (None, "fex")
        if legacy:
            # Restored a removed native/x86 install: leave it stopped and
            # disabled, with autostart cleared, so it is never re-enabled.
            self._systemctl("disable")
            self._write_state({"autostart": False})
        elif was_active:
            if not self._start_unit():
                raise RuntimeError("回滚后服务启动失败")
            if not self._is_active():
                raise RuntimeError("回滚后服务未处于运行状态")

    def _snapshot(self, manifest):
        unit_text = None
        if self.unit_path.is_file():
            unit_text = self.unit_path.read_text(encoding="utf-8", errors="replace")
        return {
            "engine": manifest.get("engine") if manifest else None,
            "unit_text": unit_text,
            "manifest_bytes": self._read_bytes(self.manifest_path),
            "release": self._release_from_manifest(manifest),
            "launch": self._read_bytes(self.launch_path),
            "supervisor": self._read_bytes(self.supervisor_path),
        }

    def _make_manifest(self, choice, version, md5, release):
        return {
            "engine": choice["engine"],
            "version": version,
            "md5": md5,
            "package_type": choice["package_type"],
            "expected_arch": choice["expected_arch"],
            "release": str(release),
        }

    # -- live-state helpers ---------------------------------------------
    def _ensure_identity(self):
        path = self.identity_path
        if not path.exists():
            self._write_identity(str(uuid.uuid4()))
        return path

    def _read_identity(self):
        try:
            return self.identity_path.read_text(encoding="utf-8")
        except OSError:
            return None

    def _write_identity(self, value):
        # Written in place so the existing ``run/.uuplugin_uuid`` symlink keeps
        # pointing at the same identity path.
        self.identity_path.parent.mkdir(parents=True, exist_ok=True)
        self.identity_path.write_text(value, encoding="utf-8")

    def _restore_identity(self, value):
        if value is None:
            self._remove_file(self.identity_path)
        else:
            self._write_identity(value)

    def _clear_qr_marker(self):
        # The marker can live beside the release executable (the real core's
        # location) and/or in the legacy run/ aliases; clear both. A missing or
        # broken symlink is tolerated (existing semantics).
        self._remove_file(self.run_dir / _QRCODE_NAME)
        self._remove_file(self.current_link / _QRCODE_NAME)

    def _link_release(self, release):
        release = Path(release)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        for name in _PAYLOAD_LINKS:
            source = release / name
            link = self.run_dir / name
            if source.exists():
                self._replace_symlink(link, source)
            else:
                # The new release lacks this (optional) member: drop any stale
                # run symlink we own, never an unrelated file.
                self._remove_owned_link(link)
        self._replace_symlink(self.run_dir / _IDENTITY_NAME, self.identity_path)

    def _remove_owned_link(self, link):
        """Remove ``link`` only when it is a symlink pointing into our payload."""
        link = Path(link)
        if not link.is_symlink():
            return
        try:
            target = Path(os.readlink(link))
        except OSError:
            return
        if not target.is_absolute():
            target = link.parent / target
        try:
            resolved = target.resolve()
            base = self.payload_dir.resolve()
        except OSError:
            return
        if resolved == base or base in resolved.parents:
            self._remove_file(link)

    def _write_supervisor(self):
        source = self.plugin_dir / _SUPERVISOR_SOURCE
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(source), str(self.supervisor_path))

    def _write_launch(self, choice):
        launch = {
            "engine": choice["engine"],
            "launch_prefix": list(choice.get("launch_prefix") or []),
            "executable": str(self.run_dir / "uuplugin"),
            "config_path": str(self.run_dir / "uu.conf"),
            "cwd": str(self.run_dir),
            "pid_file": str(self.run_dir / _CORE_PID_NAME),
            "log_file": str(self.logs_dir / "core.log"),
        }
        # The sole supported FEX route always needs the bundled cgroup module.
        launch["kernel_compat"] = str(
            self.plugin_dir / "compat" / _KERNEL_COMPAT_DIR
        )
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self._write_json(self.launch_path, launch)

    def _write_unit(self, text):
        self.unit_path.parent.mkdir(parents=True, exist_ok=True)
        self.unit_path.write_text(text, encoding="utf-8")

    def _write_unit_text(self, text):
        self._write_unit(text)

    def _write_manifest(self, manifest):
        self._write_json(self.manifest_path, manifest)

    def _binding_state(self):
        """Report the binding QR read from the *live* release's marker.

        The real core writes ``.steam_deck_sn_qrcode`` beside the payload it was
        launched from, i.e. inside the ``current`` release, not in ``run/``. We
        therefore prefer ``current/.steam_deck_sn_qrcode`` and only fall back to
        the legacy ``run/`` copy when the release-side marker is absent or
        unreadable. ANSI escapes are stripped and the cleaned text is rendered
        to SVG; ``available`` is true only when a non-empty SVG was produced.
        We never invent a ``bound``/``accelerated`` verdict from this text.
        """
        text = self._read_qr_text(self.current_link / _QRCODE_NAME)
        if text is None:
            text = self._read_qr_text(self.run_dir / _QRCODE_NAME)
        if text is None:
            return {"qr_text": "", "qr_svg": "", "available": False}
        cleaned = _ANSI_RE.sub("", text)
        svg = terminal_qr_svg(cleaned)
        return {"qr_text": cleaned, "qr_svg": svg, "available": bool(svg)}

    @staticmethod
    def _read_qr_text(path):
        try:
            return Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None

    def _core_running(self):
        """Whether the core PID recorded in our own ``run/core.pid`` is alive.

        This is *not* the systemd unit state: the core can die while the unit
        is still considered active, and vice versa. We never invent a
        ``bound``/``accelerated`` status from it.
        """
        try:
            pid = int((self.run_dir / _CORE_PID_NAME).read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return False
        if pid <= 0:
            return False
        if (Path("/proc") / str(pid)).exists():
            return True
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    # -- systemctl -------------------------------------------------------
    def _systemctl(self, verb, check=True):
        argv = ["systemctl", verb]
        if verb != "daemon-reload":
            argv.append(UNIT_NAME)
        result = self._command_runner(argv)
        code = getattr(result, "returncode", 1)
        if check and code != 0:
            raise RuntimeError("systemctl {} 失败 (退出码 {})".format(verb, code))
        return result

    def _is_active(self):
        return getattr(self._systemctl("is-active", check=False), "returncode", 1) == 0

    def _is_enabled(self):
        return getattr(self._systemctl("is-enabled", check=False), "returncode", 1) == 0

    def _start_unit(self):
        """Start the owned unit, surfacing a fresh supervisor diagnosis.

        The supervisor writes ``run/startup-error.txt`` only while refusing a
        kernel-compat preflight. That file is therefore cleared immediately
        before every ``start`` (a leftover from an earlier attempt must never be
        reported as this start's reason) and read afterwards only when this
        start failed; an empty or absent file keeps the previous generic
        failure result. No journal or global log is consulted.
        """
        diagnostic = self.run_dir / STARTUP_ERROR_NAME
        self._remove_file(diagnostic)
        if getattr(self._systemctl("start", check=False), "returncode", 1) == 0:
            return True
        reason = self._read_startup_error(diagnostic)
        if reason:
            raise RuntimeError("网络组件准备失败：" + reason)
        return False

    @staticmethod
    def _read_startup_error(path):
        """Return the diagnosis text written by this start, or ``None``."""
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        return text.strip() or None

    def _stop_unit(self):
        """Stop the owned unit, confirming it actually stopped; never silent."""
        self._systemctl("stop")
        if self._is_active():
            raise RuntimeError("UU 加速器服务未能停止")

    # -- guards ----------------------------------------------------------
    def _assert_own_unit(self):
        if self.unit_path.is_file():
            text = self.unit_path.read_text(encoding="utf-8", errors="replace")
            if OWNERSHIP_MARKER not in text:
                raise ValueError(
                    "检测到不属于本插件的同名服务单元，已拒绝操作"
                )

    # -- state -----------------------------------------------------------
    def _platform(self):
        return self._platform_provider()

    def _update(self, phase, progress=None):
        self._phase = phase
        if progress is not None:
            self._progress = max(0, min(100, int(progress)))

    def _download_progress(self):
        def report(done, total):
            if total:
                self._update("downloading", 15 + int(55 * done / total))
            else:
                self._update("downloading", 35)

        return report

    def _read_state(self):
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write_state(self, update):
        state = self._read_state()
        state.update(update)
        self.settings_dir.mkdir(parents=True, exist_ok=True)
        self._write_json(self.state_path, state)

    def _read_manifest(self):
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _release_from_manifest(self, manifest):
        if not manifest:
            return None
        raw = manifest.get("release")
        return Path(raw) if raw else None

    def _remove_runtime_artifacts(self):
        # Own required data: an absent file is harmless, but a real deletion
        # failure must surface instead of masquerading as a clean uninstall.
        self._remove_tree_required(self.run_dir)
        self._unlink_required(self.current_link)
        self._remove_tree_required(self.payload_dir)
        self._remove_tree_required(self.downloads_dir)
        self._unlink_required(self.manifest_path)
        self._unlink_required(self.runtime_dir / _LAUNCH_NAME)
        self._unlink_required(self.runtime_dir / _SUPERVISOR_NAME)

    # -- filesystem ------------------------------------------------------
    def _replace_symlink(self, link, target):
        link = Path(link)
        if link.is_symlink() or link.exists():
            if link.is_dir() and not link.is_symlink():
                shutil.rmtree(link, ignore_errors=True)
            else:
                try:
                    link.unlink()
                except OSError:
                    pass
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(str(target))

    def _read_bytes(self, path):
        try:
            return Path(path).read_bytes()
        except OSError:
            return None

    def _write_bytes(self, path, data):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def _write_json(self, path, data):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(str(tmp), str(path))

    def _file_md5(self, path):
        digest = hashlib.md5()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(64 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _remove_file(self, path):
        try:
            os.unlink(path)
        except OSError:
            pass

    def _unlink_required(self, path):
        """Unlink own data; a missing file is fine, any other failure surfaces."""
        try:
            os.unlink(path)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise RuntimeError("删除失败: {}: {}".format(path, exc))

    def _remove_tree_required(self, path):
        """Remove an owned file/tree/symlink; absent is fine, failure surfaces."""
        path = Path(path)
        try:
            if path.is_symlink() or path.is_file():
                os.unlink(path)
            elif path.exists():
                shutil.rmtree(path)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise RuntimeError("删除失败: {}: {}".format(path, exc))

    def _remove_tree(self, path):
        path = Path(path)
        try:
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.exists():
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass
