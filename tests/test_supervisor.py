"""Contract tests for the standalone project-root supervisor.py.

supervisor.py does not exist yet, so this module is expected to be red. It
pins a small, dependency-free supervisor API:

* ``build_command(config) -> list[str]`` turns a launch config (the exact keys
  ``Manager._write_launch`` writes: engine, launch_prefix, executable,
  config_path, cwd, pid_file, log_file) into the argv used to spawn the core.
  The argv is passed to a shell-free exec, never string-concatenated.
* ``python supervisor.py launch.json`` runs as the long-lived wrapper: it
  records its own PID, streams the core's stdout/stderr into the configured
  log, forwards signals to its child, enforces ``shutdown_timeout`` and
  removes its PID file on exit.

Every core is a tiny executable Python fake created in a temp dir; nothing
here touches UU, the network, systemd or a real device.

Run with:
    PYTHONPATH=py_modules python3 -m unittest discover -s tests -v
"""

import importlib.util
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SUPERVISOR_PATH = PROJECT_ROOT / "supervisor.py"

CORE_SOURCE = '''\
import json, os, signal, subprocess, sys, time

cfg = json.loads(open(sys.argv[1], encoding="utf-8").read())
mode = cfg.get("mode", "exit0")
if cfg.get("pidfile"):
    with open(cfg["pidfile"], "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))

if mode == "exit5":
    print("core-out", flush=True)
    print("core-err", file=sys.stderr, flush=True)
    sys.exit(5)

if mode == "term":
    def _handler(signum, frame):
        print("term-marker", flush=True)
        sys.exit(0)
    signal.signal(signal.SIGTERM, _handler)
    print("ready", flush=True)
    while True:
        time.sleep(0.05)

if mode == "ignore":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    print("ready", flush=True)
    while True:
        time.sleep(0.05)

if mode == "guardian":
    # Start a tiny helper in the same process group, then exit immediately on
    # TERM (default disposition) while the helper outlives us and cleans up.
    helper_src = "\\n".join([
        "import os, sys, time",
        "parent = int(sys.argv[1])",
        "marker = sys.argv[2]",
        "while True:",
        "    try:",
        "        os.kill(parent, 0)",
        "    except OSError:",
        "        break",
        "    time.sleep(0.05)",
        "time.sleep(0.2)",
        "open(marker, 'w', encoding='utf-8').write('cleaned')",
    ])
    helper = subprocess.Popen(
        [sys.executable, "-c", helper_src, str(os.getpid()), cfg["marker"]])
    if cfg.get("helperpid"):
        with open(cfg["helperpid"], "w", encoding="utf-8") as handle:
            handle.write(str(helper.pid))
    print("ready", flush=True)
    while True:
        time.sleep(0.05)

print("noop", flush=True)
sys.exit(0)
'''


def load_supervisor():
    """Import the project-root supervisor module, or fail loudly if absent."""
    if not SUPERVISOR_PATH.is_file():
        raise FileNotFoundError("missing supervisor.py at {}".format(SUPERVISOR_PATH))
    spec = importlib.util.spec_from_file_location("uu_supervisor", SUPERVISOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def pids_with_cmdline(marker):
    """PIDs whose ``/proc/<pid>/cmdline`` contains ``marker`` (a byte string).

    Used to catch a leaked fake core by its unique fixture path even when the
    core's own PID file never got written.
    """
    marker = marker.encode("utf-8")
    matches = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            raw = Path("/proc", entry, "cmdline").read_bytes()
        except OSError:
            continue
        if marker in raw:
            matches.append(int(entry))
    return matches


class SupervisorTestCase(unittest.TestCase):
    def setUp(self):
        self.assertTrue(
            SUPERVISOR_PATH.is_file(),
            "missing standalone supervisor.py at {}".format(SUPERVISOR_PATH),
        )
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(self.tmp), ignore_errors=True)
        self.children = []
        self.addCleanup(self._reap_children)

        self.core = self.tmp / "fake-core.py"
        self.core.write_text(CORE_SOURCE, encoding="utf-8")
        self.log_file = self.tmp / "core.log"
        self.pid_file = self.tmp / "supervisor.pid"
        self.core_pid_file = self.tmp / "core.child.pid"

    # -- helpers ---------------------------------------------------------
    def _reap_children(self):
        for proc in self.children:
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
            # Closed own stdio pipes; bystander procs spawned without PIPE have
            # ``None`` here, and an unclosed pipe is what raised ResourceWarning.
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass

    def wait_for(self, predicate, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return False

    def log_text(self):
        try:
            return self.log_file.read_text(encoding="utf-8")
        except OSError:
            return ""

    def wait_for_ready(self):
        """Wait until the fake core installed its SIGTERM handling.

        The fake core prints ``ready`` only *after* registering (or ignoring)
        its SIGTERM handler. Signalling the wrapper before that point races the
        handler installation, so every shutdown test waits for this marker
        instead of sleeping for an arbitrary interval.
        """
        return self.wait_for(lambda: "ready" in self.log_text())

    def launch_config(self, mode="exit0", **extra):
        core_config = self.tmp / "core-config.json"
        core = {"mode": mode, "pidfile": str(self.core_pid_file)}
        core.update(extra)
        core_config.write_text(json.dumps(core), encoding="utf-8")
        return {
            "engine": "fex",
            "launch_prefix": [sys.executable],
            "executable": str(self.core),
            "config_path": str(core_config),
            "cwd": str(self.tmp),
            "pid_file": str(self.pid_file),
            "log_file": str(self.log_file),
        }

    def write_launch(self, config, name="launch.json"):
        path = self.tmp / name
        path.write_text(json.dumps(config), encoding="utf-8")
        return path

    def spawn(self, launch_path, env=None):
        proc = subprocess.Popen(
            [sys.executable, str(SUPERVISOR_PATH), str(launch_path)],
            cwd=str(self.tmp),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.children.append(proc)
        return proc

    def notify_socket(self):
        """Bind a real AF_UNIX datagram socket and expose its path.

        ``NOTIFY_SOCKET`` is only ever placed in the *wrapper's* environment by
        the caller; the test process's own environment is never mutated and no
        real systemd is involved. The socket is closed and its path unlinked by
        the cleanup registered here.
        """
        path = self.tmp / "notify.sock"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(str(path))
        self.addCleanup(self._close_notify, sock, path)
        return sock, str(path)

    @staticmethod
    def _close_notify(sock, path):
        try:
            sock.close()
        except OSError:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass

    def recv_notify(self, sock, timeout):
        """Return one datagram within ``timeout`` or ``None`` if none arrives."""
        sock.settimeout(timeout)
        try:
            return sock.recv(4096)
        except socket.timeout:
            return None

    # -- tests -----------------------------------------------------------
    def test_build_command_is_argv_with_literal_spaces(self):
        supervisor = load_supervisor()
        config = {
            "engine": "fex",
            "launch_prefix": ["/opt/FEX Interpreter/FEXInterpreter", "--flag one"],
            "executable": "/run dir/uuplugin",
            "config_path": "/run dir/uu.conf",
            "cwd": "/run dir",
            "pid_file": "/run/self.pid",
            "log_file": "/logs/core.log",
        }

        argv = supervisor.build_command(config)

        self.assertIsInstance(argv, list)
        self.assertEqual(
            argv,
            ["/opt/FEX Interpreter/FEXInterpreter", "--flag one",
             "/run dir/uuplugin", "/run dir/uu.conf"],
        )
        self.assertEqual(len(argv), len(config["launch_prefix"]) + 2)
        for token in argv:
            self.assertIsInstance(token, str)

    def test_natural_nonzero_exit_propagates_and_streams_log(self):
        config = self.launch_config(mode="exit5")
        launch = self.write_launch(config)
        self.log_file.write_text("preexisting\n", encoding="utf-8")

        proc = self.spawn(launch)
        rc = proc.wait(timeout=6)

        self.assertEqual(rc, 5)
        self.assertFalse(self.pid_file.exists())
        log = self.log_file.read_text(encoding="utf-8")
        self.assertIn("preexisting", log)  # appended, not truncated
        self.assertIn("core-out", log)
        self.assertIn("core-err", log)

    def test_sigterm_is_forwarded_and_wrapper_cleans_up(self):
        config = self.launch_config(mode="term")
        launch = self.write_launch(config)
        proc = self.spawn(launch)

        self.assertTrue(self.wait_for(lambda: self.pid_file.exists()))
        self.assertTrue(self.wait_for(lambda: self.core_pid_file.exists()))
        core_pid = int(self.core_pid_file.read_text(encoding="utf-8"))
        self.assertTrue(self.wait_for_ready())  # handler registered, not a sleep

        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=6)

        self.assertEqual(rc, 0)
        self.assertTrue(self.wait_for(lambda: not pid_alive(core_pid)))
        self.assertFalse(self.pid_file.exists())
        self.assertIn("term-marker", self.log_file.read_text(encoding="utf-8"))

    def test_ignored_sigterm_hits_shutdown_timeout_without_collateral(self):
        config = self.launch_config(mode="ignore")
        config["shutdown_timeout"] = 1
        launch = self.write_launch(config)

        bystander = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"])
        self.children.append(bystander)

        proc = self.spawn(launch)
        self.assertTrue(self.wait_for(lambda: self.pid_file.exists()))
        self.assertTrue(self.wait_for(lambda: self.core_pid_file.exists()))
        core_pid = int(self.core_pid_file.read_text(encoding="utf-8"))
        self.assertTrue(self.wait_for_ready())  # SIGTERM handler registered first

        started = time.time()
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=6)
        elapsed = time.time() - started

        self.assertLess(elapsed, 5.0)
        self.assertTrue(self.wait_for(lambda: not pid_alive(core_pid)))
        self.assertIsNone(bystander.poll())  # only its own child group was hit
        self.assertFalse(self.pid_file.exists())

    def test_malformed_launch_config_fails_without_pid_or_worker(self):
        launch = self.tmp / "bad.json"
        launch.write_text("{not valid json", encoding="utf-8")

        proc = self.spawn(launch)
        rc = proc.wait(timeout=6)

        self.assertNotEqual(rc, 0)
        self.assertFalse(self.pid_file.exists())
        self.assertFalse(self.core_pid_file.exists())

    def test_wrapper_waits_for_guardian_cleanup_after_core_exit(self):
        """A supervised guardian in the core's group must clean up before exit.

        The core exits immediately on TERM, but the helper it started in the same
        process group needs a moment to notice the dead parent, write its cleanup
        marker and exit. The wrapper must not return before that marker exists,
        even though its *direct* child is already gone.
        """
        marker = self.tmp / "guardian.cleaned"
        helper_pid_file = self.tmp / "guardian.helper.pid"
        config = self.launch_config(
            mode="guardian", marker=str(marker), helperpid=str(helper_pid_file))
        config["shutdown_timeout"] = 2
        launch = self.write_launch(config)

        proc = self.spawn(launch)
        helper_pid = None
        try:
            self.assertTrue(self.wait_for(lambda: self.core_pid_file.exists()))
            core_pid = int(self.core_pid_file.read_text(encoding="utf-8"))
            self.assertTrue(self.wait_for_ready())  # core started its guardian
            self.assertTrue(self.wait_for(lambda: helper_pid_file.exists()))
            helper_pid = int(helper_pid_file.read_text(encoding="utf-8"))
            self.assertTrue(pid_alive(helper_pid))

            proc.send_signal(signal.SIGTERM)
            rc = proc.wait(timeout=8)
            self.assertEqual(rc, 0)

            # The wrapper must not have returned before the guardian cleaned up:
            # assert the marker is present the instant the wrapper is reaped.
            self.assertTrue(
                marker.exists(),
                "wrapper returned before the guardian wrote its cleanup marker",
            )
            self.assertEqual(marker.read_text(encoding="utf-8"), "cleaned")
            self.assertTrue(self.wait_for(lambda: not pid_alive(core_pid)))
            self.assertFalse(self.pid_file.exists())
        finally:
            if helper_pid is not None and pid_alive(helper_pid):
                try:
                    os.kill(helper_pid, signal.SIGKILL)
                except OSError:
                    pass

    def test_pid_publication_failure_stops_spawned_core(self):
        """A failed PID publish must fail nonzero and reap the spawned core.

        The pid_file points at a missing parent directory, so the core is spawned
        and then ``_write_pid`` fails. The wrapper must not leave that core alive.
        The fake core's unique fixture path is scanned for in ``/proc`` so a leak
        is caught even if the core was killed before it could write its PID file.
        """
        core_path = str(self.core)
        config = self.launch_config(mode="term")
        bad_pid = self.tmp / "missing-parent" / "supervisor.pid"
        config["pid_file"] = str(bad_pid)
        launch = self.write_launch(config)

        proc = self.spawn(launch)
        core_pid = None
        try:
            rc = proc.wait(timeout=8)
            self.assertNotEqual(rc, 0)

            if self.core_pid_file.exists():
                core_pid = int(self.core_pid_file.read_text(encoding="utf-8"))
                self.assertTrue(
                    self.wait_for(lambda: not pid_alive(core_pid)),
                    "wrapper left its spawned core alive after PID publish failure",
                )

            self.assertEqual(
                pids_with_cmdline(core_path), [],
                "wrapper left a fake core process running after PID publish failure",
            )
            self.assertFalse(bad_pid.exists())
        finally:
            if core_pid is not None and pid_alive(core_pid):
                try:
                    os.kill(core_pid, signal.SIGKILL)
                except OSError:
                    pass

    def test_notify_ready_only_after_core_stabilizes(self):
        """With NOTIFY_SOCKET set the wrapper reports READY=1 once the core lives.

        The unit is Type=notify, so the wrapper must not claim readiness the
        instant the core spawns: a live core earns READY=1 only after surviving
        the stabilization window (the first 0.1s probe must time out), and the
        wrapper then exits cleanly on TERM, taking its core with it.
        """
        sock, sock_path = self.notify_socket()
        config = self.launch_config(mode="term")
        launch = self.write_launch(config)
        env = dict(os.environ, NOTIFY_SOCKET=sock_path)

        proc = self.spawn(launch, env=env)
        core_pid = None
        try:
            self.assertIsNone(
                self.recv_notify(sock, 0.1),
                "wrapper claimed READY=1 before the core stabilized",
            )
            data = self.recv_notify(sock, 5.0)
            self.assertIsNotNone(data, "wrapper never reported READY=1")
            self.assertIn(b"READY=1", data)

            self.assertTrue(self.wait_for(lambda: self.core_pid_file.exists()))
            core_pid = int(self.core_pid_file.read_text(encoding="utf-8"))
            self.assertTrue(pid_alive(core_pid))

            proc.send_signal(signal.SIGTERM)
            self.assertEqual(proc.wait(timeout=6), 0)
            self.assertTrue(self.wait_for(lambda: not pid_alive(core_pid)))
            self.assertFalse(self.pid_file.exists())
        finally:
            if core_pid is not None and pid_alive(core_pid):
                try:
                    os.kill(core_pid, signal.SIGKILL)
                except OSError:
                    pass

    def test_no_notify_ready_when_core_exits_before_stabilizing(self):
        """A core that exits early keeps its natural code and sends no READY=1."""
        sock, sock_path = self.notify_socket()
        config = self.launch_config(mode="exit5")
        launch = self.write_launch(config)
        env = dict(os.environ, NOTIFY_SOCKET=sock_path)

        proc = self.spawn(launch, env=env)
        rc = proc.wait(timeout=6)

        self.assertEqual(rc, 5)
        self.assertIsNone(
            self.recv_notify(sock, 1.0),
            "wrapper reported READY=1 for a core that exited before stabilizing",
        )

    def test_load_config_rejects_non_fex_engines(self):
        supervisor = load_supervisor()
        for engine in ("native", "x86", "bogus", ""):
            with self.subTest(engine=engine):
                config = self.launch_config(mode="exit0")
                config["engine"] = engine
                launch = self.write_launch(config, "engine-{}.json".format(engine or "empty"))
                with self.assertRaises(supervisor.ConfigError):
                    supervisor.load_config(str(launch))

    def test_run_refuses_non_fex_without_spawning(self):
        supervisor = load_supervisor()
        for engine in ("native", "x86", "bogus"):
            with self.subTest(engine=engine):
                config = self.launch_config(mode="term")
                config["engine"] = engine
                launch = self.write_launch(config, "run-{}.json".format(engine))
                with mock.patch.object(supervisor.subprocess, "Popen") as spawn:
                    rc = supervisor.run(str(launch))
                spawn.assert_not_called()
                self.assertEqual(rc, 78)
                self.assertFalse(self.pid_file.exists())
                self.assertFalse(self.core_pid_file.exists())

    # -- kernel-compat preflight ------------------------------------------
    def test_preflight_failure_writes_startup_error_and_exits_78(self):
        """A refused preflight leaves its own diagnosis and exits 78.

        The supervisor owns ``startup-error.txt`` beside its pid file: the raw
        reason is written as UTF-8 so the manager can show it, and the run ends
        with 78 (the unit's ``RestartPreventExitStatus``) before any core is
        spawned -- no Popen, no pid file, no READY=1.
        """
        supervisor = load_supervisor()
        config = self.launch_config(mode="term")
        # A present key is what makes the supervisor run the preflight at all.
        config["kernel_compat"] = str(self.tmp / "compat-missing")
        launch = self.write_launch(config)

        startup_error = self.pid_file.with_name("startup-error.txt")
        reason = "内核编译版本不匹配: 期望 #1 SMP Fri Oct 16，实际 #1 SMP Mon Oct 19"

        with mock.patch.object(
            supervisor, "ensure_cgroup_support", side_effect=RuntimeError(reason)
        ):
            with mock.patch.object(supervisor.subprocess, "Popen") as spawn:
                rc = supervisor.run(str(launch))

        spawn.assert_not_called()
        self.assertEqual(rc, 78)
        self.assertFalse(self.pid_file.exists())
        self.assertTrue(startup_error.is_file(), "missing {}".format(startup_error))
        text = startup_error.read_text(encoding="utf-8")  # must be valid UTF-8
        self.assertIn(reason, text)
