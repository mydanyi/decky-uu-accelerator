#!/usr/bin/env python3
"""Static syntax verification of the generated UU systemd unit.

Builds the current unit text with ``service.build_unit`` for a real temporary
run directory whose path deliberately contains Chinese characters, spaces and a
literal ``%``, writes the unit under ``--output`` and runs
``systemd-analyze verify --man=no`` against it. Nothing is started, enabled or
installed: this only checks that systemd can parse the unit.

Expected unit shape (pinned by tests/test_manager.py):

* ``WorkingDirectory`` is a *scalar* value, so it must be the raw unquoted
  absolute path with ``%`` doubled as ``%%`` (a double quote would be parsed as
  part of the path).
* ``ExecStart`` and ``BindPaths`` keep their quoted argument syntax so embedded
  spaces survive.

The tool exits non-zero if ``systemd-analyze`` reports a parser error or if any
of the structural checks above fail. It is static syntax verification only, not
a live service or device test.

Run with (from the project root, inside the systemd validation image):
    python3 tools/verify_service.py --output <dir>
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "py_modules"))

from uu_accelerator import service  # noqa: E402


def unit_field(text, key):
    for line in text.splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description="verify the generated systemd unit")
    parser.add_argument("--output", required=True,
                        help="directory for the generated unit and the report")
    parser.add_argument("--systemd-analyze", default="systemd-analyze")
    args = parser.parse_args(argv)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    base = Path(tempfile.mkdtemp(prefix="uu-verify-service-"))
    try:
        run_dir = base / "运行 100% 目录" / "run"
        run_dir.mkdir(parents=True, exist_ok=True)
        supervisor = PROJECT_ROOT / "supervisor.py"
        launch = run_dir / "launch.json"
        launch.write_text("{}", encoding="utf-8")

        unit_text = service.build_unit(
            run_dir, supervisor, launch, python=service.PYTHON)
        unit_path = output_dir / service.UNIT_NAME
        unit_path.write_text(unit_text, encoding="utf-8")

        expected_wd = str(run_dir).replace("%", "%%")
        expected_exec = "{} {} {}".format(
            service.systemd_quote(service.PYTHON),
            service.systemd_quote(str(supervisor)),
            service.systemd_quote(str(launch)),
        )
        expected_bind = service.systemd_quote(
            "{}:{}".format(run_dir, service.BIND_TARGET))

        working_directory = unit_field(unit_text, "WorkingDirectory")
        exec_start = unit_field(unit_text, "ExecStart")
        bind_paths = unit_field(unit_text, "BindPaths")

        checks = {
            "working_directory_unquoted_escaped": (
                working_directory == expected_wd
                and '"' not in (working_directory or "")
            ),
            "exec_start_argument_syntax": exec_start == expected_exec,
            "bind_paths_argument_syntax": bind_paths == expected_bind,
        }

        verify_argv = [args.systemd_analyze, "verify", "--man=no", str(unit_path)]
        analyze = subprocess.run(verify_argv, capture_output=True, text=True)

        failed = analyze.returncode != 0 or not all(checks.values())
        report = {
            "unit_path": str(unit_path),
            "run_dir": str(run_dir),
            "expected_working_directory": expected_wd,
            "working_directory": working_directory,
            "exec_start": exec_start,
            "bind_paths": bind_paths,
            "checks": checks,
            "systemd_analyze": {
                "argv": verify_argv,
                "returncode": analyze.returncode,
                "stdout": analyze.stdout,
                "stderr": analyze.stderr,
            },
            "ok": not failed,
        }

        text = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
        (output_dir / "verify_service.json").write_text(text + "\n", encoding="utf-8")
        print(text)
        return 1 if failed else 0
    finally:
        shutil.rmtree(str(base), ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
