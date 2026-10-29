"""systemd unit generation for the UU accelerator plugin.

The plugin owns exactly one unit, :data:`UNIT_NAME`. Its text is generated as
plain strings with systemd's quoting rules so that working directories and
arguments containing spaces, non-ASCII characters or ``%`` specifiers survive
intact (``%`` is a systemd specifier introducer and must be doubled).

Nothing here talks to systemd; :mod:`uu_accelerator.manager` owns
``systemctl``. This module is deliberately free of sandbox/capability
hardening: the official core needs to create a TUN device and run firewall
helpers, and over-restrictive directives would silently break it.
"""

UNIT_NAME = "uu-accelerator.service"
OWNERSHIP_MARKER = "Managed by UU加速器"

# Native interpreter bundled with the OS; the supervisor and the plugin are
# plain CPython, never a packaged runtime.
PYTHON = "/usr/bin/python3"

# The official core hard-codes this run path; we bind our own run directory
# onto it per-unit instead of touching /tmp globally or the immutable image.
BIND_TARGET = "/tmp/uu"


def systemd_quote(value):
    """Quote ``value`` for use in a systemd unit, doubling ``%``.

    ``%`` starts a systemd specifier even inside quotes, so it is doubled
    first; backslashes and double quotes are escaped per systemd string rules.
    """
    text = str(value)
    text = text.replace("%", "%%")
    text = text.replace("\\", "\\\\")
    text = text.replace('"', '\\"')
    return '"{}"'.format(text)


def build_unit(run_dir, supervisor_path, launch_path, python=PYTHON):
    """Return the complete text of the plugin's own systemd unit.

    ``run_dir`` is both the working directory and the source of the
    unit-specific bind mount onto :data:`BIND_TARGET`. ``supervisor_path`` and
    ``launch_path`` are handed to the native interpreter as arguments.
    """
    return "\n".join(
        [
            "# {}".format(OWNERSHIP_MARKER),
            "[Unit]",
            "Description=UU加速器 加速服务",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            # The supervisor notifies readiness once the core has survived a
            # short stabilization window; systemd holds `start` until then, and
            # a core that dies on launch fails the start within this bound.
            # Two bounded kernel-compat preflights (xt_cgroup and xt_nat, each
            # probed then summed over bounded subprocess timeouts) can together
            # exceed 15s, so the start bound is 45s (the manager's own command
            # timeout stays at 60s).
            "Type=notify",
            "NotifyAccess=main",
            "TimeoutStartSec=45",
            # WorkingDirectory is a scalar path: systemd hands the raw rvalue to
            # unit_path_printf/path_simplify, so a leading double quote would be
            # parsed as part of the path. Emit the literal path with ``%`` doubled
            # (spaces/Chinese stay literal); ExecStart/BindPaths keep quoting.
            "WorkingDirectory={}".format(str(run_dir).replace("%", "%%")),
            "ExecStart={} {} {}".format(
                systemd_quote(python),
                systemd_quote(supervisor_path),
                systemd_quote(launch_path),
            ),
            "BindPaths={}".format(
                systemd_quote("{}:{}".format(run_dir, BIND_TARGET))
            ),
            "KillMode=mixed",
            "TimeoutStopSec=45",
            "Restart=on-failure",
            # 78 is the supervisor's kernel-compat refusal, i.e. a configuration
            # problem an immediate restart cannot fix: keep restarting real
            # crashes, but never loop on an unsupported kernel.
            "RestartPreventExitStatus=78",
            "RestartSec=5",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )
