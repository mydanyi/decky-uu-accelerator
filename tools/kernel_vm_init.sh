#!/bin/busybox sh
# Offline ARM64 QEMU init used only to exercise the bundled-module routes
# against the official 7.2.6 kernel. NOT shipped with the plugin: this file is
# a local verification aid and lives under tools/ only.
#
# Touches nothing outside this ephemeral guest: the owned /sys entries it
# creates and its own throwaway iptables probe chains.
set -eu

export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PYTHONDONTWRITEBYTECODE=1

echo "UU_VM_BOOT $(/bin/busybox uname -r) $(/bin/busybox uname -m)"

fail() {
    echo "UU_VM_FAIL $*" >&2
    sync || true
    poweroff -f || true
    while :; do sleep 1; done
}

/bin/busybox mkdir -p /bin /sbin /proc /sys /dev /tmp /plugin || true
# Install applets into /bin only: /sbin already holds the kmod binaries
# (modprobe, insmod, rmmod) this guest relies on.
/bin/busybox --install -s /bin || fail "busybox install /bin"

mount -t proc proc /proc || fail "mount proc"
mount -t sysfs sysfs /sys || fail "mount sysfs"
mkdir -p /sys/fs/cgroup || fail "mkdir cgroup"
mount -t devtmpfs devtmpfs /dev || fail "mount devtmpfs"
mount -t cgroup2 none /sys/fs/cgroup || fail "mount cgroup2"

trap 'fail "unexpected exit near line $LINENO"' EXIT

echo "UU_VM_UNAME $(uname -r) $(uname -m)"
iptables --version || fail "iptables --version"

cd /plugin || fail "cd /plugin"
export PYTHONPATH=/plugin

# Route 1: generic preflight with the official current config. The cgroup
# dependency is resolved through the portable manifest (the legacy exact
# profile does not carry the current kernel config), and the probes must then
# accept a real rule.
python3 - <<'PY' || fail "cgroup/nat preflight"
from supervisor import ensure_cgroup_support, ensure_nat_support, _probe_network_feature

config = {"engine": "fex", "kernel_compat": "/plugin/compat/armada-7.2.6"}
diagnostics = []
ensure_cgroup_support(config, root="/", diagnostics=diagnostics)
ensure_nat_support(config, root="/", diagnostics=diagnostics)
for name in ("xt_cgroup", "xt_nat"):
    if not _probe_network_feature(name, diagnostics=diagnostics):
        raise SystemExit("probe {} failed: {}".format(name, diagnostics))
print("UU_VM_PREFLIGHT_PROBE_PASS")
PY

[ -e /sys/module/xt_cgroup ] || fail "/sys/module/xt_cgroup missing after portable load"

# Route 2: portable xt_nat, exercised independently of the preflight: drop the
# loaded system module (guest only), then let the portable helper prove, load
# and probe the bundled module itself.
python3 - <<'PY' || fail "portable xt_nat exercise"
import subprocess

from supervisor import _probe_network_feature, _validate_portable_kernel_compat

COMPAT = "/plugin/compat/armada-7.2.6"
DROP = ["/sbin/rmmod", "xt_nat"]

dropped = subprocess.run(DROP, capture_output=True, text=True)
if dropped.returncode != 0:
    raise SystemExit("rmmod xt_nat failed: {}".format(dropped.stderr))

diagnostics = []
path = _validate_portable_kernel_compat(
    COMPAT,
    "/",
    "xt_nat",
    ["-a", "x_tables", "nf_nat"],
    subprocess.run,
    diagnostics,
)
if not path:
    raise SystemExit("no portable xt_nat profile in manifest")

load = subprocess.run(["/sbin/insmod", path], capture_output=True, text=True)
if load.returncode != 0:
    raise SystemExit("insmod {} failed: {}".format(path, load.stderr))
if not _probe_network_feature("xt_nat", diagnostics=diagnostics):
    raise SystemExit("portable xt_nat probe failed: {}".format(diagnostics))
print("UU_VM_PORTABLE_NAT_PASS {}".format(path))
PY

trap - EXIT
echo "UU_VM_PREFLIGHT_PASS"
echo "UU_VM_PASS"
sync || true
poweroff -f || true
while :; do sleep 1; done
