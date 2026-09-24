#!/bin/bash
#
# vsphere_vm_cpus.sh — set the vCPU count of lab VMs in vSphere through govc
#
# Usage: scripts/vsphere_vm_cpus.sh <cpus> <vm-name> [<vm-name> ...]
#
# Shuts each guest down cleanly (VMware Tools), waits for it to power off,
# sets the vCPU count, and powers it back on.  vCenter credentials come from
# the osimager secrets file (section vsphere/lab: server, username, password)
# and are handed to govc through its environment, never on a command line.
#
set -eu

CPUS="${1:?usage: $0 <cpus> <vm-name> [...]}"
shift
[ $# -ge 1 ] || { echo "usage: $0 <cpus> <vm-name> [...]" >&2; exit 2; }

SECRETS="${OSIMAGER_SECRETS:-$HOME/.config/osimager/secrets}"
eval "$(python3 - "$SECRETS" <<'EOF'
import re, shlex, sys
for line in open(sys.argv[1]):
    if line.startswith("vsphere/lab"):
        f = dict(re.findall(r"(\w+)=(\S+)", line))
        print("export GOVC_URL=%s" % shlex.quote("https://" + f["server"] + "/sdk"))
        print("export GOVC_USERNAME=%s" % shlex.quote(f["username"]))
        print("export GOVC_PASSWORD=%s" % shlex.quote(f["password"]))
        break
else:
    sys.exit("no vsphere/lab entry in " + sys.argv[1])
EOF
)"
export GOVC_INSECURE=1

for vm in "$@"; do
    path=$(timeout 30 govc find / -type m -name "$vm" | head -1)
    [ -n "$path" ] || { echo "$vm: not found in vCenter" >&2; exit 1; }
    echo "$vm ($path): $(timeout 30 govc vm.info -json "$path" | python3 -c 'import json,sys; c=json.load(sys.stdin)["virtualMachines"][0]["config"]["hardware"]; print(c["numCPU"], "vCPU,", c["memoryMB"], "MB")')"
    state=$(timeout 30 govc vm.info -json "$path" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtualMachines"][0]["runtime"]["powerState"])')
    if [ "$state" = poweredOn ]; then
        # Never a hard power-off: a guest may have a shared LUN mounted.  A
        # refused guest shutdown (Tools not answering, or a shutdown already
        # started from inside) still waits below for the guest to power off.
        timeout 30 govc vm.power -s "$path" ||
            echo "$vm: guest shutdown not accepted; waiting for a shutdown started inside the guest"
        # Block on the power state itself (govc waits server-side), bounded.
        timeout 180 govc object.collect -s -wait 170 "$path" -runtime.powerState poweredOff >/dev/null 2>&1 || true
    fi
    state=$(timeout 30 govc vm.info -json "$path" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtualMachines"][0]["runtime"]["powerState"])')
    [ "$state" = poweredOff ] || { echo "$vm: still $state after the guest shutdown; not resizing" >&2; exit 1; }
    timeout 60 govc vm.change -vm "$path" -c "$CPUS"
    timeout 60 govc vm.power -on "$path"
    echo "$vm: now $(timeout 30 govc vm.info -json "$path" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtualMachines"][0]["config"]["hardware"]["numCPU"])') vCPU, powered on"
done
