#!/bin/bash
# vm_cycle.sh — power-cycle test VMs (virsh destroy+start), wait for ssh,
# restore /src (NFS is deliberately not an fstab automount on the nodes).
# Test VMs only, never the host.  Mirrors scripts/rig.sh cycle_vms and
# run.sh power_cycle_node, for chains that run under MXFS_NODE_LIST (where
# run.sh refuses to cycle because it cannot tell a VM from an external host).
#
# Usage: scripts/vm_cycle.sh [--if-loaded] <node>...
#   --if-loaded   cycle only the nodes that still have mxfs loaded after a
#                 bounded umount+rmmod attempt (a shut-down or fenced mount
#                 holds the module); a node that releases cleanly is left up.
# Exit 0 iff every cycled node answers ssh and has /src.
# budget: a VM boots to ssh in 60-120 s; 240 s per node bound.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
ONLY_LOADED=0
[ "${1:-}" = "--if-loaded" ] && { ONLY_LOADED=1; shift; }
[ $# -gt 0 ] || { echo "usage: $0 [--if-loaded] <node>..." >&2; exit 2; }
say() { echo "[vm_cycle] $*"; }
ssh_n() { timeout "${3:-30}" "$SSH" "$1" "$2" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you|^$'; }

want=()
for n in "$@"; do
    if [ "$ONLY_LOADED" = 1 ]; then
        st=$(ssh_n "$n" "mountpoint -q $MNT && timeout 20 umount -f $MNT >/dev/null 2>&1; for i in 1 2 3; do rmmod mxfs 2>/dev/null; grep -qw '^mxfs' /proc/modules || break; sleep 2; done; grep -qw '^mxfs' /proc/modules && echo LOADED || echo CLEAN" 45 | tail -1)
        if [ "$st" = CLEAN ]; then say "$n: mxfs released cleanly; not cycling"; continue; fi
        say "$n: mxfs still held ($st) — cycling"
    fi
    want+=("$n")
done
[ ${#want[@]} -gt 0 ] || exit 0

for n in "${want[@]}"; do
    state=$(timeout 60 $VIRSH domstate "$n" 2>/dev/null | head -1)
    say "cycling $n (was: ${state:-unknown})"
    ( timeout 60 $VIRSH destroy "$n" >/dev/null 2>&1; sleep 2; timeout 60 $VIRSH start "$n" >/dev/null 2>&1 ) &
done
wait
rc=0
for n in "${want[@]}"; do
    dl=$(( SECONDS + 240 )); up=0
    while [ "$SECONDS" -lt "$dl" ]; do
        # sshd answers while /run/nologin still exists; pam prints the
        # "System is booting up" banner into every command's output until
        # systemd removes the file, and prep_cluster's srcversion gate then
        # reads the banner as part of the version string (sess525 s525a).
        ssh_n "$n" "test ! -e /run/nologin && echo SSH_UP" 10 | grep -q SSH_UP && { up=1; break; }
        sleep 3
    done
    if [ "$up" != 1 ]; then say "ERROR: $n did not answer ssh within 240 s"; rc=1; continue; fi
    src=$(ssh_n "$n" 'mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }; mountpoint -q /src && echo SRC_OK || echo SRC_MISSING' 90 | tail -1)
    say "$n: up after cycle, /src=$src"
    [ "$src" = SRC_OK ] || rc=1
done
exit $rc
