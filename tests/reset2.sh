#!/bin/bash
# reset2.sh — hard-reset the 2-node test cluster (test1, test2) to a clean
# slate via virsh VM reboot, then wait until both are SSH-reachable with the
# /src QNAP NFS mounted and mxfs unloaded/unmounted.
#
# WHY: after a dir_reuse_coherency (2/tcp) run the leftover mxfs mount on one
# node frequently wedges on unmount — the xfs-reclaim kworker blocks in
# D-state waiting on a degraded DLM, so `umount`/`rmmod` (even -l/-f) hang
# uninterruptibly and the next run's mkfs fails "device busy".  D-state procs
# can't be killed; only a VM reboot recovers.  Host (clyde) reboot is
# PROHIBITED (CLAUDE.md RULE 2) — VM reboot via the system libvirt URI is fine
# (memory reference_node_power_control).
#
# Usage: tests/reset2.sh        (reboots both)
#        tests/reset2.sh test1  (reboot just one)
set -u
VIRSH="virsh -c qemu:///system"
SSH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/tools/mxfs_sshpass.sh"
PF="${MXFS_PASS:-/tmp/.mxfs_pass}"
NODES=("$@"); [ "${#NODES[@]}" -eq 0 ] && NODES=(test1 test2)

for n in "${NODES[@]}"; do
    echo "--- reboot $n ---"
    $VIRSH destroy "$n" 2>&1 | sed 's/^/  /'
done
sleep 3
for n in "${NODES[@]}"; do
    $VIRSH start "$n" 2>&1 | sed 's/^/  /'
done

for n in "${NODES[@]}"; do
    echo -n "--- waiting for $n ssh+nfs "
    ok=0
    for i in $(seq 1 40); do
        if timeout 6 "$SSH" "$n" "$PF" 'mountpoint -q /src || mount | grep -q " /src "' >/dev/null 2>&1; then
            ok=1; echo "up (~$((i*5))s)"; break
        fi
        echo -n "."; sleep 5
    done
    [ "$ok" = 1 ] || { echo " TIMEOUT"; exit 1; }
    # belt-and-suspenders: ensure mxfs not loaded / not mounted post-boot
    timeout 15 "$SSH" "$n" "$PF" '
        mountpoint -q /mnt/shared && umount -l /mnt/shared 2>/dev/null
        lsmod | grep -q "^mxfs " && rmmod mxfs 2>/dev/null
        echo "  $(hostname): loaded=$(lsmod|grep -q "^mxfs "&&echo Y||echo N) mounted=$(mountpoint -q /mnt/shared&&echo Y||echo N) src=$(mount|grep -q " /src "&&echo Y||echo N)"' 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'
done
echo "=== reset2 done ==="
