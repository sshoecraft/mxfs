#!/bin/bash
# rig_recover.sh — bring the test cluster back to a state prep_cluster can use.
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess23)
#   run.sh's prep gate requires BOTH `SRC_OK` and `MXFS_CLEAN` from every node,
#   and escalates to `virsh destroy+start` when either is missing.  That
#   escalation is self-sustaining: /src is deliberately NOT an fstab automount
#   on the test VMs (a hard NFS mount can hang boot if the server is down — see
#   ccmemory feedback-src-nfs-not-fstab-automount), so a power-cycled node comes
#   back WITHOUT /src, the next prep sees SRC_MISSING, and cycles it again.
#   Observed live: 14 nodes cycled, then 5, then 4, never converging, with prep
#   timing out each pass.
#
#   The trigger is that prep restores /src with `timeout 12 mount`.  Measured on
#   this rig under load, the NFS mount needs longer than that; a manual restore
#   with `timeout 25` succeeded on 16/16 nodes immediately after prep had failed
#   on 8 of them.  So the loop is a TIMEOUT that is too short, not a wedged node.
#
# WHAT IT DOES, in the order that actually converges:
#   1. every node reachable over ssh (power-cycle + wait for the ones that are not)
#   2. /src restored with a generous timeout, retried
#   3. mxfs unmounted and the module removed, with a generous retry
#   4. per-node readiness report
#
# Run this BEFORE `MXFS_FORCE_PREP=1 ./run.sh N caw prep_cluster` whenever prep
# has started power-cycling.  Once every node reports READY, prep's own checks
# short-circuit (`mountpoint -q /src && break`) and it completes normally.
#
# USAGE: scripts/rig_recover.sh [nodes]
# EXIT:  0 = every node READY.  1 = at least one node not recoverable.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
N="${1:-32}"
MNT="${MXFS_MNT:-/mnt/shared}"
SRCSRV="${MXFS_SRC_NFS:-192.168.1.4:/src}"

echo "=== rig_recover: nodes=$N ==="

# ---- 1. reachability ------------------------------------------------------
echo "--- phase 1: ssh reachability ---"
for pass in 1 2 3; do
    down=()
    for i in $(seq 1 "$N"); do
        timeout 15 "$SSH" "test$i" "true" >/dev/null 2>&1 || down+=("test$i")
    done
    [ "${#down[@]}" -eq 0 ] && { echo "    all $N nodes reachable"; break; }
    echo "    unreachable (pass $pass): ${down[*]}"
    [ "$pass" -eq 3 ] && break
    for n in "${down[@]}"; do
        echo "    power-cycling $n"
        virsh -c qemu:///system destroy "$n" >/dev/null 2>&1
        sleep 2
        virsh -c qemu:///system start "$n" >/dev/null 2>&1
    done
    # give the cycled nodes time to boot before re-probing
    for w in $(seq 1 30); do
        allup=1
        for n in "${down[@]}"; do
            timeout 10 "$SSH" "$n" "true" >/dev/null 2>&1 || allup=0
        done
        [ "$allup" = "1" ] && break
        sleep 10
    done
done

# ---- 2. /src ---------------------------------------------------------------
echo "--- phase 2: /src NFS restore ---"
td=$(mktemp -d)
for i in $(seq 1 "$N"); do
    ( timeout 180 "$SSH" "test$i" "
        for try in 1 2 3 4; do
            mountpoint -q /src && break
            mkdir -p /src
            timeout 40 mount -t nfs $SRCSRV /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null
            sleep 3
        done
        mountpoint -q /src && echo SRC_OK || echo SRC_MISSING" > "$td/src$i" 2>&1 ) &
done
wait
src_ok=0
for i in $(seq 1 "$N"); do
    grep -q SRC_OK "$td/src$i" 2>/dev/null && src_ok=$((src_ok+1)) || echo "    test$i: /src MISSING"
done
echo "    /src present on $src_ok/$N"

# ---- 3. release mxfs -------------------------------------------------------
echo "--- phase 3: unmount + rmmod ---"
for i in $(seq 1 "$N"); do
    ( timeout 200 "$SSH" "test$i" "
        for t in 1 2 3 4 5 6; do
            mountpoint -q $MNT || break
            fuser -km $MNT 2>/dev/null; sleep 1
            umount $MNT 2>/dev/null && break
            timeout 25 umount -f $MNT 2>/dev/null && break
            sleep 2
        done
        mountpoint -q $MNT && umount -l $MNT 2>/dev/null
        sleep 1
        for t in 1 2 3 4 5 6 7 8; do
            lsmod | grep -q '^mxfs ' || break
            rmmod mxfs 2>/dev/null && break
            sleep 3
        done
        lsmod | grep -q '^mxfs ' && echo MXFS_STILL_LOADED || echo MXFS_CLEAN" > "$td/rel$i" 2>&1 ) &
done
wait

# ---- 4. report -------------------------------------------------------------
bad=0
for i in $(seq 1 "$N"); do
    s=$(grep -hoE 'SRC_OK|SRC_MISSING' "$td/src$i" 2>/dev/null | tail -1)
    m=$(grep -hoE 'MXFS_CLEAN|MXFS_STILL_LOADED' "$td/rel$i" 2>/dev/null | tail -1)
    if [ "$s" = "SRC_OK" ] && [ "$m" = "MXFS_CLEAN" ]; then
        continue
    fi
    echo "    test$i NOT READY: src=${s:-UNREACHABLE} mxfs=${m:-UNREACHABLE}"
    bad=1
done

if [ "$bad" = "0" ]; then
    echo "=== rig_recover: all $N nodes READY (src mounted, mxfs released) ==="
    exit 0
fi
echo "=== rig_recover: at least one node NOT READY — see above ==="
exit 1
