#!/bin/bash
# precond_readiness — P0 gate: confirm the node has a healthy, writable MXFS
# mount before any real test runs. Agnostic: $1 = mount point only.

SUITE_TEST_NAME=precond_readiness
MNT="${1:-/mnt/shared}"
NODES="${MXFS_NODES:-1}"
# Normally mxfs; the native-XFS timing baseline (run.sh DLM=xfs, N=1 only)
# mounts plain xfs instead — this gate should still pass there, just checking
# for the FS type run.sh actually put on the mount.
FSTYPE="${MXFS_EXPECT_FSTYPE:-mxfs}"
source "$(dirname "$(readlink -f "$0")")/lib.sh"

ck   "is a mountpoint"   mountpoint -q "$MNT"
ck   "type is $FSTYPE"   grep -q " $MNT $FSTYPE " /proc/mounts

W="$MNT/.suite_readiness.$(hostname).$$"
ck   "mkdir on mount"    mkdir -p "$W"
echo hi > "$W/f" 2>/dev/null
ckeq "write/read back"   "hi" "$(cat "$W/f" 2>/dev/null)"
ck   "fsync ok"          dd if=/dev/zero of="$W/s" bs=4096 count=1 oflag=dsync status=none
ck   "unlink/cleanup"    rm -rf "$W"

avail=$(df -P "$MNT" 2>/dev/null | awk 'NR==2{print $4}')
ck   "has free space"    test "${avail:-0}" -gt 0

# ─── NODE-FAULT GATE (ccloop c7ee71c6 sess24) ──────────────────────────────
#
# WHY: every check above PASSES on a node that is permanently deadlocked.
# D-BAST-WRITEBACK-ABBA-DEADLOCK was captured live on test27: mxfs mounted, `ls`
# answering, mkdir/write/fsync/unlink all fine, no BUG/WARNING, no filesystem
# shutdown -- and yet `sync` could never complete, because mxfs_dlm_bast_process
# held the inode lock waiting on a folio lock while writeback held that folio
# lock waiting on the inode lock.
#
# Consequence if undetected: barrier criteria need every rank, so ONE such node
# makes the whole board read `FAIL nodes_pass=0/32
# states:NO_TERMINAL_RECORD=32`. That happened to SEVEN criteria at once
# (cache_coherency, strong_consistency, posix_multi, mmap_coherency,
# zero_silent_loss, dlm_fairness, dlm_membership) on a cluster where 31 of 32
# nodes were healthy. A node fault must be reported AS a node fault, at P0,
# before it can be laundered into correctness reds.
#
# Two direct probes, both cheap and both specific to the failure mode:
#   1. a bounded `sync` -- the exact operation the deadlock makes impossible
#   2. D-state MXFS/writeback kernel tasks -- the deadlock's signature
# Ordinary load is NOT used as a predicate: it is a symptom with many innocent
# causes, and convicting on it would fail healthy nodes under legitimate work.

# 1) sync must complete inside a bound.  The deadlock pins it forever; a healthy
#    32-node cluster syncs in well under a second (measured 11ms/write).
sync_ok=0
( sync ) & sync_pid=$!
for _si in $(seq 1 60); do
    kill -0 "$sync_pid" 2>/dev/null || { sync_ok=1; break; }
    sleep 0.25
done
if [ "$sync_ok" != 1 ]; then
    kill -9 "$sync_pid" 2>/dev/null
    echo "mxfs-precond-SYNC-WEDGED host=$(hostname)" > /dev/kmsg 2>/dev/null
fi
ckeq "sync completes within 15s" "1" "$sync_ok"

# 2) No MXFS or writeback kernel task may be stuck in uninterruptible sleep.
#    Matches the captured signature: mxfs-ino-bast / mxfs-* kworkers, the
#    flush-<dev> writeback worker, and any D-state `sync`.  Reported with the
#    offending comm+wchan so the cell names the fault instead of just counting.
dstuck=""
for dpid in $(ps -eo stat,pid --no-headers 2>/dev/null | awk '$1 ~ /^D/ {print $2}'); do
    dcomm=$(cat "/proc/$dpid/comm" 2>/dev/null)
    case "$dcomm" in
        *mxfs*|flush-*|sync|*xfsaild*)
            dwchan=$(cat "/proc/$dpid/wchan" 2>/dev/null)
            dstuck="$dstuck ${dcomm}[${dwchan}]"
            echo "mxfs-precond-DSTATE host=$(hostname) pid=$dpid comm=$dcomm wchan=$dwchan" \
                > /dev/kmsg 2>/dev/null
            ;;
    esac
done
ckeq "no D-state mxfs/writeback task" "" "$dstuck"

finish
