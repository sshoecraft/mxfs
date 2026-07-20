#!/bin/bash
# drc_cap2.sh — run ONE dir_reuse_coherency 2/tcp iteration with ROBUST full
# kernel-log capture (sess36 ccloop).  The sess35 node-side `dmesg --follow`
# approach lost the file (node-side backgrounding under non-TTY ssh hangs the
# channel → output lost; /tmp wiped on the reset-reboot).  This version STREAMS
# `dmesg --follow` over a HOST-side backgrounded ssh straight into a host file
# (/src/mxfs/tests/_cap/<host>.log) — no node-side detachment, survives the
# prep rmmod/insmod (dmesg reads /dev/kmsg, independent of mxfs), and the data
# lands on the host directly so nothing wraps and nothing is lost.
#
# Usage: tests/drc_cap2.sh
set -u
cd /src/mxfs
SSH=tools/mxfs_sshpass.sh
PF="${MXFS_PASS:-/tmp/.mxfs_pass}"
NODES=(test1 test2)
CAPDIR=/src/mxfs/tests/_cap
strip() { grep -vE '^Warning:|^Unauthorized|^If you'; }

mkdir -p "$CAPDIR"
echo "=== drc_cap2 @ $(date -u +%T) build=$(modinfo mxfs.ko 2>/dev/null|awk '/srcversion/{print $2}') ==="

# 1. Kill any stale followers, then start a host-side streaming ssh per node.
declare -a SPID
for n in "${NODES[@]}"; do
    timeout 10 $SSH "$n" "$PF" 'pkill -f "dmesg --follow" 2>/dev/null; true' >/dev/null 2>&1
    : > "$CAPDIR/$n.log"
    # sess42 (ccloop 8ddb16a2): CLEAR the kernel ring buffer before streaming so
    # the capture contains ONLY this run's lines.  `dmesg --follow` alone dumps
    # the entire existing ring buffer (prior runs' tails) at stream start, which
    # makes timestamp<->round correlation unreliable (stale P108/P91/drc-FAIL
    # entries from a previous iter masquerade as this run's) — a trap that has
    # wasted diagnosis effort across many sessions.
    timeout 500 $SSH "$n" "$PF" 'dmesg -C 2>/dev/null; dmesg --follow' > "$CAPDIR/$n.log" 2>/dev/null &
    SPID+=($!)
done
sleep 2
for i in "${!NODES[@]}"; do
    echo "  stream ${NODES[$i]}: hostpid=${SPID[$i]} lines=$(grep -c . "$CAPDIR/${NODES[$i]}.log" 2>/dev/null)"
done

# 2. Run the single test (run.sh handles prep/mkfs/mount/load + record).
echo "--- running ./run.sh 2 tcp dir_reuse_coherency ---"
timeout 450 ./run.sh 2 tcp dir_reuse_coherency 2>&1 | strip | tail -8

# 3. Stop streamers (kill host-side ssh + node-side follower).
sleep 2
for p in "${SPID[@]}"; do kill "$p" 2>/dev/null; done
for n in "${NODES[@]}"; do
    timeout 10 $SSH "$n" "$PF" 'pkill -f "dmesg --follow" 2>/dev/null; true' >/dev/null 2>&1
    echo "  $n.log: $(grep -c . "$CAPDIR/$n.log" 2>/dev/null) lines captured"
done
echo "=== capture done @ $(date -u +%T) — logs in $CAPDIR/<host>.log ==="
