#!/bin/bash
# drc_run_capture.sh — run a single dir_reuse_coherency 2/tcp iteration with
# FULL kernel-log capture on both nodes (the default dmesg ring WRAPS during a
# 24-round run, hiding P34/P-DIRBAST/P35 evidence).  sess35 (ccloop).
#
# Starts `dmesg --follow` -> a file on each node BEFORE the run (survives the
# rmmod/insmod that run.sh's prep does), runs the test, then leaves the full
# per-node logs at /tmp/drc_full.<host>.log on each node and pulls a summary.
#
# Usage: tests/drc_run_capture.sh
set -u
cd /src/mxfs
SSH=tools/mxfs_sshpass.sh
PF="${MXFS_PASS:-/tmp/.mxfs_pass}"
NODES=(test1 test2)
strip() { grep -vE '^Warning:|^Unauthorized|^If you'; }

echo "=== drc_run_capture @ $(date -u +%T) build=$(modinfo mxfs.ko 2>/dev/null|awk '/srcversion/{print $2}') ==="

# 1. Start full dmesg capture on each node (kill any prior capture first).
for n in "${NODES[@]}"; do
    timeout 12 $SSH "$n" "$PF" '
        pkill -f "dmesg --follow" 2>/dev/null; sleep 1
        : > /tmp/drc_full.log
        # Detach ALL std fds (esp. stdin </dev/null) + setsid so the ssh
        # channel closes immediately and timeout does not kill the follower.
        setsid sh -c "exec dmesg --follow > /tmp/drc_full.log 2>&1" </dev/null >/dev/null 2>&1 &
        sleep 1
        echo "  capture on $(hostname): pid=$(pgrep -f \"dmesg --follow\"|head -1) lines=$(wc -l < /tmp/drc_full.log)"' 2>&1 | strip
done

# 2. Run the single test (run.sh handles prep/mkfs/mount/load + record).
echo "--- running ./run.sh 2 tcp dir_reuse_coherency ---"
timeout 450 ./run.sh 2 tcp dir_reuse_coherency 2>&1 | strip | tail -8

# 3. Stop capture, leave the full log in place on each node.
for n in "${NODES[@]}"; do
    timeout 12 $SSH "$n" "$PF" 'pkill -f "dmesg --follow" 2>/dev/null;
        echo "  $(hostname): $(wc -l < /tmp/drc_full.log) lines captured"' 2>&1 | strip
done
echo "=== capture done @ $(date -u +%T) — analyze /tmp/drc_full.log on each node ==="
