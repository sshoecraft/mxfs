#!/bin/bash
# drc_platter.sh [MAXRUNS] [GUARD] — sess28 decisive read-vs-write classifier.
# Reboots 8 nodes, runs dir_reuse_coherency with the targeted platter guard
# (dir_addname_platter_guard=GUARD) on the working modargs, then collects
# P28W-CLOBBER from EVERY node's dmesg.  P28W-CLOBBER firing => the addname's
# chosen slot is OCCUPIED on the platter while in-core thinks FREE = READ-side
# stale base (the clobber caught red-handed at the write offset).  Zero hits
# across a failing run => WRITE-side (platter genuinely lacks the peer entry).
set -u
MAX="${1:-1}"
GUARD="${2:-1}"
MODARGS="dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_addname_platter_guard=$GUARD"
SCR="$(dirname "$0")/drc_cap"; mkdir -p "$SCR"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
LOG="$SCR/platter.log"
echo "=== drc_platter MAX=$MAX modargs=[$MODARGS] $(date -u) ===" | tee "$LOG"
for run in $(seq 1 "$MAX"); do
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
    sleep 5
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
    for w in $(seq 1 30); do up=0; for n in 1 2 3 4 5 6 7 8; do timeout 5 $SSH test$n /tmp/.mxfs_pass true >/dev/null 2>&1 && up=$((up+1)); done; [ "$up" = 8 ] && break; sleep 3; done
    for n in 1 2 3 4 5 6 7 8; do timeout 8 $SSH test$n /tmp/.mxfs_pass 'rm -f /root/drc_failrounds.txt 2>/dev/null' >/dev/null 2>&1; done
    t0=$(date +%s)
    MXFS_EXTRA_MODARGS="$MODARGS" \
        timeout 590 /src/mxfs/run.sh 8 tcp dir_reuse_coherency > "$SCR/platter_run${run}.log" 2>&1
    t1=$(date +%s)
    RES=$(grep -qE "PASS  dir_reuse_coherency" "$SCR/platter_run${run}.log" && echo PASS || echo FAIL)
    echo "run $run: $RES wall=$((t1-t0))s" | tee -a "$LOG"
    # collect P28W-CLOBBER + readdir miss from every node
    tot=0
    for n in 1 2 3 4 5 6 7 8; do
        c=$(timeout 15 $SSH test$n /tmp/.mxfs_pass 'dmesg | grep -c "P28W-CLOBBER"' 2>/dev/null)
        c=${c:-0}; tot=$((tot+c))
        [ "$c" -gt 0 ] && echo "  test$n P28W-CLOBBER=$c" | tee -a "$LOG"
        timeout 15 $SSH test$n /tmp/.mxfs_pass 'dmesg | grep "P28W-CLOBBER" | head -3' 2>/dev/null | sed "s/^/    test$n: /" | tee -a "$LOG"
    done
    echo "run $run: TOTAL P28W-CLOBBER=$tot ($RES)" | tee -a "$LOG"
done
echo "=== done $(date -u) ===" | tee -a "$LOG"
