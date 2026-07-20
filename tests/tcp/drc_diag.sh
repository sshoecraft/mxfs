#!/bin/bash
# drc_diag.sh [MAXRUNS] [COHERENT] — sess28 cascade-vs-loss diagnostic.
# Reboots 8 nodes, runs dir_reuse with dir_addname_coherent=COHERENT, and on
# EACH run captures from every node: result, wall, shutdown/corruption count,
# P28C-REFRESH count, drc-RDMISS count.  Distinguishes a SHUTDOWN cascade
# (corruption>0) from a clean dirent loss (RDMISS>0, corruption=0).
set -u
MAX="${1:-3}"
COH="${2:-1}"
MODARGS="dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_addname_coherent=$COH"
SCR="$(dirname "$0")/drc_cap"; mkdir -p "$SCR"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
LOG="$SCR/diag.log"
echo "=== drc_diag MAX=$MAX coherent=$COH modargs=[$MODARGS] $(date -u) ===" | tee "$LOG"
for run in $(seq 1 "$MAX"); do
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
    sleep 6
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
    for w in $(seq 1 40); do up=0; for n in 1 2 3 4 5 6 7 8; do timeout 5 $SSH test$n /tmp/.mxfs_pass true >/dev/null 2>&1 && up=$((up+1)); done; [ "$up" = 8 ] && break; sleep 3; done
    t0=$(date +%s)
    MXFS_EXTRA_MODARGS="$MODARGS" \
        timeout 590 /src/mxfs/run.sh 8 tcp dir_reuse_coherency > "$SCR/diag_run${run}.log" 2>&1
    t1=$(date +%s)
    RES=$(grep -qE "PASS  dir_reuse_coherency" "$SCR/diag_run${run}.log" && echo PASS || echo FAIL)
    echo "run $run: $RES wall=$((t1-t0))s" | tee -a "$LOG"
    for n in 1 2 3 4 5 6 7 8; do
        line=$(timeout 12 $SSH test$n /tmp/.mxfs_pass 'echo "shut=$(dmesg|grep -ciE "Corruption of in-memory|EFSCORRUPTED|EFSBADCRC|Internal error|forced shutdown")  p28c=$(dmesg|grep -c P28C-REFRESH)  rdmiss=$(dmesg|grep -c drc-RDMISS)"' 2>/dev/null)
        echo "  test$n: $line" | tee -a "$LOG"
    done
done
echo "=== done $(date -u) ===" | tee -a "$LOG"
