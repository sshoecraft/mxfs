#!/bin/bash
# drc_one.sh [COHERENT] [ROUNDS] — single instrumented dir_reuse 8/tcp run.
# Reset, run with dir_addname_coherent=COHERENT and DRC_ROUNDS=ROUNDS, then
# capture from every node: result, P28E (helper reached FUA; diff=1 => stale
# caught), P28C-STALE (fix fired), drc-RDMISS (loss), corruption/shutdown.
set -u
COH="${1:-1}"
RND="${2:-24}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
SCR="$(dirname "$0")/drc_cap"; mkdir -p "$SCR"
LOG="$SCR/one.log"
for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
sleep 7
for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
for w in $(seq 1 40); do up=0; for n in 1 2 3 4 5 6 7 8; do timeout 5 $SSH test$n /tmp/.mxfs_pass true >/dev/null 2>&1 && up=$((up+1)); done; [ "$up" = 8 ] && break; sleep 3; done
echo "=== drc_one coherent=$COH rounds=$RND nodes_up=$up $(date -u) ===" | tee "$LOG"
t0=$(date +%s)
MXFS_EXTRA_MODARGS="dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_addname_coherent=$COH ${EXTRA:-}" \
    MXFS_TEST_ENV="DRC_ROUNDS=$RND ${DRC_STREAM:+DRC_STREAM=1}" \
    timeout 590 /src/mxfs/run.sh 8 tcp dir_reuse_coherency > "$SCR/one_run.log" 2>&1
t1=$(date +%s)
RES=$(grep -qE "PASS  dir_reuse_coherency" "$SCR/one_run.log" && echo PASS || echo FAIL)
echo "RESULT: $RES wall=$((t1-t0))s" | tee -a "$LOG"
for n in 1 2 3 4 5 6 7 8; do
    line=$(timeout 15 $SSH test$n /tmp/.mxfs_pass 'echo "p28e=$(dmesg|grep -c "P28E ")  diff1=$(dmesg|grep "P28E "|grep -c "diff=1")  p28c=$(dmesg|grep -c P28C-STALE)  p26=$(dmesg|grep -c P26-SUBSET-SKIP)  p12=$(dmesg|grep -c P12-DIR-EXGUARD)  rdmiss=$(dmesg|grep -c drc-RDMISS)  corrupt=$(dmesg|grep -ciE "Corruption of in-memory|EFSCORRUPTED|EFSBADCRC|forced shutdown")"' 2>/dev/null)
    echo "  test$n: $line" | tee -a "$LOG"
done
echo "=== P-WMERGE classification (all nodes) ===" | tee -a "$LOG"
for n in 1 2 3 4 5 6 7 8; do
    mn=$(timeout 12 $SSH test$n /tmp/.mxfs_pass 'echo "merge=$(dmesg|grep -c "MERGE-NEEDED")  stale=$(dmesg|grep "P-WMERGE"|grep -c "pure-stale")"' 2>/dev/null)
    echo "  test$n: $mn" | tee -a "$LOG"
done
echo "=== sample P-WMERGE lines (test1) ===" | tee -a "$LOG"
timeout 12 $SSH test1 /tmp/.mxfs_pass 'dmesg|grep "P-WMERGE"|head -4' 2>/dev/null | tee -a "$LOG"
echo "=== done $(date -u) ===" | tee -a "$LOG"
