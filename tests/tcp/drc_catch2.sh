#!/bin/bash
# drc_catch2.sh [MAXRUNS] [MODARGS] — reboot+run dir_reuse 8/tcp until a FAIL,
# then for the ACTUAL fail round (read from /root/drc_failrounds.txt) pull every
# node's create+verify dmesg snapshot AND extract the loss-mechanism probe lines
# (RDMISS/CLASS = which name + lookup-state; DIR-STALE-SKIP = stale base kept;
# P60-GENMATCH-STALE = gen-match-but-stale; P63/P-FASTEX = handoff/epoch fires).
# Fixes drc_catch_loss.sh which grabbed `ls drc_fail_*.dmesg | head -1` = the
# stale ROUND-1 file, missing the real (e.g. round-13) single-entry loss trail.
set -u
MAX="${1:-8}"; MODARGS="${2:-}"
SCR=/tmp/claude-1000/-src-mxfs/efdc16a7-85d5-4b89-985f-6934a7de0517/scratchpad
mkdir -p "$SCR"
CAP=/src/mxfs/tests/tcp/loss_cap2; mkdir -p "$CAP"; rm -f "$CAP"/* 2>/dev/null
SSH=/src/mxfs/tools/mxfs_sshpass.sh
echo "=== catch2 MAX=$MAX modargs=[$MODARGS] $(date -u) ===" | tee "$SCR/catch2.log"
for run in $(seq 1 "$MAX"); do
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
    sleep 5
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
    for w in $(seq 1 30); do up=0; for n in 1 2 3 4 5 6 7 8; do timeout 5 $SSH test$n /tmp/.mxfs_pass true >/dev/null 2>&1 && up=$((up+1)); done; [ "$up" = 8 ] && break; sleep 3; done
    t0=$(date +%s)
    MXFS_EXTRA_MODARGS="$MODARGS" timeout 590 /src/mxfs/run.sh 8 tcp dir_reuse_coherency > "$SCR/c2_run${run}.log" 2>&1
    t1=$(date +%s)
    if grep -q "PASS  dir_reuse_coherency" "$SCR/c2_run${run}.log"; then
        echo "run $run: PASS wall=$((t1-t0))s" | tee -a "$SCR/catch2.log"
        continue
    fi
    echo "run $run: FAIL wall=$((t1-t0))s — capturing actual fail round" | tee -a "$SCR/catch2.log"
    # which round failed (from rank1's persistent marker)
    FR=$(timeout 15 $SSH test1 /tmp/.mxfs_pass "head -1 /root/drc_failrounds.txt 2>/dev/null")
    RND=$(echo "$FR" | grep -oE "round=[0-9]+" | head -1 | cut -d= -f2)
    echo "fail marker: $FR  (round=$RND)" | tee -a "$SCR/catch2.log"
    for n in 1 2 3 4 5 6 7 8; do
        timeout 15 $SSH test$n /tmp/.mxfs_pass "cat /root/drc_failrounds.txt 2>/dev/null" > "$CAP/failrounds_test$n.txt" 2>/dev/null
        if [ -n "$RND" ]; then
            timeout 30 $SSH test$n /tmp/.mxfs_pass "cat /root/drc_failverify_r${RND}_rank${n}.dmesg 2>/dev/null" > "$CAP/failverify_r${RND}_test$n.txt" 2>/dev/null
            timeout 30 $SSH test$n /tmp/.mxfs_pass "cat /root/drc_create_r${RND}_rank${n}.dmesg /dev/shm/drc_create_r${RND}_rank${n}.dmesg 2>/dev/null" > "$CAP/create_r${RND}_test$n.txt" 2>/dev/null
        fi
    done
    echo "--- RDMISS/CLASS (round $RND) ---" | tee -a "$SCR/catch2.log"
    grep -h "drc-RDMISS round=$RND\|drc-CLASS round=$RND" "$CAP"/failverify_r${RND}_test*.txt 2>/dev/null | sort -u | tee -a "$SCR/catch2.log"
    echo "--- DIR-STALE-SKIP / P60-GENMATCH-STALE counts per node (round $RND verify dmesg) ---" | tee -a "$SCR/catch2.log"
    for n in 1 2 3 4 5 6 7 8; do
        ss=$(grep -c "DIR-STALE-SKIP" "$CAP/failverify_r${RND}_test$n.txt" 2>/dev/null)
        gm=$(grep -c "P60-GENMATCH-STALE" "$CAP/failverify_r${RND}_test$n.txt" 2>/dev/null)
        echo "test$n: DIR-STALE-SKIP=$ss P60-GENMATCH-STALE=$gm" | tee -a "$SCR/catch2.log"
    done
    echo "captured to $CAP" | tee -a "$SCR/catch2.log"
    break
done
echo "=== catch2 done ===" | tee -a "$SCR/catch2.log"
