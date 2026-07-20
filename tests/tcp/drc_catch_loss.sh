#!/bin/bash
# drc_catch_loss.sh [MAXRUNS] [MODARGS] — reboot+run dir_reuse 8/tcp until a FAIL,
# then pull every node's fail-round dmesg snapshot + failrounds marker to the dev
# host for post-mortem (which dir block was the stale base; evict-decision trail).
set -u
MAX="${1:-6}"; MODARGS="${2:-}"
SCR=/tmp/claude-1000/-src-mxfs/9f2cd211-1a2f-47f2-bb46-086b0e960a08/scratchpad
CAP=/src/mxfs/tests/tcp/loss_cap; mkdir -p "$CAP"; rm -f "$CAP"/* 2>/dev/null
echo "=== catch_loss MAX=$MAX modargs=[$MODARGS] $(date -u) ===" | tee "$SCR/catch.log"
for run in $(seq 1 "$MAX"); do
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
    sleep 5
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
    for w in $(seq 1 30); do up=0; for n in 1 2 3 4 5 6 7 8; do timeout 5 tools/mxfs_sshpass.sh test$n /tmp/.mxfs_pass true >/dev/null 2>&1 && up=$((up+1)); done; [ "$up" = 8 ] && break; sleep 3; done
    t0=$(date +%s)
    MXFS_EXTRA_MODARGS="$MODARGS" timeout 590 ./run.sh 8 tcp dir_reuse_coherency > "$SCR/cl_run${run}.log" 2>&1
    t1=$(date +%s)
    if grep -q "PASS  dir_reuse_coherency" "$SCR/cl_run${run}.log"; then
        echo "run $run: PASS wall=$((t1-t0))s" | tee -a "$SCR/catch.log"
    else
        echo "run $run: FAIL wall=$((t1-t0))s — capturing" | tee -a "$SCR/catch.log"
        for n in 1 2 3 4 5 6 7 8; do
            timeout 15 tools/mxfs_sshpass.sh test$n /tmp/.mxfs_pass "cat /root/drc_failrounds.txt 2>/dev/null" > "$CAP/failrounds_test$n.txt" 2>/dev/null
            timeout 30 tools/mxfs_sshpass.sh test$n /tmp/.mxfs_pass "ls /root/drc_fail_*.dmesg 2>/dev/null | head -1 | xargs cat 2>/dev/null" > "$CAP/faildmesg_test$n.txt" 2>/dev/null
        done
        echo "captured to $CAP" | tee -a "$SCR/catch.log"
        break
    fi
done
echo "=== catch done ===" | tee -a "$SCR/catch.log"
