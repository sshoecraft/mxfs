#!/bin/bash
# drc_passrate2.sh N "MODARGS" — dir_reuse_coherency 8/tcp reliability.
# Clean-reboots all 8 nodes + CLEARS the stale /root/drc_* markers (sess27
# contamination) before EVERY run, runs dir_reuse with the given modargs,
# records PASS/FAIL + wall + the actual readdir count on FAIL (from the fresh
# fail-round marker, not the stale head).
set -u
N="${1:?need run count}"; MODARGS="${2:-}"
SCR=/tmp/claude-1000/-src-mxfs/efdc16a7-85d5-4b89-985f-6934a7de0517/scratchpad
mkdir -p "$SCR"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
OUT="$SCR/passrate2.log"
echo "=== drc_passrate2 N=$N modargs=[$MODARGS] $(date -u) ===" | tee "$OUT"
pass=0; fail=0
for run in $(seq 1 "$N"); do
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
    sleep 5
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
    up=0
    for w in $(seq 1 30); do
        up=0
        for n in 1 2 3 4 5 6 7 8; do timeout 5 $SSH test$n /tmp/.mxfs_pass true >/dev/null 2>&1 && up=$((up+1)); done
        [ "$up" = 8 ] && break
        sleep 3
    done
    for n in 1 2 3 4 5 6 7 8; do timeout 8 $SSH test$n /tmp/.mxfs_pass 'rm -f /root/drc_failrounds.txt /root/drc_*.dmesg 2>/dev/null' >/dev/null 2>&1; done
    t0=$(date +%s)
    MXFS_EXTRA_MODARGS="$MODARGS" timeout 590 /src/mxfs/run.sh 8 tcp dir_reuse_coherency > "$SCR/pr2_run${run}.log" 2>&1
    rc=$?
    t1=$(date +%s)
    if grep -q "PASS  dir_reuse_coherency" "$SCR/pr2_run${run}.log"; then
        res=PASS; pass=$((pass+1)); extra=""
    else
        res=FAIL; fail=$((fail+1))
        fr=$(timeout 15 $SSH test1 /tmp/.mxfs_pass 'head -1 /root/drc_failrounds.txt 2>/dev/null')
        extra=" [$fr]"
    fi
    echo "run $run: $res rc=$rc wall=$((t1-t0))s up=$up$extra" | tee -a "$OUT"
done
echo "=== TOTAL pass=$pass fail=$fail of $N ===" | tee -a "$OUT"
