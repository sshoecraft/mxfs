#!/bin/bash
# drc_passrate.sh N "MODARGS" — characterize dir_reuse_coherency 8/tcp reliability.
# Clean-reboots all 8 nodes before EVERY run (a contaminated cluster gives false
# cascade fails), runs dir_reuse with the given modargs, records PASS/FAIL + wall.
# Usage: tests/tcp/drc_passrate.sh 4 "inode_mht_ms=1200"
set -u
N="${1:?need run count}"; MODARGS="${2:-}"
SCR=/tmp/claude-1000/-src-mxfs/9f2cd211-1a2f-47f2-bb46-086b0e960a08/scratchpad
OUT="$SCR/passrate.log"
echo "=== drc_passrate N=$N modargs=[$MODARGS] $(date -u) ===" | tee "$OUT"
pass=0; fail=0
for run in $(seq 1 "$N"); do
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
    sleep 5
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
    # wait for all up
    up=0
    for w in $(seq 1 30); do
        up=0
        for n in 1 2 3 4 5 6 7 8; do timeout 5 tools/mxfs_sshpass.sh test$n /tmp/.mxfs_pass true >/dev/null 2>&1 && up=$((up+1)); done
        [ "$up" = 8 ] && break
        sleep 3
    done
    t0=$(date +%s)
    MXFS_EXTRA_MODARGS="$MODARGS" timeout 590 ./run.sh 8 tcp dir_reuse_coherency > "$SCR/pr_run${run}.log" 2>&1
    rc=$?
    t1=$(date +%s)
    if grep -q "PASS  dir_reuse_coherency" "$SCR/pr_run${run}.log"; then
        res=PASS; pass=$((pass+1))
    else
        res=FAIL; fail=$((fail+1))
    fi
    echo "run $run: $res rc=$rc wall=$((t1-t0))s up=$up" | tee -a "$OUT"
done
echo "=== TOTAL pass=$pass fail=$fail of $N ===" | tee -a "$OUT"
