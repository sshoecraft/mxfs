#!/bin/bash
# drc_ab.sh — A/B reliability comparison for the dir_reuse_coherency 8/tcp blocker.
# Runs RUNS_PER iterations under each of the two modarg sets, clean-rebooting all
# 8 nodes + clearing markers before EVERY run, and records PASS/FAIL + the
# numeric-first fail round + loss count.  Lets us tell whether a lever is net
# positive without conflating it with the high run-to-run variance.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
RUNS_PER="${1:-4}"
SCR=/tmp/claude-1000/-src-mxfs/87ee9acf-8602-41fc-8637-6be2e51b8128/scratchpad
mkdir -p "$SCR"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
OUT="$SCR/ab.log"
flt() { grep -vE '^Warning:|^Unauthorized|^If you'; }
echo "=== drc_ab RUNS_PER=$RUNS_PER $(date -u) ===" | tee "$OUT"

run_one() {  # $1=label $2=modargs
    local label="$1" modargs="$2" run rc t0 t1 res fr
    local pass=0 fail=0
    for run in $(seq 1 "$RUNS_PER"); do
        for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
        sleep 5
        for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
        local up=0
        for w in $(seq 1 40); do up=0; for n in 1 2 3 4 5 6 7 8; do timeout 5 $SSH test$n $PASS true >/dev/null 2>&1 && up=$((up+1)); done; [ "$up" = 8 ] && break; sleep 3; done
        sleep 15
        for n in 1 2 3 4 5 6 7 8; do timeout 8 $SSH test$n $PASS 'rm -f /root/drc_failrounds.txt /root/drc_*.dmesg 2>/dev/null; dmesg -C' >/dev/null 2>&1; done
        t0=$(date +%s)
        MXFS_EXTRA_MODARGS="$modargs" timeout 590 ./run.sh 8 tcp dir_reuse_coherency > "$SCR/ab_${label}_${run}.log" 2>&1
        rc=$?; t1=$(date +%s)
        if grep -q "PASS  dir_reuse_coherency" "$SCR/ab_${label}_${run}.log"; then
            res=PASS; pass=$((pass+1)); fr=""
        else
            res=FAIL; fail=$((fail+1))
            fr=$(timeout 15 $SSH test1 $PASS 'sort -t= -k2 -n /root/drc_failrounds.txt 2>/dev/null | head -1' 2>/dev/null | flt | tr -d "\r")
        fi
        echo "[$label] run $run: $res rc=$rc wall=$((t1-t0))s up=$up {$fr}" | tee -a "$OUT"
    done
    echo "[$label] TOTAL pass=$pass fail=$fail of $RUNS_PER" | tee -a "$OUT"
}

run_one "refresh0" "mxfs.dir_addname_epoch_refresh=0"
run_one "refresh1" "mxfs.dir_addname_epoch_refresh=1"
echo "=== drc_ab DONE $(date -u) ===" | tee -a "$OUT"
