#!/bin/bash
# drc_pr_p54.sh N "MODARGS" — dir_reuse_coherency 8/tcp reliability with P54
# residual capture.  Clean-reboots all 8 nodes + clears stale /root/drc_*
# markers before EVERY run, runs dir_reuse, records PASS/FAIL + wall.  On FAIL
# it pulls the numeric-FIRST fail-round dmesg snapshot from each node and
# reports the lost dirent + the sess54 P54/P28 epoch-refresh counts so the
# residual under-fire is captured WITHOUT a second reboot wiping it.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd); cd "$REPO"
N="${1:?need run count}"; MODARGS="${2:-}"
SCR=/tmp/claude-1000/-src-mxfs/87ee9acf-8602-41fc-8637-6be2e51b8128/scratchpad
mkdir -p "$SCR"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
OUT="$SCR/pr_p54.log"
flt() { grep -vE '^Warning:|^Unauthorized|^If you'; }
echo "=== drc_pr_p54 N=$N modargs=[$MODARGS] $(date -u) ===" | tee "$OUT"
pass=0; fail=0
for run in $(seq 1 "$N"); do
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
    sleep 5
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
    up=0
    for w in $(seq 1 40); do
        up=0
        for n in 1 2 3 4 5 6 7 8; do timeout 5 $SSH test$n $PASS true >/dev/null 2>&1 && up=$((up+1)); done
        [ "$up" = 8 ] && break
        sleep 3
    done
    sleep 15
    for n in 1 2 3 4 5 6 7 8; do timeout 8 $SSH test$n $PASS 'rm -f /root/drc_failrounds.txt /root/drc_*.dmesg 2>/dev/null; dmesg -C' >/dev/null 2>&1; done
    t0=$(date +%s)
    MXFS_EXTRA_MODARGS="$MODARGS" timeout 590 ./run.sh 8 tcp dir_reuse_coherency > "$SCR/prp54_run${run}.log" 2>&1
    rc=$?
    t1=$(date +%s)
    if grep -q "PASS  dir_reuse_coherency" "$SCR/prp54_run${run}.log"; then
        echo "run $run: PASS rc=$rc wall=$((t1-t0))s up=$up" | tee -a "$OUT"
        pass=$((pass+1))
    else
        fail=$((fail+1))
        fr=$(timeout 15 $SSH test1 $PASS 'head -2 /root/drc_failrounds.txt 2>/dev/null' 2>/dev/null | flt | tr '\n' ' ')
        echo "run $run: FAIL rc=$rc wall=$((t1-t0))s up=$up [$fr]" | tee -a "$OUT"
        for n in 1 2 3 4 5 6 7 8; do
            line=$(timeout 20 $SSH test$n $PASS '
                FR=$(ls -1 /root/drc_fail_r*.dmesg 2>/dev/null | sed -E "s/.*_r([0-9]+)_.*/\1 &/" | sort -n | head -1 | cut -d" " -f2-)
                [ -z "$FR" ] && exit 0
                lost=$(grep -aoE "missing_from_readdir=\[[^]]*\]" "$FR" | tail -1 | head -c 90)
                printf "lost=%s KG=%s MEPZ=%s REFRESH=%s P51UF=%s NEWSLOT=%s" \
                  "$lost" \
                  "$(grep -ac P54-KEEPGUARD-STALE "$FR")" \
                  "$(grep -ac P54-MEPZERO "$FR")" \
                  "$(grep -ac P28-ADDNAME-EPOCHSTALE "$FR")" \
                  "$(grep -ac P51-HANDOFF-UNDERFIRE "$FR")" \
                  "$(grep -ac "P-DGEX-NEWSLOT ino=131" "$FR")"
            ' 2>/dev/null | flt)
            echo "    test$n: $line" | tee -a "$OUT"
        done
    fi
done
echo "=== TOTAL pass=$pass fail=$fail of $N ===" | tee -a "$OUT"
