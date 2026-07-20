#!/bin/bash
# repro_fdw_only_loop.sh — rapid-fire fence_during_write-ONLY iterations
# (skips dir_reuse_coherency) to maximize repro attempts/wall-clock for a
# rare bug that only shows up under fence_during_write's hot-dir churn.
# Per RULE 3 this lives in the source tree (reusable for any future rare-bug
# hunt under this specific test, not just this session's).
#
# Usage: repro_fdw_only_loop.sh <N_nodes> <iters> <outdir>
# Stops early (prints STOP_EARLY) if any node shows a crash signature
# (invalid opcode / kernel BUG) or the P125-EVICT-SUSPECT diagnostic fires.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
cd "$REPO"

N="${1:-8}"
ITERS="${2:-10}"
OUT="${3:?usage: repro_fdw_only_loop.sh <N> <iters> <outdir>}"
mkdir -p "$OUT"

for n in $(seq 1 "$N"); do
    ( timeout 15 "$SSH" "test$n" "$PASS" "dmesg -C" >/dev/null 2>&1 ) &
done
wait

for i in $(seq 1 "$ITERS"); do
    echo "$(date -u +%H:%M:%S) === iter $i/$ITERS ===" | tee -a "$OUT/loop.log"
    rm -f /tmp/mxfs_run.lock
    MXFS_DEV=/dev/mapper/mpatha TEST_TIMEOUT=180 timeout 240 ./run.sh "$N" caw fence_during_write \
        > "$OUT/iter${i}.log" 2>&1
    rc=$?
    tail -5 "$OUT/iter${i}.log" | tee -a "$OUT/loop.log"
    echo "$(date -u +%H:%M:%S) iter $i rc=$rc" | tee -a "$OUT/loop.log"

    hit=0
    for n in $(seq 1 "$N"); do
        out=$(timeout 8 "$SSH" "test$n" "$PASS" "
            dmesg | grep -ciE 'invalid opcode|kernel BUG|P125-EVICT-SUSPECT|P124-DWFN-BADREF'
        " 2>/dev/null | tail -1)
        if [ -n "$out" ] && [ "$out" != "0" ]; then
            echo "$(date -u +%H:%M:%S) test$n HIT ($out matches) — dumping" | tee -a "$OUT/loop.log"
            timeout 10 "$SSH" "test$n" "$PASS" "
                dmesg -T | grep -iE 'invalid opcode|kernel BUG|P125-EVICT-SUSPECT|P124-DWFN-BADREF' -A5 -B5
            " 2>/dev/null > "$OUT/hit_test${n}_iter${i}.log"
            hit=1
        fi
    done
    if [ "$hit" = 1 ]; then
        echo "$(date -u +%H:%M:%S) STOP_EARLY at iter $i — evidence captured in $OUT/hit_test*.log" | tee -a "$OUT/loop.log"
        echo DONE_EARLY > "$OUT/.done"
        exit 0
    fi
done
echo "$(date -u +%H:%M:%S) completed $ITERS iterations with no hit" | tee -a "$OUT/loop.log"
echo DONE_CLEAN > "$OUT/.done"
