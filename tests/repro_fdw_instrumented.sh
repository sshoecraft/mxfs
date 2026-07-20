#!/bin/bash
# repro_fdw_instrumented.sh — one dir_reuse_coherency+fence_during_write pass
# at 8/caw with a live sampler running alongside (ps state histogram + any
# non-R/S process names + dmesg tail per node, every 15s) so a stall is
# caught with a timeline instead of requiring a post-mortem D-state search.
# Sess: diagnosing the NEW (non-hung, non-D-state) fence_during_write@8/caw
# timeout that survived the ccloop703f-sess1 demoter/irele fix.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
cd "$REPO"
N=8
OUT="${1:?usage: repro_fdw_instrumented.sh <outdir>}"
mkdir -p "$OUT"

for n in $(seq 1 "$N"); do
    ( timeout 15 "$SSH" "test$n" "$PASS" "dmesg -C" >/dev/null 2>&1 ) &
done
wait

DRC_TT=$(( 140 * N + 300 ))
OUTER=$(( DRC_TT + 300 ))

( MXFS_DEV=/dev/mapper/mpatha TEST_TIMEOUT="$DRC_TT" timeout "$OUTER" \
    ./run.sh "$N" caw dir_reuse_coherency fence_during_write \
    > "$OUT/run.log" 2>&1
  echo "RUN_EXIT=$?" >> "$OUT/run.log" ) &
RUNPID=$!

sample_end=$(( $(date +%s) + OUTER + 30 ))
while kill -0 "$RUNPID" 2>/dev/null && [ "$(date +%s)" -lt "$sample_end" ]; do
    ts=$(date -u +%H:%M:%S)
    for n in $(seq 1 "$N"); do
        (
            out=$(timeout 8 "$SSH" "test$n" "$PASS" "
                st=\$(ps -eo stat,pid,comm --no-headers | awk '{print substr(\$1,1,1)}' | sort | uniq -c | tr '\n' ' ')
                bad=\$(ps -eo stat,pid,etimes,comm --no-headers | awk '\$1 !~ /^[RS]/')
                dm=\$(dmesg | tail -3)
                echo \"STATES: \$st\"
                [ -n \"\$bad\" ] && echo \"NONRS: \$bad\"
                echo \"DMESG: \$dm\"
            " 2>/dev/null)
            echo "[$ts] test$n: $out" >> "$OUT/sample.log"
        ) &
    done
    wait
    sleep 15
done
wait "$RUNPID" 2>/dev/null
echo "=== sampler done, run.log tail: ==="
tail -20 "$OUT/run.log"
