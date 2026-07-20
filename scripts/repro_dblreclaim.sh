#!/bin/bash
# repro_dblreclaim.sh — loop a warmup test (default dir_reuse_coherency, which
# heavily churns inode allocation/reuse) immediately followed by
# fence_during_write in the SAME cluster session (fresh prep only between
# loop iterations, not between the two tests), checking dmesg on every node
# after each iteration for the P-DBLRECLAIM diagnostic (xfs_icache.c
# XFS_ALL_IRECLAIM_FLAGS double-set) or a soft/hard lockup.
#
# Rationale (ccloopff21 sess1): an isolated fresh-prep fence_during_write loop
# (15 iters) never reproduced the wedge seen in the original 8/caw "full" run,
# where fence_during_write was the 14th of 17 tests in one continuous cluster
# session (13 prior tests, including dir_reuse_coherency, had already run).
# This script recreates that "warmed up" AG/inode state cheaply (2 tests
# instead of 13) rather than a full 17-test replay.
#
# Usage: scripts/repro_dblreclaim.sh <N> <iters> [warmup_test]
set -u
N="${1:?usage: repro_dblreclaim.sh <N> <iters> [warmup_test]}"
ITERS="${2:?usage: repro_dblreclaim.sh <N> <iters> [warmup_test]}"
WARMUP="${3:-dir_reuse_coherency}"
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
cd "$REPO"

DRC_TT=$(( 140 * N + 300 ))
OUTER=$(( DRC_TT + 300 ))

for i in $(seq 1 "$ITERS"); do
    echo "=== repro_dblreclaim iter $i/$ITERS warmup=$WARMUP + fence_during_write N=$N ==="
    for n in $(seq 1 "$N"); do
        ( timeout 15 "$SSH" "test$n" "$PASS" "dmesg -C" >/dev/null 2>&1 ) &
    done
    wait
    MXFS_DEV=/dev/mapper/mpatha TEST_TIMEOUT="$DRC_TT" timeout "$OUTER" \
        ./run.sh "$N" caw "$WARMUP" fence_during_write
    rc=$?
    hit=0
    for n in $(seq 1 "$N"); do
        out=$(timeout 15 "$SSH" "test$n" "$PASS" \
            "dmesg | grep -E 'P-DBLRECLAIM|soft lockup|hard lockup|Assertion failed'" 2>/dev/null)
        if [ -n "$out" ]; then
            echo "--- HIT on test$n (iter $i) ---"
            echo "$out"
            hit=1
        fi
    done
    if [ "$hit" = 1 ]; then
        echo "=== REPRO on iter $i — stopping loop, node(s) left as-is for inspection ==="
        exit 0
    fi
    if [ "$rc" != 0 ]; then
        echo "=== run.sh rc=$rc on iter $i (non-hang failure, continuing) ==="
    fi
done
echo "=== repro_dblreclaim: $ITERS iters, NO HIT ==="
exit 1
