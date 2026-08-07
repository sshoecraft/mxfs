#!/bin/bash
# drc_pace_ab.sh <arm_ms> [runs]
#
# Acceptance measurement for the sess24 bounded shared-class patience fix
# (mxfs.caw_pr_defer_max_ms), stated in the units RULE 0 cares about: how many
# dir_reuse_coherency reuse ROUNDS fit inside the criterion's fixed 100s time box
# at 32 nodes.
#
# Rounds are not printed directly, but they are recoverable exactly: the node
# script emits 1 ready barrier + 7 checks per completed round (4 barriers + 3
# ckeq) + 1 final pace assertion, so
#
#       checks = 7 * rounds + 2
#
# Verified integral against every recorded condition in criteria.json (1..32
# nodes, caw/cawd/cawp/tcp/xfs -- all 25 conditions give an exact integer).
#
# Why this matters: DRC_MIN_ROUNDS=8 is a hard floor, and the 32-node column sat
# at EXACTLY 8 rounds pre-fix (7 on the run that failed).  Zero margin is why
# D-DIR-REUSE-COHERENCY-32-FLAKY presented as "all 32 nodes agree on a wrong
# answer" -- rank 1 coordinates the time box, so every node fails the same pace
# assertion together.  Margin, not luck, is the fix criterion.
#
# One run per invocation so each stays inside a foreground timeout (project
# guidance: no backgrounded batches).  Call it alternately per arm.
set -u
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
ARM="${1:?usage: drc_pace_ab.sh <caw_pr_defer_max_ms> [runs]}"
RUNS="${2:-1}"
N=32

for i in $(seq 1 "$N"); do
    ( "$SSH" "test$i" \
        "echo $ARM > /sys/module/mxfs/parameters/caw_pr_defer_max_ms" \
        >/dev/null 2>&1 ) &
done
wait
bad=0
for i in $(seq 1 "$N"); do
    got=$("$SSH" "test$i" "cat /sys/module/mxfs/parameters/caw_pr_defer_max_ms" \
          2>/dev/null | tr -d '\r\n ')
    [ "$got" = "$ARM" ] || { echo "!! test$i arm=[$got] want=$ARM"; bad=1; }
done
[ "$bad" = 0 ] || { echo "!! ARM NOT UNIFORM -- measurement invalid"; exit 3; }
echo "=== arm caw_pr_defer_max_ms=$ARM verified on all $N nodes ==="

for r in $(seq 1 "$RUNS"); do
    out=$(cd "$REPO" && timeout 380 ./run.sh 32 caw dir_reuse_coherency 2>&1 \
          | grep -E "dir_reuse_coherency" | tail -1)
    ch=$(echo "$out" | grep -oE "checks=[0-9]+" | head -1 | cut -d= -f2)
    st=$(echo "$out" | grep -oE "^ *(PASS|FAIL|BLOCKED|ABORTED|NOT_RUN)" | tr -d ' ')
    el=$(echo "$out" | grep -oE "\[[0-9]+s/[0-9]+s\]" | head -1)
    if [ -n "$ch" ]; then
        printf 'ARM=%-4s run %d  %-6s checks=%-4s rounds=%s  %s\n' \
            "$ARM" "$r" "${st:-?}" "$ch" "$(( (ch - 2) / 7 ))" "$el"
    else
        printf 'ARM=%-4s run %d  %-6s NO CHECK COUNT: %s\n' \
            "$ARM" "$r" "${st:-?}" "$out"
    fi
done
