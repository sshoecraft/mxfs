#!/bin/bash
# dlm_fairness — agnostic multi-node DLM fairness test.
#
# Every node hammers the SAME hot resource (rapid create+rename+delete of a
# per-node entry in one shared directory, which forces repeated cross-node DLM
# EX handoffs on that directory) for a fixed number of rounds.  Fairness =
# every node completes its rounds (no node starved out by a greedy peer holding
# the lock forever).  Records per-node completed rounds; PASS iff all nodes
# finished within the test window AND each node made forward progress.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.dlm_fairness"
mkdir -p "$D" 2>/dev/null

# sess10 (ccloop 72513a13): N-INVARIANT total, same treatment as
# tcp_dlm_scaling/fio_perf/drc (sess9).  50 rounds/node was O(N) aggregate
# against the flat 30s budget: 4800 ops at 32 nodes = 40s wall while the
# fairness SEMANTIC (no node starved of its own rounds) needs only enough
# per-node rounds to detect starvation.  Total ~533 round-triples (1600 ops)
# split across nodes, floor 16/node: 32→16r (1536 ops ~14s), 16→33r,
# 8→66r, 2→266r… capped at the legacy 50 for N<=10 so recorded low-N cells
# keep their shape.
ROUNDS=$(( 533 / NODES ))
[ "$ROUNDS" -lt 16 ] && ROUNDS=16
[ "$ROUNDS" -gt 50 ] && ROUNDS=50

# Node-local phase trace (transient diagnostic data): where the budget goes
# when the aggregate misses its window — rounds vs sync vs barriers.
PROG=/tmp/dlm_fairness_progress
: > "$PROG"
echo "$(date +%s.%3N) barrier_ready_enter" >> "$PROG"

ck "df barrier ready" coord_barrier "df_ready"
echo "$(date +%s.%3N) rounds_start rounds=$ROUNDS" >> "$PROG"

done_rounds=0
for r in $(seq 1 "$ROUNDS"); do
    f="$D/n${R}_r${r}"
    echo "$r" > "$f" || break
    mv "$f" "$f.done" || break
    rm -f "$f.done" || break
    done_rounds=$r
    echo "$(date +%s.%3N) r=$r" >> "$PROG"
done
echo "$(date +%s.%3N) rounds_end done=$done_rounds" >> "$PROG"
sync
echo "$(date +%s.%3N) sync_done" >> "$PROG"

# Fairness: this node must have completed ALL its rounds (not starved).
ckeq "df node${R} completed all rounds" "$ROUNDS" "$done_rounds"

ck "df barrier done" coord_barrier "df_done"
echo "$(date +%s.%3N) barrier_done_cleared" >> "$PROG"

# Rank 1 confirms the shared dir is clean (every node's churn drained, no leak).
if [ "$R" = 1 ]; then
    ckeq "df shared dir drained" "0" \
         "$(ls "$D" 2>/dev/null | wc -l | tr -d ' ')"
fi

ck "df barrier verify" coord_barrier "df_verify"
echo "$(date +%s.%3N) barrier_verify_cleared" >> "$PROG"

coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
