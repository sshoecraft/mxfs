#!/bin/bash
# sl_straggler_capture.sh — catch sustained_load's stragglers WHILE they are
# stuck, not after.  (ccloop c7ee71c6 sess28, D-MOUNT-DEGRADES-WITH-USE.)
#
# WHY
#   sustained_load fails at 32/caw with bar2=121032 ms and
#   states:NO_TERMINAL_RECORD=2..4.  The per-op /dev/kmsg trail added to
#   tests/suite/sustained_load.sh names the stragglers precisely — 30 nodes
#   reach "SYNCED elapsed=1788..4760" while test21 and test22 both stop at
#   "SLOW phase=rmdir k=8 ms=772/765" and emit nothing further — but by the time
#   the run returns, run.sh has killed the test at its budget and the D-state is
#   gone.  Post-mortem finds only the normal bounded disklock heartbeat
#   (mxfs_pal_cond_timedwait in disklock_hb_fn), which is NOT a wedge and must
#   never be convicted as one (that false-positive is recorded in state.md).
#
#   So the capture has to happen DURING the run.  This starts the criterion,
#   sweeps every node for D-state tasks with kernel stacks at two points inside
#   the window, and reports only nodes that actually have a non-heartbeat
#   blocked task.
#
# RULE 0
#   The criterion's own budget is 180 s (tests/suite/manifest) and run.sh
#   enforces it.  Sweeps are placed inside that window (default 45 s and 110 s)
#   because the trail shows the stall begins ~5 s in and persists to the kill.
#   The outer wait is budget + measured run.sh overhead.
#
# USAGE
#   tests/sl_straggler_capture.sh [nodes] [sweep1_s] [sweep2_s]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

N="${1:-32}"
S1="${2:-45}"
S2="${3:-110}"
BUDGET=180
OVERHEAD=60

nodes() { local i; for ((i=1; i<=N; i++)); do echo "test$i"; done; }

# The disklock heartbeat parks in a BOUNDED timedwait by design; it is present
# on healthy nodes and is not evidence of anything.  Everything else is.
sweep() {
    local tag="$1" h d
    d=$(mktemp -d)
    for h in $(nodes); do
        (
        timeout 25 tools/mxfs_sshpass.sh "$h" '
            for p in $(ps -eo state,pid --no-headers | awk "\$1 ~ /D/ {print \$2}"); do
                c=$(cat /proc/$p/comm 2>/dev/null)
                s=$(cat /proc/$p/stack 2>/dev/null | head -8 | tr "\n" "|")
                case "$s" in
                    *disklock_hb_fn*) continue ;;   # normal bounded heartbeat
                esac
                echo "pid=$p comm=$c stack=$s"
            done
        ' 2>/dev/null | grep -E '^pid=' > "$d/$h"
        ) &
    done
    wait
    echo "--- sweep $tag (non-heartbeat D-state only) ---"
    local any=0
    for h in $(nodes); do
        if [ -s "$d/$h" ]; then
            any=1
            echo "### $h"
            sed 's/|/\n    /g' "$d/$h" | head -24
        fi
    done
    [ "$any" = 1 ] || echo "  (none — every node's only D-state task is the heartbeat)"
}

echo "=== sl_straggler_capture: N=$N sweeps at ${S1}s and ${S2}s of a ${BUDGET}s budget ==="
timeout $((BUDGET + OVERHEAD)) ./run.sh "$N" caw sustained_load > /tmp/slcap.$$ 2>&1 &
RUNPID=$!

sleep "$S1"; sweep "t=${S1}s"
sleep $((S2 - S1)); sweep "t=${S2}s"

wait "$RUNPID" || true
echo "--- criterion result ---"
grep -E "PASS|FAIL|BLOCK" /tmp/slcap.$$ || tail -5 /tmp/slcap.$$

echo "--- per-node progress trail (last MXFS_SL line) ---"
d=$(mktemp -d)
for h in $(nodes); do
    ( timeout 25 tools/mxfs_sshpass.sh "$h" \
        "dmesg | grep 'MXFS_SL ' | tail -1 | sed -E 's/^.*MXFS_SL //'" \
        2>/dev/null | tail -1 > "$d/$h" ) &
done
wait
for h in $(nodes); do printf '%-8s %s\n' "$h" "$(cat "$d/$h" 2>/dev/null)"; done
