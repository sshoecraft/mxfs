#!/bin/bash
# run_one.sh — run ONE agnostic FS test on a node, capture its RESULT line,
# and record it into .suite_results.json. Runs on the coordinator (clyde);
# this is the embryo of the full battery runner.
#
# Usage:  tests/suite/run_one.sh <test-name> <node> [nodes_count]
#   e.g.  tests/suite/run_one.sh posix_single test1 1
# Env:    MXFS_MOUNT (/mnt/shared)
#
# The test runs ON <node> against the mount point and prints exactly one
# `RESULT: ... | test=.. | nodes=.. | measured=.. | reason=..` line.

set -u
T="${1:?test name required}"
NODE="${2:?node required}"
NCOUNT="${3:-1}"

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
SUITE_DIR="${MXFS_SUITE_DIR:-tests/suite}"          # which suite's scripts live here
RESULTS="${MXFS_RESULTS:-$REPO/.suite_results.json}"
DLM="${MXFS_DLM:-tcp}"                               # transport the test ran under (recorded)
MNT="${MXFS_MOUNT:-/mnt/shared}"
SCRIPT="/src/mxfs/$SUITE_DIR/$T.sh"   # path as seen on the node (NFS)

[ -f "$REPO/$SUITE_DIR/$T.sh" ] || { echo "no such test: $T ($REPO/$SUITE_DIR/$T.sh)"; exit 2; }

# Look up this test's declared budget_s from the board so a
# lone run_one.sh invocation enforces and records the same budget the full
# run.sh conditions-runner would.  The board is read through tools/criteria.py,
# which is the only thing that knows its shape.
CRITPY="$REPO/tools/criteria.py"
[ -x "$CRITPY" ] || { echo "ERROR: $CRITPY missing — nothing can record a result"; exit 1; }
budget=$("$CRITPY" rows | awk -F'\t' -v k="$T" '$3==k{print $7; exit}')
[ -n "$budget" ] || budget=300

t0=$(date +%s)
out=$(timeout "$budget" "$SSH" "$NODE" "$PASS" "MXFS_NODES=$NCOUNT MXFS_DLM=$DLM bash $SCRIPT '$MNT'" 2>&1 \
        | grep -vE '^Warning:|^Unauthorized|^If you')
rc=$?
t1=$(date +%s); elapsed=$(( t1 - t0 ))
echo "$out"

if [ "$rc" -eq 124 ]; then
    echo "ERROR: $T on $NODE timed out (elapsed=${elapsed}s budget=${budget}s)"
fi
line=$(echo "$out" | grep -E '^RESULT:' | tail -1)
[ -n "$line" ] || { echo "ERROR: no RESULT line from $T on $NODE"; exit 1; }

field() { awk -F' \\| ' -v key="$1" '{for(i=1;i<=NF;i++){n=index($i,"=");
        if(n && substr($i,1,n-1)==key){print substr($i,n+1)}}}' <<<"$line"; }
status=$(awk '{print $2}' <<<"$line")     # token after "RESULT:"
nodes=$(field nodes);  measured=$(field measured);  reason=$(field reason)
[ -n "$nodes" ] || nodes="$NCOUNT"

# elapsed_s > budget_s flips a functional PASS to FAIL even with zero
# correctness errors (a timeout IS a test failure).
if [ "$status" = PASS ] && [ "$elapsed" -gt "$budget" ] 2>/dev/null; then
    status=FAIL
    reason="budget exceeded: elapsed=${elapsed}s > budget=${budget}s (functional checks passed)${reason:+; }$reason"
fi

# Record the cell through criteria.py.  It pushes the outgoing verdict onto the
# bounded flake history first — the jq this replaced overwrote the cell whole
# and dropped the history, so a lone run_one.sh silently erased the evidence
# that a criterion was intermittent.
cond="${nodes}/${DLM}"
args=(update "$T" --at "$cond" -s "$status" -m "$measured" -e "$elapsed")
[ -n "$reason" ] && args+=(--reason "$reason")
"$CRITPY" "${args[@]}" >/dev/null

echo "recorded: $T = $status @ $cond (${elapsed}s/${budget}s)"
