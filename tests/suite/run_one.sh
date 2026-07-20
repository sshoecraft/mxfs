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

# RULE 0 (CLAUDE.md): look up this test's manifest-declared budget_s from
# criteria.json (single source of truth) so a lone run_one.sh invocation
# enforces + records the same budget the full run.sh conditions-runner would.
CRIT="$REPO/criteria.json"
budget=300
[ -s "$CRIT" ] && command -v jq >/dev/null 2>&1 && \
    budget=$(jq -r --arg k "$T" '[.categories[].tests[] | select(.name==$k) | (.budget_s // 300)][0] // 300' "$CRIT")

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
# correctness errors (RULE 0: a timeout IS a test failure).
if [ "$status" = PASS ] && [ "$elapsed" -gt "$budget" ] 2>/dev/null; then
    status=FAIL
    reason="RULE-0 budget exceeded: elapsed=${elapsed}s > budget=${budget}s (functional checks passed)${reason:+; }$reason"
fi

# Record into criteria.json (single source of truth): set this test's
# runs["<nodes>/<dlm>"] entry, wherever the test lives in the matrix.
cond="${nodes}/${DLM}"
[ -s "$CRIT" ] || { echo "ERROR: $CRIT missing (run scripts/gen_criteria.py)"; exit 1; }
tmp=$(mktemp)
jq --arg k "$T" --arg c "$cond" --arg s "$status" \
   --arg m "$measured" --arg r "$reason" --arg t "$(date -u +%FT%TZ)" \
   --argjson e "$elapsed" --argjson b "$budget" \
   '.categories[].tests |= map(if .name==$k then (.runs[$c] = {status:$s, measured:$m, reason:$r, iso:$t, elapsed_s:$e, budget_s:$b}) else . end)' \
   "$CRIT" > "$tmp" && mv "$tmp" "$CRIT"

echo "recorded: $T = $status @ $cond (${elapsed}s/${budget}s)"
