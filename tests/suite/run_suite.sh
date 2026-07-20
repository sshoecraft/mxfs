#!/bin/bash
# run_suite.sh — the overarching FS test battery. Runs the suite against a
# given node count.
#
# Usage:  tests/suite/run_suite.sh <N> [node1 node2 ...]
#   <N>    : node count this run targets (1..32)
#   nodes  : explicit node list; defaults to test1..testN
#
# For each manifest entry, in order:
#   - MINNODES > N            -> record SKIPPED (not run; "needs >= MINNODES nodes")
#   - no script yet           -> leave PENDING
#   - COORD == none           -> run on node1 via run_one (records its own result)
#   - COORD != none (needs coordination) -> SKIPPED for now ("coordinated runner TBD")
#
# Assumes the config layer has already prepped/mounted the nodes (readiness
# contract). precond_readiness will catch an unmounted node.

set -u
N="${1:?node count required}"; shift || true
NODES=("$@")
[ "${#NODES[@]}" -gt 0 ] || mapfile -t NODES < <(seq 1 "$N" | sed 's/^/test/')
NODE1="${NODES[0]}"

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
MANIFEST="${MXFS_MANIFEST:-$REPO/tests/suite/manifest}"
RESULTS="${MXFS_RESULTS:-$REPO/.suite_results.json}"
SUITE_DIR="${MXFS_SUITE_DIR:-tests/suite}"
DLM="${MXFS_DLM:-tcp}"
RUNONE="$REPO/tests/suite/run_one.sh"
[ -s "$RESULTS" ] || echo '{}' > "$RESULTS"

record() {  # name status measured reason
    local tmp; tmp=$(mktemp)
    jq --arg k "$1" --arg s "$2" --argjson n "$N" --arg m "$3" --arg r "$4" --arg t "$(date -u +%FT%TZ)" \
       '.[$k] = {status:$s, nodes:$n, measured:$m, reason:$r, last_run_iso:$t}' \
       "$RESULTS" > "$tmp" && mv "$tmp" "$RESULTS"
}

echo "=== running FS suite @ $N node(s): ${NODES[*]} ==="
while read -r ph test coord minn _rest; do
    case "$ph" in ''|\#*) continue ;; esac
    minn=${minn:-1}
    script="$REPO/$SUITE_DIR/$test.sh"

    if [ "$minn" -gt "$N" ]; then
        # node-gating is per-run, NOT a stored result — don't record it; showstat
        # derives SKIPPED at display time from the requested node count.
        printf "  SKIPPED  %-22s (needs %s nodes — not recorded)\n" "$test" "$minn"
    elif [ ! -f "$script" ]; then
        printf "  PENDING  %-22s (no script yet)\n" "$test"
    elif [ "$coord" = none ]; then
        printf "  RUN      %-22s on %s\n" "$test" "$NODE1"
        MXFS_SUITE_DIR="$SUITE_DIR" MXFS_RESULTS="$RESULTS" MXFS_DLM="$DLM" \
            "$RUNONE" "$test" "$NODE1" "$N" </dev/null >/dev/null 2>&1 || true
    else
        record "$test" SKIP "coord=$coord" "coordinated multi-node runner not yet implemented"
        printf "  SKIPPED  %-22s (coordinated; runner TBD)\n" "$test"
    fi
done < "$MANIFEST"
echo "=== done — see ./showstat.sh ==="
