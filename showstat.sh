#!/bin/bash
# showstat.sh [<nodes> <dlm>]
#
# Reads criteria.json (the single source of truth: test matrix + per-condition
# status) and shows the status of every applicable test.
#
#   <nodes> <dlm> : conditioned view — include categories whose transport is
#                   "any" or == <dlm>; for each test show runs["<nodes>/<dlm>"]
#                   (PASS/FAIL), else PENDING; min_nodes > <nodes> -> SKIPPED.
#   (no args)     : use last-run conditions (.last_run.json) if present; else
#                   show each test's most-recent run across all conditions.

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd); cd "$SCRIPT_DIR" || exit 1
# MXFS_CRIT mirrors run.sh: a second rig's board lives in its own file (cells
# are keyed "<N>/<dlm>" with no rig dimension), so point both at the same one.
CRIT="${MXFS_CRIT:-criteria.json}"; LASTRUN=".last_run.json"
[ -s "$CRIT" ] || { echo "no criteria.json — run scripts/gen_criteria.py" >&2; exit 1; }

NODES="${1:-}"; DLM="${2:-}"
if [ -z "$NODES" ] && [ -z "$DLM" ] && [ -s "$LASTRUN" ]; then
    NODES=$(jq -r '.nodes // empty' "$LASTRUN"); DLM=$(jq -r '.dlm // empty' "$LASTRUN")
fi
if [ -n "$NODES" ] && [ -n "$DLM" ]; then COND="conditions — nodes=$NODES dlm=$DLM"; MODE=cond
else COND="latest recorded run per test"; MODE=latest; fi

rows() {
    if [ "$MODE" = cond ]; then
        # Only APPLICABLE tests: transport matches AND min_nodes <= requested
        # node count. Non-applicable tests are excluded entirely (not shown).
        # Transport applicability is by BASE transport: the cawd (direct
        # iSCSI) and cawp (passthrough) conditions run the caw categories.
        jq -r --arg N "$NODES" --arg D "$DLM" \
              --arg B "$(case "$DLM" in cawd|cawp) echo caw;; *) echo "$DLM";; esac)" '
          ($N|tonumber) as $nn |
          .categories[] | select(.transport=="any" or .transport==$B) | .category as $cat |
          .tests[]
          | select(.min_nodes <= $nn and ((.max_nodes // 0) == 0 or .max_nodes >= $nn))
          | . as $t | ($t.runs[$N+"/"+$D]) as $r |
          [ $cat, $t.name,
            (if $r then $r.status else "PENDING" end),
            ($N+"/"+$D),
            (if $r then $r.measured else "n/a" end),
            (if $r and $r.elapsed_s then ($r.elapsed_s|tostring) else "-" end),
            (if $r and $r.budget_s then ($r.budget_s|tostring) else "-" end)
          ] | @tsv' "$CRIT"
    else
        jq -r '
          .categories[] | .category as $cat |
          .tests[] | . as $t |
          ([$t.runs | to_entries[]] | sort_by(.value.iso) | last) as $r |
          [ $cat, $t.name,
            (if $r then $r.value.status else "PENDING" end),
            (if $r then $r.key else "-" end),
            (if $r then $r.value.measured else "n/a" end),
            (if $r and $r.value.elapsed_s then ($r.value.elapsed_s|tostring) else "-" end),
            (if $r and $r.value.budget_s then ($r.value.budget_s|tostring) else "-" end)
          ] | @tsv' "$CRIT"
    fi
}

echo "=== MXFS TEST STATUS — $COND ==="
printf "%-3s | %-8s | %-24s | %-7s | %-10s | %-9s | %s\n" "#" "CAT" "TEST" "COND" "STATUS" "TIME"  "MEASURED"
echo "----+----------+--------------------------+---------+------------+-----------+----------------------------"
n=0 pass=0 fail=0 skip=0 pend=0
while IFS=$'\t' read -r cat name st cond measured elapsed budget; do
    [ -z "$name" ] && continue
    n=$((n+1))
    case "$st" in
        PASS) e="✅"; w="PASS";    pass=$((pass+1)) ;;
        FAIL) e="❌"; w="FAIL";    fail=$((fail+1)) ;;
        SKIP) e="🚫"; w="SKIPPED"; skip=$((skip+1)) ;;
        *)    e="⏳"; w="PENDING"; pend=$((pend+1)) ;;
    esac
    status="$e $(printf '%-7s' "$w")"
    if [ "$elapsed" = "-" ] || [ "$budget" = "-" ]; then time="-"; else time="${elapsed}/${budget}s"; fi
    printf "%-3d | %-8s | %-24s | %-7s | %s | %-9s | %s\n" "$n" "$cat" "$name" "$cond" "$status" "$time" "$measured"
done < <(rows)
echo "------------------------------------------------------------------------------------------"
echo "Total: $n — $pass PASS, $fail FAIL, $skip SKIPPED, $pend PENDING   [$COND]"
