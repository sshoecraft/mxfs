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
            (if $r and $r.budget_s then ($r.budget_s|tostring) else "-" end),
            (if $r then ((($r.history // []) | map(select(.status=="FAIL"
                and (((.reason // "") + " " + (.measured // ""))
                     | test("pre-assert|NO_TERMINAL_RECORD|run was killed|prep fail|PREP FAIL"; "i") | not)
                # sess93: win_src=none is the dirent window helper reporting
                # that its PRODUCER workload (dirent_durability) never ran in
                # this boot, so the P8 scanners scanned ZERO lines.  The FAIL
                # is correct — a board must not report a green it did not earn
                # — but a run that could not OBSERVE cannot CONVICT, so it is
                # not evidence of an MXFS fault and must not enter the flake
                # tally.  (Seen when sess93 split a board into chunks and put
                # the producer in the other chunk; the same criteria passed
                # 32/32 with win_src=marker minutes later on the same build.)
                and (((.measured // "") | test("win_src=none")) | not)
                # The reconvergence gate itself was defective until
                # 2026-08-02T04:00Z: it compared the LEASE beacon against N,
                # but a dead identity from a fault test lingers in the lease for
                # 10 minutes (lease.h MXFS_LEASE_TIMEOUT_DEFAULT_MS), so a
                # healthy cluster read as "did not reconverge" and blocked
                # the chunk. A provably-broken gate cannot produce evidence
                # about the filesystem, so its pre-fix verdicts are excluded.
                # The gate now consults the on-disk heartbeat table, and any
                # verdict AFTER the fix counts normally.
                and ((((.reason // "") | test("reconverge|recovery_postcondition"))
                      and ((.iso // "") < "2026-08-02T04:00:00Z")) | not)
             )) | length)|tostring) + "/" + ((($r.history // [])|length)|tostring) else "0/0" end)
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
            (if $r and $r.value.budget_s then ($r.value.budget_s|tostring) else "-" end),
            (if $r then (((($r.value.history // []) | map(select(.status=="FAIL"
                and (((.reason // "") + " " + (.measured // ""))
                     | test("pre-assert|NO_TERMINAL_RECORD|run was killed|prep fail|PREP FAIL"; "i") | not)
                # sess93: win_src=none is the dirent window helper reporting
                # that its PRODUCER workload (dirent_durability) never ran in
                # this boot, so the P8 scanners scanned ZERO lines.  The FAIL
                # is correct — a board must not report a green it did not earn
                # — but a run that could not OBSERVE cannot CONVICT, so it is
                # not evidence of an MXFS fault and must not enter the flake
                # tally.  (Seen when sess93 split a board into chunks and put
                # the producer in the other chunk; the same criteria passed
                # 32/32 with win_src=marker minutes later on the same build.)
                and (((.measured // "") | test("win_src=none")) | not)
                # The reconvergence gate itself was defective until
                # 2026-08-02T04:00Z: it compared the LEASE beacon against N,
                # but a dead identity from a fault test lingers in the lease for
                # 10 minutes (lease.h MXFS_LEASE_TIMEOUT_DEFAULT_MS), so a
                # healthy cluster read as "did not reconverge" and blocked
                # the chunk. A provably-broken gate cannot produce evidence
                # about the filesystem, so its pre-fix verdicts are excluded.
                # The gate now consults the on-disk heartbeat table, and any
                # verdict AFTER the fix counts normally.
                and ((((.reason // "") | test("reconverge|recovery_postcondition"))
                      and ((.iso // "") < "2026-08-02T04:00:00Z")) | not)
             )) | length))|tostring) + "/" + ((($r.value.history // [])|length)|tostring) else "0/0" end)
          ] | @tsv' "$CRIT"
    fi
}

echo "=== MXFS TEST STATUS — $COND ==="
printf "%-3s | %-8s | %-24s | %-7s | %-10s | %-9s | %s\n" "#" "CAT" "TEST" "COND" "STATUS" "TIME"  "MEASURED"
echo "----+----------+--------------------------+---------+------------+-----------+----------------------------"
# sess23 (ccloop c7ee71c6): a board is only useful if a red cell means "this
# run detected a fault".  Three states used to be rendered identically as ❌:
#   * a real detected failure,
#   * a test that never ran (truncated sweep),
#   * the open_defects POLICY gate, which is red BY DESIGN under RULE 6 while
#     any ledger defect is unresolved.
# Conflating them made an interrupted run look like a broken filesystem, and
# made the permanent policy red look like a regression.  They are now counted
# and labelled separately.  Note NOT_RUN/ABORTED are NOT green and still block
# an all-green verdict — they just no longer masquerade as detected faults.
n=0 pass=0 fail=0 skip=0 pend=0 notrun=0 aborted=0 policy=0 blocked=0 flaky=0
while IFS=$'\t' read -r cat name st cond measured elapsed budget flake; do
    [ -z "$name" ] && continue
    n=$((n+1))
    case "$st" in
        PASS)    e="✅"; w="PASS";    pass=$((pass+1)) ;;
        FAIL)    if [ "$name" = "open_defects" ]; then
                     e="📋"; w="POLICY"; policy=$((policy+1))
                 else
                     e="❌"; w="FAIL";  fail=$((fail+1))
                 fi ;;
        SKIP)    e="🚫"; w="SKIPPED"; skip=$((skip+1)) ;;
        NOT_RUN) e="⏸"; w="NOT RUN"; notrun=$((notrun+1)) ;;
        ABORTED) e="⚠"; w="ABORTED"; aborted=$((aborted+1)) ;;
        BLOCKED) e="⛔"; w="BLOCKED"; blocked=$((blocked+1)) ;;
        *)       e="⏳"; w="PENDING"; pend=$((pend+1)) ;;
    esac
    # sess43 (user directive, two rounds): FLAKY means exactly one thing —
    # the TEST ITSELF detected a fault on a formed cluster in a recent run,
    # and that incident has not aged out.  Those cells stay ⚠ FLAKY until
    # 11 clean runs OR the incident is root-caused and the ledger closes it —
    # a flake is a defect to fix, not a label to launder.  What FLAKY must
    # NOT mean is "the rig broke that day": failures whose recorded cause is
    # rig-formation (pre-assert, prep failure, killed run, no terminal
    # record) are excluded by the jq filter above; prep_cluster (the
    # rig-forming step) and open_defects (the policy gate) never flake.
    pf=${flake%%/*}; pr=${flake##*/}
    { [ "$name" = prep_cluster ] || [ "$name" = open_defects ]; } && pf=0
    if [ "${pf:-0}" -gt 0 ] 2>/dev/null; then
        if [ "$st" = PASS ]; then
            e="⚠"; w="FLAKY"; flaky=$((flaky+1)); pass=$((pass-1))
        fi
        measured="$measured  [${pf} genuine FAIL(s) in last $((pr+1)) runs — root-cause via ledger]"
    fi
    # open_defects: the cell is the LAST RUN's snapshot; append the live count
    # so ledger updates between runs are visible immediately.
    if [ "$name" = open_defects ] && [ -s tests/criteria/OPEN_DEFECTS.json ]; then
        live=$(jq '[(.defects // .)[] | select((.status // "OPEN") == "OPEN")] | length' \
               tests/criteria/OPEN_DEFECTS.json 2>/dev/null)
        [ -n "$live" ] && measured="[live ledger: ${live} OPEN] $measured"
    fi
    status="$e $(printf '%-7s' "$w")"
    if [ "$elapsed" = "-" ] || [ "$budget" = "-" ]; then time="-"; else time="${elapsed}/${budget}s"; fi
    printf "%-3d | %-8s | %-24s | %-7s | %s | %-9s | %s\n" "$n" "$cat" "$name" "$cond" "$status" "$time" "$measured"
done < <(rows)
echo "------------------------------------------------------------------------------------------"
echo "Total: $n — $pass PASS, $flaky FLAKY, $fail FAIL, $policy POLICY, $aborted ABORTED, $blocked BLOCKED, $notrun NOT-RUN, $skip SKIPPED, $pend PENDING   [$COND]"
# The verdict line states plainly what the board means, so nobody has to infer
# it from the icon soup.  Green requires: no detected failure, nothing aborted,
# nothing unrun, nothing still pending — AND no open policy failure.
if [ "$fail" -gt 0 ]; then
    echo "VERDICT: $fail criterion/criteria DETECTED A FAULT on this build — investigate those first."
elif [ $((aborted + notrun + pend + blocked)) -gt 0 ]; then
    echo "VERDICT: no detected faults, but coverage is INCOMPLETE ($aborted aborted, $blocked blocked, $notrun not-run, $pend pending) — re-run before drawing any conclusion."
elif [ "$policy" -gt 0 ]; then
    echo "VERDICT: every criterion passed, but the RULE-6 open-defect ledger is non-empty — NOT production ready until it is."
else
    echo "VERDICT: all criteria green and the open-defect ledger is empty."
fi
if [ "$flaky" -gt 0 ]; then
    echo "NOTE: $flaky cell(s) are FLAKY — they PASS now but a recent run of the TEST ITSELF detected a fault (rig-caused failures are already excluded). Each incident's disposition is tracked in the RULE-6 ledger (tests/criteria/OPEN_DEFECTS.json); a flake clears by root-cause fix, not by aging out."
fi
