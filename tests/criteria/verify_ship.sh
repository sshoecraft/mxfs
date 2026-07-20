#!/bin/bash
# verify_ship.sh — Ship-gate driver.
#
# Runs every criterion in SUCCESS_CRITERIA.md, in order, and STOPS at
# the first FAIL.  Exits 0 only if every criterion PASSes.
#
# **This script is the ship gate.** If it does not exit 0, MXFS is not
# ready to ship and the model MUST NOT declare the work done. The
# correct response to a FAIL is to investigate and fix the underlying
# issue, then re-run this script. Per CLAUDE.md Rule 1 (NEVER STOP),
# a non-zero exit is the *start* of the next investigation, not the
# end of the session.
#
# Output: one line per criterion (the RESULT line each script emits)
# plus a final SHIP_GATE: PASS or SHIP_GATE: FAIL line.
#
# Usage:
#   tests/criteria/verify_ship.sh              # run all gating criteria
#   tests/criteria/verify_ship.sh --include-soak  # also run 1h soak
#   tests/criteria/verify_ship.sh --keep-going    # don't stop at first FAIL
#                                              # (useful for "what's broken"
#                                              # surveys; never use as
#                                              # ship sign-off)

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

INCLUDE_SOAK=0
KEEP_GOING=0
STATUS_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --include-soak) INCLUDE_SOAK=1; shift ;;
        --keep-going)   KEEP_GOING=1; shift ;;
        --status)       STATUS_ONLY=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

CRITERIA_RESULTS_FILE="${CRITERIA_RESULTS_FILE:-$(cd "$SCRIPT_DIR/../.." && pwd)/.criteria_results.json}"

if [ "$STATUS_ONLY" = "1" ]; then
    if [ ! -f "$CRITERIA_RESULTS_FILE" ]; then
        echo "No results file at $CRITERIA_RESULTS_FILE — no criterion has been run yet."
        exit 0
    fi
    if ! command -v jq >/dev/null 2>&1; then
        echo "jq not installed; cat \"$CRITERIA_RESULTS_FILE\" to view raw."
        exit 1
    fi
    echo "Criteria status from $CRITERIA_RESULTS_FILE:"
    echo
    # Print as a fixed-width table: criterion | status | last-run | measured
    jq -r 'to_entries
        | sort_by(.key)
        | .[]
        | [.key, .value.status, .value.last_run_iso, .value.measured]
        | @tsv' "$CRITERIA_RESULTS_FILE" \
        | awk -F'\t' 'BEGIN {
            printf "%-26s %-6s %-22s %s\n", "CRITERION", "STATUS", "LAST RUN (UTC)", "MEASURED"
            printf "%-26s %-6s %-22s %s\n", "---------", "------", "--------------", "--------"
          }
          { printf "%-26s %-6s %-22s %s\n", $1, $2, $3, $4 }'
    echo
    pass=$(jq -r '[ .[] | select(.status=="PASS") ] | length' "$CRITERIA_RESULTS_FILE")
    fail=$(jq -r '[ .[] | select(.status=="FAIL") ] | length' "$CRITERIA_RESULTS_FILE")
    echo "Totals: PASS=$pass  FAIL=$fail"
    if [ "$fail" = "0" ] && [ "$pass" -gt 0 ]; then
        echo
        echo "Note: --status only reflects each criterion's LAST run.  The"
        echo "ship gate also requires that every PASS came from the SAME"
        echo "end-to-end verify_ship.sh run.  Run verify_ship.sh to gate."
    fi
    exit 0
fi

# Order matters: cheap correctness checks first, expensive perf last.
# A failure early aborts the run, so we don't burn 30 min on perf when
# correctness is broken.
GATING_CRITERIA=(
    # Tooling (fast, cheap)
    "mkfs_timing.sh --nodes 1"
    "chk_clean.sh --nodes 2"
    "dkms_install.sh --nodes 1"
    "online_resize.sh --nodes 1"

    # Cluster lifecycle
    "cluster_ops_timing.sh --nodes 4"
    "wedged_unmount.sh --nodes 4"
    "online_membership.sh --nodes 3"

    # Robustness
    "dmesg_clean.sh --nodes 4"
    "cache_caps.sh --nodes 1"

    # Correctness — single-node
    "posix_semantics.sh --nodes 1"

    # Correctness — cluster (failures here = silent loss / coherency bugs)
    "cache_coherency.sh --nodes 4"
    "strong_consistency.sh --nodes 4"
    "zero_silent_loss.sh --iters 3 --dpn 100 --mode 1"

    # Crash / fence
    "crash_consistency.sh --nodes 2"
    "fence_during_write.sh --nodes 4"

    # Performance (last — slowest, only meaningful if correctness passes)
    "single_node_paired.sh --nodes 1"
    "rsync_paired.sh --nodes 4 --iters 1"
    "scaling_curve.sh --nodes 16"

    # Transport — TCP DLM scaling sweep (separate-initiator iSCSI to QNAP)
    "tcp_dlm_scaling.sh --nodes 16"

    # Full cluster test framework
    "posix_semantics.sh --nodes 16"
)
[ "$INCLUDE_SOAK" = "1" ] && GATING_CRITERIA+=("soak.sh --nodes 4")

total=${#GATING_CRITERIA[@]}
passed=0
failed=0
first_fail=""

# ─── Environment warm-up (sess30 run14d) ───
# After a VM reboot the first criterion silently absorbed the whole
# cold-prep cost (sshd settling, NFS mount of /src, iSCSI login via
# prep_tcm_node) inside its RULE-0 budget: chk_clean's 60s watchdog
# killed it mid-prep with no RESULT line.  Warm every node's
# environment up front so per-criterion budgets assert FS performance
# only.  Changes no thresholds; aborts the gate early (clear env
# message) instead of burning an hour into a half-booted cluster.
source "$SCRIPT_DIR/lib.sh"
WARMDIR=$(mktemp -d /tmp/vship_warm.XXXXXX)
warm_start=$SECONDS
echo "=== verify_ship: warming ${#DEFAULT_NODES[@]} node environments ==="
for n in "${DEFAULT_NODES[@]}"; do
    (
        ok=0
        for attempt in 1 2 3 4 5 6; do
            out=$(MXFS_SSH_TIMEOUT=120 ssh_node "$n" '
                for try in 1 2 3 4 5 6 7 8 9 10; do
                    mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
                    [ -f '"$MXFS_MODULE"' ] && break
                    sleep 3
                done
                [ -f '"$MXFS_MODULE"' ] || exit 50
                '"$MXFS_PREP"' >/tmp/prep.log 2>&1
                modprobe libcrc32c 2>/dev/null
                echo WARM_OK')
            echo "$out" | grep -q WARM_OK && { ok=1; break; }
            sleep 5
        done
        echo "$ok" > "$WARMDIR/$n"
    ) &
done
wait
warm_fails=""
for n in "${DEFAULT_NODES[@]}"; do
    [ "$(cat "$WARMDIR/$n" 2>/dev/null)" = "1" ] || warm_fails="$warm_fails $n"
done
rm -rf "$WARMDIR"
echo "=== warm-up done in $((SECONDS - warm_start))s ==="
if [ -n "$warm_fails" ]; then
    echo "=== SHIP_GATE: ABORT — environment warm-up failed on:$warm_fails ==="
    echo "Fix node reachability/NFS/iSCSI first; no criterion was run."
    exit 3
fi

echo "=== verify_ship: running $total criteria ==="
for entry in "${GATING_CRITERIA[@]}"; do
    name=$(echo "$entry" | awk '{print $1}' | sed 's/\.sh$//')
    echo
    echo "--- [$((passed + failed + 1))/$total] $name ---"
    # $entry is "script.sh --flag val ..."; split into the script path plus
    # its args so bash gets a real filename (not the whole string as one path).
    read -ra _parts <<< "$entry"
    out=$(bash "$SCRIPT_DIR/${_parts[0]}" "${_parts[@]:1}" 2>&1)
    result_line=$(echo "$out" | grep -E '^RESULT:' | tail -1)
    if [ -z "$result_line" ]; then
        # No RESULT line emitted (script crashed before reporting). Treat
        # as FAIL with full output for diagnosis.
        result_line="RESULT: FAIL  criterion=$name  measured=n/a  threshold=n/a  reason=no RESULT line (script crashed)"
        echo "$out" | tail -20
    fi
    echo "$result_line"
    if echo "$result_line" | grep -q 'RESULT: PASS'; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        [ -z "$first_fail" ] && first_fail="$name"
        if [ "$KEEP_GOING" = "0" ]; then
            echo
            echo "=== SHIP_GATE: FAIL ==="
            echo "First failure: $name"
            echo "Criteria passed before this: $passed/$total"
            echo
            echo "Per CLAUDE.md: this run is not done. Investigate the"
            echo "failure above, fix the underlying issue (in the FS,"
            echo "the tooling, or — only if the criterion itself is"
            echo "wrong — in the verifier script), and re-run"
            echo "verify_ship.sh. Do NOT declare ship-readiness until"
            echo "this script exits 0."
            exit 1
        fi
    fi
done

echo
if [ "$failed" = "0" ]; then
    echo "=== SHIP_GATE: PASS ==="
    echo "$passed/$total criteria passed."
    exit 0
else
    echo "=== SHIP_GATE: FAIL ==="
    echo "$failed of $total criteria failed (first: $first_fail)."
    echo "Per CLAUDE.md: keep working until every criterion passes."
    exit 1
fi
