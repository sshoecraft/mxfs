#!/bin/bash
# sf_storm_ab.sh — paired A/B of one module parameter against sf_mkdir_storm.
#
# WHY THIS EXISTS
#   The storm's failure rate depends strongly on how long the cluster has been
#   up since the last prep.  Measured on one build, same params, back to back:
#
#       run 1 (immediately after prep)   21 of 30 rounds inconsistent
#       run 2                             7
#       run 3                             7
#       run 4                             4
#
#   So a single run after a fresh prep is NOT comparable with a single run
#   later, and every "the fix helped / hurt" conclusion drawn that way is
#   confounded by prep age.  This script removes that: one prep, one discarded
#   warm-up, then ALTERNATING passes on the same cluster state, so the only
#   thing differing between the A samples and the B samples is the parameter.
#
# USAGE
#   tests/sf_storm_ab.sh <param> <a_value> <b_value> [pairs] [rounds] [nodes]
#     e.g. tests/sf_storm_ab.sh dir_nl_require_grant 1 0 3 30 32
#
#   Assumes the cluster is already prepped with the build under test.  Does NOT
#   prep — prepping mid-experiment is exactly the confound this avoids.
#
# OUTPUT: per-pass failing-round counts plus the A and B totals.  Treat a
#   difference smaller than the spread between same-value passes as noise.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

PARAM="${1:?usage: sf_storm_ab.sh <param> <a_value> <b_value> [pairs] [rounds] [nodes]}"
AVAL="${2:?}"
BVAL="${3:?}"
PAIRS="${4:-3}"
ROUNDS="${5:-30}"
N="${6:-32}"

set_param() {
    local v="$1" i
    for i in $(seq 1 "$N"); do
        ( timeout 20 "$SSH" "test$i" \
            "echo $v > /sys/module/mxfs/parameters/$PARAM" >/dev/null 2>&1 ) &
    done
    wait
    local got
    got=$(timeout 20 "$SSH" test1 "cat /sys/module/mxfs/parameters/$PARAM" \
          2>/dev/null | tr -dc '0-9-')
    [ "$got" = "$v" ] || { echo "PARAM SET FAILED: $PARAM wanted=$v got=$got" >&2; exit 2; }
}

# Count failing rounds from one storm run.  An INFRA-FAIL (a node that never
# ran its mkdirs) is NOT a data point — it must not be averaged in as if it
# were a clean sample.
run_once() {
    local out rc
    out=$(timeout $(( ROUNDS * 2 + 240 )) "$SCRIPT_DIR/sf_mkdir_storm.sh" \
          "$ROUNDS" "$N" 2 1 2>&1)
    rc=$?
    if echo "$out" | grep -q INFRA-FAIL; then
        echo "INFRA"
        return
    fi
    if [ "$rc" = 0 ]; then
        echo 0
        return
    fi
    echo "$out" | sed -n 's/.*inconsistent (rounds: \(.*\) ).*/\1/p' | wc -w
}

echo "=== paired A/B: $PARAM  A=$AVAL  B=$BVAL  pairs=$PAIRS rounds=$ROUNDS nodes=$N ==="
echo "--- warm-up pass (discarded: the first run after a prep is systematically"
echo "    the worst, and mixing it into either arm biases that arm) ---"
set_param "$AVAL"
w=$(run_once); echo "    warm-up: $w failing rounds (discarded)"

asum=0; bsum=0; an=0; bn=0
for p in $(seq 1 "$PAIRS"); do
    set_param "$AVAL"; a=$(run_once)
    set_param "$BVAL"; b=$(run_once)
    echo "  pair $p:  A($AVAL)=$a   B($BVAL)=$b"
    case "$a" in ''|*[!0-9]*) ;; *) asum=$((asum + a)); an=$((an + 1)) ;; esac
    case "$b" in ''|*[!0-9]*) ;; *) bsum=$((bsum + b)); bn=$((bn + 1)) ;; esac
done

echo "--- result ---"
[ "$an" -gt 0 ] && echo "  A ($PARAM=$AVAL): $asum failing rounds over $an passes ($((ROUNDS * an)) rounds)"
[ "$bn" -gt 0 ] && echo "  B ($PARAM=$BVAL): $bsum failing rounds over $bn passes ($((ROUNDS * bn)) rounds)"
