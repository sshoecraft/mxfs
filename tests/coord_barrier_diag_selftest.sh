#!/bin/bash
# tests/coord_barrier_diag_selftest.sh — prove that a failed barrier now hands
# its own diagnosis back to the caller.
#
# WHY THIS EXISTS.  coord_barrier knows exactly why it failed: either its
# reporting budget was already spent (so it never waited at all) or it waited
# the whole window and the peer never arrived.  Those are different defects
# with different fixes, and both used to reach the defect ledger as the same
# undifferentiated string "BARRIER_TIMEOUT round=N barrier=<tag>", because
# coord_barrier_or_abort sent the barrier's stderr to /dev/null.  A 2026-09-05
# two-node failure could not be diagnosed from its own capture for exactly
# that reason.
#
# This runs entirely against the MQTT broker with NO filesystem, NO mount and
# NO cluster: it fakes a 2-node rendezvous in which the second rank never
# shows up.  Cost is the barrier window (default 6s) times two cases, so keep
# the windows small — this is a instrument check, not a pace measurement.
#
# Usage: tests/coord_barrier_diag_selftest.sh [broker]
set -u
cd "$(dirname "$0")/.." || exit 2

BROKER="${1:-${MXFS_COORD_BROKER:-192.168.1.149}}"
export MXFS_COORD_BROKER="$BROKER"
export MXFS_COORD_PREFIX="mxfs/coord/selftest/$$-$(date +%s)"
export MXFS_NODES=2
export MXFS_RANK=1

if ! timeout 5 mosquitto_pub -h "$BROKER" -t "$MXFS_COORD_PREFIX/ping" -m 1 2>/dev/null; then
    echo "SKIP: broker $BROKER unreachable — this probe measures nothing without it"
    exit 3
fi

# shellcheck source=/dev/null
. tests/suite/coord.sh

fails=0
ck() {  # <label> <expect-substring> <actual>
    case "$3" in
        *"$2"*) echo "  PASS $1" ;;
        *)      echo "  FAIL $1"; echo "        expected substring: $2"
                echo "        actual            : $3"; fails=$((fails + 1)) ;;
    esac
}

echo "=== coord_barrier_diag_selftest broker=$BROKER prefix=$MXFS_COORD_PREFIX ==="

# ---- Case 1: peer never arrives, reporting budget healthy.
# Expect the caller to receive "TIMEOUT (saw 1/2 ...)": rank 1 published its own
# marker and counted only itself.
export COORD_TIMEOUT=6
unset SUITE_REPORT_S SUITE_T0_S
t0=$(date +%s)
out=$(coord_barrier_or_abort "selftest_peer_absent"); rc=$?
w=$(( $(date +%s) - t0 ))
echo "case1 peer-absent: rc=$rc waited=${w}s out=[$out]"
ck "case1 rc is a timeout (not 0, not the abort code 2)" "" "$( [ "$rc" != 0 ] && [ "$rc" != 2 ] && echo "" || echo "rc=$rc" )"
ck "case1 diagnosis reached the caller"        "TIMEOUT" "$out"
ck "case1 names the distinct-rank count it saw" "saw 1/2" "$out"
ck "case1 carries the window it used"           "eff="    "$out"
# It must actually have waited; an instant return here would mean the budget
# path fired instead and the two cases are not separated after all.
if [ "$w" -ge 4 ]; then echo "  PASS case1 waited the window (${w}s >= 4s)"
else echo "  FAIL case1 returned in ${w}s — it did not wait"; fails=$((fails + 1)); fi

# ---- Case 2: reporting budget already spent.
# coord_eff_timeout returns 0, coord_barrier refuses to wait at all.  This is
# the case that used to be indistinguishable from case 1 in the ledger.
export SUITE_T0_S=$(( $(date +%s) - 900 ))
export SUITE_REPORT_S=60          # 900s elapsed against a 60s budget => spent
t0=$(date +%s)
out2=$(coord_barrier_or_abort "selftest_budget_spent"); rc2=$?
w2=$(( $(date +%s) - t0 ))
echo "case2 budget-spent: rc=$rc2 waited=${w2}s out=[$out2]"
ck "case2 diagnosis reached the caller"     "NO_REPORTING_TIME" "$out2"
ck "case2 carries the spent budget"         "report_s=60"       "$out2"
if [ "$w2" -le 2 ]; then echo "  PASS case2 returned without waiting (${w2}s)"
else echo "  FAIL case2 waited ${w2}s — it should not wait at all"; fails=$((fails + 1)); fi

# ---- Case 3: the success path must stay silent, or every passing barrier
# starts feeding noise into callers that capture stdout.
unset SUITE_REPORT_S SUITE_T0_S
export COORD_TIMEOUT=6
mosquitto_pub -h "$BROKER" -r -q 1 \
    -t "$MXFS_COORD_PREFIX/bar/selftest_ok/r/2" -m 1 2>/dev/null
out3=$(coord_barrier_or_abort "selftest_ok"); rc3=$?
echo "case3 both-present: rc=$rc3 out=[$out3]"
if [ "$rc3" = 0 ] && [ -z "$out3" ]; then echo "  PASS case3 clears silently"
else echo "  FAIL case3 rc=$rc3 out=[$out3] — expected rc=0 and no output"; fails=$((fails + 1)); fi

# ---- Case 4: no temp files leaked.  The wrapper makes two per call.
leaked=$(find /tmp -maxdepth 1 -name '.coord_bardiag.*' -newermt '-10 minutes' 2>/dev/null | grep -c .)
if [ "$leaked" = 0 ]; then echo "  PASS case4 no .coord_bardiag temp files leaked"
else echo "  FAIL case4 $leaked .coord_bardiag temp file(s) leaked"; fails=$((fails + 1)); fi

timeout 10 mosquitto_sub -h "$BROKER" -t "$MXFS_COORD_PREFIX/#" \
    --remove-retained -W 2 >/dev/null 2>&1

echo "=== RESULT: $( [ "$fails" = 0 ] && echo PASS || echo "FAIL ($fails failed)" ) ==="
[ "$fails" = 0 ]
