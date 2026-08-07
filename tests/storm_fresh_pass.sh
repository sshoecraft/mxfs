#!/bin/bash
# storm_fresh_pass.sh — ONE storm pass on a FRESHLY PREPPED cluster.
#
# WHY THIS EXISTS (and why sf_storm_ab.sh's protocol is not enough here)
#   sf_storm_ab.sh removes the prep-age confound by prepping once and then
#   ALTERNATING arms on the same cluster state.  That works when the effect
#   being measured is present at a steady rate.  It does NOT work for the
#   silent-dirent-loss family, because that defect's rate collapses after the
#   first pass following a prep:
#
#       ccloop c7ee71c6 sess22, build 0.11.174, one prep, three passes:
#           WARMUP  durable=0   B  durable=0   A  durable=0
#       same build/cluster, first pass after a prep, other builds:
#           0.11.173 levers OFF durable=4      0.11.173 levers OFF durable=5
#
#   With every pass after the first reading 0 in BOTH arms, an alternating
#   series measures nothing at all — it just confirms that passes 2..N are
#   quiet.  So the only comparable unit for this defect is FIRST PASS AFTER A
#   PREP, and the arms have to alternate across PREPS instead of within one.
#
#   The cost is a prep (~50-110s) per data point.  That is the price of a
#   measurement that means something; a cheaper series that compares
#   pass-2-of-A against pass-1-of-B is worse than no series, because it will
#   confidently report whichever arm happened to run later as the winner.
#
# USAGE
#   tests/storm_fresh_pass.sh <arm-label> <param=val[,...]> [rounds] [nodes] [tally]
#
#   Records into the same tally format as storm_ab_pass.sh, with prep=1 so the
#   two protocols can never be mixed up when the tally is read back.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)

ARM="${1:?usage: storm_fresh_pass.sh <arm-label> <param=val,...> [rounds] [nodes] [tally]}"
SPEC="${2:?}"
ROUNDS="${3:-60}"
N="${4:-32}"
TALLY="${5:-$REPO/tests/logs/storm_fresh_tally.txt}"

# RULE 0: prep is infrastructure, not workload.  Measured 48-126s at 32 nodes;
# 400s is ~3x the worst observed, and a prep that needs more than that is
# itself a failure worth seeing rather than waiting out.
if ! MXFS_FORCE_PREP=1 timeout 400 "$REPO/run.sh" "$N" caw prep_cluster >/dev/null 2>&1; then
    echo "PASS-RESULT arm=$ARM prep=1 PREP-FAILED (not a data point)" | tee -a "$TALLY"
    exit 2
fi

out=$("$SCRIPT_DIR/storm_ab_pass.sh" "$ARM" "$SPEC" "$ROUNDS" "$N" /dev/null 2>&1)
rc=$?
line=$(printf '%s\n' "$out" | grep '^PASS-RESULT' | tail -1)
[ -n "$line" ] || line="PASS-RESULT arm=$ARM prep=1 NO-RESULT rc=$rc"
printf '%s prep=1\n' "$line" | tee -a "$TALLY"
exit $rc
