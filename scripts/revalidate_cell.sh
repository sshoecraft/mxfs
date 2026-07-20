#!/bin/bash
# revalidate_cell.sh — run one (N, caw) criteria-matrix cell-group on the
# CURRENT build with fresh prep, cleared dmesg rings, RULE-0-derived
# budgets, and a post-run probe sweep.  Built for the 0.10.66 full-matrix
# re-validation (ccloop daf50d34): every recorded PASS must come from THIS
# build, ship config (no MXFS_EXTRA_MODARGS), MXFS_DEV=/dev/mapper/mpatha.
#
# Usage: scripts/revalidate_cell.sh <N> <full|nodr|dr|g1|g2>
#   full — every applicable test (run.sh default)         [N<=8]
#   nodr — all EXCEPT dir_reuse_coherency                 [N=16]
#   dr   — dir_reuse_coherency alone                      [N=16,32]
#   g1   — 32-node coherency/perf group (12 tests)        [N=32]
#   g2   — 32-node membership/destructive group (4 tests) [N=32]
#
# TEST_TIMEOUT (per-test budget, RULE 0):
#   N>=32 -> 600s  (cache_coherency@32 measured "alone >=480s")
#   N=16  -> 480s  (cache_coherency/posix scale; 300s calibrated at <=8)
#   else  -> run.sh default 300s
# dir_reuse_coherency budget is computed by run.sh itself (caw: 140*N).
#
# Ring hygiene: dmesg -C on every participating node BEFORE the run so the
# post-run probe_sweep is unambiguous (membership beacons re-emit during
# formation, so the run.sh convergence gate still works — dlm.c:2716).

set -u
N="${1:?usage: revalidate_cell.sh <N> <full|nodr|dr|g1|g2>}"
GRP="${2:?usage: revalidate_cell.sh <N> <full|nodr|dr|g1|g2>}"
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"

NODR="precond_readiness cache_coherency strong_consistency posix_multi \
mmap_coherency zero_silent_loss dlm_fairness dlm_membership scaling_curve \
dlm_scaling rsync_paired crash_consistency fence_during_write \
fault_netpartition soak dlm_lock_correctness"
G1="precond_readiness cache_coherency strong_consistency posix_multi \
mmap_coherency zero_silent_loss dlm_fairness rsync_paired \
dlm_lock_correctness soak scaling_curve dlm_scaling"
G2="dlm_membership fence_during_write fault_netpartition crash_consistency"

case "$GRP" in
    full) TESTS="" ;;
    nodr) TESTS="$NODR" ;;
    dr)   TESTS="dir_reuse_coherency" ;;
    g1)   TESTS="$G1" ;;
    g2)   TESTS="$G2" ;;
    t:*)  TESTS="${GRP#t:}" ;;          # single named test, isolated fresh prep
    *) echo "unknown group '$GRP'"; exit 2 ;;
esac

TT=300
[ "$N" -ge 32 ] && TT=600
[ "$N" -eq 16 ] && TT=480

# Outer wall budget: prep (~60s + ~15s/node incl. possible power-cycles is
# generous headroom; measured healthy 32-node prep ~= 200s) + per-test caps.
ntests=$(wc -w <<<"$TESTS"); [ "$ntests" -eq 0 ] && ntests=17
if [ "$GRP" = dr ]; then
    OUTER=$(( 140 * N + 900 ))
else
    OUTER=$(( ntests * TT + 900 ))
fi

echo "=== revalidate_cell N=$N grp=$GRP tests=${ntests} TEST_TIMEOUT=$TT outer=${OUTER}s ==="

# Clear rings on participating nodes (parallel).
for i in $(seq 1 "$N"); do
    ( timeout 15 "$SSH" "test$i" "$PASS" "dmesg -C" >/dev/null 2>&1 ) &
done
wait
echo "--- rings cleared on test1..test$N ---"

cd "$REPO"
MXFS_DEV=/dev/mapper/mpatha TEST_TIMEOUT="$TT" \
    timeout "$OUTER" ./run.sh "$N" caw $TESTS
rc=$?
echo "=== run.sh rc=$rc (124=outer-timeout=FAIL) ==="

"$REPO/scripts/probe_sweep.sh" "$N"
src=$?
echo "=== probe_sweep rc=$src ==="

[ "$rc" -eq 0 ] && [ "$src" -eq 0 ] && { echo "CELL-GROUP OK N=$N grp=$GRP"; exit 0; }
echo "CELL-GROUP NOT-CLEAN N=$N grp=$GRP (run=$rc sweep=$src)"
exit 1
