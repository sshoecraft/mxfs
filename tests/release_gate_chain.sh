#!/bin/bash
#
# release_gate_chain.sh — the laps a fix owes, and only when every one of them
# passed, the release verification on the same deployed module.
#
# A fix for a fault that shows in about one lap in ten is verified by a run
# long enough that a clean result means something, and the release boards are
# not worth their hours on a module that failed it.  This runs the two in that
# order, detached, so the rig is never idle between them and never runs the
# boards on a module the laps have just failed:
#
#   1  tests/quiesce_remount_chain.sh <tag> <laps> 0 0 <inject_laps>: the
#      injected laps first, then the natural ones, no control arm
#   2  every LAP line of its summary must read rc=0, and there must be
#      <laps> + <inject_laps> of them; anything else ends the run here with
#      GATE-LAPS verdict=FAIL.  The laps must also have met what they were
#      run for: the walk's kept-buffer counter (each lap's WALK line) has to
#      have moved in at least one of them, or the run ends with
#      GATE-LAPS verdict=VACUOUS
#   3  tests/release_verify_chain.sh <version>, with W4_LAPS, W2TCP, W2CAWD,
#      FULL and BOARDS2 taken from the environment as that script reads them
#
# The module is whatever the fleet runs when this starts; each lap checks that
# it is this tree's build and aborts if it is not, and the release chain makes
# its own clean build of the tree, so the tree's source must not change while
# this runs.
#
# budget: laps x 880 s worst case (about 120 s each when healthy), then the
# release chain's own budgets; nothing here wraps a step in a timeout, every
# step enforces its own.
#
# Log: tests/evidence/release_gate_<tag>.log, lines GATE-BEGIN, GATE-LAPS,
# GATE-RELEASE-CHAIN and GATE-END.
#
# Usage: nohup setsid tests/release_gate_chain.sh <tag> <laps> <version> [inject_laps] \
#            > tests/evidence/release_gate_<tag>.out 2>&1 < /dev/null &
set -u
TAG=${1:?tag}
LAPS=${2:?laps}
V=${3:?version}
INJECT=${4:-0}
cd "$(dirname "$0")/.." || exit 2
case $LAPS in ''|*[!0-9]*) echo "laps must be a count"; exit 2 ;; esac
case $INJECT in ''|*[!0-9]*) echo "inject_laps must be a count"; exit 2 ;; esac
WANT=$(( LAPS + INJECT ))
for s in tests/quiesce_remount_chain.sh tests/release_verify_chain.sh; do
    [ -x "$s" ] || { echo "chain defect: $s is not executable; nothing run"; exit 2; }
done
L=tests/evidence/release_gate_$TAG.log
S=tests/evidence/quiesce_remount_access/chain_$TAG.summary
echo "GATE-BEGIN tag=$TAG laps=$LAPS inject_laps=$INJECT version=$V sv=$(modinfo -F srcversion mxfs.ko 2>/dev/null) $(date -u +%FT%TZ)" | tee -a "$L"

tests/quiesce_remount_chain.sh "$TAG" "$LAPS" 0 0 "$INJECT" > "tests/evidence/quiesce_remount_access/chain_$TAG.log" 2>&1
ran=$(grep -ac '^LAP ' "$S" 2>/dev/null)
ok=$(grep -a '^LAP ' "$S" 2>/dev/null | grep -ac ' rc=0 ')
# what the laps exercised: cluster buffers the fresh-grant walk kept because
# they were queued for write, summed over the laps, and the laps that met one
kept=$(grep -a '^LAP ' "$S" 2>/dev/null | grep -ao ' kept_queued=[0-9]*' | cut -d= -f2 | awk '{s += $1} END {print s + 0}')
keptlaps=$(grep -a '^LAP ' "$S" 2>/dev/null | grep -ac ' kept_queued=[1-9]')
if [ "${ran:-0}" = "$WANT" ] && [ "${ok:-0}" = "$WANT" ] && [ "${kept:-0}" -gt 0 ]; then
    echo "GATE-LAPS verdict=PASS ran=$ran passed=$ok kept_queued=$kept laps_that_kept=$keptlaps summary=$S $(date -u +%FT%TZ)" | tee -a "$L"
elif [ "${ran:-0}" = "$WANT" ] && [ "${ok:-0}" = "$WANT" ]; then
    # every lap passed and none met a cluster buffer queued for write at the
    # walk: nothing here exercised the rule the laps were run for
    echo "GATE-LAPS verdict=VACUOUS ran=$ran passed=$ok kept_queued=0 summary=$S $(date -u +%FT%TZ)" | tee -a "$L"
    echo "GATE-END released_chain=not-run $(date -u +%FT%TZ)" | tee -a "$L"
    exit 1
else
    echo "GATE-LAPS verdict=FAIL ran=${ran:-0} passed=${ok:-0} wanted=$WANT summary=$S $(date -u +%FT%TZ)" | tee -a "$L"
    grep -a '^LAP ' "$S" 2>/dev/null | grep -av ' rc=0 ' | sed 's/ :: TENANT.* :: failed:/ failed:/' | cut -c1-400 | tee -a "$L"
    echo "GATE-END released_chain=not-run $(date -u +%FT%TZ)" | tee -a "$L"
    exit 1
fi

tests/release_verify_chain.sh "$V" > "tests/evidence/release_gate_${TAG}_chain.out" 2>&1
rc=$?
echo "GATE-RELEASE-CHAIN rc=$rc log=tests/evidence/release_verify_$V.log $(date -u +%FT%TZ)" | tee -a "$L"
echo "GATE-END released_chain=ran $(date -u +%FT%TZ)" | tee -a "$L"
