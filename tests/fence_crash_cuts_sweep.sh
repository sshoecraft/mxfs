#!/bin/bash
# tests/fence_crash_cuts_sweep.sh — the fence crash cuts in sequence, detached,
# one console per cut and one summary line per cut a driver reads back.
#
# Each cut of tests/fence_crash_cuts.sh is a 450-900 s lap that destroys both
# VMs and brings them back, so six of them cannot be driven from one bounded
# tool call; this runs them in order under their own 1200 s bound each and
# appends to tests/evidence/fcut_sweep_<label>.log:
#     SWEEP cut=<n> rc=<rc> wall=<s>s <the lap's RESULT line, or none>
# and a final `SWEEP DONE cuts=<n> pass=<n> wall=<s>s`.  A cut's own verdict
# (PASS/FAIL/ABORT/VACUOUS) is recorded and the sweep moves on: the next lap's
# prep restores the fleet.  Nothing here widens or retries a lap.
#
# Usage: nohup setsid tests/fence_crash_cuts_sweep.sh <label> [cut...] \
#            > tests/evidence/fcut_sweep_<label>.out 2>&1 &
#        (default cuts: 1 2 3 4 5 6; VICTIM=destroy|silent selects the victim
#        arm of every lap and is recorded on the START line — the two arms
#        are separate sweeps, credited separately)
set -u
LABEL=${1:?label}; shift
CUTS=${*:-1 2 3 4 5 6}
export VICTIM=${VICTIM:-destroy}
cd "$(dirname "$0")/.." || exit 2
LOG=tests/evidence/fcut_sweep_$LABEL.log
s0=$(date +%s); n=0; pass=0
echo "SWEEP START label=$LABEL cuts=[$CUTS] victim=$VICTIM $(date -u +%FT%TZ)" >> "$LOG"
for c in $CUTS; do
    n=$((n+1)); s=$(date +%s)
    con=tests/evidence/fcut_${LABEL}_c$c.console
    timeout 1200 tests/fence_crash_cuts.sh "$LABEL-c$c" "$c" > "$con" 2>&1
    rc=$?
    r=$(grep -a '^RESULT' "$con" | tail -1 | cut -c1-300)
    echo "SWEEP cut=$c rc=$rc wall=$(( $(date +%s) - s ))s ${r:-no RESULT line} console=$con" >> "$LOG"
    [ "$rc" = 0 ] && pass=$((pass+1))
done
echo "SWEEP DONE cuts=$n pass=$pass wall=$(( $(date +%s) - s0 ))s $(date -u +%FT%TZ)" >> "$LOG"
