#!/bin/bash
# tests/fence_partition_sweep.sh — the partition/reconnect arms in sequence,
# each under its own derived bound, one summary line per arm.
#
# Same shape as tests/fence_crash_cuts_sweep.sh: a lap's verdict is recorded
# and the sweep moves on, because the next lap's own prep restores the fleet.
# Nothing here widens or retries a lap.
#
# The bounds are the ones tests/fence_partition_reconnect.sh derives in its own
# header and nothing else:
#     storage  ~380-460 s of work + up to 150 s of boot  -> 700
#     network  -> 900, re-derived when the arm stopped reading its verdict at
#       one instant and started grading the resolution to the end.  It is not
#       the same arm at a longer bound: it now holds the partition through two
#       bounded waits it did not have.  prep 300 (measured 233) + identities
#       and baseline 25 + B's 64 oracle files 10 + the sampler 5 + the
#       partition 120 + the fence settle 100 (measured 67.5 from the first
#       fence marker, most of it inside the partition) + the victim's slice
#       replayed to completion 180 + the heal, its 45 s settle, containment,
#       the oracle read and cleanup 140  =  880.  -> 1000 when the arm stopped
#       naming one node the survivor: grading the observed direction costs two
#       more dmesg captures, the loser's containment window (bound 60) and the
#       loser's final window (bound 40), each measured at a few seconds.
# The APTPL prerequisite reads four SCSI commands over ssh -> 90.
#
# Usage: tests/fence_partition_sweep.sh <label> [arm...]
#        arms: aptpl storage network   (default: all three, in that order —
#        the APTPL probe is the restart laps' prerequisite and is cheap, so it
#        runs first and its verdict is on the record before anything is
#        partitioned)
set -u
LABEL=${1:?label}; shift
ARMS=${*:-aptpl storage network}
cd "$(dirname "$0")/.." || exit 2
LOG=tests/evidence/fpart_sweep_$LABEL.log
s0=$(date +%s); n=0; pass=0
echo "SWEEP START label=$LABEL arms=[$ARMS] $(date -u +%FT%TZ)" >> "$LOG"
for a in $ARMS; do
    n=$((n+1)); s=$(date +%s)
    con=tests/evidence/fpart_${LABEL}_$a.console
    case $a in
        aptpl)   timeout 90  tests/pr_aptpl_probe.sh "$LABEL-$a" > "$con" 2>&1 ;;
        storage) ARM=storage timeout 700 tests/fence_partition_reconnect.sh "$LABEL-$a" > "$con" 2>&1 ;;
        network) ARM=network timeout 1000 tests/fence_partition_reconnect.sh "$LABEL-$a" > "$con" 2>&1 ;;
        *)       echo "SWEEP arm=$a rc=2 unknown arm" >> "$LOG"; continue ;;
    esac
    rc=$?
    r=$(grep -a '^RESULT' "$con" | tail -1 | cut -c1-300)
    echo "SWEEP arm=$a rc=$rc wall=$(( $(date +%s) - s ))s ${r:-no RESULT line} console=$con" >> "$LOG"
    [ "$rc" = 0 ] && pass=$((pass+1))
done
echo "SWEEP DONE arms=$n pass=$pass wall=$(( $(date +%s) - s0 ))s $(date -u +%FT%TZ)" >> "$LOG"
