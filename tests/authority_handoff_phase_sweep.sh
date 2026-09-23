#!/bin/bash
# tests/authority_handoff_phase_sweep.sh — the phase sweep whose MINIMUM is the
# answer the ledger is asking for, and one lap is never that answer.
#
# tests/authority_handoff_phase.sh measures ONE relative phase between the
# victim's heartbeat and the peer's unseen sampler.  The peer's sampling phase
# cannot be set from here, so it is sampled: each lap arms the pause at a
# different offset inside one MXFS_DISKLOCK_HB_INTERVAL_MS (dlm/disklock.h:145,
# 2000), and the offsets span the interval.  The number that answers "the
# EARLIEST instant a peer can ACTUALLY complete a handoff" is the SMALLEST
# margin across the sweep — a per-lap PASS says nothing about the worst case
# and this sweep prints the minimum so nobody has to infer it.
#
# Each lap's own bound is the one its harness derives (600 s of work plus up to
# 150 s of boot = 750); four laps at that bound is 3000 s, and nothing here
# widens or retries a lap.  A lap's verdict is recorded and the sweep moves on,
# because the next lap's own prep restores the fleet.
#
# Usage: nohup setsid tests/authority_handoff_phase_sweep.sh <label> [phase_ms...] \
#            > tests/evidence/ahphase_sweep_<label>.out 2>&1 &
#        (default phases: 0 500 1000 1500 — one heartbeat interval in quarters)
set -u
LABEL=${1:?label}; shift
PHASES=${*:-0 500 1000 1500}
cd "$(dirname "$0")/.." || exit 2
LOG=tests/evidence/ahphase_sweep_$LABEL.log
s0=$(date +%s); n=0; pass=0
# the lap's own derived bound: 750 with boot; the SILENT arm adds its
# log-settle wait (see the lap header) — 850
BOUND=750; [ "${SILENT:-0}" = 1 ] && BOUND=850
echo "SWEEP START label=$LABEL phases=[$PHASES] silent=${SILENT:-0} $(date -u +%FT%TZ)" >> "$LOG"
for p in $PHASES; do
    n=$((n+1)); s=$(date +%s)
    con=tests/evidence/ahphase_${LABEL}_$p.console
    timeout $BOUND tests/authority_handoff_phase.sh "$LABEL-p$p" "$p" > "$con" 2>&1
    rc=$?
    r=$(grep -a '^RESULT' "$con" | tail -1 | cut -c1-300)
    echo "SWEEP phase=$p rc=$rc wall=$(( $(date +%s) - s ))s ${r:-no RESULT line} console=$con" >> "$LOG"
    [ "$rc" = 0 ] && pass=$((pass+1))
done
# THE MINIMUM IS THE RESULT.  It is computed from the MARGIN lines the laps
# printed, and only from laps that produced one: a VACUOUS or ABORTed lap has
# no margin and must not be read as a large one.
MIN=$(grep -ah '^MARGIN ' tests/evidence/ahphase_${LABEL}_*.console 2>/dev/null \
      | sed -n 's/.*margin_s=\([-0-9.]*\).*/\1/p' \
      | sort -g | head -1)
GOT=$(grep -ahc '^MARGIN ' tests/evidence/ahphase_${LABEL}_*.console 2>/dev/null | paste -sd+ - | bc 2>/dev/null)
echo "SWEEP DONE phases=$n pass=$pass margins=${GOT:-0} min_margin_s=${MIN:-none} wall=$(( $(date +%s) - s0 ))s $(date -u +%FT%TZ)" >> "$LOG"
