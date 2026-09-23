#!/bin/bash
# sess448 chain 62: fleet probe census on an idle rig after chain 61 — the
# probes whose absence/presence dispositions minor/high records:
#   'bogus i_mode'          D-RELOAD-FREED-ADOPT-BOGUS-IMODE (verify: zero cluster-wide)
#   P283-REL-FINISH-SKIP    D-DUP-RELEASE-HANDOFF invariant 4 guard occurrences
#   P285-F4-BLI-FREED-OPEN  the f4truth GEN-OPEN residue path (0.55.0 probe; survivors keep their journal)
#   P-RELMARK-ICLUS-*       chain 59/60 LAB laps' marker counters
#   P-HB-INC-ZERO / P237-RECOV-INC-UNOBSERVED   chain 61
# Window: since 3 h before now (covers chains 59-61 on the survivors; victims
# rebooted by the harnesses lose their journal — trap sess433).  Bound: 32
# parallel 25 s ssh => 40 s.  Gated on chain 61 DONE.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess448_chain61_incarnation_zero_s448d.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s448e}
LOG=tests/evidence/sess448_chain62_probe_sweep_$LABEL.log
{
  echo "=== sess448 chain62 start $(date -u +%FT%TZ) ==="
  timeout 60 tests/fleet_probe_sweep.sh tests/evidence/sess448_probesweep_$LABEL '-3h' 32 'bogus i_mode' 'P283-REL-FINISH-SKIP' 'P285-F4-BLI-FREED-OPEN' 'P-RELMARK-ICLUS-UNMARKED' 'P-RELMARK-ICLUS-REINSTALL-REFUSED' 'P-HB-INC-ZERO' 'P237-RECOV-INC-UNOBSERVED' 'P-ICLUS-WEDGE' 'P228-RELBAR-DEFER' 'BUG:' 'Oops'; echo "STAGE sweep rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
