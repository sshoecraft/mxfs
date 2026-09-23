#!/bin/bash
# sess415 0.28.1 verification chain — D-512 cycle-2 arms (P34J drain-error
# fail-stop, P34K dirty-mismatch containment; both dormant asserts on a
# healthy cluster):
#   1. prep fleet on 0.28.1 (full prep: new srcversion)         ~120s, cap 300
#   2. d512_incarn_gate_verify (cycle-1 regression, knob-forced) ~30s,  cap 100
#   3. zero_silent_loss x2 (the D-512 sentinel criterion)        ~45s ea, cap 120
#   4. full 28-row regression board (~690s walls + 12s*28 + 15s) cap 1150
# Expected board reds: open_defects (policy), crash_consistency first-run
# pace face (D-401, symptom of D-32NODE-SHARED-DIR-CREATE-PACE).
# PASS criteria for the arms: zero P34J / P34K fires fleet-wide (swept after).
cd /src/mxfs || exit 1
LOG=tests/evidence/sess415_verify_0281.log
{
  echo "=== sess415 0.28.1 verify start $(date -u +%FT%TZ) build=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  timeout 300 ./run.sh 32 caw prep_cluster
  echo "STAGE prep rc=$?"
  timeout 100 tests/d512_incarn_gate_verify.sh s415a test5
  echo "STAGE d512 rc=$?"
  timeout 120 ./run.sh 32 caw zero_silent_loss
  echo "STAGE zsl1 rc=$?"
  timeout 120 ./run.sh 32 caw zero_silent_loss
  echo "STAGE zsl2 rc=$?"
  timeout 1150 ./run.sh 32 caw
  echo "STAGE board rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
