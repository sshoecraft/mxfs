#!/bin/bash
# sess415 0.28.2 verification chain — D-512 cycle-2 arms v2:
#   P-D512-* marker rename (P34J collided with the pre-existing sess22
#   P34J-RELOAD family), drain-hard + P-D512-DIRTY-MISMATCH now wedge via
#   mxfs_inode_wedge (pin grant on disk, refuse pre-CAS unlock, shutdown),
#   drain site 2 rc captured -> wedge on failure.  All arms dormant asserts.
# Stage caps (budget, derived):
#   prep: fleet fully unmounted + 2 nodes module-unloaded -> full prep, 300s
#   d512: ~30s measured, bound 90 -> 100
#   zsl:  29s/23s measured, budget 60 + 12 harness -> 120
#   board: healthy walls ~1040s + observed convoy stall overhead 181s +
#          ndr variance 150s = ~1370 -> 1400 (sum-of-budgets would be ~2600;
#          1400 keeps per-test budgets as the failing mechanism without
#          losing the final row to the outer kill like the 1150 cap did)
# PASS criteria: d512 matrix rc=0; zsl x2 PASS; board green except
# open_defects (policy) and any known D-401 / D-...-CONVOY-0281 faces;
# P-D512 fleet marker count = 0.
cd /src/mxfs || exit 1
LOG=tests/evidence/sess415_verify_0282.log
{
  echo "=== sess415 0.28.2 verify start $(date -u +%FT%TZ) build=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  timeout 300 ./run.sh 32 caw prep_cluster
  echo "STAGE prep rc=$?"
  timeout 100 tests/d512_incarn_gate_verify.sh s415b test5
  echo "STAGE d512 rc=$?"
  timeout 120 ./run.sh 32 caw zero_silent_loss
  echo "STAGE zsl1 rc=$?"
  timeout 120 ./run.sh 32 caw zero_silent_loss
  echo "STAGE zsl2 rc=$?"
  timeout 1400 ./run.sh 32 caw
  echo "STAGE board rc=$?"
  # P-D512 arm sweep: the arms are dormant asserts — any fire is a defect
  # signal.  One parallel fan-out, per-node counts (bare hostname: the
  # sshpass chokepoint prepends root@ itself).
  D512SWEEP=$(mktemp -d)
  for i in $(seq 1 32); do
    ( timeout 12 tools/mxfs_sshpass.sh test$i \
        "dmesg | grep -c 'P-D512-'" > "$D512SWEEP/test$i" 2>/dev/null ) &
  done
  wait
  echo "P-D512 fleet counts (nonzero only):"
  for i in $(seq 1 32); do
    c=$(cat "$D512SWEEP/test$i" 2>/dev/null | tr -dc 0-9)
    [ -n "$c" ] && [ "$c" != "0" ] && echo "  test$i=$c"
  done
  echo "P-D512 sweep done (absent lines = zero)"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
