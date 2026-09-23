#!/bin/bash
# sess423_chain.sh — re-run the three s421 harness arms whose evidence was
# lost (harness faults fixed sess423: FIEMAP-row extent count, replayer =
# lowest live slot instead of the literal test1, dmesg capture on every exit).
#  1. prep 32/caw; tests/d_intents_undischarged_verify.sh burst   (180 s)
#  2. prep;        tests/d_mount_window_death_verify.sh window    (220 s)
#  3. prep;        tests/d_mount_window_death_verify.sh control   (160 s)
# budget: 3 x prep 300 + 180 + 220 + 160 = 1460 s.
set -u
cd /src/mxfs || exit 2
LABEL=${1:-s423}
E=tests/evidence
prep_caw() { timeout 300 ./run.sh 32 caw prep_cluster > "$E/sess423_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep caw $1 rc=$?"; }
{
  echo "=== sess423 chain $LABEL start $(date -u +%FT%TZ) build=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  prep_caw intents_burst
  timeout 180 tests/d_intents_undischarged_verify.sh "$LABEL" burst; echo "STAGE intents burst rc=$?"
  prep_caw mwindow_window
  timeout 220 tests/d_mount_window_death_verify.sh "$LABEL" window; echo "STAGE mwindow window rc=$?"
  prep_caw mwindow_control
  timeout 160 tests/d_mount_window_death_verify.sh "$LABEL" control; echo "STAGE mwindow control rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} > "$E/sess423_${LABEL}.log" 2>&1
