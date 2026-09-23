#!/bin/bash
# sess421_chain.sh — build + verify 0.32.0 (intent/done census fail-before-
# purge, settle_own_slot pass-1 no-purge, barrier hold knob), relay-proof.
#
#  0. build VERSION (make modules + make tools) and PROVE it complete (second
#     make compiles nothing — see sess419_master_chain.sh for why).
#  1. prep 32/caw; tests/d_intents_undischarged_verify.sh burst   (180 s)
#  2. prep;        tests/d_intents_undischarged_verify.sh clean   (180 s)
#  3. prep;        tests/d_mount_window_death_verify.sh window    (220 s)
#  4. prep;        tests/d_mount_window_death_verify.sh control   (160 s)
#  5. prep;        full 32/caw board (tests/sess416_board_0286.sh, 1900 s) —
#     node_death_replay is EXPECTED to go red on a churn kill that leaves an
#     EFI open (honest red, docs/dlm-protocol.md census section).
#
# budget: build 500 + proof 500 + 5 preps x 300 + 740 s of arms + 1900 board
# => ~5100 s.  Each stage carries its own timeout; nothing here is padded.
#
# Usage: setsid nohup tests/sess421_chain.sh <label>   (or via tests/rig_after.sh)
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
LOG=tests/evidence/sess421_${LABEL}.log
E=tests/evidence
prep_caw() { timeout 300 ./run.sh 32 caw prep_cluster > "$E/sess421_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep caw $1 rc=$?"; }
{
  echo "=== sess421 chain $LABEL start $(date -u +%FT%TZ) build=$(cat VERSION) ==="
  B="$E/sess421_${LABEL}_build.log"
  timeout 500 make modules > "$B" 2>&1; brc=$?
  timeout 120 make tools >> "$B" 2>&1; trc=$?
  echo "STAGE build rc=$brc tools_rc=$trc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') warnings=$(grep -c 'warning:' "$B") skew=$(grep -c 'Clock skew' "$B")"
  if [ $brc -ne 0 ] || [ $trc -ne 0 ]; then echo "ABORT: build failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 500 make modules > "$B.2" 2>&1
  cc2=$(grep -c '^  CC ' "$B.2")
  echo "STAGE build-complete-proof second_make_cc_lines=$cc2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  if [ "$cc2" -ne 0 ]; then echo "ABORT: first build was incomplete ($cc2 objects rebuilt on the second pass)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  prep_caw intents_burst
  timeout 180 tests/d_intents_undischarged_verify.sh "$LABEL" burst; echo "STAGE intents burst rc=$?"
  prep_caw intents_clean
  timeout 180 tests/d_intents_undischarged_verify.sh "$LABEL" clean; echo "STAGE intents clean rc=$?"
  prep_caw mwindow_window
  timeout 220 tests/d_mount_window_death_verify.sh "$LABEL" window; echo "STAGE mwindow window rc=$?"
  prep_caw mwindow_control
  timeout 160 tests/d_mount_window_death_verify.sh "$LABEL" control; echo "STAGE mwindow control rc=$?"
  prep_caw board
  echo "--- board chain $(date -u +%FT%TZ)"
  timeout 1900 bash tests/sess416_board_0286.sh; echo "STAGE boardchain rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
