#!/bin/bash
# sess453 chain 73 (0.59.3): full 32/caw regression board after the 0.59.2
# RETIRE_PENDING settlement fixes (bracketed PR proof, probe thread, OWN
# restricted to P305, key-0 never ABSENT, asserted departure quiescence) and
# the 0.59.3 PAL-log newline fix (D-0518).  The quiescence gate sits on EVERY
# clean unmount and the newline fix changes what every dmesg capture can see,
# so the board is the broad regression gate for both.  Watch for
# P304-RETIRE-NOT-QUIESCED on clean unmounts (a leaked inflight count would be
# a zero-defect bar defect, not a harness fault).
# budget: summed measured walls (showstat 32/caw, 2026-08-29 board) = 1057 s;
# wrapper = 1057 + 12 s x 29 rows + 15 s = 1420 s.  No rebuild here (chain 72
# runs on the 0.59.3 build, sv 9727DA882F7381B8CC32ED8); waits for chain 72
# (tests/evidence/sess452_chain71_retire_pending_s453a.log) to print DONE.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess452_chain71_retire_pending_s453a.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s453b}
LOG=tests/evidence/sess453_chain73_0593_board_$LABEL.log
{
  echo "=== sess453 chain73 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  if [ "$(modinfo mxfs.ko | awk '/srcversion/{print $2}')" != 9727DA882F7381B8CC32ED8 ]; then echo "ABORT: mxfs.ko is not the 0.59.3 build chain 72 ran"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  if grep -q '^ABORT' tests/evidence/sess452_chain71_retire_pending_s453a.log; then echo "ABORT: chain 72 aborted"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s)
  timeout 1420 ./run.sh 32 caw; echo "STAGE board rc=$? wall=$(( $(date +%s) - T0 ))s"
  ./showstat.sh 32 caw 2>/dev/null | tail -34
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
