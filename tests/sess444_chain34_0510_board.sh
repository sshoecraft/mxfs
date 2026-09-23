#!/bin/bash
# sess444 chain 34 (0.51.0): full 32/caw regression board after the ICREATE
# SYNCINIT landing.  The SYNCINIT geometry gate + mandatory FUA init now sit
# on EVERY inode-chunk carve (single-node included) and every ICREATE record
# carries the trailer; the board is the only broad regression gate for that.
# budget: summed measured walls (showstat 32/caw, 2026-08-29) = 1002 s;
# wrapper = 1002 + 12 s x 29 rows + 15 s = 1365 s -> bound 1400 (as chains
# 435-437 used).  No rebuild (chain 32 built 0.51.0).
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess444_chain33_0510_icreate_refuse_negative_s444b.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s444c}
LOG=tests/evidence/sess444_chain34_0510_board_$LABEL.log
{
  echo "=== sess444 chain34 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  if grep -q '^ABORT' tests/evidence/sess444_chain32_0510_icreate_syncinit_s444a.log; then echo "ABORT: chain 32 aborted (no 0.51.0 build)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s)
  timeout 1400 ./run.sh 32 caw; echo "STAGE board rc=$? wall=$(( $(date +%s) - T0 ))s"
  ./showstat.sh 32 caw 2>/dev/null | tail -34
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
