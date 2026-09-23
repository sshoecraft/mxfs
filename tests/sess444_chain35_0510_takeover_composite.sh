#!/bin/bash
# sess444 chain 35 (0.51.0): item 5f STAGE C — takeover points 13/14 (old
# owner destroyed AFTER K was claimed / after the 8th foreign completion):
# the contender must adopt K with COMPOSITE provenance (docs/
# whole-cluster-restart.md §6.8.5): tokens naming an earlier incarnation of
# the slice are judged by the lineage pair's sealed manifest + certificate
# (P-BOOT-K-COMPOSITE / P-BOOT-K-COMPOSITE-EVAL), never by K's current
# bits; point 14 additionally inherits 8 completions (INHERITED tombstones).
#   prep; bootstrap_takeover 13; prep; bootstrap_takeover 14; prep2
# Budgets as chain 31: prep bound 300; takeover bound 1500 x2.  No rebuild.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess444_chain34_0510_board_s444c.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s444d}
LOG=tests/evidence/sess444_chain35_0510_takeover_composite_$LABEL.log
EV=tests/evidence/sess444_chain35_0510_takeover_composite_$LABEL
mkdir -p "$EV"
{
  echo "=== sess444 chain35 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  if grep -q '^ABORT' tests/evidence/sess444_chain32_0510_icreate_syncinit_s444a.log; then echo "ABORT: chain 32 aborted (no 0.51.0 build)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  for pt in 13 14; do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_before_takeover$pt rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed before takeover $pt"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
    timeout 1500 tests/bootstrap_takeover.sh ${LABEL}t$pt $pt 32 test1 test2; echo "STAGE bootstrap_takeover$pt rc=$?"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
