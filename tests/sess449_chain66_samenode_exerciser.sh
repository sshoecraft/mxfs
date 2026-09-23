#!/bin/bash
# sess449 chain 66: CAW same-node reconcile exerciser (0.56.0,
# tests/caw_samenode_selftest.sh) — the defect-bar closure vehicle for
# D-SAMENODE-WAITER-CANCEL-COLLISION / D-RECONCILE-SLOT-IDENTITY-UNCHECKED /
# D-RECONCILE-EXHAUSTION-SILENT / D-TRACK-PUBLISH-ORDERING.  Runs on the
# PRODUCTION build the fleet carries after chain 65 (the tree's mxfs.ko must
# carry the P275 trigger: chain 59 built the tree AFTER 0.56.0 landed — the
# strings check below proves it; if it does not, this chain rebuilds and
# re-preps first).  budget: harness bound 90 s (2 arms ≈ 45 s); build 300;
# prep 300.  Gated on chain 65 DONE.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess449_chain65_relgate_inode_s449a.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s449b}
LOG=tests/evidence/sess449_chain66_samenode_$LABEL.log
{
  echo "=== sess449 chain66 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) p275=$(strings -a mxfs.ko | grep -c 'P275-SAMENODE') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'P275-SAMENODE')" = 0 ]; then
    T0=$(date +%s); timeout 300 make modules -j8 > tests/evidence/sess449_chain66_build_$LABEL.log 2>&1; echo "STAGE build rc=$? wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') p275=$(strings -a mxfs.ko | grep -c 'P275-SAMENODE')"
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  fi
  for lap in 1 2 3; do
    T0=$(date +%s); timeout 90 tests/caw_samenode_selftest.sh test1 test2 all; echo "STAGE samenode lap=$lap rc=$? wall=$(( $(date +%s) - T0 ))s"
  done
  # a second local/peer pair so the verdict is not one node's slot bit
  T0=$(date +%s); timeout 90 tests/caw_samenode_selftest.sh test7 test19 all; echo "STAGE samenode pair2 rc=$? wall=$(( $(date +%s) - T0 ))s"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
