#!/bin/bash
# sess449 chain 66b (replaces chain 66, which was killed in its gate loop
# before any rig work — its harness bound of 90 s predates arms 4/5 and the
# 14 s hold): CAW same-node reconcile exerciser (0.57.0,
# tests/caw_samenode_selftest.sh, arms collide / negative / collide_late (B)
# / collide_owed (C)) — defect-bar closure vehicle for
# D-SAMENODE-WAITER-CANCEL-COLLISION and siblings.  Runs on the PRODUCTION
# build; rebuilds + re-preps first if the tree's mxfs.ko lacks the P276 hook
# strings.  budget: harness bound 150 s (4 arms ≈ 110 s); build 300; prep
# 300.  Gated on chain 65 DONE.  Same LOG name as chain 66 so chain 67's
# gate is unchanged.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess449_chain65_relgate_inode_s449a.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s449b}
LOG=tests/evidence/sess449_chain66_samenode_$LABEL.log
{
  echo "=== sess449 chain66b start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) p276=$(strings -a mxfs.ko | grep -c 'P276-INJECT') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'P276-INJECT')" = 0 ]; then
    T0=$(date +%s); timeout 300 make modules -j8 > tests/evidence/sess449_chain66_build_$LABEL.log 2>&1; echo "STAGE build rc=$? wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') p276=$(strings -a mxfs.ko | grep -c 'P276-INJECT')"
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  fi
  for lap in 1 2 3; do
    T0=$(date +%s); timeout 150 tests/caw_samenode_selftest.sh test1 test2 all; echo "STAGE samenode lap=$lap rc=$? wall=$(( $(date +%s) - T0 ))s"
  done
  T0=$(date +%s); timeout 150 tests/caw_samenode_selftest.sh test7 test19 all; echo "STAGE samenode pair2 rc=$? wall=$(( $(date +%s) - T0 ))s"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
