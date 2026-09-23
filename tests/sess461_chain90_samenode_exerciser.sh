#!/bin/bash
# sess461 chain 90: CAW same-node reconcile exerciser — first REAL run.
# Chain 66 (sess449) reported INFRA-FAIL on every lap because the harness's
# precheck read the debugfs path as the node's srcversion; sess451 fixed the
# precheck (tests/caw_samenode_selftest.sh:81-94) and nothing re-ran it, so
# the defect-bar closure vehicle for D-SAMENODE-WAITER-CANCEL-COLLISION,
# D-RECONCILE-SLOT-IDENTITY-UNCHECKED, D-RECONCILE-EXHAUSTION-SILENT and
# D-TRACK-PUBLISH-ORDERING has never produced a verdict.  Runs on the
# PRODUCTION build the fleet carries after chain 89's prod rebuild + prep
# (the harness refuses a loaded srcversion that differs from the tree's, so
# this chain must run before any later chain rebuilds the tree).
# Arms: collide(2) negative(3) collide_late(4, hook B) collide_owed(5, hook C).
# budget: per invocation 4 arms x ~26 s + harvest ≈ 110 s -> bound 150 s
# (harness header); 3 laps test1/test2 + pair test7/test19 ≈ 8 min.
cd /src/mxfs || exit 1
LABEL=${1:-s461b}
GATE=${GATE:-tests/evidence/sess461_chain89_relmark_prekill_s461a.log}
LOG=tests/evidence/sess461_chain90_samenode_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
{
  echo "=== sess461 chain90 START $(date -u +%FT%TZ) tree sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) p275=$(strings -a mxfs.ko | grep -c 'P275-SAMENODE') lab=$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab) ==="
  echo "fleet: $(timeout 20 tools/mxfs_sshpass.sh test1 'cat /sys/module/mxfs/srcversion; grep -c " mxfs " /proc/mounts' 2>/dev/null | grep -av '^Unauthorized access\|^Warning: Permanently\|^If you are not' | tr '\n' ' ')"
  for lap in 1 2 3; do
    T0=$(date +%s); timeout 150 tests/caw_samenode_selftest.sh test1 test2 all; echo "STAGE samenode lap=$lap rc=$? wall=$(( $(date +%s) - T0 ))s"
  done
  T0=$(date +%s); timeout 150 tests/caw_samenode_selftest.sh test7 test19 all; echo "STAGE samenode pair2 rc=$? wall=$(( $(date +%s) - T0 ))s"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
