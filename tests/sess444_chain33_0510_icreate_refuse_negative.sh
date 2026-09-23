#!/bin/bash
# sess444 chain 33 (0.51.0): D-ICREATE-REPLAY-REINIT-CLOBBERS-PEER-INODES-0510
# NEGATIVE ARM — the refusal side of the SYNCINIT verify.  test5's payload
# dinode is corrupted on the image after the whole-cluster crash; the
# bootstrap must REFUSE that slice (P-ICREATE-VERIFY-FAIL why=magic,
# P-ICREATE-REFUSE, slice failed, term REFUSED) and the sector must be
# byte-identical afterwards — the replay never re-initialises a cluster it
# cannot verify.  the zero-defect bar F&V for D-0510 needs this arm exercised, not only
# the verify-and-skip arm chain 32 measures.
#   prep                    (bound 300; no rebuild — chain 32 built 0.51.0)
#   bootstrap_full_restart  negative arm (bound 1080; the refusal ends the
#                           mount attempt early, peers are not started)
#   prep2
cd /src/mxfs || exit 1
# queued behind chain 32 — wait for its DONE
while ! grep -q "^DONE" tests/evidence/sess444_chain32_0510_icreate_syncinit_s444a.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s444b}
LOG=tests/evidence/sess444_chain33_0510_icreate_refuse_negative_$LABEL.log
EV=tests/evidence/sess444_chain33_0510_icreate_refuse_negative_$LABEL
mkdir -p "$EV"
{
  echo "=== sess444 chain33 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  if grep -q '^ABORT' tests/evidence/sess444_chain32_0510_icreate_syncinit_s444a.log; then echo "ABORT: chain 32 aborted (no 0.51.0 build to measure)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed on $(cat VERSION)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  MXFS_ICREATE_CORRUPT=test5 timeout 1080 tests/bootstrap_full_restart.sh $LABEL 32 test1; echo "STAGE bootstrap_full_restart_negative rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
