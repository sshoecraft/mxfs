#!/bin/bash
# sess445 chain 41 (0.53.0): D-0510 ICREATE negative arm, lap 3.  Lap 2
# (chain 37) corrupted the PAYLOAD dinode, which the victim had also logged
# as an inode item, so xfs_inode_buf_verify on the inode-item replay refused
# the cluster (-117, nothing written) before the ICREATE verify ran.  The
# harness now zeroes the magic of a FREE inode of the freshly carved chunk
# (ino | 63) — ICREATE-only coverage — expecting P-ICREATE-VERIFY-FAIL
# why=magic + P-ICREATE-REFUSE, the term refused (rc=32), the sector
# byte-identical, and P-ICREATE-VERIFIED on the other 30 slices.
# budget: prep (300); negative full restart (1080: chain 37 measured 4 min
# to the refusal); prep2.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess445_chain40_0511_prefetch_ring_s445c.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s445d}
LOG=tests/evidence/sess445_chain41_0510_icreate_negative3_$LABEL.log
{
  echo "=== sess445 chain41 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  MXFS_ICREATE_CORRUPT=test5 timeout 1080 tests/bootstrap_full_restart.sh $LABEL 32 test1; echo "STAGE bootstrap_full_restart_negative rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
