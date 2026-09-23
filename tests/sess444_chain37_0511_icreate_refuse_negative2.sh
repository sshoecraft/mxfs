#!/bin/bash
# sess444 chain 37 (0.51.1): D-0510 NEGATIVE ARM, second lap.  Chain 33's
# lap corrupted a dinode whose chunk had no ICREATE in the victim's replay
# window (prep-carved chunk, syncfs-covered log) and was caught by the
# inode-buffer verifier instead.  bootstrap_full_restart.sh's NEG payload
# now makes every node carve a fresh chunk right before the crash (200
# fsync'd files in a private dir, log covering held off) and corrupts the
# last file's dinode on test5.  Expected: P-ICREATE-VERIFY-FAIL why=magic
# ino=<test5 payload>, P-ICREATE-REFUSE (content -> -EFSCORRUPTED -> TORN),
# slot failed, term REFUSED, sector byte-identical; >=1 P-ICREATE-VERIFIED
# on the other slices.  Runs on 0.51.1 (chain 36 built it); no rebuild.
#   prep (bound 300); negative full_restart (bound 1080); prep2
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess444_chain36_0511_purge_pace_s444e.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s444f}
LOG=tests/evidence/sess444_chain37_0511_icreate_refuse_negative2_$LABEL.log
{
  echo "=== sess444 chain37 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  if grep -q '^ABORT' tests/evidence/sess444_chain36_0511_purge_pace_s444e.log; then echo "ABORT: chain 36 aborted (no 0.51.1 build)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed on $(cat VERSION)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  MXFS_ICREATE_CORRUPT=test5 timeout 1080 tests/bootstrap_full_restart.sh $LABEL 32 test1; echo "STAGE bootstrap_full_restart_negative rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
