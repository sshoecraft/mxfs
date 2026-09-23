#!/bin/bash
# sess446 chain 46 (0.53.0): D-0510 ICREATE negative arm, lap 4.  Lap 3
# (chain 41, tests/evidence/20260829T110503Z_bootfull) never met an ICREATE:
# every slice held only the node's last two transactions (buf=8 txn=2
# icreate=0/0/0 on 31/31) because mxfs_destage_kick pushes the AIL on every
# create, so the chunk carved ~55 creates before the payload was already
# covered.  The harness now creates until a create returns ino % 64 == 0 (the
# create that carved the chunk), makes THAT file the payload and stops, so the
# ICREATE is in the last create txn.  Expect on the corrupted free inode
# (ino | 63): P-ICREATE-VERIFY-FAIL why=magic + P-ICREATE-REFUSE, the term
# refused (rc=32), the sector byte-identical; P-ICREATE-VERIFIED on the other
# 30 slices (positive arm, skipped, nothing written).
# budget: prep 79-120 s (300); negative full restart (1080: lap 3 measured
# 245 s to the verdict on the ring build); prep2 (300).
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess446_chain45_owncrash_nosurvivor_s446b.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s446c}
LOG=tests/evidence/sess446_chain46_0510_icreate_negative4_$LABEL.log
{
  echo "=== sess446 chain46 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s); MXFS_ICREATE_CORRUPT=test5 timeout 1080 tests/bootstrap_full_restart.sh $LABEL 32 test1; echo "STAGE bootstrap_full_restart_negative rc=$? wall=$(( $(date +%s) - T0 ))s"
  D=$(ls -dt tests/evidence/*_bootfull | head -1); echo "EVIDENCE $D"
  R=$D/remounter_dmesg.txt
  echo "ICREATE verified=$(grep -ac 'P-ICREATE-VERIFIED' $R) vfail=$(grep -ac 'P-ICREATE-VERIFY-FAIL' $R) refuse=$(grep -ac 'P-ICREATE-REFUSE' $R) auth=$(grep -ac 'P-ICREATE-AUTH' $R) slices_with_icreate=$(grep -a 'P273-SHADOW-EVAL' $R | grep -vc 'icreate=0/0/0') complete=$(grep -ac 'foreign replay of slot [0-9]* complete' $R) failed=$(grep -ac 'foreign replay of slot [0-9]* .*failed' $R)"
  grep -a 'P-ICREATE-VERIFY-FAIL\|P-ICREATE-REFUSE' $R | head -3 | cut -c1-220
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
