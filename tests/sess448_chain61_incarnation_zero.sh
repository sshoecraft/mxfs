#!/bin/bash
# sess448 chain 61: D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO verification (fix
# landed 0.36.0/0.41.10: dlm/disklock.c hb_rebase_epoch retains a known
# nonzero cached incarnation when the sector reads 0, logging P-HB-INC-ZERO)
# and the D-RECOV-ZERO-EPOCH refusal property, via
# tests/incarnation_mismatch_probe.sh on the PRODUCTION build (chain 60 ends
# on it, fleet prepped).  Arms: zero (survivor must REFUSE: P237-RECOV-INC-
# MISMATCH victim_inc=E1 slot_inc=0, no RECOVERY_GUARD; round 2 must NOT reach
# P237-RECOV-INC-UNOBSERVED — P-HB-INC-ZERO instead) and nonzero
# (P237-RECOV-SUPERSEDED).  The budget rule (harness header): detect 45 s + heal 180 s
# => 260 s bound per arm; prep 300.  Gated on chain 60 DONE.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess448_chain60_iclus_relmark_faults_s448c.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s448d}
LOG=tests/evidence/sess448_chain61_incarnation_zero_$LABEL.log
sweep() { for i in 1 32; do printf "test%s:%s " "$i" "$(timeout 25 tools/mxfs_sshpass.sh test$i "journalctl -k --since -8min --no-pager 2>/dev/null | grep -ac '$1'" 2>/dev/null | tr -dc '0-9')"; done; echo; }
{
  echo "=== sess448 chain61 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') modinfo_lab=$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab) ==="
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  for arm in zero nonzero; do
    T0=$(date +%s); timeout 260 tests/incarnation_mismatch_probe.sh $arm test32 test1 > tests/evidence/sess448_chain61_${arm}_$LABEL.txt 2>&1; rc=$?
    echo "STAGE probe_$arm rc=$rc wall=$(( $(date +%s) - T0 ))s"
    grep -a 'PASS\|FAIL\|VERDICT\|RESULT\|budget' tests/evidence/sess448_chain61_${arm}_$LABEL.txt | head -12 | cut -c1-200
    for p in P-HB-INC-ZERO P237-RECOV-INC-UNOBSERVED P237-RECOV-INC-MISMATCH P237-RECOV-SUPERSEDED RECOVERY_GUARD P234-COMPLETE-FENCEFAIL; do echo "$arm $p: $(sweep $p)"; done
    timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_after_$arm rc=$?"
  done
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
