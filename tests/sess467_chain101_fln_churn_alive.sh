#!/bin/bash
# sess467 chain 101: D-RSYNC-OVERWRITE-LAP-USERSPACE-FAIL-ERRNO-UNKNOWN item 2
# (a fenced node's syscalls fail EIO, never the raw SCSI RESERVATION CONFLICT
# EBADE) with the churn ALIVE at the withdrawal.  Chain 11 (0.41.10) recorded
# EBADE=0 EIO=0 because its 4000-file churn finished in ~18 s while the victim
# withdrew at +67 s; tests/fence_live_node.sh now churns until the first
# failure or its 120 s bound and treats EIO=0 as INCONCLUSIVE.
#   1. prep 32/caw on the tree module (prod 0.64.3 after chain 100);
#   2. tests/fence_live_node.sh <label> churn test20 test1 32;
#   3. prep_final.
# Gated on chain 100 DONE.
# budget: prep 300 (measured 86-117 s); fln churn 420 (chain 11 shape: prep
# inside the harness + 75 s hb pause + 67 s withdraw + sweeps); prep 300.
cd /src/mxfs || exit 1
LABEL=${1:-s467c}
GATE=${GATE:-tests/evidence/sess467_chain100_relmark_release_s467b.log}
LOG=tests/evidence/sess467_chain101_fln_churn_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess467 chain101 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') lab=$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab) ==="
  if [ "$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab)" != 0 ]; then echo "ABORT: tree module is a LAB build"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 300 prep ./run.sh 32 caw prep_cluster
  T1=$(date +%s); timeout 420 tests/fence_live_node.sh "$LABEL" churn test20 test1 32 > tests/evidence/sess467_chain101_fln_churn_arm_$LABEL.log 2>&1; echo "STAGE fln_churn rc=$? wall=$(( $(date +%s) - T1 ))s"
  grep -a 'churn started\|WITHDRAW seen\|victim mounted/churn\|churn errno\|INCONCLUSIVE\|^FAIL\|VERDICT' tests/evidence/sess467_chain101_fln_churn_arm_$LABEL.log | cut -c1-220
  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
