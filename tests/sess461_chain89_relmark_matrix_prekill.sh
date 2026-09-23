#!/bin/bash
# sess461 chain 89: D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY / D-0517 — the
# ICLUS relmark fault matrix re-run with STAGE-HIT EVIDENCE.  Chains 60/85
# reported 'P282 stage hits (fleet): sum=0' for every arm although the knobs
# read back armed (stage 19/20/21, force/oneshot as designed) and
# release_proof_enforce=1.  Two hypotheses, discriminated here:
#   H1 the workload never reaches the marker block of mxfs_iclus_disk_release
#      on ANY node inside the arm window (vacuous by construction) — predicts
#      relmark iclus_marked+failed+unmarked == 0 fleet-wide (debugfs
#      inode_authority, swept per arm) and the victims' pre-kill stage knob
#      still == armed value.
#   H2 the stage fires on the RELEASING node = the victim, whose volatile
#      journal dies with the virsh destroy (trap sess433) — predicts the
#      pre-kill probe (tmpfile_churn_kill.sh TCK_PREKILL_GREP, auto-armed by
#      relgate_fault_stage in TCK_PARAMS) shows stage=0 (oneshot consumed)
#      and a P282-RELGATE-FAULT line on the victim.
# Gated on chain 88 DONE.  Steps: LAB build, prep icluster_dlm=1
# dino_clobber_check=1, the 4-arm matrix, sweep, PRODUCTION rebuild + prep.
# budget: build 600 (measured 286-326 s), prep 300, matrix 1500 (4 arms x
# ~230-300 s measured on chain 85), prod build 600, prep 300.
cd /src/mxfs || exit 1
LABEL=${1:-s461a}
GATE=${GATE:-tests/evidence/sess460_chain88_matrix_resolve_s460c.log}
LOG=tests/evidence/sess461_chain89_relmark_prekill_$LABEL.log
EV=tests/evidence/sess461_relmark_prekill_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$EV"
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess461 chain89 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  T0=$(date +%s)
  timeout 600 make modules KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1 > tests/evidence/sess461_chain89_build_lab_$LABEL.log 2>&1; brc=$?
  LAB=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab')
  echo "STAGE build_lab rc=$brc wall=$(( $(date +%s) - T0 ))s modinfo_lab=$LAB sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess461_chain89_build_lab_$LABEL.log)"
  if [ "$brc" -ne 0 ] || [ "$LAB" -ne 1 ]; then echo "ABORT: lab build"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 120 tools make tools
  export MXFS_EXTRA_MODARGS='icluster_dlm=1 dino_clobber_check=1'
  lap 300 prep_lab ./run.sh 32 caw prep_cluster
  unset MXFS_EXTRA_MODARGS
  echo "knob check: $(for i in 1 16; do printf 'test%s:%s ' $i "$(timeout 20 $SSH test$i 'cat /sys/module/mxfs/parameters/dino_clobber_check /sys/module/mxfs/parameters/icluster_dlm /sys/module/mxfs/parameters/release_proof_enforce 2>/dev/null | tr "\n" ,' 2>/dev/null)"; done)"
  M=$EV/matrix; mkdir -p "$M"
  echo "=== matrix START $(date -u +%FT%TZ) ==="
  T0=$(date +%s)
  timeout 1500 tests/iclus_relmark_faults.sh "$M"; echo "STAGE matrix rc=$? wall=$(( $(date +%s) - T0 ))s"
  grep -a '^=== arm\|^rc=\|^PREKILL\|^prekill\|^P282\|^relmark\|^chk\|^FAIL\|^VERDICT\|^ICLUS' "$M/matrix.txt" 2>/dev/null | cut -c1-300 | head -60
  for pk in "$M"/*/prekill_test*.txt; do [ -f "$pk" ] && { echo "--- $pk"; cut -c1-240 "$pk" | head -8; }; done
  T0=$(date +%s)
  timeout 600 make modules > tests/evidence/sess461_chain89_build_prod_$LABEL.log 2>&1; brc=$?
  echo "STAGE build_prod rc=$brc wall=$(( $(date +%s) - T0 ))s modinfo_lab=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab') sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess461_chain89_build_prod_$LABEL.log)"
  lap 300 prep_prod ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
