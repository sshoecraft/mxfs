#!/bin/bash
# sess467 chain 100: D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY — the ICLUS
# relmark fault matrix with a FORCED cluster release on each victim before its
# kill.  Chain 89 (sess461, tests/evidence/sess461_chain89_relmark_prekill_s461a.log)
# discriminated the vacuous matrix: every victim's pre-kill probe read
# iclus_marked=0 iclus_failed=0 iclus_unmarked=0 P282=0 with the stage knob
# still armed -> H1 (the churn alone never makes the victim release its
# cluster grant, so the marker block carrying stages 19-21 is never entered
# before the destroy), H2 refuted.  tmpfile_churn_kill.sh now auto-arms
# TCK_PREKILL_RELEASE with the stage knob: a peer reads the victim's churn dir
# and stats its live files (PR on routed inodes -> BAST -> the victim's
# cluster EX is released through the marker block), then the probe reads the
# victim's counters/journal, then the kill.
#   1. install the frozen LAB 0.64.3 (SCRATCH_KO/SCRATCH_SV; modinfo
#      mxfs_iclus_relmark_lab=1) + tools into the tree;
#   2. prep 32/caw with icluster_dlm=1 dino_clobber_check=1;
#   3. tests/iclus_relmark_faults.sh (4 arms: 19, 20/force, 21, 21/force);
#   4. install the frozen PRODUCTION 0.64.3 (PROD_KO/PROD_SV) back into the
#      tree; prep 32/caw.
# Evidence wanted per arm: PREKILL-RELEASE lines with statted>0, PREKILL
# probe with iclus_marked>0 or iclus_unmarked>0 (stage 20/force) and P282>=1
# (stage=0 after a oneshot hit), and the arm's own VERDICT; then the
# certificate assertions of the ruling's 6.3 matrix apply.
# Gated on chain 99 DONE.
# budget: install 30; prep 300 (measured 86-117 s); matrix 1500 (4 arms x
# 230-300 s measured on chains 85/89 + ~5 s per victim for the release); prep 300.
cd /src/mxfs || exit 1
LABEL=${1:-s467b}
GATE=${GATE:-tests/evidence/sess467_chain99_d0523_peerloss_attrib_s467a.log}
LOG=tests/evidence/sess467_chain100_relmark_release_$LABEL.log
EV=tests/evidence/sess467_relmark_release_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$EV"
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
install_ko() { # <ko> <sv> <label>
  local ko="$1" sv="$2" l="$3" t rc=1
  if [ -f "$ko" ] && [ "$(modinfo "$ko" | awk '/srcversion/{print $2}')" = "$sv" ]; then
    cp "$ko" mxfs.ko; rc=$?
    for t in "$(dirname "$ko")"/tools/*; do
      [ -f "$t" ] && [ -x "$t" ] && file "$t" | grep -q ELF && cp "$t" tools/
    done
  fi
  echo "STAGE install_$l rc=$rc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') lab=$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab) from=$ko"
  return $rc
}
{
  echo "=== sess467 chain100 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  install_ko "${SCRATCH_KO:-}" "${SCRATCH_SV:-}" lab || { echo "ABORT: lab install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  [ "$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab)" = 1 ] || { echo "ABORT: not a LAB module"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  export MXFS_EXTRA_MODARGS='icluster_dlm=1 dino_clobber_check=1'
  lap 300 prep_lab ./run.sh 32 caw prep_cluster
  unset MXFS_EXTRA_MODARGS
  echo "knob check: $(for i in 1 16; do printf 'test%s:%s ' $i "$(timeout 20 $SSH test$i 'cat /sys/module/mxfs/parameters/dino_clobber_check /sys/module/mxfs/parameters/icluster_dlm /sys/module/mxfs/parameters/release_proof_enforce 2>/dev/null | tr "\n" ,' 2>/dev/null)"; done)"
  M=$EV/matrix; mkdir -p "$M"
  echo "=== matrix START $(date -u +%FT%TZ) ==="
  T0=$(date +%s)
  timeout 1500 tests/iclus_relmark_faults.sh "$M"; echo "STAGE matrix rc=$? wall=$(( $(date +%s) - T0 ))s"
  grep -a '^=== arm\|^rc=\|^PREKILL\|^prekill\|^P282\|^relmark\|^chk\|^FAIL\|^VERDICT\|^ICLUS' "$M/matrix.txt" 2>/dev/null | cut -c1-300 | head -70
  for pk in "$M"/*/prekill_test*.txt "$M"/*/prekill_release_test*.txt; do [ -f "$pk" ] && { echo "--- $pk"; cut -c1-240 "$pk" | head -8; }; done
  install_ko "${PROD_KO:-}" "${PROD_SV:-}" prod || { echo "ABORT: prod install (tree left on the LAB module!)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  lap 300 prep_prod ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
