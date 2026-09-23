#!/bin/bash
# sess480 chain 122: run the remaining sess480 rig work IN SEQUENCE, waiting for
# the rig between stages instead of racing for it.
#
# Why a sequencer.  Four chains were launched separately, each gated on the
# previous one's "DONE" line.  That gate is wrong: DONE means a harness finished
# writing its log, not that the rig is free.  All of them woke within 30 s of one
# DONE and collided -- a board left over from an earlier session held the run
# lock, two chains hit "another run.sh holds" and burned themselves to a one-second
# FAIL, and the LAB build chain began relinking mxfs.ko while that board's preps
# were shipping it to 32 nodes.  Sequencing the work in one process, with an
# explicit rig-free wait between stages, removes the race rather than narrowing it.
#
# Stage 0 harvests the board that is already running when this launches.  It must
# come first and it must be read from .last_run.json: that board is the criterion
# (2) evidence for D-FOREIGN-REPLAY-UNGATED-IMAGES, and if any later stage takes
# the lock before it is recorded, the harvest renders whatever ran last instead.
#
# derived time budgets, all from measured walls: board harvest 120 s (showstat only);
# NDR streak 10 laps x (prep 88-112 s + row 333-392 s) plus slack = its own
# script's per-lap timeouts, wrapper 6000 s; LAB build 1200 s (one object plus a
# 69 MB relink); relmark matrix 2400 s (install 30 + prep 300 + matrix 1500 +
# prep 300, measured 230-300 s per arm on chains 85/89).  A stage that hits its
# budget is a failure to diagnose, never a number to widen.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s480f}
LOG=tests/evidence/sess480_chain122_sequencer_$LABEL.log
FREEZE_PROD=$PWD/tests/evidence/sess479_frozen_06437/mxfs.ko
SV=EAD72FC7EC56BA505829901
W=tests/rig_wait_free.sh
{
  echo "=== sess480 chain122 sequencer START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="

  # ---- stage 0: harvest the in-flight board ------------------------------
  echo "--- stage 0: waiting for the in-flight board, then harvesting it ---"
  pre_id=$(python3 -c "import json;print(json.load(open('.last_run.json'))['run_id'])" 2>/dev/null || echo none)
  echo "STAGE0 run_id_before_wait=$pre_id"
  bash "$W" 7200; wrc=$?
  echo "STAGE0 rig_wait rc=$wrc"
  post_id=$(python3 -c "import json;print(json.load(open('.last_run.json'))['run_id'])" 2>/dev/null || echo none)
  echo "STAGE0 run_id_after=$post_id"
  if [ "$post_id" != "$pre_id" ] && [ "$post_id" != none ]; then
    echo "STAGE0 A NEW BOARD LANDED (run_id $pre_id -> $post_id) — this is criterion (2) evidence for D-FOREIGN-REPLAY-UNGATED-IMAGES on $SV"
    echo "--- conditions (run_id=$post_id) ---"
    timeout 120 ./showstat.sh 32 caw 2>&1 | grep -av '^\s*$'
  else
    echo "STAGE0 NO new board recorded (run_id still $pre_id).  The in-flight run did not complete a board; nothing here may be cited for criterion (2)."
  fi

  # ---- stage 1: NDR streak x10 (criterion 3) -----------------------------
  echo "--- stage 1: NDR streak x10 on $SV ---"
  bash "$W" 7200 || { echo "STAGE1 SKIPPED: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  T=$(date +%s)
  PROD_KO=$FREEZE_PROD PROD_SV=$SV GATE=tests/evidence/sess475_chain116_d0133_s479k.log \
    timeout 6000 bash tests/sess480_chain120_ndr_streak_06437.sh "${LABEL}_ndr" 10
  echo "STAGE1 ndr_streak rc=$? wall=$(( $(date +%s) - T ))s budget=6000s"
  grep -a 'NDR_STREAK\|LAP.* PASS\|LAP.* FAIL' "tests/evidence/sess480_chain120_ndr_streak_${LABEL}_ndr.log" 2>/dev/null | tail -20

  # ---- stage 2: LAB build (exclusive with any rig run) -------------------
  echo "--- stage 2: LAB build of $SV ---"
  bash "$W" 7200 || { echo "STAGE2 SKIPPED: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  T=$(date +%s)
  WANT_SV=$SV PROD_KO=$FREEZE_PROD GATE=tests/evidence/sess475_chain116_d0133_s479k.log \
    timeout 1500 bash tests/sess480_chain121_lab_build_06437.sh "${LABEL}_lab"
  echo "STAGE2 lab_build rc=$? wall=$(( $(date +%s) - T ))s"
  grep -a 'STAGE ' "tests/evidence/sess480_chain121_lab_build_${LABEL}_lab.log" 2>/dev/null | tail -8

  # ---- stage 3: ICLUS relmark fault matrix -------------------------------
  echo "--- stage 3: ICLUS relmark 4-arm matrix (D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY) ---"
  LABKO=$PWD/tests/evidence/sess480_frozen_06437_lab/mxfs.ko
  if [ ! -f "$LABKO" ] || [ "$(modinfo "$LABKO" 2>/dev/null | grep -c mxfs_iclus_relmark_lab)" != 1 ]; then
    echo "STAGE3 SKIPPED: no LAB module at $LABKO (stage 2 did not produce one).  Without lab=1 the mount validator refuses icluster_dlm=1 and every arm would be vacuous."
    echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  bash "$W" 7200 || { echo "STAGE3 SKIPPED: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  T=$(date +%s)
  SCRATCH_KO=$LABKO SCRATCH_SV=$SV PROD_KO=$FREEZE_PROD PROD_SV=$SV GATE=tests/evidence/sess475_chain116_d0133_s479k.log \
    timeout 2400 bash tests/sess467_chain100_relmark_matrix_release.sh "${LABEL}_mx"
  echo "STAGE3 matrix rc=$? wall=$(( $(date +%s) - T ))s budget=2400s"
  grep -a 'VACUOUS ARM\|VERDICT\|PREKILL\|STAGE ' "tests/evidence/sess467_chain100_relmark_release_${LABEL}_mx.log" 2>/dev/null | tail -25

  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
