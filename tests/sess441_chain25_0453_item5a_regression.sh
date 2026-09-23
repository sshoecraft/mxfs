#!/bin/bash
# sess441 chain 25: deploy 0.45.3 (item 5a groundwork built by sess440 but never
# run as a module: MXFS_PROTO_GEN 14, 8 KB bootstrap region + manifest sectors,
# MXFS_RECOV_F_OWNER_BOOTSTRAP on every descriptor owner write, pre-drawn
# incarnation in claim_slot, D-0450 seq-based bootstrap-owner liveness) and
# regression-gate it on the rows those changes touch:
#   prep               32/32 (mkfs writes the new region; gen-14 admission)
#   fence_during_write descriptor owner writes under a live fence
#   node_death_replay  fence certificate + foreign replay + completion ladder
#   remount_snx        same-boot dirty remount (P305 -> P238 own-key fence)
#   remount_refused    refusal keeps the retained key (0.45.2 fix stays)
#   prep2              fleet re-preps
# Module is ALREADY built (sv 9B0387CF); this chain only checks identity.
# Budgets (measured): prep 77 s (bound 300), fence_during_write 21 s (bound
# 60 in-manifest, wrapper 100), node_death_replay 334 s (bound 470, wrapper
# 497), lone_mount arms 100 each, prep2 300.
cd /src/mxfs || exit 1
LABEL=${1:-s441a}
LOG=tests/evidence/sess441_chain25_0453_item5a_regression_$LABEL.log
EV=tests/evidence/sess441_chain25_0453_item5a_regression_$LABEL
mkdir -p "$EV"
{
  echo "=== sess441 chain25 start $(date -u +%FT%TZ) ==="
  SV=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "VERSION=$(cat VERSION) sv=$SV"
  [ -x tools/mkfs_mxfs ] || { echo "ABORT: tools missing"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed on $(cat VERSION)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 100 ./run.sh 32 caw fence_during_write; echo "STAGE fence_during_write rc=$?"
  timeout 497 ./run.sh 32 caw node_death_replay; echo "STAGE node_death_replay rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_mid rc=$?"
  timeout 100 tests/lone_mount_create.sh ${LABEL}_snx test1 32 remount_snx; echo "STAGE remount_snx rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_mid2 rc=$?"
  timeout 100 tests/lone_mount_create.sh ${LABEL}_refused test1 32 remount_refused; echo "STAGE remount_refused rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
