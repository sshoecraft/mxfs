#!/bin/bash
# sess480 chain 121: build and freeze the LAB variant of 0.64.37 so the ICLUS
# relmark fault matrix (D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY) can be
# re-run on the current candidate.
#
# Why a separate chain just to build.  The rig preps insmod the TREE's
# /src/mxfs/mxfs.ko over NFS, so rebuilding while any harness is in flight
# splits that run's srcversion across the fleet and silently corrupts its
# evidence.  This chain therefore waits for the board chains to finish before
# it touches the tree, and it is gated rather than run by hand for the same
# reason.
#
# What LAB means here.  MXFS_ICLUS_RELMARK_READY defaults to 0, and
# pal/linux/xfs_super.c:2990 makes the mount validator refuse icluster_dlm=1
# while it is 0 -- so the ICLUS clean-release marker path (relgate stages
# 19-21) cannot be exercised on a production build at all.  KCFLAGS
# -DMXFS_ICLUS_RELMARK_READY=1 lifts exactly that, and nothing else: the macro
# has two use sites, both in xfs_super.c.  srcversion hashes SOURCE, so the LAB
# module carries the SAME srcversion as production and is distinguishable only
# by the MODULE_INFO(mxfs_iclus_relmark_lab) field -- which is why every check
# below tests `lab=` and not the srcversion alone.
#
# budget: the macro touches one object, so this is one compile plus a relink of
# a 69 MB module.  BUILD_BUDGET is a first-measurement upper bound, not a
# derived figure -- the chain prints its actual wall precisely so the next run
# can tighten it toward what was measured.  A build that hits the budget is a
# failure to diagnose, not a number to raise.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s480d}
GATE=${GATE:-tests/evidence/sess480_chain120_ndr_streak_s480c.log}
LOG=tests/evidence/sess480_chain121_lab_build_$LABEL.log
FREEZE=${FREEZE:-tests/evidence/sess480_frozen_06437_lab}
WANT_SV=${WANT_SV:?WANT_SV required}
PROD_KO=${PROD_KO:?PROD_KO required}
BUILD_BUDGET=${BUILD_BUDGET:-1200}
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
{
  echo "=== sess480 chain121 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) want_sv=$WANT_SV ==="
  mkdir -p "$FREEZE/tools"
  T0=$(date +%s)
  timeout "$BUILD_BUDGET" make modules KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1 > "$FREEZE/build.log" 2>&1
  brc=$?; wall=$(( $(date +%s) - T0 ))
  echo "STAGE lab_build rc=$brc wall=${wall}s budget=${BUILD_BUDGET}s"
  if [ "$brc" = 124 ]; then
    echo "FAIL: the LAB build exceeded its ${BUILD_BUDGET}s budget (wall=${wall}s) — diagnose the slowness, do not widen the number."
    echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  if [ "$brc" != 0 ]; then
    echo "FAIL: LAB build rc=$brc — tail of build.log:"; tail -25 "$FREEZE/build.log"
    echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  lab=$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab)
  echo "STAGE lab_identity sv=$sv want=$WANT_SV lab=$lab"
  # Both gates matter and neither is redundant: the srcversion proves this is
  # the SAME SOURCE as the production candidate (so the matrix speaks about the
  # build under test), and lab=1 proves the marker path is actually reachable
  # (so the matrix is not vacuous for the third-plus time).
  if [ "$sv" != "$WANT_SV" ]; then
    echo "FAIL: srcversion $sv != $WANT_SV — the tree is not the candidate source; this LAB module would not speak about 0.64.37."
    echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  if [ "$lab" != 1 ]; then
    echo "FAIL: modinfo carries no mxfs_iclus_relmark_lab — KCFLAGS did not reach the compile, so icluster_dlm=1 would still be refused and every arm would be vacuous."
    echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  cp mxfs.ko "$FREEZE/mxfs.ko" || { echo "FAIL: freeze copy"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  for t in mkfs_mxfs chk_mxfs resize_mxfs fua_verify caw_verify; do
    [ -x "tools/$t" ] && cp "tools/$t" "$FREEZE/tools/$t"
  done
  echo "STAGE freeze path=$FREEZE sv=$(modinfo "$FREEZE/mxfs.ko" | awk '/srcversion/{print $2}') lab=$(modinfo "$FREEZE/mxfs.ko" | grep -c mxfs_iclus_relmark_lab) bytes=$(stat -c %s "$FREEZE/mxfs.ko")"
  # Leave the tree on PRODUCTION.  A tree left carrying the LAB module is how a
  # later prep silently mounts a lab build under a production criterion.
  if [ -f "$PROD_KO" ]; then
    cp "$PROD_KO" mxfs.ko
    echo "STAGE restore_prod sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') lab=$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab)"
  else
    echo "WARN: $PROD_KO missing — the tree is LEFT ON THE LAB MODULE; do not run a production criterion until it is restored."
  fi
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
