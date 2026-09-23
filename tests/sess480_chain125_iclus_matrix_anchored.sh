#!/bin/bash
# sess480 chain 125: the ICLUS relmark fault matrix, fifth attempt — this time
# with a trigger that can reach the injected code, and a cheap pre-flight that
# refuses to start the matrix if it cannot.
#
# The four previous attempts (chains 85, 89, 100 and today's s480f_mx) all
# measured nothing: every victim probe read iclus_marked=0 iclus_unmarked=0
# P282=0 with the one-shot stage knob still armed.  Three printed VERDICT PASS
# on that and could have been cited to close a critical record; the fourth
# printed VACUOUS ARM on all four arms, because a gate now detects it.
#
# The root, proven from xfs/xfs_mxfs_dlm.c rather than guessed:
# mxfs_iclus_disk_release -- the function holding relgate stages 19-21 -- is
# reached from mxfs_iclus_unlock only behind :57131,
#     if (ic->bast_pending && ic->disk_mode > MXFS_LOCK_NL && !ic->busy) { ... }
#     if (!sweep) return busy_gate ? -EBUSY : 0;
# so an unlock with NO PEER DEMAND retains the grant.  No victim-side action can
# enter the marker block; only a genuine peer BAST can.  The churn could not
# produce one because its files are O_TMPFILE and carry a name for
# sub-milliseconds, so the peer's ls read entries=0 on every lap of every arm.
#
# Two changes make the trigger real:
#   - tmpfile_churn_kill.sh now retains every 64th of its OWN linked files as a
#     named anchor (TCK_ANCHOR_EVERY, auto-armed with the stage knob).  Because
#     the anchors come out of the churn's own allocation stream they sit in the
#     churn's own 16 KB inode clusters BY CONSTRUCTION, not by luck, and each
#     one's inode is printed so the evidence shows co-location instead of
#     assuming it.  The peer now has something to stat.
#   - stage 1 below runs tests/relgate_reachability_preflight.sh, a two-node
#     probe that takes about a minute: node A creates a named file, node B reads
#     it, and A's cluster-release counters are compared before and after.  If
#     they did not move, the matrix WOULD be vacuous and this chain stops
#     without starting it.  Four 32-node matrices -- roughly two hours of rig
#     time -- were spent discovering unreachability that this establishes in
#     minutes.
#
# budget: install 30 s; prep 300 s (measured 88-117 s); pre-flight 120 s (two
# nodes, a create, a read and two counter reads -- if it takes longer than that
# the slowness is itself a finding); matrix 1500 s (4 arms measured 230-300 s
# each on chains 85/89, plus the added anchor statting).
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s480k}
GATE=${GATE:-tests/evidence/sess480_chain124_pace_s480j.log}
LOG=tests/evidence/sess480_chain125_iclus_anchored_$LABEL.log
EV=tests/evidence/sess480_iclus_anchored_$LABEL
LAB_KO=${LAB_KO:?LAB_KO required}
PROD_KO=${PROD_KO:?PROD_KO required}
SV=${SV:?SV required}
mkdir -p "$EV"
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
install_ko() { # <ko> <label>
  cp "$1" mxfs.ko || return 1
  local t d; d=$(dirname "$1")
  for t in mkfs_mxfs chk_mxfs resize_mxfs fua_verify; do
    [ -f "$d/tools/$t" ] && cp "$d/tools/$t" "tools/$t"
  done
  echo "STAGE install_$2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') lab=$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab)"
}
{
  echo "=== sess480 chain125 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  install_ko "$LAB_KO" lab || { echo "ABORT: lab install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  [ "$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab)" = 1 ] || {
    echo "ABORT: not a LAB module — icluster_dlm=1 would be refused and every arm would be vacuous"
    echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  export MXFS_EXTRA_MODARGS='icluster_dlm=1 dino_clobber_check=1'
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?
  unset MXFS_EXTRA_MODARGS
  echo "STAGE prep rc=$prc"
  [ "$prc" = 0 ] || { echo "ABORT: prep rc=$prc"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  echo "--- stage 1: REACHABILITY PRE-FLIGHT (refuse to spend a matrix on an unreachable path) ---"
  T0=$(date +%s)
  timeout 120 bash tests/relgate_reachability_preflight.sh test1 test2 | tee "$EV/preflight.txt"
  rc=${PIPESTATUS[0]}
  echo "STAGE preflight rc=$rc wall=$(( $(date +%s) - T0 ))s"
  if [ "$rc" != 0 ]; then
    echo "STOP: the cluster-release path is NOT reachable, so the 4-arm matrix would be vacuous exactly as chains 85/89/100/s480f_mx were.  NOT starting it — that is the whole point of this pre-flight.  Fix the trigger, then re-run this chain."
    install_ko "$PROD_KO" prod; timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_prod rc=$?"
    echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi

  echo "--- stage 2: the 4-arm matrix, with the anchor trigger armed ---"
  M=$EV/matrix; mkdir -p "$M"
  T0=$(date +%s)
  timeout 1500 tests/iclus_relmark_faults.sh "$M"
  echo "STAGE matrix rc=$? wall=$(( $(date +%s) - T0 ))s budget=1500s"
  grep -a '^=== arm\|^VERDICT\|VACUOUS ARM\|^PREKILL\|PREKILL-ANCHORS\|anchors:' "$M/matrix.txt" 2>/dev/null | cut -c1-260 | head -60

  install_ko "$PROD_KO" prod || echo "WARN: prod restore failed — the tree is LEFT ON THE LAB MODULE"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_prod rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
