#!/bin/bash
# unmount_leak_repro.sh — drive the D-UNMOUNT-BUSY-INODES reproducer in a loop
# until a leak is caught, then dump the attribution.
#
# The leak is INTERMITTENT (recorded as 1-2 of 16 nodes), so a single clean
# cycle proves nothing and must not be read as "fixed".  This loops the exact
# documented sequence and stops at the first catch.
#
# What makes a catch useful: P203-LEVEL, the grab-by-refcount-LEVEL table.  The
# older P202-REFEV ring is a fixed 10-entry HISTORY that has wrapped many times
# by unmount, so it structurally cannot hold an OLD unmatched grab.
#
# NOTE (sess26): P203-GRABSTACK does NOT exist — this script used to grep for it
# and would have printed nothing.  `strings mxfs.ko` confirms zero hits.  What is
# in the tree is P203-LEVEL[n], and it has a real limit: it is sound only under
# LIFO release order.  If grab A takes the count 0->1 and B takes it 1->2 and A
# releases first, the survivor is B's while LEVEL[1] still names A.  So treat its
# attribution as PLAUSIBLE, not proven, and read P205-REFBAL alongside it: that
# says whether the surviving reference came through a TRACKED igrab path at all.
#
# Usage: tests/unmount_leak_repro.sh [N] [cycles]
set -u
N="${1:-16}"; CYCLES="${2:-1}"
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO" || exit 2

for c in $(seq 1 "$CYCLES"); do
  echo "=========== cycle $c/$CYCLES (N=$N) ==========="
  MXFS_FORCE_PREP=1 timeout 580 ./run.sh "$N" caw prep_cluster 2>&1 | tail -1
  # A/B arm: MXFS_LEGACY_CLOBBER=1 restores the pre-sess25 unqualified
  # i_dlm_demoter claim, re-arming D-BAST-IRELE-INACTIVE-SELF-WEDGE.  Used to
  # test whether D-UNMOUNT-BUSY-INODES is a CONSEQUENCE of that wedge (a
  # permanently-stuck kworker parked inside xfs_irele holds an inode reference,
  # which is exactly "busy inodes after unmount").
  ARM="${MXFS_LEGACY_CLOBBER:-0}"
  for i in $(seq 1 "$N"); do
    ( timeout 20 "$REPO/tools/mxfs_sshpass.sh" "test$i" \
        "echo $ARM > /sys/module/mxfs/parameters/demoter_legacy_clobber" >/dev/null 2>&1 ) &
  done; wait
  echo "  demoter_legacy_clobber=$ARM on $N nodes"
  timeout 260 tests/inode_reuse_typeflip.sh 15 "$N" 2 8 2>&1 | tail -1
  timeout 200 ./run.sh "$N" caw cache_coherency 2>&1 | grep -E "PASS|FAIL" | tail -1
  timeout 300 tests/sf_mkdir_storm.sh 12 "$N" 2 1 2>&1 | tail -1
  out=$(timeout 260 tests/unmount_leak_check.sh "$N" 2>&1 | tail -3)
  printf '%s\n' "$out"
  if printf '%s' "$out" | grep -qE "leak=[1-9]"; then
    echo "=== LEAK CAUGHT on cycle $c — attribution below ==="
    for i in $(seq 1 "$N"); do
      r=$(timeout 30 "$REPO/tools/mxfs_sshpass.sh" "test$i" \
            "dmesg | grep -E 'P203-LEVEL|P202-LEAKED-INODE|P204-CANCEL-ARMED-REF|P205-REFBAL' | tail -24" 2>/dev/null)
      [ -n "$r" ] && printf '##### test%s #####\n%s\n' "$i" "$r"
    done
    exit 0
  fi
done
echo "=== no leak caught in $CYCLES cycle(s) — NOT evidence of absence (intermittent, 1-2 of 16) ==="
exit 1
