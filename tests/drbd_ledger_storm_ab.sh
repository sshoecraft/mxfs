#!/bin/bash
# drbd_ledger_storm_ab.sh — one leg of an A/B of the TCP authority ledger's
# commit cost on an MXFS-on-DRBD pair (the rig's DRBD groups or the physical
# PVE pair), so two builds can be compared under exactly the same workload.
#
# The workload is tests/pve_tree_walk.sh's: participant 0 creates and fsyncs
# SEED_DIRS x SEED_FILES files (seed0: the create cost), participant 1 walks
# them cold (p1: a stat of the peer's new file), participant 0 creates one
# file in the seed's top directory (touch0: participant 1 loses the directory
# it reads to a peer's write and releases every idle read grant it holds at
# once — a release storm, one ledger transition each), and participant 1 walks
# again (p1).  Around it, tests/pve_pair_profile.sh counts and times the
# ledger's page commits, the store's flushes and the DRBD compare-and-swaps on
# both nodes.
#
# Usage: tests/drbd_ledger_storm_ab.sh <label>
# Env:
#   PVE_PAIR      "<addr> <addr>" (required): the pair's two nodes
#   SEED_DIRS / SEED_FILES   the seed's shape (default 2 x 200)
#   SLOW_TRACE    1 = also keep the slow-call trace (default 0: the rig's 6.8
#                 guests run one function-graph user at a time)
#   EVID          default tests/evidence/drbd_ledger_storm/<UTC stamp>-<label>
# Output: $EVID/walk.out (the walk harness's grades and per-op percentiles),
# $EVID/profile/ (the profile snapshots), $EVID/summary.txt (both, condensed).
# It grades nothing beyond what the walk harness grades; it is an instrument.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
LABEL=${1:?usage: tests/drbd_ledger_storm_ab.sh <label>}
PAIR=${PVE_PAIR:?PVE_PAIR must name the pair}
SEED_DIRS=${SEED_DIRS:-2}
SEED_FILES=${SEED_FILES:-200}
EVID=${EVID:-$REPO/tests/evidence/drbd_ledger_storm/$(date -u +%Y%m%dT%H%M%SZ)-$LABEL}
mkdir -p "$EVID" || exit 1
FNS="mxfs_tauth_ledger_commit mxfs_tauth_page_write mxfs_tauth_page_write_many mxfs_pal_bdev_flush mxfs_pal_bdev_compare_and_write mxfs_pal_bdev_compare_and_write_many mxfs_pal_drbd_cas_emulate mxfs_pal_drbd_cas_emulate_many mxfs_drbd_cas_serve dlm_promote_txn dlm_txn_commit mxfs_dlm_process_remote_release mxfs_dlm_process_remote_request mxfs_dlm_unlock_open dlm_lock_impl xfs_create xfs_vn_getattr"

env PVE_PAIR="$PAIR" EVID="$EVID/profile" STOP_FILE="$EVID/profile.stop" INTERVAL_S=5 SLOW_TRACE="${SLOW_TRACE:-0}" FNS="$FNS" \
    "$REPO/tests/pve_pair_profile.sh" > "$EVID/profile.out" 2>&1 &
prof=$!
# the profile's setup is two ssh round trips and a filter write per node
for i in $(seq 1 120); do
    grep -q 'profiling until' "$EVID/profile/summary.txt" 2>/dev/null && break
    kill -0 "$prof" 2>/dev/null || break
    sleep 1
done
grep -q 'profiling until' "$EVID/profile/summary.txt" 2>/dev/null || { echo "drbd_ledger_storm_ab: the profile did not start: $(tail -2 "$EVID/profile.out")"; touch "$EVID/profile.stop"; wait "$prof"; exit 1; }

env PVE_PAIR="$PAIR" SEED_DIRS="$SEED_DIRS" SEED_FILES="$SEED_FILES" DIR=/mnt/shared/walkseed \
    "$REPO/tests/pve_tree_walk.sh" seed0 p1 touch0 p1 > "$EVID/walk.out" 2>&1
walk_rc=$?
# let the release storm the touch started drain into the profile: the last
# snapshot is taken when the stop file is seen, within 5 s
sleep 10
touch "$EVID/profile.stop"
wait "$prof"

{
    echo "label=$LABEL pair=$PAIR seed=${SEED_DIRS}x${SEED_FILES} walk_rc=$walk_rc"
    grep -a -E '^\[.*(phase|entries=|TOUCH_MS|RESULT|name=)|^    (create|fsync) ' "$EVID/walk.out"
    sed -n '/: function, calls/,$p' "$EVID/profile/summary.txt"
} > "$EVID/summary.txt"
cat "$EVID/summary.txt"
echo "evidence: $EVID"
