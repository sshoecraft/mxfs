#!/bin/bash
# pve_ledger_commit_profile.sh — where a cold create's time goes on an
# MXFS-on-DRBD Proxmox pair, split down to the authority ledger's page commit:
# its two compare-and-swaps, its FUA body write and its explicit flushes.
#
# For D-DRBD-PAIR-NEW-FILES-COST-A-LEDGER-COMMIT-TO-CREATE-AND-TO-STAT-FROM-THE-PEER.
# A ledger page commit (dlm/tauth_store.c mxfs_tauth_page_write) is: read both
# copies, CAS the ticket, flush, FUA the body, flush, CAS the publish, flush,
# read back.  On DRBD every CAS is the emulator's lock plus a FUA target write
# (pal/linux/drbd.c), and an empty flush completes on the local disk alone,
# so each of the three flushes follows a write that is already durable on
# both hosts.  This puts numbers on that: calls and total wall of each piece,
# against the creates that paid for them.
#
# Runs tests/pve_pair_profile.sh on both hosts (SLOW_TRACE=0) for the whole of
# tests/pve_tree_walk.sh seed0 (participant 0 creates SEED_DIRS x SEED_FILES
# 4 KiB files, each fsynced, the peer mounted and otherwise idle): about half
# of the resources a create locks are mastered by the peer, and their ledger
# commits run there.
#
# Usage: tests/pve_ledger_commit_profile.sh [label]
# Env:
#   PVE_PAIR     "<addr> <addr>" (default the physical pair)
#   SEED_DIRS / SEED_FILES   (default 1 x 100)
#   PHASES       the tests/pve_tree_walk.sh phases profiled (default seed0;
#                "seed both" profiles both hosts creating, then both walking
#                each other's files)
#   FNS          the functions profiled (default below)
# Output: tests/evidence/pve_ledger_commit_profile/<stamp>-<label>/: the
# profile's summary.txt and the seed's own per-create timings.  It grades
# nothing; it is an instrument.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
LABEL=${1:-run}
PAIR=${PVE_PAIR:-192.168.1.80 192.168.1.81}
read -r -a HOSTS <<<"$PAIR"
EVID="$REPO/tests/evidence/pve_ledger_commit_profile/$(date -u +%Y%m%dT%H%M%SZ)-$LABEL"
mkdir -p "$EVID" || exit 1
FNS=${FNS:-mxfs_tauth_ledger_commit mxfs_tauth_page_write mxfs_tauth_page_write_many mxfs_pal_bdev_flush mxfs_pal_bdev_write_fua mxfs_pal_bdev_compare_and_write mxfs_pal_drbd_cas_emulate mxfs_pal_drbd_cas_emulate_many mxfs_pal_drbd_cas_emulate_span mxfs_drbd_reg_put xfs_create xfs_file_fsync mxfs_dlm_lock mxfs_v5_dlm_inode_reserve_try xfs_log_force_seq}

echo "[$(date +%T)] evidence $EVID" | tee "$EVID/log"
# named before the profiler's own assignments: in one assignment list a later
# word sees an earlier one, so STOP_FILE="$EVID/stop" after EVID=... would name
# a file inside the profile directory
STOP="$EVID/stop"
PVE_PAIR="$PAIR" SLOW_TRACE=0 INTERVAL_S=600 FNS="$FNS" \
    EVID="$EVID/profile" STOP_FILE="$STOP" \
    "$REPO/tests/pve_pair_profile.sh" > "$EVID/profile.out" 2>&1 &
prof=$!
sleep 20     # the profiler selects its functions by index before it counts
read -r -a PH <<<"${PHASES:-seed0}"
PVE_PAIR="$PAIR" SEED_DIRS=${SEED_DIRS:-1} SEED_FILES=${SEED_FILES:-100} \
    "$REPO/tests/pve_tree_walk.sh" "${PH[@]}" > "$EVID/seed.out" 2>&1
echo "seed rc=$?" | tee -a "$EVID/log"
touch "$STOP"
wait "$prof"
echo "profile rc=$?" | tee -a "$EVID/log"
grep -aE 'create|fsync|seed|entries=' "$EVID/seed.out" | tail -10 | tee -a "$EVID/log"
cat "$EVID/profile/summary.txt" 2>/dev/null | tee -a "$EVID/log"
