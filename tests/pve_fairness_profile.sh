#!/bin/bash
# pve_fairness_profile.sh — where each host's time goes while both churn one
# shared directory (tests/pve_churn_fairness.sh), function by function.
#
# The churn's tenure report showed the two hosts trade the directory's lock
# about evenly, but participant 1 does ~5 operations per tenure against
# participant 0's ~95.  This runs tests/pve_pair_profile.sh (ftrace's function
# profiler on both hosts: calls, total and mean wall time, sleep included) for
# exactly the churn's window, over the functions a create, rename, remove and
# append can wait in, so the two hosts' tables can be compared row by row.
#
# Usage: tests/pve_fairness_profile.sh
# Env:   PVE_PAIR (default the physical pair), CHURN (8), WORK_S (60),
#        MKDIR_ON (0), FNS (default below), and anything
#        tests/pve_churn_fairness.sh takes.
# Output: tests/evidence/pve_fairness_profile/<UTC stamp>/ with the churn's
#         log (churn.log) and the profile's summary.txt.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$REPO/tests/evidence/pve_fairness_profile/$STAMP"
mkdir -p "$OUT" || exit 1
export FNS=${FNS:-xfs_create xfs_rename xfs_remove xfs_file_write_iter xfs_file_fsync xfs_dialloc xfs_trans_alloc xfs_trans_commit xfs_log_force xfs_log_force_seq mxfs_ilock_fallible mxfs_lock_inodes_fallible mxfs_ilock_wait_for_transition mxfs_dlm_lock_retries mxfs_ag_dlm_lock mxfs_trans_preacquire_inode_ags mxfs_tauth_ledger_commit mxfs_tauth_page_write mxfs_pal_drbd_cas_emulate mxfs_drbd_reg_put mxfs_dlm_bast_work_fn mxfs_dlm_ag_bast_work_fn mxfs_pal_ioq_admit}
export SLOW_TRACE=${SLOW_TRACE:-0}
export INTERVAL_S=${INTERVAL_S:-3600}
export EVID="$OUT/profile"
STOP="$OUT/profile/stop"
export STOP_FILE="$STOP"

"$REPO/tests/pve_pair_profile.sh" > "$OUT/profile.out" 2>&1 &
PROF=$!
# the profiler arms both hosts before the churn starts; its first line per
# host says it is running
for i in $(seq 1 120); do
    grep -q 'profiling until' "$OUT/profile.out" 2>/dev/null && break
    kill -0 "$PROF" 2>/dev/null || break
    sleep 1
done
"$REPO/tests/pve_churn_fairness.sh" > "$OUT/churn.log" 2>&1
crc=$?
touch "$STOP"
wait "$PROF"
prc=$?
echo "churn rc=$crc profile rc=$prc"
grep -aE 'iterations .*made' "$OUT/churn.log"
echo "profile summary: $OUT/profile/summary.txt"
