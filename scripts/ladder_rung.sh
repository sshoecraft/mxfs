#!/bin/bash
# ladder_rung.sh — run ONE node-count rung of a deployment-condition criteria
# ladder (sess7 ccloop 8ba7ae5c; generalized to all 4 conditions.md rigs in
# ccloop 72513a13).  Fresh prep, then the full applicable suite in
# dependency-safe chunks, serialized, with NO outer kill-timeouts (the
# harness's own per-test ceilings apply; killing run.sh mid-flight shuts
# down nodes and poisons the next hour — see ccmemory
# ccloop8ba7-sess7-clyde-memballoon-and-harness-timeouts).
#
# Usage: scripts/ladder_rung.sh <N> [cond]
#   cond = caw (dm-multipath, default) | cawd (direct iSCSI) |
#          cawp (SCST passthrough)     | tcp (LIO commodity block)
#   The matching rig must already be up (scripts/rig.sh <rig> 32).
#   MXFS_DEV is optional — run.sh picks the per-condition default.
# Exit:  0 = every chunk's tests PASS; 1 = any FAIL (grep the log).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
N="${1:?usage: ladder_rung.sh <N> [caw|cawd|cawp|tcp]}"
COND="${2:-caw}"
case "$COND" in caw|cawd|cawp|tcp) ;; *) echo "cond must be caw|cawd|cawp|tcp"; exit 2 ;; esac
LOG="$REPO/tests/logs/ladder_rung_${N}${COND}.log"
mkdir -p "$(dirname "$LOG")"
: > "$LOG"

# run.sh exits 0 even when tests FAIL (FAILs land in criteria.json + the log);
# ANY nonzero exit is an infra abort (1=prep/env, 2=usage, 3=run lock,
# 143=killed) — the chunk did not run, so continuing would fabricate a
# vacuous "FAIL_count=0 rung complete" over cells that were never exercised
# (exactly what launch 2596127 did against an orphan-held lock).  Hard-abort.
run() {  # chunk name...
    echo "--- chunk: $* ---" | tee -a "$LOG"
    RULE0_CALIBRATE="${RULE0_CALIBRATE:-1}" ./run.sh "$N" "$COND" "$@" 2>&1 | tee -a "$LOG" | grep -E "^  (PASS|FAIL|SKIP)"
    local rc=${PIPESTATUS[0]}
    if [ "$rc" -ne 0 ]; then
        echo "=== rung ${N}/${COND} ABORTED: run.sh exit $rc during chunk [$*] — remaining chunks NOT run ===" | tee -a "$LOG"
        exit 3
    fi
}

# Host hygiene (RULE 4, 2026-07-20): 1/tcp fio_perf_vs_xfs + fio_vs_xfs_baseline
# were FAILing at 51-59% of the xfs write baseline. Root-caused to clyde host
# swap exhaustion (8G/8G used, neighbor workloads) inflating fio noise, NOT an
# mxfs regression: a clean-host + freshly-paired-baseline rerun landed
# seqW=697 vs xfs 679 (>100%) and worst_write=93%. Best-effort (perf hygiene,
# not correctness-load-bearing) so a sudo hiccup doesn't abort the rung.
echo "--- health gate: clearing host swap pressure ---" | tee -a "$LOG"
sudo -n swapoff -a >>"$LOG" 2>&1 || echo "WARN: swapoff failed, continuing" | tee -a "$LOG"
sync
echo 3 | sudo -n tee /proc/sys/vm/drop_caches >/dev/null 2>&1
sudo -n swapon -a >>"$LOG" 2>&1 || echo "WARN: swapon failed, continuing" | tee -a "$LOG"
free -h | tee -a "$LOG"

# Fresh per-condition native-XFS write-throughput baseline, captured
# immediately before (paired in time with) this rung's own mxfs run — a
# baseline captured hours earlier under different host load is what produced
# the false FAILs above (see ccmemory ladder-rung-health-gate-and-baseline-
# pairing-fix). Always N=1 (xfs mode is single-node-only, run.sh enforces
# this); device must match this COND's real device, since xfs mode's own
# DEV_DEFAULT only covers cawp/tcp (/dev/sda).
case "$COND" in
    caw)  XFS_BASE_DEV=/dev/mapper/mpatha ;;
    cawd) XFS_BASE_DEV="/dev/disk/by-path/ip-192.168.120.1:3260-iscsi-iqn.2026-05.local.mxfs:shared-lun-0" ;;
    *)    XFS_BASE_DEV=/dev/sda ;;
esac
echo "--- refreshing .xfs_fio_baseline.${COND}.json (dev=$XFS_BASE_DEV) ---" | tee -a "$LOG"
MXFS_DEV="$XFS_BASE_DEV" MXFS_FORCE_PREP=1 ./run.sh 1 xfs prep_cluster 2>&1 | tee -a "$LOG" | tail -3
xfsprep_rc=${PIPESTATUS[0]}
if [ "$xfsprep_rc" -ne 0 ]; then
    echo "=== rung ${N}/${COND} ABORTED: xfs baseline prep failed (exit $xfsprep_rc) ===" | tee -a "$LOG"
    exit 3
fi
MXFS_DEV="$XFS_BASE_DEV" MXFS_TEST_ENV="XFS_BASELINE=$REPO/.xfs_fio_baseline.${COND}.json" \
    ./run.sh 1 xfs fio_perf 2>&1 | tee -a "$LOG" | tail -5
xfsfio_rc=${PIPESTATUS[0]}
if [ "$xfsfio_rc" -ne 0 ]; then
    echo "=== rung ${N}/${COND} ABORTED: xfs baseline fio_perf failed (exit $xfsfio_rc) ===" | tee -a "$LOG"
    exit 3
fi

MXFS_FORCE_PREP=1 RULE0_CALIBRATE="${RULE0_CALIBRATE:-1}" ./run.sh "$N" "$COND" prep_cluster 2>&1 | tee -a "$LOG" | tail -1
prep_rc=${PIPESTATUS[0]}
if [ "$prep_rc" -ne 0 ]; then
    echo "=== rung ${N}/${COND} ABORTED: prep_cluster failed (run.sh exit $prep_rc) ===" | tee -a "$LOG"
    exit 3
fi

# Chunk lists cover BOTH transport families: run.sh applicability silently
# no-ops names whose category transport doesn't match this condition
# (dlm_lock_correctness under tcp; tcp_dlm_scaling under caw-family), and
# max_nodes=1 tooling rows only dispatch at N=1.
run precond_readiness posix_single fsx fio_verify integrity_filetypes fault_enospc
run cache_coherency strong_consistency posix_multi mmap_coherency
run zero_silent_loss dlm_fairness dlm_membership scaling_curve dlm_scaling rsync_paired
run crash_consistency fence_during_write fault_netpartition dlm_lock_correctness tcp_dlm_scaling
run fio_perf fio_perf_vs_xfs
run dir_reuse_coherency
run soak
# Tooling LAST (N=1 rung only — max_nodes=1 rows no-op elsewhere):
# mkfs_timing reformats the shared LUN and dkms_install/single_node_paired
# churn module + LUN state, so nothing that needs the live cluster FS may
# follow them.
run mkfs_timing chk_clean online_resize dkms_install single_node_paired fio_vs_xfs_baseline cluster_ops_timing fault_io_error

fails=$(grep -cE "^  FAIL" "$LOG")
echo "=== rung ${N}/${COND} complete: FAIL_count=$fails (log: $LOG) ===" | tee -a "$LOG"
[ "$fails" -eq 0 ]
