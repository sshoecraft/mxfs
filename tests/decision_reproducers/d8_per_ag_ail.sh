#!/bin/bash
#
# Decision D8 — Per-AG AIL drain reproducer.
#
# Verifies that mxfs_dlm_ag_bast_work_fn no longer deadlocks under
# 5×512MB cross-node stress.  Pre-fix (xfs_ail_push_all_sync), at this
# workload size both nodes' bast_work_fn block in xfs_ail_push_all_sync
# waiting on AIL items belonging to the AG that the OTHER node holds.
# Post-fix (xfs_ail_push_ag_sync, v0.3.112), the drain only waits on
# items in this AG.
#
# Spec reference: docs/mxfs-architecture-spec.md §11.3 (Phase 1).
# Acceptance: 15/15 iterations pass on both nodes.
#
# Usage:
#   tests/decision_reproducers/d8_per_ag_ail.sh         # 15×512MB (default)
#   tests/decision_reproducers/d8_per_ag_ail.sh 5 256   # smaller smoke run
#
# Wraps scripts/stress_session.sh (session-level stress harness)
# which already requires T1_DD_OK + T2_DD_OK every iter and scans
# dmesg for Internal error / Shutting down / Corruption markers.
#
# Cluster reset (umount + rmmod + insmod + mkfs + mount) is the
# caller's responsibility — invoke scripts/cluster_reset.sh first
# if needed.

set -e

ITERS="${1:-15}"
MB="${2:-512}"
HARNESS=/src/mxfs/scripts/stress_session.sh

if [ ! -x "$HARNESS" ]; then
    echo "ERROR: $HARNESS not found or not executable" >&2
    exit 1
fi

echo "=== D8 per-AG AIL drain reproducer ==="
echo "    workload: ${ITERS}×${MB}MB cross-node dd"
echo "    acceptance: ${ITERS}/${ITERS} pass on both T1 and T2"
echo

exec "$HARNESS" "$ITERS" "$MB"
