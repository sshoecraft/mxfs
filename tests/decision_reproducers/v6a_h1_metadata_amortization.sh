#!/bin/bash
# v6a Hypothesis H1 reproducer (v0.2 — corrected):
#
#   "If we narrow mxfs_buf_needs_fua_read from 'always' to 'only when
#    the buf has not yet been re-read since its last stale event',
#    subsequent metadata reads in the same lock-hold hit the kernel
#    xfs_buf cache rather than triggering SCSI READ FUA, and the
#    2-node rsync bench drops from 9+ min to under 60 s (strong:
#    under 30 s)."
#
# Reference: /src/mxfs/docs/v6-cache-architecture-proposal.md §11.4 H1
#            (the v0.2 correction; supersedes §3.6 wording).
# v5 invalidate-on-acquire is already in place (sess25 v0.3.84/v0.3.99/
# v0.3.105).  The gap is FUA-on-EVERY-read; v6a narrows it to
# FUA-on-FIRST-read-after-invalidate.
#
# Usage:
#   v6a_h1_metadata_amortization.sh <build_label>
#
# Procedure:
#   1. Cluster reset (mxfs_cluster_reset.sh).
#   2. Build/load module identified by <build_label>.  This script does
#      NOT build the module — it expects mxfs.ko to be loaded with the
#      v6a code path active.
#   3. Run the rsync bench cross-node parallel.
#   4. Emit ITER lines + a final PASS/FAIL/MARGINAL verdict per the
#      H1 thresholds.
#
# Pass conditions:
#   - All iters cross-node parallel: wall_s < 60 (strong: < 30).
#   - All iters: match=Y and md5=Y (correctness preserved).
#   - All iters: dmesg_hits=0.
#   - Single-node runs (control): wall_s within 25% of XFS native.
#
# Failing this reproducer means v6a's H1 is rejected as designed.

set -u
LABEL=${1:?"build label required (e.g., v0.4.0_v6a_phase1)"}
BENCH=/src/mxfs/bench/rsync_bench.sh
RESET=/src/mxfs/scripts/cluster_reset.sh
HOSTS_2NODE=192.168.120.186,192.168.120.182
HOSTS_T1=192.168.120.186
HOSTS_T2=192.168.120.182
ITERS=3

# Pass thresholds (seconds).
THRESH_2NODE_PASS=60
THRESH_2NODE_STRONG=30
THRESH_SOLO_REGRESS_PCT=25

[ -x "$BENCH" ] || { echo "FAIL: $BENCH not executable"; exit 2; }

echo "=== v6a H1 reproducer label=$LABEL ==="

# Step 1: cluster reset.  Aborts on failure — H1 isn't measurable on a
# wedged cluster.
echo "--- cluster reset ---"
if [ -x "$RESET" ]; then
  "$RESET" || { echo "FAIL: cluster reset failed"; exit 2; }
else
  echo "WARN: $RESET not present, skipping (tests may be on dirty cluster)"
fi

# Step 2: solo-test1 baseline.
echo "--- solo test1 ---"
"$BENCH" "${LABEL}_solo_t1" "$HOSTS_T1" "$ITERS"

echo "--- solo test2 ---"
"$BENCH" "${LABEL}_solo_t2" "$HOSTS_T2" "$ITERS"

# Step 3: cross-node parallel — the H1 measurement.
echo "--- 2-node parallel (THE H1 MEASUREMENT) ---"
"$BENCH" "${LABEL}_2node" "$HOSTS_2NODE" "$ITERS"

# A future enhancement: parse output to emit a single-line verdict.
# For now, manual review of the ITER lines is required — the script
# is informational, not auto-judging.  Per the methodology, a human
# must look at the numbers and decide whether H1 holds.

cat <<EOF

=== verdict guidance ===

Look at the 2-node parallel ITER lines:

  - All iters wall_s < ${THRESH_2NODE_STRONG}s : H1 STRONG PASS — ship v6a.
  - All iters wall_s < ${THRESH_2NODE_PASS}s   : H1 PASS — ship v6a, profile residual.
  - Any iter ${THRESH_2NODE_PASS}s <= wall_s < 120s : H1 MARGINAL — phase 4 yield-quantum tuning.
  - Any iter wall_s >= 120s OR DNF       : H1 REJECTED — re-evaluate before phase 4.
  - Any iter match=N or md5=N            : CORRECTNESS REGRESSION — STOP, do not ship.
  - Any iter dmesg_hits != 0             : KERNEL ERROR — investigate before declaring pass.

Append the result to /src/mxfs/bench.json with the v6a build label.

EOF
