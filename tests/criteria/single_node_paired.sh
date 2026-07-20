#!/bin/bash
# Criterion: Single-node mxfs operations within <= 5% of native XFS on
# the same LUN.  Verifier: format the device twice — once XFS, once
# mxfs — and run the same workload on each.  Workload: rsync of the
# canonical open-gpu-kernel-modules tree (8137 files, ~700 MB).
# Threshold: mxfs wall <= 1.05 * xfs wall (mxfs ratio <= 1.05).
#
# Anything >1.05 is a regression vs sess74's 1.00-1.86 baseline; per
# CLAUDE.md anything worse than 5% over is a regression, not a target.
#
# Appends a paired entry to bench.json on every run.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "single_node_paired"
# Bump SSH per-call timeout so rsync of 600 MB / 8 k files survives
# without dropping the leg.  Default 60 s strands the mxfs leg.
: "${MXFS_SSH_TIMEOUT:=600}"
set_script_timeout 600

parse_common_args "$@"
NODE="${NODES[0]}"
RATIO_THRESHOLD_PCT=105  # mxfs/xfs * 100 must be <= 105

teardown_all "$NODE"

# Workload: rsync canonical tree.  --no-i-r so iteration is sequential
# (matches the v1.0 canonical rsync bench in docs/rsync_bench.md).
WORKLOAD="rsync -a --no-i-r /root/open-gpu-kernel-modules/ ./dest/"

out=$(paired_workload_wall_ms "$NODE" "mkdir -p ./dest && $WORKLOAD && sync")
# Anchor on a leading non-word char (or start of line) so "xfs_ms"
# does NOT also match inside "mxfs_ms".  Previously both fields
# captured the mxfs_ms value because greedy .* + "xfs_ms" matched
# the last occurrence — which is the suffix of "mxfs_ms".
xfs_ms=$(echo "$out" | grep -oE '(^|[^a-zA-Z_])xfs_ms=[0-9]+' | head -1 | grep -oE '[0-9]+')
mxfs_ms=$(echo "$out" | grep -oE 'mxfs_ms=[0-9]+' | head -1 | grep -oE '[0-9]+')

[ -n "$xfs_ms" ]  && [ "$xfs_ms"  -gt 0 ] || result_fail "xfs=$xfs_ms mxfs=$mxfs_ms" "ratio<=1.05" "xfs run failed"
[ -n "$mxfs_ms" ] && [ "$mxfs_ms" -gt 0 ] || result_fail "xfs=$xfs_ms mxfs=$mxfs_ms" "ratio<=1.05" "mxfs run failed"

# Ratio = mxfs / xfs, expressed as integer pct (e.g. 102 = 1.02x).
ratio_pct=$(( mxfs_ms * 100 / xfs_ms ))

# Record to bench.json regardless of pass/fail
KEY="single_node_paired_rsync_$(date +%Y%m%d_%H%M%S)"
INFRA="$(ssh_node "$NODE" "uname -a" | head -1 | tr -d '\r' | sed 's/"/\\"/g')"
bench_append "$KEY" \
"\"infra\":\"$INFRA\",\"workload\":\"rsync_-a_open-gpu-kernel-modules\",\"node\":\"$NODE\",\"xfs_wall_ms\":$xfs_ms,\"mxfs_wall_ms\":$mxfs_ms,\"ratio_pct\":$ratio_pct"

measured="xfs=${xfs_ms}ms mxfs=${mxfs_ms}ms ratio=${ratio_pct}%"
threshold="ratio<=${RATIO_THRESHOLD_PCT}%"

[ "$ratio_pct" -le "$RATIO_THRESHOLD_PCT" ] \
    || result_fail "$measured" "$threshold" "mxfs slower than 5% over xfs"
result_pass "$measured" "$threshold"
