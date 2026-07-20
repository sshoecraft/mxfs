#!/bin/bash
# Criterion: Canonical N-node rsync bench — each node rsyncs the
# open-gpu-kernel-modules tree to its own subdir, in parallel.  Wall
# time scales near-linearly (no quadratic blow-up), and zero corruption.
# Threshold: per-node mxfs wall <= 1.2 * single-node xfs wall.
#
# The existing tools/mxfs_multinode_bench.sh is the workhorse; this
# script wraps it, parses the bench.json entry it appends, computes the
# ratio against the reference single-node xfs wall recorded earlier in
# bench.json (sess74_dd_baseline or single_node_paired_rsync_*), and
# emits PASS/FAIL.
#
# Usage: rsync_paired.sh [--nodes N] [--iters I]   (default 4 nodes, 1 iter)

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "rsync_paired"
# Multi-node rsync + mxfs metadata flushes can easily run several
# minutes per iter; the prior 300 s cap killed otherwise-passing runs.
: "${MXFS_SSH_TIMEOUT:=600}"
set_script_timeout 1200

ITERS=1
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --iters) ITERS="$2"; shift 2 ;;
        *) ARGS+=("$1"); shift ;;
    esac
done
parse_common_args "${ARGS[@]+"${ARGS[@]}"}"
[ "${#NODES[@]}" -gt 4 ] && [ -z "${MXFS_FULL_SCALE:-}" ] && NODES=("${NODES[@]:0:4}")

RATIO_THRESHOLD_PCT=120

# Find the most recent single-node XFS reference from bench.json.  Prefer
# a single_node_paired_rsync_* entry; fall back to a per-iter xfs_wall
# from sess74_dd_baseline if needed.
ref_xfs_ms=""
if command -v jq >/dev/null 2>&1 && [ -f "$MXFS_BENCH_JSON" ]; then
    ref_xfs_ms=$(jq -r '
        [ to_entries[]
          | select(.key | startswith("single_node_paired_rsync_"))
          | .value.xfs_wall_ms ]
        | last // empty
    ' "$MXFS_BENCH_JSON")
fi
if [ -z "$ref_xfs_ms" ]; then
    # No reference yet — run single-node paired first to establish one
    "$SCRIPT_DIR/single_node_paired.sh" --nodes 1 >/tmp/snp_for_rsync_paired.log 2>&1 \
        || result_fail "n/a" "ratio<=${RATIO_THRESHOLD_PCT}%" "no XFS reference and single_node_paired failed"
    ref_xfs_ms=$(jq -r '[ to_entries[]
        | select(.key | startswith("single_node_paired_rsync_"))
        | .value.xfs_wall_ms ] | last // empty' "$MXFS_BENCH_JSON")
fi
[ -n "$ref_xfs_ms" ] && [ "$ref_xfs_ms" -gt 0 ] \
    || result_fail "n/a" "ratio<=${RATIO_THRESHOLD_PCT}%" "could not establish XFS reference wall"

# Pre-ensure NFS + module visible on every node — the multinode bench
# script's own prep step races with NFS auto-mount on a recently-booted
# VM, and a single FAIL aborts the whole bench.  Also tear down any
# stale mxfs state (mounts, modules, SCSI PR reservations from a prior
# crashed run) BEFORE the bench's prep phase runs — its CAW probe
# trips on residual reservations and aborts the whole bench.
teardown_all "${NODES[*]}"
# Also clear any leftover SCSI PR reservations from prior runs.  CAW
# in prep_tcm_node_scst.sh trips on a stale Write-Exclusive reservation.
# sg_persist register/clear is idempotent and safe.
parallel_ssh_quiet "${NODES[*]}" "
    for k in \$(sg_persist --read-keys $MXFS_DEV 2>/dev/null | awk '/^    0x/ {print \$1}'); do
        sg_persist --out --register --param-rk=\$k --param-sark=0 $MXFS_DEV 2>/dev/null || true
    done
    sg_persist --out --clear --param-rk=0 $MXFS_DEV 2>/dev/null || true
"
parallel_ssh_quiet "${NODES[*]}" "
    mkdir -p /src
    for try in 1 2 3 4 5; do
        mountpoint -q /src || mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null
        [ -f $MXFS_MODULE ] && break
        sleep 2
    done
"

# Run the multinode bench
KEY="rsync_paired_$(date +%Y%m%d_%H%M%S)"
BENCH_KEY="$KEY" "$MXFS_REPO/tools/mxfs_multinode_bench.sh" "$ITERS" "${NODES[@]}" \
    >/tmp/rsync_paired_run.log 2>&1 \
    || result_fail "n/a" "ratio<=${RATIO_THRESHOLD_PCT}%" "multinode bench failed (see /tmp/rsync_paired_run.log)"

# The multinode bench appends per-iter per-node rows under $KEY.results[].
# Each row has wall_s, md5_match, dst_files, expected_files, dmesg_flagged.
# Extract the worst per-iter average mxfs wall, compare to ref_xfs_ms.
worst_ms=$(jq -r --arg k "$KEY" '
    .[$k].results
    | group_by(.iter)
    | map( [ .[].wall_s | select(. != null) ] | (add // 0) / (length | if . == 0 then 1 else . end) * 1000 | round )
    | max // 0
' "$MXFS_BENCH_JSON")

[ -n "$worst_ms" ] && [ "$worst_ms" -gt 0 ] \
    || result_fail "n/a" "ratio<=${RATIO_THRESHOLD_PCT}%" "bench.json had no parseable wall (key=$KEY)"

ratio_pct=$(( worst_ms * 100 / ref_xfs_ms ))
measured="ref_xfs=${ref_xfs_ms}ms worst_mxfs=${worst_ms}ms ratio=${ratio_pct}%"
threshold="ratio<=${RATIO_THRESHOLD_PCT}%"

# Also check for any corruption flag the bench recorded
fails=$(jq -r --arg k "$KEY" '
    [ .[$k].results[]
      | select((.dmesg_flagged // 0) > 0
            or .md5_match == false
            or (.dst_files != .expected_files)
            or (.rsync_ec != null and .rsync_ec != 0)) ] | length
' "$MXFS_BENCH_JSON")
fails=${fails:-0}
[ "$fails" = "0" ] || result_fail "$measured fails=$fails" "$threshold" "corruption flags in bench output"

[ "$ratio_pct" -le "$RATIO_THRESHOLD_PCT" ] \
    || result_fail "$measured" "$threshold" "worst per-iter wall over 1.2x XFS ref"
result_pass "$measured" "$threshold"
