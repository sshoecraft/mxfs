#!/bin/bash
# paired_perf_diag — instrumented single-leg pair for the single_node_paired
# ~5% residual (sess16 a9a03929).  Runs ONE native-XFS leg and ONE mxfs leg of
# the same rsync workload, each under a chosen instrument, and dumps per-leg
# artifacts to /root/pdiag/.  NOT a pass/fail test — a RULE-4 measurement tool.
#
# Runs ON the node (like single_node_paired.sh).
#   $1 = instrument: ftrace | perf | stats   (default ftrace)
#   $2 = mount point (default /mnt/shared)
#
# ftrace mode: function profiler filtered to the leg's module (:mod:xfs /
#   :mod:mxfs) -> per-function HIT COUNT + TOTAL TIME (graph time, includes
#   children & sleep).  Answers: xlog_grant_head_wait pressure, xfs_log_force
#   count, xfsaild push volume, mxfs hook call counts (mxfs_dlm_is_single_node,
#   mxfs_ag_dlm_lock/unlock, mxfs_dlm_ilock_begin/end).
# perf mode: system-wide cycles during the rsync; report resolved per-symbol
#   for the leg's module WHILE STILL LOADED (perf report -d <module>).
# stats mode: /proc/diskstats + /sys/block deltas only (cheapest).

INSTR="${1:-ftrace}"
MNT="${2:-/mnt/shared}"
DEV="${MXFS_DEV:-/dev/sda}"
MODULE="${MXFS_MODULE:-/src/mxfs/mxfs.ko}"
MKFS_MXFS="${MKFS_MXFS:-/src/mxfs/tools/mkfs_mxfs}"
SRC="${SRC_TREE:-/root/open-gpu-kernel-modules}"
OUT=/root/pdiag
TR=/sys/kernel/debug/tracing

mkdir -p "$OUT"
BDEV=$(basename "$DEV")

fail() { echo "PDIAG-FAIL: $*"; exit 1; }

[ -d "$SRC" ] && [ "$(find "$SRC" -type f | head -1000 | wc -l)" -ge 1000 ] || \
    fail "source tree $SRC missing/thin — run single_node_paired first to seed"

ftrace_reset() {
    echo 0 > "$TR/function_profile_enabled" 2>/dev/null
    echo > "$TR/set_ftrace_filter" 2>/dev/null
}

diskstat_snap() { awk -v d="$BDEV" '$3==d {print $4,$6,$8,$10}' /proc/diskstats; }

run_leg() {  # <label> <modfilter>   — device must be freshly mounted at $MNT
    local label="$1" modfilter="$2" t0 t1 ds0 ds1
    local dst="$MNT/w"
    mkdir -p "$dst"
    sync; echo 3 > /proc/sys/vm/drop_caches

    case "$INSTR" in
    ftrace)
        ftrace_reset
        echo "*:mod:$modfilter" > "$TR/set_ftrace_filter" || \
            fail "$label: set_ftrace_filter :mod:$modfilter"
        echo 1 > "$TR/function_profile_enabled"
        ;;
    perf)
        perf record -a -g -o "$OUT/$label.perf" -- sleep 600 &
        PERF_PID=$!
        sleep 0.5
        ;;
    esac

    ds0=$(diskstat_snap)
    t0=$(date +%s%3N)
    rsync -a "$SRC/" "$dst/" && sync
    t1=$(date +%s%3N)
    ds1=$(diskstat_snap)

    case "$INSTR" in
    ftrace)
        echo 0 > "$TR/function_profile_enabled"
        # trace_stat/function<N> per cpu; concatenate raw, then a merged
        # count/time-per-function summary sorted by total time.
        cat "$TR"/trace_stat/function* > "$OUT/$label.fprof.raw" 2>/dev/null
        awk 'NR>2 && $2 ~ /^[0-9]+$/ {hit[$1]+=$2; t[$1]+=$3} \
             END {for (f in hit) printf "%12d %16.1f  %s\n", hit[f], t[f], f}' \
            "$OUT/$label.fprof.raw" | sort -k2 -rn > "$OUT/$label.fprof"
        ftrace_reset
        ;;
    perf)
        kill -INT $PERF_PID 2>/dev/null; wait $PERF_PID 2>/dev/null
        # resolve module symbols NOW (module still loaded)
        perf report -i "$OUT/$label.perf" --stdio --sort=symbol \
            2>/dev/null | head -60 > "$OUT/$label.perf.sym"
        ;;
    esac

    echo "$ds0"  > "$OUT/$label.diskstat0"
    echo "$ds1"  > "$OUT/$label.diskstat1"
    echo $((t1 - t0)) > "$OUT/$label.wall_ms"
    echo "PDIAG $label: wall=$((t1 - t0))ms diskstat(rd_ios wr_ios rd_sec wr_sec δ): " \
         "$(paste <(echo "$ds0") <(echo "$ds1") | awk '{print $5-$1, $6-$2, $7-$3, $8-$4}')"
}

# ---- native XFS leg ----
mountpoint -q "$MNT" && umount "$MNT"
lsmod | grep -q '^mxfs' && rmmod mxfs 2>/dev/null
mkfs.xfs -f "$DEV" >/dev/null 2>&1 || fail "mkfs.xfs"
mount "$DEV" "$MNT" || fail "xfs mount"
run_leg xfs xfs
umount "$MNT"

# ---- mxfs leg ----
modprobe libcrc32c 2>/dev/null || true
lsmod | grep -q '^mxfs' || insmod "$MODULE" force_transport=1 || fail "insmod"
"$MKFS_MXFS" -f "$DEV" >/dev/null 2>&1 || fail "mkfs_mxfs"
mount -t mxfs "$DEV" "$MNT" || fail "mxfs mount"
run_leg mxfs mxfs
# perf symbol resolution for mxfs already done while loaded; leave mounted.

echo "PDIAG-DONE instr=$INSTR out=$OUT"
if [ "$INSTR" = ftrace ]; then
    echo "== top-25 by total time: xfs ==";  head -25 "$OUT/xfs.fprof"
    echo "== top-25 by total time: mxfs =="; head -25 "$OUT/mxfs.fprof"
    for f in xlog_grant_head_wait xfs_log_force xfsaild mxfs_dlm_is_single_node \
             mxfs_ag_dlm_lock mxfs_ag_dlm_unlock mxfs_dlm_ilock_begin mxfs_dlm_ilock_end; do
        echo "-- $f:"; grep -h " $f" "$OUT"/xfs.fprof "$OUT"/mxfs.fprof 2>/dev/null | head -4
    done
fi
