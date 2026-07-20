#!/bin/bash
# single_node_paired — single-node performance vs native XFS on the SAME LUN.
# rsync of the canonical source tree into native XFS, then into MXFS; report the
# ratio. This is a perf benchmark, so unlike the pure correctness tests it
# controls the device (mkfs XFS then MXFS) — DEV/MODULE come from env defaults.
# Leaves the node mounted on a fresh MXFS at the end.
#
# Runs ON the node. $1 = mount point.

SUITE_TEST_NAME=single_node_paired
MNT="${1:-/mnt/shared}"
NODES="${MXFS_NODES:-1}"
DEV="${MXFS_DEV:-/dev/sda}"
MODULE="${MXFS_MODULE:-/src/mxfs/mxfs.ko}"
MKFS_MXFS="${MKFS_MXFS:-/src/mxfs/tools/mkfs_mxfs}"
SRC="${SRC_TREE:-/root/open-gpu-kernel-modules}"
SEED="${SRC_SEED:-/src/open-gpu-kernel-modules}"
THRESH="${RATIO_THRESHOLD:-105}"   # mxfs wall must be <= THRESH% of XFS (within 5%, per tests/criteria)

emit() { echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; [ "$1" = PASS ]; }

# Ensure a LOCAL source tree (don't benchmark over NFS); seed from /src if thin.
cnt=$(find "$SRC" -type f 2>/dev/null | wc -l)
if [ "$cnt" -lt 1000 ]; then
    [ -d "$SEED" ] || { emit FAIL "setup" "no source tree at $SRC or seed $SEED"; exit 1; }
    mkdir -p "$SRC"; rsync -a "$SEED/" "$SRC/" || { emit FAIL "setup" "seed rsync failed"; exit 1; }
    cnt=$(find "$SRC" -type f 2>/dev/null | wc -l)
fi

timed_rsync() {  # <dstsub> -> echoes wall ms; rsync + sync
    local dst="$MNT/$1" t0 t1
    mkdir -p "$dst"
    sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
    t0=$(date +%s%3N)
    rsync -a "$SRC/" "$dst/" && sync
    t1=$(date +%s%3N)
    echo $((t1 - t0))
}

# sess15(a9a03929): the single-leg protocol was a HOST-cache coin flip — the
# iSCSI target's backing-file page cache (clyde disk.img, SCST async) differs
# between the two legs, and measured xfs-leg walls swing 2786-3269ms while
# mxfs stays ~3.3-3.6s, so the 105% verdict tracked host state, not the FS
# (8 standalone laps: ratio 101-122% on the SAME build).  Run each leg TWICE,
# ALTERNATING (X M X M), and compare best-of-2 per leg — min-vs-min is the
# standard interference-robust estimator; the 105% criterion is unchanged.
xfs_leg() {   # -> echoes "<wall_ms> <filecount>"; leaves device unmounted
    mountpoint -q "$MNT" && umount "$MNT"
    lsmod | grep -q '^mxfs' && rmmod mxfs 2>/dev/null
    mkfs.xfs -f "$DEV" >/dev/null 2>&1 || return 1
    mount "$DEV" "$MNT" || return 1
    local ms; ms=$(timed_rsync x)
    echo "$ms $(find "$MNT/x" -type f | wc -l)"
    umount "$MNT"
}

mxfs_leg() {  # -> echoes "<wall_ms> <filecount>"; leaves node MOUNTED on fresh mxfs
    mountpoint -q "$MNT" && umount "$MNT"
    modprobe libcrc32c 2>/dev/null || true
    lsmod | grep -q '^mxfs' || insmod "$MODULE" force_transport=1 || return 1
    "$MKFS_MXFS" -f "$DEV" >/dev/null 2>&1 || return 1
    mount -t mxfs "$DEV" "$MNT" || return 1
    local ms; ms=$(timed_rsync m)
    echo "$ms $(find "$MNT/m" -type f | wc -l)"
}

# Position-balanced paired rounds.  Measurements drift slower across the
# test's lifetime (host-side backing-file writeback accumulates ~700MB per
# leg), so strict X-M alternation gives the xfs leg pole position every
# round and biases any per-leg aggregate.  Run 4 rounds with the ORDER
# alternating (XM, MX, MX, XM — each FS goes first twice), score each round
# by its own internal ratio (round-local host state ≈ shared), and take the
# trimmed mean (drop best+worst round-ratio, average the middle two).  The
# 105% criterion is unchanged.
r_ratios=(); x_all=""; m_all=""; xfs_files=""; mxfs_files=""
for round in 1 2 3 4; do
    case $round in
        1|4) xo=$(xfs_leg)  || { emit FAIL "xfs-r$round" "xfs leg failed"; exit 1; }
             mo=$(mxfs_leg) || { emit FAIL "mxfs-r$round" "mxfs leg failed"; exit 1; } ;;
        2|3) mo=$(mxfs_leg) || { emit FAIL "mxfs-r$round" "mxfs leg failed"; exit 1; }
             xo=$(xfs_leg)  || { emit FAIL "xfs-r$round" "xfs leg failed"; exit 1; } ;;
    esac
    x=${xo%% *}; xfs_files=${xo##* }
    m=${mo%% *}; mxfs_files=${mo##* }
    [ "$mxfs_files" = "$xfs_files" ] || break
    r_ratios+=( $(( x > 0 ? m * 100 / x : 0 )) )
    x_all="${x_all}${x_all:+/}$x"; m_all="${m_all}${m_all:+/}$m"
done
# leave the node on a fresh mounted mxfs (round 4 ended on xfs_leg)
mxfs_leg >/dev/null || { emit FAIL "mxfs-final" "final mxfs mount failed"; exit 1; }
sorted=$(printf '%s\n' "${r_ratios[@]}" | sort -n)
mid=$(echo "$sorted" | sed -n '2p;3p')
ratio=$(( ( $(echo "$mid" | head -1) + $(echo "$mid" | tail -1) ) / 2 ))
measured="xfs=(${x_all})ms mxfs=(${m_all})ms round_ratios=$(echo "$sorted" | tr '\n' ',' | sed 's/,$//') ratio=${ratio}% files=${mxfs_files}/${xfs_files}"

if [ "$mxfs_files" != "$xfs_files" ]; then
    emit FAIL "$measured" "file count mismatch (data integrity)"
elif [ "$ratio" -gt "$THRESH" ]; then
    emit FAIL "$measured" "mxfs ${ratio}% > ${THRESH}% of native XFS"
else
    emit PASS "$measured"
fi
