#!/bin/bash
# pve_bio_census.sh — what a filesystem on a DRBD device writes, and what the
# disk under it is asked to do, while a workload runs: every bio queued to the
# DRBD device and every request issued to its backing disk, on one host,
# counted by issuing task, flags (rwbs: a leading F is a preflush, an F after
# the op is FUA, S sync, M metadata), size and region of the device.
#
# A guest writing through MXFS is slower than through XFS on the same DRBD
# device; this says whether that is MXFS writing more, writing differently
# (FUA, flushes, small sync writes outside the data area), or the same writes
# waiting longer.  On a disk with no native FUA (/sys/block/<disk>/queue/fua
# 0) the kernel turns each FUA write into a write and a cache flush, so the
# disk side shows the flushes the bio side does not.
#
# Usage: tests/pve_bio_census.sh <host> <seconds> <outdir> [drbd minor] [disk]
#   drbd minor default 2, disk default sdb.  Run one per host, alongside the
#   workload.  Uses its own trace instance (mxfs_bio_census), removed at the
#   end, so it does not touch any other tracing on the host.
# Output: <outdir>/<host>.trace (raw), <outdir>/<host>.census (the counts).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
H=${1:?host}; SECS=${2:?seconds}; OUT=${3:?outdir}; MINOR=${4:-2}; DISK=${5:-sdb}
mkdir -p "$OUT" || exit 1
# the tracepoints' dev field is the kernel dev_t: major << 20 | minor
timeout $(( SECS + 120 )) "$SSHP" "$H" "set -u
    T=/sys/kernel/tracing/instances/mxfs_bio_census
    rmdir \$T 2>/dev/null; mkdir \$T || { echo NO_INSTANCE; exit 1; }
    dd=\$(( 147 << 20 | $MINOR ))
    sd=\$(( \$(cat /sys/block/$DISK/dev | cut -d: -f1) << 20 | \$(cat /sys/block/$DISK/dev | cut -d: -f2) ))
    echo 16384 > \$T/buffer_size_kb
    echo \"dev == \$dd\" > \$T/events/block/block_bio_queue/filter
    echo \"dev == \$sd\" > \$T/events/block/block_rq_issue/filter
    echo 1 > \$T/events/block/block_bio_queue/enable
    echo 1 > \$T/events/block/block_rq_issue/enable
    echo 1 > \$T/tracing_on
    sleep $SECS
    echo 0 > \$T/tracing_on
    cat \$T/trace
    echo \"# drbd_dev=\$dd disk_dev=\$sd disk_sectors=\$(cat /sys/block/$DISK/size) drbd_sectors=\$(cat /sys/block/drbd$MINOR/size) overrun=\$(grep -h overrun \$T/per_cpu/cpu*/stats | awk '{s += \$2} END {print s}')\"
    echo 0 > \$T/events/block/block_bio_queue/enable
    echo 0 > \$T/events/block/block_rq_issue/enable
    rmdir \$T" </dev/null 2>/dev/null > "$OUT/$H.trace"
rc=$?
[ "$rc" = 0 ] || { echo "pve_bio_census: $H: trace failed rc=$rc ($(tail -1 "$OUT/$H.trace"))"; exit 1; }
python3 -I "$REPO/tests/pve_bio_census.py" "$OUT/$H.trace" "$SECS" | tee "$OUT/$H.census"
