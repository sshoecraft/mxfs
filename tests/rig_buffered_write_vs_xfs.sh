#!/bin/bash
# rig_buffered_write_vs_xfs.sh — one buffered sequential writer on the rig's
# shared LUN: MXFS (both nodes mounted) with write-time allocation, MXFS with
# delayed allocation (dbg_cluster_delalloc=1, the behaviour before 0.90.104),
# and native XFS on the same LUN.
#
# The board's fio_perf rows write with O_DIRECT, so they never exercise the
# buffered path 0.90.104 changed (a cluster mount's buffered write allocates
# at write time instead of delaying it).  This measures that path.
#
# Steps: on WRITER, dd SIZE_MB buffered with conv=fsync and read it back with
# the page cache dropped, LAPS times per MXFS
# arm, the arms interleaved, with both nodes mounted; then both MXFS mounts
# come down (each umount bounded), WRITER makes XFS on its device, mounts it at
# /mnt/xfsbase and runs the same dd LAPS times, and unmounts it.  MXFS is left
# unmounted: re-prep the rig afterwards
# (MXFS_FORCE_PREP=1 ./run.sh 2/net/mesh/direct prep_cluster).
#
# Usage: tests/rig_buffered_write_vs_xfs.sh
# Env:   NODES ("test1 test2"; the first writes), SIZE_MB (1024), LAPS (2),
#        SIZES (MiB list, default SIZE_MB: each size in turn, in every arm),
#        ARMS ("0 1": dbg_cluster_delalloc values; "0" = the default only)
# Budget: the rig LUN writes GiB/s; at SIZE_MB=10240 each dd is ~10-20 s, each
# umount bounded at 60 s, mkfs 60 s; the whole run well under 10 min.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a N <<<"${NODES:-test1 test2}"
SIZE_MB=${SIZE_MB:-1024}
SIZES=${SIZES:-$SIZE_MB}
ARMS=${ARMS:-0 1}
LAPS=${LAPS:-2}
W=${N[0]}
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$|^ *$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*"; }
# the write (buffered, fsync before dd reports), then the read back with the
# page cache dropped first, so it comes from the LUN
dd_cmd() {  # <size MiB>: the command, with $D the directory
    echo "dd if=/dev/zero of=\$D/bw bs=1M count=$1 conv=fsync 2>&1 | tail -1 | sed 's/^/write: /'; sync; echo 3 > /proc/sys/vm/drop_caches; dd if=\$D/bw of=/dev/null bs=1M 2>&1 | tail -1 | sed 's/^/read: /'; rm -f \$D/bw; sync"
}

say "$W build=$(on "$W" 'cat /sys/module/mxfs/srcversion') mounts: $(on "$W" "grep -c ' /mnt/shared mxfs ' /proc/mounts") / $(on "${N[1]}" "grep -c ' /mnt/shared mxfs ' /proc/mounts")"
for lap in $(seq 1 "$LAPS"); do
    for k in $ARMS; do
        for n in "${N[@]}"; do on "$n" "echo $k > /sys/module/mxfs/parameters/dbg_cluster_delalloc" 20; done
        arm=$([ "$k" = 0 ] && echo "mxfs write-time alloc" || echo "mxfs delayed alloc")
        for sz in $SIZES; do
            say "lap $lap $arm ${sz}MiB: $(on "$W" "D=/mnt/shared; $(dd_cmd "$sz")" 600 | tr '\n' ' ')"
        done
    done
done
for n in "${N[@]}"; do on "$n" "echo 0 > /sys/module/mxfs/parameters/dbg_cluster_delalloc" 20; done

DEV=$(on "$W" "awk '\$2 == \"/mnt/shared\" && \$3 == \"mxfs\" {print \$1}' /proc/mounts" 20)
case "$DEV" in /dev/*) ;; *) say "cannot tell $W's shared device ($DEV); stopping"; exit 1 ;; esac
for n in "${N[@]}"; do
    r=$(on "$n" "timeout 60 umount /mnt/shared && echo UMOUNT_OK" 90)
    case "$r" in *UMOUNT_OK*) say "$n: mxfs unmounted" ;; *) say "$n: umount did not complete ($r); stopping, nothing reformatted"; exit 1 ;; esac
done
r=$(on "$W" "mkfs.xfs -f -q $DEV && mkdir -p /mnt/xfsbase && mount -t xfs $DEV /mnt/xfsbase && echo XFS_OK" 120)
case "$r" in *XFS_OK*) say "$W: XFS made and mounted on $DEV" ;; *) say "$W: could not make or mount XFS on $DEV ($r)"; exit 1 ;; esac
for lap in $(seq 1 "$LAPS"); do
    for sz in $SIZES; do
        say "lap $lap native xfs ${sz}MiB: $(on "$W" "D=/mnt/xfsbase; $(dd_cmd "$sz")" 600 | tr '\n' ' ')"
    done
done
r=$(on "$W" "timeout 60 umount /mnt/xfsbase && echo UMOUNT_OK" 90)
case "$r" in *UMOUNT_OK*) say "$W: xfs unmounted; re-prep the rig for MXFS" ;; *) say "$W: xfs umount did not complete ($r)"; exit 1 ;; esac
