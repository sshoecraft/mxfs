#!/bin/bash
# online_resize — grow an MXFS after its device expands (resize_mxfs), using a
# self-contained SCRATCH loop device (does NOT touch the shared LUN; sidesteps
# the lack of a mkfs size flag because the scratch device itself is small).
# Verifies the FS grows and prior data is preserved.
SUITE_TEST_NAME=online_resize
NODES="${MXFS_NODES:-1}"
MODULE="${MXFS_MODULE:-/src/mxfs/mxfs.ko}"
MKFS="${MKFS_MXFS:-/src/mxfs/tools/mkfs_mxfs}"
RESIZE="${RESIZE_MXFS:-/src/mxfs/tools/resize_mxfs}"
IMG="/tmp/mxfs_resize.$$.img"; MP="/tmp/mxfs_resize.$$.mnt"; LOOP=""
SMALL=$((2*1024*1024*1024)); BIG=$((4*1024*1024*1024))
# native-XFS baseline (run.sh DLM=xfs, N=1 only): mkfs.xfs + xfs_growfs instead
# of mkfs_mxfs/resize_mxfs. xfs_growfs is an ONLINE grow (runs against the
# MOUNTPOINT, filesystem must be mounted) unlike resize_mxfs (runs against the
# device, offline) -- the two branches below are ordered differently to match
# each tool's actual contract, not just a command substitution.
FSTYPE="${MXFS_EXPECT_FSTYPE:-mxfs}"
emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }
cleanup(){ mountpoint -q "$MP" 2>/dev/null && umount "$MP"; [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null; rm -f "$IMG"; rmdir "$MP" 2>/dev/null; }
trap cleanup EXIT
mkdir -p "$MP"

if [ "$FSTYPE" = xfs ]; then
    truncate -s "$SMALL" "$IMG"
    LOOP=$(losetup --find --show "$IMG") || { emit FAIL setup losetup; exit 1; }
    mkfs.xfs -f "$LOOP" >/dev/null 2>&1 || { emit FAIL mkfs "mkfs.xfs on scratch loop failed"; exit 1; }
    mount "$LOOP" "$MP" || { emit FAIL mount "mount scratch failed"; exit 1; }
    pre_kb=$(df -P "$MP" | awk 'NR==2{print $2}')
    head -c $((64*1024*1024)) /dev/urandom > "$MP/data"
    sum=$(md5sum < "$MP/data" | awk '{print $1}')

    truncate -s "$BIG" "$IMG"
    losetup -c "$LOOP"
    xfs_growfs "$MP" >/dev/null 2>&1 || { emit FAIL resize "xfs_growfs failed"; exit 1; }

    post_kb=$(df -P "$MP" | awk 'NR==2{print $2}')
    sum2=$(md5sum < "$MP/data" | awk '{print $1}')
    umount "$MP"
else
[ -x "$RESIZE" ] || { emit FAIL setup "resize_mxfs missing"; exit 1; }
modprobe libcrc32c 2>/dev/null || true; lsmod | grep -q '^mxfs' || insmod "$MODULE" force_transport=1 2>/dev/null

truncate -s "$SMALL" "$IMG"
LOOP=$(losetup --find --show "$IMG") || { emit FAIL setup losetup; exit 1; }
"$MKFS" -f "$LOOP" >/dev/null 2>&1 || { emit FAIL mkfs "mkfs on scratch loop failed"; exit 1; }
mount -t mxfs "$LOOP" "$MP" || { emit FAIL mount "mount scratch failed"; exit 1; }
pre_kb=$(df -P "$MP" | awk 'NR==2{print $2}')
head -c $((64*1024*1024)) /dev/urandom > "$MP/data"
sum=$(md5sum < "$MP/data" | awk '{print $1}')
umount "$MP"

truncate -s "$BIG" "$IMG"
losetup -c "$LOOP"
"$RESIZE" "$LOOP" >/dev/null 2>&1 || { emit FAIL resize "resize_mxfs failed"; exit 1; }

mount -t mxfs "$LOOP" "$MP" || { emit FAIL remount "remount after resize failed"; exit 1; }
post_kb=$(df -P "$MP" | awk 'NR==2{print $2}')
sum2=$(md5sum < "$MP/data" | awk '{print $1}')
umount "$MP"
fi
# grow must recover >= 90% of the ADDED space (port of tests/criteria threshold),
# not merely "got bigger".
added_mb=$(( (BIG - SMALL) / 1048576 ))
delta_mb=$(( (post_kb - pre_kb) / 1024 ))
need_mb=$(( added_mb * 90 / 100 ))
intact=$([ "$sum" = "$sum2" ] && echo yes || echo no)
measured="pre=$((pre_kb/1024))MB post=$((post_kb/1024))MB delta=${delta_mb}MB/+${added_mb}MB data_intact=$intact"
{ [ "$delta_mb" -ge "$need_mb" ] && [ "$intact" = yes ]; } \
    && emit PASS "$measured" \
    || emit FAIL "$measured" "grow recovered <90% of added space ($delta_mb<$need_mb) or data lost"
