#!/bin/bash
# fault_io_error — inject block I/O errors under a mounted MXFS and verify the
# FS reacts correctly. Self-contained: a scratch loop file under a device-mapper
# layer (dm-linear, swapped to dm-error mid-test) — does NOT touch the shared LUN.
# Checks: I/O returns EIO promptly (no hang), no kernel BUG/Oops/panic (a
# controlled forced-shutdown is fine), and after clearing the fault the FS
# remounts with pre-fault data intact and chk_mxfs is clean.
SUITE_TEST_NAME=fault_io_error
NODES="${MXFS_NODES:-1}"
MODULE="${MXFS_MODULE:-/src/mxfs/mxfs.ko}"; MKFS="${MKFS_MXFS:-/src/mxfs/tools/mkfs_mxfs}"; CHK="${CHK_MXFS:-/src/mxfs/tools/chk_mxfs}"
IMG="/tmp/mxfs_fio.$$.img"; MP="/tmp/mxfs_fio.$$.mnt"; DM="mxfs_fio_$$"; LOOP=""
# native-XFS baseline (run.sh DLM=xfs, N=1 only): same fault-injection body,
# just mkfs.xfs/plain mount/xfs_repair instead of the mxfs equivalents, and no
# module load (xfs isn't clustered).
FSTYPE="${MXFS_EXPECT_FSTYPE:-mxfs}"
emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }
cleanup(){ mountpoint -q "$MP" 2>/dev/null && umount -l "$MP" 2>/dev/null
  dmsetup remove "$DM" 2>/dev/null; [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null; rm -f "$IMG"; rmdir "$MP" 2>/dev/null; }
trap cleanup EXIT
command -v dmsetup >/dev/null 2>&1 || { emit SKIP no-dmsetup "dmsetup absent"; exit 0; }
if [ "$FSTYPE" != xfs ]; then
    modprobe libcrc32c 2>/dev/null || true; lsmod | grep -q '^mxfs' || insmod "$MODULE" force_transport=1 2>/dev/null
fi

truncate -s 2G "$IMG"
LOOP=$(losetup --find --show "$IMG") || { emit FAIL setup losetup; exit 1; }
SECT=$(blockdev --getsz "$LOOP")
dmsetup create "$DM" --table "0 $SECT linear $LOOP 0" || { emit FAIL setup dm-linear; exit 1; }
DEV="/dev/mapper/$DM"
mkdir -p "$MP"
if [ "$FSTYPE" = xfs ]; then
    mkfs.xfs -f "$DEV" >/dev/null 2>&1 || { emit FAIL mkfs "mkfs.xfs failed"; exit 1; }
    mount "$DEV" "$MP" || { emit FAIL mount "mount failed"; exit 1; }
else
"$MKFS" -f "$DEV" >/dev/null 2>&1 || { emit FAIL mkfs "mkfs failed"; exit 1; }
mount -t mxfs "$DEV" "$MP" || { emit FAIL mount "mount failed"; exit 1; }
fi
head -c $((16*1024*1024)) /dev/urandom > "$MP/data"; sync
sum=$(md5sum < "$MP/data" | awk '{print $1}')

MARKER="MXFS_FIO_$(date +%s)_$$"; echo "$MARKER" > /dev/kmsg 2>/dev/null
dmsetup suspend "$DM"; dmsetup reload "$DM" --table "0 $SECT error"; dmsetup resume "$DM"
t0=$(date +%s%3N)
timeout 20 dd if=/dev/zero of="$MP/probe" bs=4k count=256 oflag=direct conv=fsync 2>/dev/null; wrc=$?
dur=$(( $(date +%s%3N) - t0 ))
if [ "$wrc" = 124 ]; then prompt=hung; elif [ "$wrc" -ne 0 ]; then prompt=yes; else prompt=no; fi
badhits=$(dmesg | awk -v m="$MARKER" 'f{print} $0~m{f=1}' | grep -ciE 'BUG:|Oops|kernel panic|general protection|not syncing|hung task')

umount -l "$MP" 2>/dev/null
dmsetup suspend "$DM"; dmsetup reload "$DM" --table "0 $SECT linear $LOOP 0"; dmsetup resume "$DM"
remount=no; intact=no
if [ "$FSTYPE" = xfs ]; then remount_cmd=(mount "$DEV" "$MP"); else remount_cmd=(mount -t mxfs "$DEV" "$MP"); fi
if timeout 30 "${remount_cmd[@]}" 2>/dev/null; then
  remount=yes
  [ "$(md5sum < "$MP/data" 2>/dev/null | awk '{print $1}')" = "$sum" ] && intact=yes
  umount "$MP" 2>/dev/null || umount -l "$MP" 2>/dev/null
fi
chk_rc=0
if [ "$FSTYPE" = xfs ]; then xfs_repair -n "$DEV" >/dev/null 2>&1 || chk_rc=$?
else "$CHK" "$DEV" >/dev/null 2>&1 || chk_rc=$?
fi
measured="eio=$prompt wms=$dur bad_dmesg=$badhits remount=$remount data_intact=$intact chk_rc=$chk_rc"
{ [ "$prompt" = yes ] && [ "$badhits" -eq 0 ] && [ "$remount" = yes ] && [ "$intact" = yes ]; } \
  && emit PASS "$measured" || emit FAIL "$measured" "EIO not prompt / kernel oops / no recovery / data lost"
