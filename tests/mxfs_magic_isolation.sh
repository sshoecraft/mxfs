#!/bin/bash
# Does anything that knows only XFS take an MXFS volume for XFS?
#
# Formats a loop image with the given mkfs_mxfs and asks the stock XFS
# consumers about it, both on the whole device and through a loop offset
# that starts exactly at the XFS region inside the MXFS envelope:
#   - xfs_repair -n on the whole device: does its secondary-superblock scan
#     find a candidate?  (That candidate is what a repair without -n would
#     write over LBA 0, destroying the envelope and the lock table.)
#   - blkid -p at the offset: does it report TYPE="xfs"?
#   - xfs_repair -n at the offset: does it accept the filesystem?
#   - mount -t xfs -o ro,norecovery at the offset: does stock xfs.ko mount it?
#
# Usage: tests/mxfs_magic_isolation.sh [MKFS]
#   MKFS    mkfs_mxfs binary (default tools/mkfs_mxfs)
# PASS only if nothing recognises the volume.
#
# Every step is bounded: xfs_repair on a 2 GiB sparse image scans in a few
# seconds, so 60 s each is a failure, not a wait; umount is bounded because
# an unbounded one can leave a task in D state on this host.

set -u
cd "$(dirname "$0")/.."

MKFS=${1:-tools/mkfs_mxfs}
OUT=tests/evidence/magic_isolation/$(date +%Y%m%dT%H%M%S)
IMG=${TMPDIR:-/tmp}/mxfs_magic_isolation.img
MNT=${TMPDIR:-/tmp}/mxfs_magic_isolation.mnt
mkdir -p "$OUT" "$MNT"

SUDO=
[ "$(id -u)" -eq 0 ] || SUDO="sudo -n"

truncate -s 0 "$IMG"
truncate -s 2G "$IMG"
LOOP=$($SUDO losetup -f --show "$IMG") || { echo "FAIL: losetup"; exit 1; }
OFFLOOP=

cleanup() {
	timeout 30 $SUDO umount "$MNT" 2>/dev/null
	[ -n "$OFFLOOP" ] && $SUDO losetup -d "$OFFLOOP"
	$SUDO losetup -d "$LOOP"
}
trap cleanup EXIT

echo "mkfs=$MKFS version=$($MKFS -V 2>&1 | head -1)" | tee "$OUT/summary.txt"
if ! timeout 60 $SUDO "$MKFS" -f "$LOOP" > "$OUT/mkfs.log" 2>&1; then
	echo "FAIL: mkfs rc!=0 (see $OUT/mkfs.log)" | tee -a "$OUT/summary.txt"
	exit 1
fi

# The XFS-derived region's superblock: the first sector after LBA 0 carrying
# the MXFS 'MXSB' superblock magic.
OFF=$($SUDO python3 - "$LOOP" <<'EOF'
import sys
with open(sys.argv[1], 'rb') as f:
    for sector in range(1, 512 * 1024):
        f.seek(sector * 512)
        if f.read(4) == b'MXSB':
            print(sector * 512)
            break
EOF
)
if [ -z "$OFF" ]; then
	echo "FAIL: no superblock found in the first 256 MiB" | tee -a "$OUT/summary.txt"
	exit 1
fi
MAGIC=$($SUDO dd if="$LOOP" bs=1 skip="$OFF" count=4 status=none)
echo "xfs_region_offset=$OFF sb_magic=$MAGIC" | tee -a "$OUT/summary.txt"

hits=0
checks=0
record() {  # name recognised(0/1) detail
	checks=$((checks + 1))
	[ "$2" -eq 1 ] && hits=$((hits + 1))
	echo "$1 recognised=$2 $3" | tee -a "$OUT/summary.txt"
}

timeout 60 $SUDO xfs_repair -n "$LOOP" > "$OUT/repair_whole.log" 2>&1
rc=$?
cand=$(grep -c -E 'found candidate secondary superblock|verified secondary superblock' "$OUT/repair_whole.log")
[ "$cand" -gt 0 ] || [ $rc -eq 0 ] && r=1 || r=0
record repair_whole_device "$r" "rc=$rc candidate_lines=$cand"

OFFLOOP=$($SUDO losetup -f --show -r -o "$OFF" "$IMG")

t=$($SUDO blkid -p -o value -s TYPE "$OFFLOOP" 2>/dev/null)
[ "$t" = xfs ] && r=1 || r=0
record blkid_at_offset "$r" "type=${t:-none}"

timeout 60 $SUDO xfs_repair -n "$OFFLOOP" > "$OUT/repair_offset.log" 2>&1
rc=$?
[ $rc -eq 0 ] && r=1 || r=0
record repair_at_offset "$r" "rc=$rc"

timeout 30 $SUDO mount -t xfs -o ro,norecovery "$OFFLOOP" "$MNT" > "$OUT/mount.log" 2>&1
rc=$?
[ $rc -eq 0 ] && r=1 || r=0
record stock_xfs_mount_at_offset "$r" "rc=$rc"
$SUDO dmesg | tail -5 > "$OUT/dmesg_tail.log"

[ $hits -eq 0 ] && v=PASS || v=FAIL
echo "RESULT $v recognised=$hits/$checks evidence=$OUT" | tee -a "$OUT/summary.txt"
[ $v = PASS ]
