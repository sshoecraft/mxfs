#!/bin/bash
# tests/chk_oracle_calibration.sh — does the offline checker FAIL what it
# claims to catch?  (ledger D-THE-CLUSTERED-STRUCTURAL-AUDIT-GATE-DOES-NOT-
# ESTABLISH-THAT, item 2: a known-clean image must pass and deliberately
# corrupted disposable images must FAIL, one per defect family the gate
# claims to cover; unsupported format, missing device, timeout and a checker
# crash must each produce a non-clean execution result rather than a pass.)
#
# Runs on THIS host, never on the rig: a disposable image in /var/tmp behind
# a loop device (mkfs_mxfs formats block devices only; the checker's cache
# drop needs CAP_SYS_ADMIN, so the device commands go through sudo -n).  Each
# fixture is a fresh format, one big-endian field patched with the block's
# XFS CRC refreshed (tools/xfs_block_patch.py) so the checker meets a
# SEMANTIC inconsistency — a checksum failure alone would prove only that
# CRCs are verified — then `chk_mxfs -v` must exit 4 AND print the detector's
# own line.  The geometry the patches need (xfs_data_offset, blocksize,
# sectsize, inopblock, the AG 0 roots, the first inode chunk) is read from
# the clean control's own listing, never assumed.
#
#   control      a fresh format: rc 0, zero ERROR lines (the known-clean image)
#   agi_freecount   AGI.freecount+1        -> "inobt total free=... != AGI freecount="
#   agi_count       AGI.count+64           -> "inobt total inodes=... != AGI count="
#   finobt_free     finobt rec 0 freecount-1 -> "finobt total free=... != inobt total free="
#   chunk_also_free bnobt rec 0 := [chunk agbno, chunk blocks]
#                                          -> "inside an allocated inode chunk AND free in the BNO btree"
#   sb_icount       sb.icount+64           -> "inobt total inodes ... != superblock icount"
#   missing_device  a path that does not exist        -> rc 4 (cannot open)
#   no_format       sector 0 of the image zeroed      -> rc 4 (no MXFS envelope)
#   truncated       the image cut to 1 MiB after the format -> rc != 0 (read error)
#   timeout         the checker under a 10 ms bound   -> rc 124 (a bound IS a failure)
#   crash           the checker killed by SIGSEGV     -> rc 139
# Not built here (recorded, not credited): "a dinode home aliasing a
# directory data block" — the checker has no such detector (s70 inventory of
# its err() strings), and the fixture needs a directory with a data block,
# which a mount, not a format, creates; and a two-level inobt (the 0.89.7
# defect's shape), likewise.
#
# the budget rule (derived): 7 formats of a 512 MiB image ~3 s each + 12
# checks ~2 s each + loop setup ~2 s ≈ 50 s; caller bound 150 s.
#
# Usage: tests/chk_oracle_calibration.sh <label>
# Env:   CALIB_IMG (default /var/tmp/mxfs_chk_calib.img), CALIB_MB (512)
# Exit 0 PASS, 1 FAIL, 2 INFRA/ABORT.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
IMG=${CALIB_IMG:-/var/tmp/mxfs_chk_calib.img}
MB=${CALIB_MB:-512}
CHK=tools/chk_mxfs
MKFS=tools/mkfs_mxfs
PATCH=tools/xfs_block_patch.py
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_chkcalib_$LABEL
mkdir -p "$OUT"
fails=0
ck()   { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
cnt()  { grep -ac "$2" "$1"; }
echo "=== chk_oracle_calibration label=$LABEL img=$IMG ${MB}MiB chk=$($CHK -V 2>/dev/null | head -1 || echo '?') $(date -u +%FT%TZ) ==="
s0=$(date +%s); el() { echo $(( $(date +%s) - s0 )); }
[ -x "$CHK" ] && [ -x "$MKFS" ] || { echo "ABORT: build the tools first (make -C tools)"; echo "RESULT: ABORT label=$LABEL stage=tools evidence=$OUT"; exit 2; }
sudo -n true 2>/dev/null || { echo "ABORT: sudo -n is not available; the loop device and the checker's cache drop need root"; echo "RESULT: ABORT label=$LABEL stage=sudo evidence=$OUT"; exit 2; }

LOOP=
cleanup() { [ -n "$LOOP" ] && sudo -n losetup -d "$LOOP" 2>/dev/null; rm -f /var/tmp/mxfs_chk_calib.img; }
trap cleanup EXIT
fresh() {   # a fresh format on a fresh image behind the same loop device
    [ -n "$LOOP" ] && sudo -n losetup -d "$LOOP" 2>/dev/null
    rm -f /var/tmp/mxfs_chk_calib.img
    truncate -s "${MB}M" "$IMG" || return 1
    LOOP=$(sudo -n losetup -f --show "$IMG") || return 1
    sudo -n "$MKFS" -f -n 2 "$LOOP" > "$OUT/mkfs_$1.txt" 2>&1 || { echo "  mkfs failed: $(tail -2 "$OUT/mkfs_$1.txt" | tr '\n' ' ')"; return 1; }
    sync
}
check() {   # <tag> -> $OUT/chk_<tag>.txt, echoes rc
    local rc
    sudo -n timeout 60 "$CHK" -v "$LOOP" > "$OUT/chk_$1.txt" 2>&1; rc=$?
    echo "$rc"
}
[ "$IMG" = /var/tmp/mxfs_chk_calib.img ] || { echo "ABORT: CALIB_IMG must be /var/tmp/mxfs_chk_calib.img (the cleanup names it literally)"; exit 2; }

# ---- control: the known-clean image, and the geometry every fixture needs
fresh control || { echo "RESULT: ABORT label=$LABEL stage=format evidence=$OUT"; exit 2; }
rc=$(check control)
echo "STAGE control: rc=$rc errors=$(cnt "$OUT/chk_control.txt" '^  ERROR:') at +$(el)s"
ck "control: a fresh format is clean (rc 0)" "$rc" 0
ck "control: zero ERROR lines" "$(cnt "$OUT/chk_control.txt" '^  ERROR:')" 0
g() { grep -ao "$1=[0-9]*" "$OUT/chk_control.txt" | head -1 | cut -d= -f2; }
XOFF=$(g xfs_data_offset); BS=$(g blocksize); SS=$(g sectsize); INOPB=$(g inopblock)
INO_ROOT=$(grep -ao 'AG 0 AGI: ino_root=[0-9]*' "$OUT/chk_control.txt" | head -1 | grep -ao '[0-9]*$')
FINO_ROOT=$(grep -ao 'AG 0 AGI: .*fino_root=[0-9]*' "$OUT/chk_control.txt" | head -1 | grep -ao 'fino_root=[0-9]*' | cut -d= -f2)
BNO_ROOT=$(grep -ao 'AG 0 AGF: bno_root=[0-9]*' "$OUT/chk_control.txt" | head -1 | grep -ao '[0-9]*$')
STARTINO=$(grep -ao 'AG 0 inobt rec 0: startino=[0-9]*' "$OUT/chk_control.txt" | head -1 | grep -ao '[0-9]*$')
CHUNKN=$(grep -ao 'AG 0 inobt rec 0: startino=[0-9]* count=[0-9]*' "$OUT/chk_control.txt" | head -1 | grep -ao 'count=[0-9]*' | cut -d= -f2)
echo "STAGE geometry: xfs_off=$XOFF bs=$BS ss=$SS inopb=$INOPB ino_root=$INO_ROOT fino_root=$FINO_ROOT bno_root=$BNO_ROOT chunk startino=$STARTINO count=$CHUNKN"
for v in XOFF BS SS INOPB INO_ROOT FINO_ROOT BNO_ROOT STARTINO CHUNKN; do
    [ -n "${!v:-}" ] || { echo "ABORT: the control listing did not yield $v"; echo "RESULT: ABORT label=$LABEL stage=geometry evidence=$OUT"; exit 2; }
done
CHUNK_AGBNO=$(( STARTINO / INOPB )); CHUNK_BLKS=$(( CHUNKN / INOPB ))
AGI_OFF=$(( XOFF + 2 * SS )); SB_OFF=$XOFF
blk_off() { echo $(( XOFF + $1 * BS )); }

# fixture <tag> <expected line regex> <patch args...>
fixture() {
    local tag=$1 want=$2; shift 2
    fresh "$tag" || { echo "RESULT: ABORT label=$LABEL stage=format-$tag evidence=$OUT"; exit 2; }
    python3 "$PATCH" "$IMG" "$@" > "$OUT/patch_$tag.txt" 2>&1 || { echo "  patch failed: $(cat "$OUT/patch_$tag.txt")"; echo "RESULT: ABORT label=$LABEL stage=patch-$tag evidence=$OUT"; exit 2; }
    sync
    local rc; rc=$(check "$tag")
    echo "STAGE $tag: $(cat "$OUT/patch_$tag.txt") -> rc=$rc errors=$(cnt "$OUT/chk_$tag.txt" '^  ERROR:') at +$(el)s"
    grep -a '^  ERROR:' "$OUT/chk_$tag.txt" | head -3 | cut -c1-170 | sed 's/^/     /'
    ck   "$tag: the checker FAILS the fixture (rc 4)" "$rc" 4
    ckge "$tag: the detector's own line is printed" "$(grep -acE -- "$want" "$OUT/chk_$tag.txt")" 1
}
# AGI: count at 0x10, freecount at 0x1C, CRC at 0x138, one sector
fixture agi_freecount 'inobt total free=[0-9]+ != AGI freecount=' "$AGI_OFF" "$SS" 0x138 0x1C 4 +1
fixture agi_count     'inobt total inodes=[0-9]+ != AGI count='   "$AGI_OFF" "$SS" 0x138 0x10 4 +64
# finobt leaf record 0 at 56: startino(4) holemask(2) count(1) freecount(1) free(8); CRC at 0x34, one block
fixture finobt_free   'finobt total free=[0-9]+ != inobt total free=' "$(blk_off "$FINO_ROOT")" "$BS" 0x34 $((56 + 7)) 1 -1
# bnobt leaf record 0 at 56: startblock(4) blockcount(4) -> exactly the
# inode chunk's blocks (both fields before the check: a startblock moved
# under the original blockcount would overflow the AG and be refused as an
# invalid extent before the cross-tree audit ever ran)
fresh chunk_also_free || { echo "RESULT: ABORT label=$LABEL stage=format-chunk_also_free evidence=$OUT"; exit 2; }
python3 "$PATCH" "$IMG" "$(blk_off "$BNO_ROOT")" "$BS" 0x34 60 4 "$CHUNK_BLKS" > "$OUT/patch_chunk_also_free.txt" 2>&1 || { echo "  patch failed: $(cat "$OUT/patch_chunk_also_free.txt")"; exit 2; }
python3 "$PATCH" "$IMG" "$(blk_off "$BNO_ROOT")" "$BS" 0x34 56 4 "$CHUNK_AGBNO" >> "$OUT/patch_chunk_also_free.txt" 2>&1 || { echo "  patch failed: $(cat "$OUT/patch_chunk_also_free.txt")"; exit 2; }
sync
rc=$(check chunk_also_free)
echo "STAGE chunk_also_free: $(tr '\n' ' ' < "$OUT/patch_chunk_also_free.txt") -> rc=$rc errors=$(cnt "$OUT/chk_chunk_also_free.txt" '^  ERROR:') at +$(el)s"
grep -a '^  ERROR:' "$OUT/chk_chunk_also_free.txt" | head -3 | cut -c1-170 | sed 's/^/     /'
ck   "chunk_also_free: the checker FAILS the fixture (rc 4)" "$rc" 4
ckge "chunk_also_free: the cross-tree audit names every block of the chunk" "$(cnt "$OUT/chk_chunk_also_free.txt" 'inside an allocated inode chunk AND free in the BNO btree')" "$CHUNK_BLKS"
# superblock: icount at 0x80 (be64), CRC at 0xE0, one sector
fixture sb_icount     'inobt total inodes [0-9]+ != superblock icount' "$SB_OFF" "$SS" 0xE0 0x80 8 +64

# ---- execution results that must not read as clean
sudo -n timeout 30 "$CHK" -v /dev/loop-does-not-exist > "$OUT/chk_missing.txt" 2>&1; rc=$?
echo "STAGE missing_device: rc=$rc $(head -c 120 "$OUT/chk_missing.txt" | tr '\n' ' ')"
ck "missing_device: rc 4, no verdict" "$rc/$(cnt "$OUT/chk_missing.txt" 'Superblock icount')" "4/0"
fresh no_format || exit 2
sudo -n dd if=/dev/zero of="$LOOP" bs=4096 count=1 conv=fsync > /dev/null 2>&1
rc=$(check no_format)
echo "STAGE no_format: rc=$rc $(grep -a 'magic\|envelope\|MXFS super' "$OUT/chk_no_format.txt" | head -1 | cut -c1-120)"
ck "no_format: rc 4, no verdict" "$rc/$(cnt "$OUT/chk_no_format.txt" 'Superblock icount')" "4/0"
fresh truncated || exit 2
sudo -n losetup -d "$LOOP"; LOOP=
truncate -s 1M "$IMG"
LOOP=$(sudo -n losetup -f --show "$IMG")
rc=$(check truncated)
echo "STAGE truncated: rc=$rc errors=$(cnt "$OUT/chk_truncated.txt" '^  ERROR:') $(grep -ai 'read error\|short read\|cannot read' "$OUT/chk_truncated.txt" | head -1 | cut -c1-100)"
ck "truncated: not clean (rc != 0)" "$([ "$rc" != 0 ] && echo nonzero || echo zero)" nonzero
ck "truncated: no clean summary line" "$(cnt "$OUT/chk_truncated.txt" '0 error(s) found\|no errors')" 0
fresh timeout || exit 2
sudo -n timeout 0.01 "$CHK" -v "$LOOP" > "$OUT/chk_timeout.txt" 2>&1; rc=$?
echo "STAGE timeout: rc=$rc lines=$(wc -l < "$OUT/chk_timeout.txt")"
ck "timeout: the bound is the verdict (rc 124)" "$rc" 124
# the SIGSEGV is delivered to the checker's process the instant it is
# spawned (microseconds, against the milliseconds sudo takes to exec it):
# s70g's first version used `timeout -s SEGV 0.05` and the checker finished
# the 512 MiB image inside the bound, exit 0 — the fixture had not fired
# (s70h: an unprivileged kill of the root-owned process was refused, so the
# kill is issued inside the same root shell that spawned the checker)
sudo -n sh -c '"$1" -v "$2" & p=$!; kill -SEGV $p; wait $p; echo CRASH_RC=$?' sh "$CHK" "$LOOP" > "$OUT/chk_crash.txt" 2>&1
rc=$(grep -ao '^CRASH_RC=[0-9]*' "$OUT/chk_crash.txt" | cut -d= -f2)
echo "STAGE crash: rc=${rc:-?} lines=$(wc -l < "$OUT/chk_crash.txt")"
ck "crash: a killed checker is not clean (rc 139, never 0)" "${rc:-?}" 139

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
