#!/usr/bin/env bash
# scsi_caw_probe.sh — qualify a shared LUN's SCSI primitives with raw CDBs.
#
#   tests/scsi_caw_probe.sh <device> <lba_512>
#
# Issues, in order, against ONE 512-byte block of <device>:
#   1. READ(16)                    plain read of the block (baseline)
#   2. READ(16) FUA=1              the read MXFS uses for cross-node coherency
#   3. COMPARE AND WRITE (0x89)    1 block, expect = current content,
#                                  new = current content with byte 0 flipped
#   4. READ(16)                    readback: did the CAW land?
#   5. COMPARE AND WRITE (0x89)    deliberately WRONG expect -> must MISCOMPARE
#   6. COMPARE AND WRITE (0x89)    restore the original content
#
# Every step prints the SCSI status and decoded sense (key/asc/ascq) verbatim
# so the verdict is the target's own answer, not this script's opinion:
#   sense 05/20/00 = INVALID COMMAND OPERATION CODE  -> opcode not implemented
#   sense 05/24/00 = INVALID FIELD IN CDB            -> opcode known, field refused
#   sense 0E/1D/00 = MISCOMPARE DURING VERIFY        -> CAW implemented, compare lost
#   status 0, no sense                               -> command succeeded
#
# The block at <lba_512> is modified (byte 0 flipped, then restored).  Point
# it at a block you own — a scratch region of a volume that is about to be
# reformatted, never a live filesystem's metadata.
#
# Why raw CDBs: some targets (the QNAP TS-453 Pro among them) reject REPORT
# SUPPORTED OPERATION CODES outright, so sg_opcodes cannot answer "is CAW
# implemented", and tools/caw_verify's FUA pre-read is itself refused there.
# Needs sg3-utils (sg_raw) and root.
set -u
DEV=${1:?usage: $0 <device> <lba_512>}
LBA=${2:?usage: $0 <device> <lba_512>}
[ -b "$DEV" ] || { echo "FAIL: $DEV is not a block device"; exit 2; }
command -v sg_raw >/dev/null || { echo "FAIL: sg_raw (sg3-utils) not installed"; exit 2; }
W=$(mktemp -d)
BLK=512
lba_hex() { printf '%016x' "$1" | sed 's/../& /g'; }
LBA8=$(lba_hex "$LBA")

# sg_raw exit code is the SCSI status class; sense is printed on stderr.
run() {  # label, then sg_raw args...
    local label=$1; shift
    echo "--- $label"
    sg_raw -v "$@" > "$W/out" 2> "$W/err"; local rc=$?
    grep -E 'SCSI Status|Sense Key|Additional sense|Fixed format|sense' "$W/err" | head -4
    echo "sg_raw rc=$rc"
    return $rc
}

# 1. plain READ(16): 88 flags LBA[8] LEN[4] group control
run "READ(16) plain @$LBA" -r $BLK -o "$W/cur" "$DEV" 88 00 $LBA8 00 00 00 01 00 00
r1=$?
# 2. READ(16) FUA
run "READ(16) FUA=1 @$LBA" -r $BLK -o "$W/curfua" "$DEV" 88 08 $LBA8 00 00 00 01 00 00
r2=$?
[ $r1 -eq 0 ] || { echo "VERDICT: plain READ(16) refused; cannot continue"; exit 1; }

# 3. CAW with correct expect, new = byte 0 flipped
cp "$W/cur" "$W/new"
b0=$(od -An -tu1 -N1 "$W/cur" | tr -d ' ')
printf "\\x$(printf %02x $(( (b0 + 1) % 256 )))" | dd of="$W/new" bs=1 count=1 conv=notrunc status=none
cat "$W/cur" "$W/new" > "$W/caw1"
# COMPARE AND WRITE: 89 flags LBA[8] rsv[3] NBLOCKS[1] group control ; data-out = 2*NBLOCKS blocks
run "COMPARE AND WRITE expect=current new=flipped @$LBA" -s $((2*BLK)) -i "$W/caw1" "$DEV" 89 00 $LBA8 00 00 00 01 00 00
r3=$?
# 4. readback
run "READ(16) readback @$LBA" -r $BLK -o "$W/rb" "$DEV" 88 00 $LBA8 00 00 00 01 00 00
if cmp -s "$W/rb" "$W/new"; then echo "readback = NEW image (CAW landed)";
elif cmp -s "$W/rb" "$W/cur"; then echo "readback = OLD image (CAW did not land)";
else echo "readback = NEITHER image"; fi
# 5. CAW with wrong expect (original content) -> must MISCOMPARE now
cat "$W/cur" "$W/cur" > "$W/caw2"
run "COMPARE AND WRITE expect=STALE (must MISCOMPARE) @$LBA" -s $((2*BLK)) -i "$W/caw2" "$DEV" 89 00 $LBA8 00 00 00 01 00 00
r5=$?
# 6. restore
cat "$W/new" "$W/cur" > "$W/caw3"
run "COMPARE AND WRITE restore original @$LBA" -s $((2*BLK)) -i "$W/caw3" "$DEV" 89 00 $LBA8 00 00 00 01 00 00
r6=$?
run "READ(16) final readback @$LBA" -r $BLK -o "$W/rb2" "$DEV" 88 00 $LBA8 00 00 00 01 00 00
cmp -s "$W/rb2" "$W/cur" && echo "final readback = ORIGINAL (restored)" || echo "final readback != original"

echo "=== summary: read16=$r1 read16_fua=$r2 caw_ok=$r3 caw_stale=$r5 caw_restore=$r6 (0 = success; see sense above)"
