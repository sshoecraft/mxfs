#!/bin/bash
# chk_quarantine_repair_unit.sh — chk_mxfs --accept-quarantine-loss against a
# forged quarantine on an image file, no cluster needed
# (docs/quarantine-repair.md).
#
# The image lives on tmpfs (/dev/shm) and the archive on this host's disk
# (/var/tmp), so the archive is provably on storage the image does not share.
# The quarantine is forged with tools/recov_forge mkguard (--feat 0x18: the
# victim's feature block says TCP on DRBD, as a real guard's copy of the victim
# record does).  Stages:
#   refusals   a wrong digest, a guard with no feature block (transport
#              unknown), an archive destination on tmpfs: each refuses, and
#              the guard sector and the slice are left byte-identical; the
#              tmpfs one took the lock first and must hand it back (IDLE,
#              journal ABANDONED)
#   repair     the whole repair: the slot cleared, the slice's lifecycle
#              ZEROING, the bootstrap record IDLE, a cold check clean
#   crash      MXFS_CHK_REPAIR_CRASH_AT at every durable transition (and half
#              way through the slice overwrite): the volume refuses mounts
#              (REFUSED) from LOSS_ACCEPTED on, --clear-bootstrap refuses
#              after the loss and abandons before it, and a re-run finishes
#
# Usage: tests/chk_quarantine_repair_unit.sh <label>
# Exit 0 PASS, 1 FAIL, 2 INFRA/ABORT.  Needs `sudo -n` for the loop device
# mkfs_mxfs formats (it formats block devices only).
# Budgets: one repair is ~21 s here (two 10 s heartbeat windows dominate);
# a check of the 512 MiB image ~1 s.  ACCEPT 60, CHK 30.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
IMG=/dev/shm/mxfs_qrepair_unit.img
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
# the archives are evidence and are never deleted: one fresh directory per run
ARCH=/var/tmp/mxfs_qrepair_unit/$STAMP
CHK=tools/chk_mxfs
MKFS=tools/mkfs_mxfs
FORGE=tools/recov_forge
OUT=${QUNIT_EVID:-tests/evidence/${STAMP}_qrepair_unit_$LABEL}
ACCEPT=60
CHKT=30
mkdir -p "$OUT" "$ARCH"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
[ -x "$CHK" ] && [ -x "$MKFS" ] && [ -x "$FORGE" ] || { echo "ABORT: build tools/chk_mxfs, tools/mkfs_mxfs and tools/recov_forge first"; exit 2; }
sudo -n true 2>/dev/null || { echo "ABORT: sudo -n is not available (the loop device)"; exit 2; }

LOOP=
cleanup() { [ -n "$LOOP" ] && sudo -n losetup -d "$LOOP" 2>/dev/null; rm -f /dev/shm/mxfs_qrepair_unit.img; }
trap cleanup EXIT

# geometry the assertions need, from the tool's own read of the envelope
dl_off() { $CHK --geometry "$IMG" | sed -n 's/.*disklock_offset=\([0-9]*\).*/\1/p' | head -1; }
fresh() {   # <tag> [--feat F]: a fresh format with a forged quarantine in slot 0
    local tag=$1; shift
    rm -f /dev/shm/mxfs_qrepair_unit.img
    truncate -s 512M "$IMG" || return 1
    LOOP=$(sudo -n losetup -f --show "$IMG") || return 1
    # two slices: four 64 MiB slices do not fit the internal log of a
    # 512 MiB image (mkfs refuses), and the forge names slice 0 anyway
    sudo -n "$MKFS" -f -n 2 "$LOOP" > "$OUT/mkfs_$tag.txt" 2>&1 || { echo "  mkfs failed: $(tail -2 "$OUT/mkfs_$tag.txt")"; return 1; }
    sync
    sudo -n losetup -d "$LOOP"; LOOP=
    "$FORGE" "$IMG" mkguard 0 --fsgen 0x1234 --node 4242 --epoch 7 --oc valid "$@" > "$OUT/forge_$tag.txt" 2>&1 || { echo "  forge failed: $(tail -2 "$OUT/forge_$tag.txt")"; return 1; }
}
digest() { $CHK --show-quarantine "$IMG" | awk '/VERDICT DIGEST/ {print $3; exit}'; }
state()  { $CHK --bootstrap "$IMG" | sed -n 's/^BOOTSTRAP state=\([A-Z_]*\).*/\1/p'; }
slot0()  { local o; o=$(dl_off); dd if="$IMG" bs=512 skip=$((o / 512)) count=1 2>/dev/null | sha256sum | cut -c1-16; }
zero512=$(head -c 512 /dev/zero | sha256sum | cut -c1-16)
accept() {  # <tag> <digest> <archive> [env...]: rc
    local tag=$1 dg=$2 ar=$3; shift 3
    env "$@" timeout $ACCEPT "$CHK" --accept-quarantine-loss 0 --confirm "$dg" --archive-to "$ar" "$IMG" > "$OUT/accept_$tag.txt" 2>&1
    echo $?
}
cold() {    # <tag>: rc of a full check-only pass
    timeout $CHKT "$CHK" -n "$IMG" > "$OUT/chk_$1.txt" 2>&1
    echo $?
}
echo "=== chk_quarantine_repair_unit label=$LABEL $(date -u +%FT%TZ) ==="

# ---- refusals
fresh refusals --feat 0x18 || exit 2
DG=$(digest); G0=$(slot0)
[ ${#DG} = 16 ] || { echo "ABORT: no verdict digest on the forged image"; exit 2; }
ck "control: the forged image checks clean apart from its quarantine" "$(cold control)" 0
rc=$(accept wrongdigest 0123456789ABCDEF "$ARCH/wrong.txt")
ck "wrong digest: refused" "$rc/$(slot0)/$(state)" "4/$G0/IDLE"
rc=$(accept tmpfsarchive "$DG" /dev/shm/mxfs_qrepair_unit_archive.txt)
ck "archive on tmpfs: refused, lock handed back, guard untouched" "$rc/$(slot0)/$(state)" "4/$G0/IDLE"
ck "archive on tmpfs: journal ABANDONED" "$(grep -c 'repair journal: ABANDONED' "$OUT/accept_tmpfsarchive.txt")" 1
fresh nofeat || exit 2
DG=$(digest); G0=$(slot0)
rc=$(accept nofeat "$DG" "$ARCH/nofeat.txt")
ck "no feature block: refused before the lock" "$rc/$(slot0)/$(state)" "4/$G0/IDLE"
ck "no feature block: names the transport" "$(grep -c 'does not show the TCP' "$OUT/accept_nofeat.txt")" 1

# ---- the whole repair
fresh repair --feat 0x18 || exit 2
DG=$(digest)
rc=$(accept repair "$DG" "$ARCH/repair.txt")
ck "repair: completes" "$rc" 0
ck "repair: slot 0 is a zero record" "$(slot0)" "$zero512"
ck "repair: bootstrap record IDLE" "$(state)" IDLE
ck "repair: cold check clean" "$(cold repair)" 0
ck "repair: slice 0 lifecycle ZEROING (the next claimant re-zeroes it)" "$(grep -c '1 ZEROING' "$OUT/chk_repair.txt")" 1
ck "repair: no quarantine left" "$($CHK --show-quarantine "$IMG" | grep -c 'quarantined verdicts    0')" 1
ck "repair: archive + slice image on disk" "$(ls "$ARCH/repair.txt" "$ARCH/repair.txt.slice" 2>/dev/null | wc -l)" 2

# ---- crash at every durable transition, then a re-run
for P in LOCKED ARCHIVED LOSS_ACCEPTED SLICE_HALF SLICE_RESET_COMPLETE CHECK_COMPLETE SLOT_CLEARED; do
    fresh "crash_$P" --feat 0x18 || exit 2
    DG=$(digest); G0=$(slot0); AR="$ARCH/crash_$P.txt"
    rc=$(accept "crash_$P" "$DG" "$AR" MXFS_CHK_REPAIR_CRASH_AT=$P)
    want_state=REFUSED; [ "$P" = LOCKED ] && want_state=IDLE
    want_slot=$G0; [ "$P" = SLOT_CLEARED ] && want_slot=$zero512
    ck "crash at $P: exits there, mounts refused, slot as it was" "$rc/$(state)/$(slot0)" "9/$want_state/$want_slot"
    case "$P" in
        ARCHIVED)
            # before the loss: the lock may be handed back, the guard stays
            timeout $CHKT "$CHK" --clear-bootstrap "$IMG" > "$OUT/clear_$P.txt" 2>&1; crc=$?
            ck "crash at $P: --clear-bootstrap abandons the unaccepted repair" "$crc/$(state)/$(slot0)" "0/IDLE/$G0"
            # the abandoned run's archive stays; the fresh run writes its own
            AR="$ARCH/crash_$P.retry.txt" ;;
        LOSS_ACCEPTED|SLICE_HALF)
            timeout $CHKT "$CHK" --clear-bootstrap "$IMG" > "$OUT/clear_$P.txt" 2>&1; crc=$?
            ck "crash at $P: --clear-bootstrap refuses an accepted loss" "$crc/$(state)" "4/REFUSED" ;;
    esac
    rc=$(accept "rerun_$P" "$DG" "$AR")
    ck "crash at $P: the re-run finishes" "$rc/$(state)/$(slot0)" "0/IDLE/$zero512"
    ck "crash at $P: cold check clean" "$(cold "rerun_$P")" 0
done

echo "RESULT: $([ $fails = 0 ] && echo PASS || echo FAIL) label=$LABEL fails=$fails evidence=$OUT"
[ $fails = 0 ]
