#!/bin/bash
# tests/chk_guard_inprogress_verify.sh — D-379 item 5 verification (sess434).
#
# chk_mxfs (0.40.1, sess433) must classify a RECOVERY GUARD whose descriptor
# is NOT flagged QUARANTINED as a recovery IN PROGRESS: counted under
# 'recoveries in progress', NOT under 'quarantined verdicts', with the
# whole-volume-blocked advice and rc=5 — never the -376 'one slot short'
# repair pointer.  The kernel only writes well-formed guards during a real
# recovery, so the shape is forged with tools/recov_forge (--live --stage 1)
# on the real LUN from a node (SG_IO FUA), on an UNMOUNTED fleet, into an
# unused slot that is saved first and restored byte-for-byte afterwards.
# chk_mxfs runs on clyde against the SCST backing image.
#
# derived time budget: umount sweep 20 s, save/forge/restore ~3 s each (SG_IO),
# chk_mxfs -Q on a 50 GiB volume ~5 s (heartbeat table only) => bound 90 s.
#
# usage: tests/chk_guard_inprogress_verify.sh <label> [slot=5] [probe=test1] [nodes=32]
set -u
LABEL=${1:?label}; SLOT=${2:-5}; PROBE=${3:-test1}; NN=${4:-32}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
FORGE=/src/mxfs/tools/recov_forge
# the forge runs on a node against the shared LUN and the checker runs on the
# host against the LUN's backing image: this is the CAW multipath rig's
# shape.  The device is resolved, never assumed (MXFS_DEV overrides).
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-caw}
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_chk_guard_inprogress_$LABEL
mkdir -p "$OUT"
SAVE=/tmp/chkgip_slot${SLOT}_$LABEL.bin
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require/mxfs_dev_resolve (tests/lib/rig.sh): every
# capture a verdict is taken from is proven to hold its tool's shape first
. "$(dirname "$0")/lib/rig.sh"
node() { rsx 30 "$1" "$2"; }
mxfs_dev_resolve "$PROBE"
DEV=$MXFS_DEV_RESOLVED
echo "=== chk_guard_inprogress_verify label=$LABEL slot=$SLOT probe=$PROBE dev=$DEV out=$OUT $(date -u +%FT%TZ) ==="
[ -x tools/chk_mxfs ] || { echo "RESULT: FAIL | chk_guard_inprogress | tools/chk_mxfs not built"; exit 1; }
[ -r "$IMG" ] || { echo "RESULT: FAIL | chk_guard_inprogress | $IMG unreadable"; exit 1; }
# 1. nobody mounted
for i in $(seq 1 "$NN"); do
  ( timeout 12 $SSH "test$i" "umount /mnt/shared 2>/dev/null; mount -t mxfs | grep -c shared" > "$OUT/umount_test$i.txt" 2>&1; echo "rc=$?" >> "$OUT/umount_test$i.txt" ) &
done
wait
STILL=$(grep -l '^1' "$OUT"/umount_test*.txt 2>/dev/null | wc -l)
[ "$STILL" = "0" ] || { echo "RESULT: FAIL | chk_guard_inprogress | precondition: $STILL node(s) still mounted"; exit 1; }
sleep 2
# 2. baseline: the slot must not be a live member; save it
node "$PROBE" "$FORGE $DEV dump $SLOT" > "$OUT/dump_before.txt"
capture_require "$OUT/dump_before.txt" 'sector_crc32c=' "the slot dump on $PROBE before the forge"
base_crc=$(sed -n 's/.*sector_crc32c=\(0x[0-9a-f]*\).*/\1/p' "$OUT/dump_before.txt" | head -1)
echo "  INFO baseline: $(head -c 200 "$OUT/dump_before.txt" | tr '\n' ' ')"
tools/chk_mxfs -Q "$IMG" > "$OUT/chk_before.txt" 2>&1; rc0=$?
capture_require "$OUT/chk_before.txt" 'recoveries in progress' "chk_mxfs -Q on the image before the forge (rc=$rc0)"
ck "chk_mxfs -Q before the forge: zero recoveries in progress" "$(grep -o 'recoveries in progress *[0-9]*' "$OUT/chk_before.txt" | tr -dc '0-9')" "0"
echo "  INFO chk before rc=$rc0 quarantined='$(grep -o 'quarantined verdicts *[0-9]*' "$OUT/chk_before.txt")'"
node "$PROBE" "$FORGE $DEV save $SLOT $SAVE && echo SAVED" | grep -q SAVED || { echo "RESULT: FAIL | chk_guard_inprogress | save failed"; exit 1; }
# 3. forge: live descriptor (no F_QUARANTINED), stage 1, no outcome record
node "$PROBE" "$FORGE $DEV mkguard $SLOT --live --stage 1" > "$OUT/forge.txt"
capture_require "$OUT/forge.txt" 'desc: ver=' "the forge on $PROBE"
echo "  INFO forge: $(head -c 300 "$OUT/forge.txt" | tr '\n' ' ')"
# sess434 (D-0358): couple the forge's descriptor version to the kernel's
KVER=$(sed -n 's/^#define MXFS_RECOV_DESC_VERSION[[:space:]]*\([0-9]*\).*/\1/p' dlm/disklock.h | head -1)
FVER=$(grep -ao 'desc: ver=[0-9]*' "$OUT/forge.txt" | head -1 | tr -dc '0-9')
ck "forge descriptor version == dlm/disklock.h MXFS_RECOV_DESC_VERSION (${KVER:-?})" "${FVER:-?}" "${KVER:-?}"
sync
# 4. classify
tools/chk_mxfs -Q "$IMG" > "$OUT/chk_forged.txt" 2>&1; rc1=$?
capture_require "$OUT/chk_forged.txt" 'recoveries in progress' "chk_mxfs -Q on the forged image (rc=$rc1)"
ck "recoveries in progress = 1" "$(grep -o 'recoveries in progress *[0-9]*' "$OUT/chk_forged.txt" | tr -dc '0-9')" "1"
ck "quarantined verdicts = 0 (guard NOT counted as a terminal quarantine)" "$(grep -o 'quarantined verdicts *[0-9]*' "$OUT/chk_forged.txt" | tr -dc '0-9')" "0"
ck "IN PROGRESS advice printed" "$(grep -c 'IN PROGRESS (no terminal verdict)' "$OUT/chk_forged.txt")" "1"
ck "advice names the whole-volume block" "$(grep -c 'blocks the whole volume, not one' "$OUT/chk_forged.txt")" "1"
ck "advice names the PREEMPT AND ABORT remedy" "$(grep -c 'PREEMPT AND ABORT' "$OUT/chk_forged.txt")" "1"
ck "no -376 'one slot short' repair pointer" "$(grep -c 'runs that many members short' "$OUT/chk_forged.txt")" "0"
ck "usable RW slices not reduced by the in-progress guard" "$(grep -o 'usable RW slices *[0-9]* of [0-9]*' "$OUT/chk_forged.txt" | awk '{print ($4==$6)?"same":"reduced"}')" "same"
ck "chk_mxfs rc=5 (in-progress guard, no terminal quarantine)" "$rc1" "5"
# 5. restore byte-for-byte
node "$PROBE" "$FORGE $DEV restore $SLOT $SAVE && echo RESTORED" | grep -q RESTORED || { echo "  FAIL restore"; fails=$((fails+1)); }
node "$PROBE" "$FORGE $DEV dump $SLOT" > "$OUT/dump_after.txt"
post_crc=$(sed -n 's/.*sector_crc32c=\(0x[0-9a-f]*\).*/\1/p' "$OUT/dump_after.txt" | head -1)
ck "sector restored (crc32c ${base_crc:-?} == ${post_crc:-?})" "$post_crc" "$base_crc"
sync
tools/chk_mxfs -Q "$IMG" > "$OUT/chk_after.txt" 2>&1; rc2=$?
ck "chk_mxfs -Q after restore: zero recoveries in progress" "$(grep -o 'recoveries in progress *[0-9]*' "$OUT/chk_after.txt" | tr -dc '0-9')" "0"
ck "chk_mxfs rc after restore equals the baseline rc" "$rc2" "$rc0"
ST=PASS; [ "$fails" = 0 ] || ST=FAIL
echo "RESULT: $ST | chk_guard_inprogress | label=$LABEL slot=$SLOT fails=$fails rc_before=$rc0 rc_forged=$rc1 rc_after=$rc2 out=$OUT"
[ "$ST" = PASS ]
