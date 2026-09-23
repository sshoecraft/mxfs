#!/bin/bash
# d_recov_zero_epoch_verify.sh — THE CLOSURE STEP for
# D-RECOV-ZERO-EPOCH-DESCRIPTOR-AUTHORITY-UNPROVEN (ledger next item 1).
#
# Claim: since sess93 no zero-incarnation recovery descriptor can be created —
# v5_pr_fence_intent (dlm/disklock.c ~5559) refuses with P238-FENCE-ZEROINC
# when the victim's ACTIVE record carries epoch 0, and recovery_begin() is
# retired.  Nothing has ever EXERCISED that refusal on the rig: a real build
# never writes epoch 0, so the class is unconstructible by natural means and
# the ledger asks for an injected one.
#
# Shape (fleet prepped 32/caw):
#   1. srcgate; victim's slot + node id from its own boot-time claim line,
#      cross-checked against the platter record (tests/hb_epoch_inject.py show).
#   2. kmsg marker on every survivor; virsh destroy the victim; IMMEDIATELY
#      rewrite the victim's HB record epoch -> 0 on the backing store with
#      both crcs resealed (the record must still read hb_feature_state()==OK,
#      or a different arm fires — the ledger's recorded trap).  The record is
#      dead so nothing overwrites the injection; survivors expire it ~62 s on.
#   3. Wait the dead window (+15 s); sweep every survivor's dmesg since the
#      marker.  PASS iff: P238-FENCE-ZEROINC slot=<S> fired on >=1 survivor,
#      NO P238-RECOV-LEASE / GUARD for that slot anywhere, the platter still
#      shows the record ACTIVE with epoch 0 (no descriptor laid), and no
#      survivor logged a corrupt-feature / WITHDRAWN arm for the slot.
#   4. RESTORE the original epoch (resealed) so the cluster can recover the
#      slice normally; wait for 'foreign replay of slot <S> ... complete' on
#      some survivor; assert 0 failed.  virsh start the victim (caller preps).
#
# the budget rule (derived): setup 15 s; kill+inject 5 s; dead window 62 s + 15 s
# margin; sweep 25 s (32 parallel ssh, 20 s each); restore 2 s; the next
# monitor pass fences + replays (expiry already counted): fence ~5 s +
# replay of an idle slice ~10 s, wait bound 90 s; final sweep 25 s.
# => ~240 s.  Caller bound 300 s.
#
# Usage: tests/d_recov_zero_epoch_verify.sh <label> [victim=test8] [N=32]
set -u
LABEL=${1:?label}
VICTIM=${2:-test8}
N=${3:-32}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
VIRSH="sudo virsh -c qemu:///system"
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
MNT=${MXFS_MNT:-/mnt/shared}
MARK="ZEROINC-$LABEL-$(date -u +%H%M%S)"
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_zeroinc
mkdir -p "$OUT"
TREE_SV=$(modinfo mxfs.ko 2>/dev/null | awk '/srcversion/{print $2}')
fails=0
pass() { echo "  PASS $1"; }
fail() { echo "  FAIL $1"; fails=$((fails+1)); }
info() { echo "  INFO $1"; }
sshq() { timeout "$1" "$SSH" "$2" "$3" 2>/dev/null | grep -av '^Unauthorized\|^Warning\|^If you'; }
SURV=(); for i in $(seq 1 "$N"); do [ "test$i" = "$VICTIM" ] || SURV+=("test$i"); done
echo "=== d_recov_zero_epoch_verify label=$LABEL victim=$VICTIM N=$N out=$OUT $(date -u +%FT%TZ) ==="
T0=$(date +%s)

# 1. srcgate + victim identity
v=$(sshq 20 "$VICTIM" "cat /sys/module/mxfs/srcversion; mountpoint -q $MNT && echo MOUNTED; dmesg | grep -ao 'claimed heartbeat slot [0-9]* for node [0-9]*' | tail -1")
echo "$v" | grep -q "^$TREE_SV" && echo "$v" | grep -q MOUNTED && pass "srcgate $VICTIM runs $TREE_SV, mounted" || fail "srcgate $VICTIM: $(echo "$v" | tr '\n' ' ')"
SLOT=$(echo "$v" | grep -ao 'slot [0-9]*' | awk '{print $2}'); NODEID=$(echo "$v" | grep -ao 'node [0-9]*' | awk '{print $2}')
[ -n "${SLOT:-}" ] && [ -n "${NODEID:-}" ] || { fail "victim claim line not found (dmesg rotated?)"; echo "=== d_recov_zero_epoch_verify $LABEL: fails=$fails out=$OUT ==="; exit 1; }
python3 tests/hb_epoch_inject.py "$IMG" "$SLOT" show > "$OUT/record_before.txt" 2>&1
grep -q "flags=ACTIVE node=$NODEID " "$OUT/record_before.txt" && pass "platter slot $SLOT is ACTIVE for node $NODEID" || fail "platter slot $SLOT: $(cat "$OUT/record_before.txt")"
EPOCH0=$(grep -ao 'epoch=[0-9]*' "$OUT/record_before.txt" | head -1 | cut -d= -f2)
grep -q 'feat{magic=ok proto_gen=[0-9]* crc_ok=1} prov{magic=ok slot_seq=[0-9]* crc_ok=1}' "$OUT/record_before.txt" && pass "feature + provenance crcs verify with the tool's formulas (epoch=$EPOCH0)" || fail "crc formulas do NOT verify on a live record — injector cannot reseal: $(cat "$OUT/record_before.txt")"
[ "${EPOCH0:-0}" != 0 ] && pass "victim incarnation is nonzero ($EPOCH0)" || fail "victim already carries epoch 0"
[ $fails -eq 0 ] || { echo "=== d_recov_zero_epoch_verify $LABEL: fails=$fails (setup) out=$OUT ==="; exit 1; }

# 2. marker, kill, inject
for n in "${SURV[@]}"; do sshq 10 "$n" "echo $MARK > /dev/kmsg" >/dev/null & done; wait
TK=$(date +%s)
$VIRSH destroy "$VICTIM" >/dev/null 2>&1 || { fail "virsh destroy $VICTIM"; echo "=== d_recov_zero_epoch_verify $LABEL: fails=$fails out=$OUT ==="; exit 1; }
python3 tests/hb_epoch_inject.py "$IMG" "$SLOT" set 0 > "$OUT/inject.txt" 2>&1; irc=$?
[ $irc -eq 0 ] && grep -q 'after:.*epoch=0 feat{magic=ok proto_gen=[0-9]* crc_ok=1} prov{magic=ok slot_seq=[0-9]* crc_ok=1}' "$OUT/inject.txt" && pass "epoch 0 injected + resealed at +$(( $(date +%s) - TK ))s after the kill" || fail "inject rc=$irc: $(tail -1 "$OUT/inject.txt")"

# 3. dead window, then sweep
sleep 77
python3 tests/hb_epoch_inject.py "$IMG" "$SLOT" show > "$OUT/record_window.txt" 2>&1
sweep() {
    local tag=$1 n
    for n in "${SURV[@]}"; do
        sshq 20 "$n" "dmesg | sed -n '/$MARK/,\$p' | grep -a 'slot=$SLOT\|slot $SLOT \|P238-FENCE-ZEROINC\|foreign replay of slot $SLOT' | cut -c1-220" > "$OUT/$n.$tag" 2>/dev/null; echo "rc=$?" > "$OUT/$n.$tag.rc" &
    done; wait
}
sweep window
answered=$(grep -l '^rc=0' "$OUT"/test*.window.rc | wc -l)
[ "$answered" -eq "${#SURV[@]}" ] && pass "sweep reached ${#SURV[@]}/${#SURV[@]} survivors" || fail "sweep reached only $answered/${#SURV[@]} survivors (counters below are NOT fleet-complete)"
zi=$(cat "$OUT"/test*.window 2>/dev/null | grep -ac "P238-FENCE-ZEROINC slot=$SLOT ")
lease=$(cat "$OUT"/test*.window 2>/dev/null | grep -ac "P238-RECOV-LEASE slot=$SLOT ")
corrupt=$(cat "$OUT"/test*.window 2>/dev/null | grep -aic "slot=$SLOT .*\(feature\|CORRUPT\|crc\)")
info "window: ZEROINC=$zi lease=$lease feature/crc-arms=$corrupt; platter: $(grep -ao 'flags=[A-Z]* .*epoch=[0-9]*' "$OUT/record_window.txt" | cut -c1-60)"
[ "$zi" -ge 1 ] && pass "P238-FENCE-ZEROINC slot=$SLOT fired ($zi survivor lines)" || fail "P238-FENCE-ZEROINC did not fire for slot $SLOT"
[ "$lease" -eq 0 ] && pass "no recovery lease/descriptor laid on slot $SLOT" || fail "a descriptor WAS laid on the zero-incarnation slot ($lease lease lines)"
grep -q 'flags=ACTIVE .*epoch=0 ' "$OUT/record_window.txt" && pass "platter record still ACTIVE with epoch 0 (nothing certified)" || fail "platter record changed: $(cat "$OUT/record_window.txt" | tail -1)"
[ "$corrupt" -eq 0 ] && pass "no feature/crc refusal arm fired (the reseal held)" || fail "$corrupt feature/crc arm lines — the injection measured the wrong refusal"

# 4. restore the real incarnation and let recovery proceed
python3 tests/hb_epoch_inject.py "$IMG" "$SLOT" set "$EPOCH0" > "$OUT/restore.txt" 2>&1 && pass "epoch $EPOCH0 restored (resealed)" || fail "restore: $(tail -1 "$OUT/restore.txt")"
TR=$(date +%s); done_c=0; done_f=0
while [ $(( $(date +%s) - TR )) -lt 90 ]; do
    sleep 10
    sweep recov
    # sess438: the kernel line is 'foreign replay of slot N complete (...)' —
    # one space; the old '.* ' pattern demanded two and counted 0 on a real
    # completion (chain 12 s437a, 0.42.0), producing a false FAIL.
    done_c=$(cat "$OUT"/test*.recov 2>/dev/null | grep -ac "foreign replay of slot $SLOT complete\|P163-RECOVERY-COMPLETE slot=$SLOT "); done_f=$(cat "$OUT"/test*.recov 2>/dev/null | grep -ac "foreign replay of slot $SLOT .*failed")
    [ $((done_c+done_f)) -ge 1 ] && break
done
info "after restore: complete=$done_c failed=$done_f in $(( $(date +%s) - TR ))s"
[ "$done_c" -ge 1 ] && [ "$done_f" -eq 0 ] && pass "slice $SLOT recovered normally once the incarnation was real" || fail "recovery after restore: complete=$done_c failed=$done_f"
python3 tests/hb_epoch_inject.py "$IMG" "$SLOT" show > "$OUT/record_after.txt" 2>&1
info "platter after: $(grep -ao 'flags=[A-Z]* .*epoch=[0-9]*' "$OUT/record_after.txt" | cut -c1-60)"
$VIRSH start "$VICTIM" >/dev/null 2>&1 && info "$VICTIM started — caller must prep_cluster" || fail "virsh start $VICTIM"
info "wall=$(( $(date +%s) - T0 ))s"
echo "=== d_recov_zero_epoch_verify $LABEL: fails=$fails out=$OUT $(date -u +%FT%TZ) ==="
[ $fails -eq 0 ]
