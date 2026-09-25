#!/bin/bash
# d0932_platter_fallback.sh — reach v5_holder_slot_state's REVOKED verdict on
# two nodes by a native judge, and prove it is the ONLY route that answers.
#
# THE STATE THE FALLBACK EXISTS FOR (s562, tests/evidence/20260909T003455Z_
# ghost_s562): a dead holder's recovery PUBLISHED — its heartbeat slot zeroed
# behind a certified fence — while a fencing attempt it held on another slot
# still stands, and a judge that neither certified that fence nor watched the
# slot zero.  Its membership view then says UNKNOWN ('node not in the heartbeat
# table') and the descriptor is untakeable for ever unless the platter answers.
#
# WHY NO SINGLE TWO-NODE EPISODE PRODUCES IT (measured s581a, judge journal
# lines 301/305/366): the episode that certifies the holder's fence notes the
# incarnation dead (P-DEAD-INC), takes every attempt it held over in the SAME
# replay round (P238-RECOV-TAKEOVER, 0 s later) and only publishes the holder
# 20 s after that (P-COMPLETE-TIMING).  Takeover before purge, always.  And
# node ids are drawn fresh per mount (dlm/v5_mount.c, node_uuid), so a later
# mount has no 'own earlier incarnation' or 'later incarnation of the same
# node' route either — it has nothing but the platter.
#
# HOW THE STATE IS STAGED WITHOUT FORGING ANYTHING.  A STAGING mount runs with
# dbg_fence_takeover_decline > 0: it fences the dead prover, certifies, notes
# it dead, proves the attempt's holder REVOKED — and DECLINES the takeover
# (P238-FENCE-TAKEOVER-DECLINED), leaving the attempt standing.  Everything
# else is the shipped code: the prover's own slice is replayed and published
# by the real writers, which zeroes its slot; the declined slice stays pending
# and the mount aborts at the barrier bound.  The platter is then the s562
# state, written entirely by real fences, real recoveries and real purges.
# A second mount with the knob at 0 is a fresh judge: new node id, empty dead
# set, no membership answer — v5_holder_slot_state must answer from the slot.
#
# SHAPE (A = prover host, B = victim host; the judge is B's host)
#   prep both -> arm dl_fence_postintent_pause_ms on A -> destroy B (A lays a
#   durable intent for B1 and parks) -> destroy A with the attempt standing ->
#   start B only -> STAGING mount on B with the decline knob (expected to
#   ABORT; A1 published, D standing) -> platter dump: A1 absent, D present,
#   else VACUOUS -> JUDGE mount on B, knob 0 -> assert verdict=REVOKED for A1's
#   tuple, P238-FENCE-TAKEOVER, certificate for B1, both recoveries complete,
#   MOUNTED -> start A and rejoin.
#
# the budget rule (derived): prep ~50 s (bound 300); A parks within the 31 x
# 2 s dead window plus the intent, ~120 s (bound 180); B destroy+start+boot
# ~150 s; NFS + module copy ~30 s; the staging mount aborts at the barrier's
# 122 s bound plus teardown (bound 200 — a staging mount that SUCCEEDS is a
# FAIL of the arm, not a slow pass); dumps ~10 s; the judge mount, measured
# 86-89 s on this shape's siblings (bound 300); A boot ~150 s; A join (bound
# 300); captures ~30 s.  Whole lap ~1000 s; wrapper bound 1300 s.
#
# Usage: tests/d0932_platter_fallback.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV (default /dev/sda),
#        MXFS_MODARGS, HOLD_MS (default 120000), STAGE_BOUND (default 200),
#        JOIN_BOUND (default 300).
# Exit 0 PASS, 1 FAIL, 2 INFRA/ABORT, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the prover that dies mid-attempt
B=${MXFS_NODE_LIST##*,}          # the victim; its host stages, then judges
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
KO=/root/mxfs.ko.prep
HOLD_MS=${HOLD_MS:-120000}
STAGE_BOUND=${STAGE_BOUND:-200}
JOIN_BOUND=${JOIN_BOUND:-300}
HOLDP=/sys/module/mxfs/parameters/dl_fence_postintent_pause_ms
DECLP=/sys/module/mxfs/parameters/dbg_fence_takeover_decline
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0932pf_$LABEL
mkdir -p "$OUT"
fails=0
ck()   { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/cnt/capture_require/ensure_src_or_abort/mxfs_dev_resolve: every
# capture a verdict is taken from is proven to hold its tool's shape first
# (tests/lib/rig.sh); a failed remote command is an ABORT, never a count of
# zero.  MXFS_DEV: the device of A's live mount after prep (MXFS_DEV
# overrides).  MXFS_FAULT_UMOUNT_SRC=<node>:<stage> (capture-contract
# verification only) unmounts /src on <node> right before the named platter
# dump (dump0 | dump1 | dump2) or module copy (deploy): the lap must ABORT.
. "$(dirname "$0")/lib/rig.sh"
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}   # rig-derived: includes this rig's retirement contract
fault_before() { # <stage>
    case ${MXFS_FAULT_UMOUNT_SRC:-} in
        *:"$1") echo "STAGE FAULT: unmounting /src on ${MXFS_FAULT_UMOUNT_SRC%%:*} before $1"; rs 30 "${MXFS_FAULT_UMOUNT_SRC%%:*}" "umount -l /src; mountpoint -q /src && echo STILL || echo GONE" | tail -1 ;;
    esac
}
VIRSH="timeout 30 virsh -c qemu:///system"
waitboot() {
    local n w=0
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 30 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait polls=$w"
}
deploy_ko() {
    local n=$1
    ensure_src_or_abort "$n"
    fault_before deploy
    rsx 60 "$n" "cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32" > "$OUT/${n}_md5.txt"
    capture_require "$OUT/${n}_md5.txt" '^[0-9a-f]{32}$' "the module copy on $n"
    ck "$n holds the tree build (md5)" "$(head -1 "$OUT/${n}_md5.txt")" "$MD5"
}
# dump <file> <stage>: the platter from B, validated against the dump tool's
# shape (the tool lives on the share: the s580f empty dump was this call)
dump() {
    ensure_src_or_abort "$B"
    fault_before "$2"
    rsx 60 "$B" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV" > "$1"
    capture_require "$1" '^slot +[0-9]+ magic=' "the platter dump on $B ($2)"
}
# mountcap <file> <what>: a mount command list's capture, validated
mountcap() { capture_require "$1" '^(MOUNTED|NOT_MOUNTED)$' "$2"; }
journalcap() { capture_require "$1" 'kernel: ' "$2"; }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
MD5=$(md5sum mxfs.ko | cut -c1-32)
echo "=== d0932_platter_fallback label=$LABEL A(prover)=$A B(victim,judge)=$B sv=$SV hold=${HOLD_MS}ms $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }

waitboot "$A" "$B"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: FAIL label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    rsx 30 "$n" "cat /sys/module/mxfs/srcversion" > "$OUT/${n}_srcversion.txt"
    capture_require "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n"
    ck "prep deployed the tree build on $n" "$(head -1 "$OUT/${n}_srcversion.txt")" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL wrong build evidence=$OUT"; exit 2; }
# the LUN as MXFS actually uses it, from A's live mount (MXFS_DEV overrides)
mxfs_dev_resolve "$A"
MXFS_DEV=$MXFS_DEV_RESOLVED
export MXFS_DEV
echo "STAGE device=$MXFS_DEV (from $A's live mount)"

# ---- 1. A parks on a durable intent for B1, then dies with it standing.
measure "$A" 30 "$OUT/rv_armed_1.txt" '^READ_RC=[0-9]+$' "armed on $A" "echo $HOLD_MS > $HOLDP; cat $HOLDP; printf '\nREAD_RC=%s\n' \$?"; armed=$(grep -av '^READ_RC=' "$OUT/rv_armed_1.txt")
ck "$A armed the post-intent hold" "$armed" "$HOLD_MS"
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL could not arm evidence=$OUT"; exit 2; }
KMARK="D0932PF-MARK-$LABEL"
rsx 15 "$A" "echo $KMARK > /dev/kmsg" > /dev/null
AMARK=$(date +%s)
$VIRSH destroy "$B" > /dev/null 2>&1
echo "STAGE destroyed $B at +$(el)s — waiting for $A to park on its intent"
# the wait crosses the capture boundary (wait_for_into: every poll is a
# status-checked window after a kernel marker), so an ssh that never ran
# cannot read as "the line never appeared"
wait_for_into heldw "$A" 180 "$KMARK" "P236-FENCE-INTENT-HOLD"
held=$([ "$heldw" = timeout ] && echo 0 || echo 1); w=$heldw
echo "STAGE A-parked=$held polls=$w wall=$(el)s"
rsx 30 "$A" "journalctl -k --since @$AMARK --no-pager | grep -a 'P236-FENCE-INTENT\|MXFS-MEMBERSHIP' | cut -c1-400; true" > "$OUT/A_intent.txt"
sed 's/^/    /' "$OUT/A_intent.txt" | cut -c1-200 | head -4
if [ "$held" != 1 ]; then
    # "never parked" is a statement about the kernel only if its journal was
    # readable: prove that before calling the lap VACUOUS
    rsx 60 "$A" "journalctl -k --since @$AMARK --no-pager | cut -c1-600" > "$OUT/A_park_journal.txt"
    journalcap "$OUT/A_park_journal.txt" "the kernel journal on $A while waiting for the intent hold"
    echo "  FAIL $A never reached P236-FENCE-INTENT-HOLD — no attempt was left standing"
    echo "RESULT: VACUOUS label=$LABEL wall=$(el)s evidence=$OUT"
    exit 3
fi
# The identities, from the intent line A itself printed:
#   P236-FENCE-INTENT slot=S victim=V epoch=E key=K slice=.. prover=P term=T
INTENT=$(grep -ao 'P236-FENCE-INTENT slot=[0-9]* victim=[0-9]* epoch=[0-9]* key=[0-9]* slice=[0-9/]* prover=[0-9]* term=[0-9]*' "$OUT/A_intent.txt" | head -1)
VSLOT=$(echo "$INTENT" | grep -ao 'slot=[0-9]*' | head -1 | cut -d= -f2)
VNODE=$(echo "$INTENT" | grep -ao 'victim=[0-9]*' | cut -d= -f2)
VEPOCH=$(echo "$INTENT" | grep -ao 'epoch=[0-9]*' | cut -d= -f2)
PNODE=$(echo "$INTENT" | grep -ao 'prover=[0-9]*' | cut -d= -f2)
echo "STAGE identities: victim B1=$VNODE/$VEPOCH in slot $VSLOT, prover A1=$PNODE"
if [ -z "$VSLOT" ] || [ -z "$VNODE" ] || [ -z "$PNODE" ]; then
    echo "  FAIL the intent line did not carry the identities this lap needs"
    echo "RESULT: FAIL label=$LABEL wall=$(el)s evidence=$OUT"; exit 2
fi
capture_require "$OUT/A_intent.txt" 'P236-FENCE-INTENT' "the intent lines on $A (the hold was observed, so they must be there)"
$VIRSH destroy "$A" > /dev/null 2>&1
echo "STAGE destroyed $A with its fencing attempt standing at +$(el)s"

# ---- 2. B's host returns alone.
$VIRSH start "$B" > /dev/null 2>&1
waitboot "$B"
deploy_ko "$B"
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL deploy evidence=$OUT"; exit 2; }
dump "$OUT/hb_0_before_staging.txt" dump0
PEPOCH=$(grep -a "node=$PNODE " "$OUT/hb_0_before_staging.txt" | grep -ao 'epoch=[0-9]*' | head -1 | cut -d= -f2)
echo "STAGE hb before staging: $(cnt "$OUT/hb_0_before_staging.txt" '^slot') record(s); prover A1=$PNODE/${PEPOCH:-?}"
grep -a "^slot\|desc v" "$OUT/hb_0_before_staging.txt" | sed 's/^/    /' | cut -c1-200
ck "before staging: A1's record stands ACTIVE in the table" "$(grep -a "node=$PNODE " "$OUT/hb_0_before_staging.txt" | grep -ac 'flags=ACTIVE')" 1
ck "before staging: B1's slot carries the FENCING attempt with A1 as prover" "$(grep -a 'desc v' "$OUT/hb_0_before_staging.txt" | grep -a "stage=FENCING" | grep -ac "prover=$PNODE/")" 1
if [ $fails != 0 ]; then
    echo "RESULT: VACUOUS label=$LABEL the setup did not leave the attempt standing wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- 3. THE STAGING MOUNT: proves A1 revoked, declines the takeover, publishes
# A1, aborts.  The knob is a count; 1000 covers every replay round of the bound.
SMARK=$(date +%s)
rsx $((STAGE_BOUND + 60)) "$B" "lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; echo 1000 > $DECLP; echo DECLINE=\$(cat $DECLP); T0=\$(date +%s%N); timeout $STAGE_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED; echo DECLINE_LEFT=\$(cat $DECLP)" > "$OUT/B_stage.txt"
mountcap "$OUT/B_stage.txt" "the staging mount on $B"
echo "STAGE staging mount rc=$(field "$OUT/B_stage.txt" MOUNT_RC) wall=$(field "$OUT/B_stage.txt" WALL_MS)ms $(grep -ao '^MOUNTED\|^NOT_MOUNTED' "$OUT/B_stage.txt") decline_left=$(field "$OUT/B_stage.txt" DECLINE_LEFT) at +$(el)s"
if grep -aq '^MOUNTED' "$OUT/B_stage.txt"; then
    echo "  FAIL the staging mount SUCCEEDED: the declined attempt was consumed by some route, nothing is staged"
    fails=$((fails+1))
    rs 90 "$B" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?" | tail -1
fi
rsx 60 "$B" "journalctl -k --since @$SMARK --no-pager | cut -c1-600" > "$OUT/B_stage_journal.txt"
journalcap "$OUT/B_stage_journal.txt" "the kernel journal on $B across the staging mount"
echo "--- staging: DECLINED=$(cnt "$OUT/B_stage_journal.txt" 'P238-FENCE-TAKEOVER-DECLINED') P-DEAD-INC(A1)=$(grep -a 'P-DEAD-INC' "$OUT/B_stage_journal.txt" | grep -ac "node=$PNODE ") verdict=UNKNOWN=$(cnt "$OUT/B_stage_journal.txt" 'verdict=UNKNOWN') verdict=REVOKED=$(cnt "$OUT/B_stage_journal.txt" 'verdict=REVOKED') TAKEOVER=$(cnt "$OUT/B_stage_journal.txt" 'P238-FENCE-TAKEOVER ') COMPLETE=$(cnt "$OUT/B_stage_journal.txt" 'P163-RECOVERY-COMPLETE')"
grep -ah 'P238-FENCE-TAKEOVER-DECLINED\|P-DEAD-INC\|P163-RECOVERY-COMPLETE\|P-COMPLETE-TIMING\|mount ABORTED' "$OUT/B_stage_journal.txt" | sed 's/.*mxfs: /    /; s/.*XFS (sda): /    /' | cut -c1-190 | sort -u | head -8
ckge "staging: the classifier answered UNKNOWN while A1's record still stood (the fail-closed side)" "$(grep -a 'verdict=UNKNOWN' "$OUT/B_stage_journal.txt" | grep -ac "holder=$PNODE/")" 1
ckge "staging: A1's fence certified and its incarnation was noted dead (P-DEAD-INC for A1)" "$(grep -a 'P-DEAD-INC' "$OUT/B_stage_journal.txt" | grep -ac "node=$PNODE ")" 1
ckge "staging: the takeover was DECLINED by the knob after the holder was proved revoked" "$(cnt "$OUT/B_stage_journal.txt" 'P238-FENCE-TAKEOVER-DECLINED')" 1
ck   "staging: no takeover happened (P238-FENCE-TAKEOVER)" "$(cnt "$OUT/B_stage_journal.txt" 'P238-FENCE-TAKEOVER ')" 0
ckge "staging: A1's own recovery was published by the real writers (P163-RECOVERY-COMPLETE for A1)" "$(grep -a 'P163-RECOVERY-COMPLETE' "$OUT/B_stage_journal.txt" | grep -ac "node=$PNODE ")" 1
ck   "staging: the mount did not complete (the declined slice held the barrier)" "$(grep -ac '^NOT_MOUNTED' "$OUT/B_stage.txt")" 1
ck   "staging: zero shutdown / BUG / Oops on $B" "$(( $(cnt "$OUT/B_stage_journal.txt" 'hutting down filesystem') + $(cnt "$OUT/B_stage_journal.txt" 'BUG:\|Oops') ))" 0
dump "$OUT/hb_1_staged.txt" dump1
echo "STAGE hb staged: $(cnt "$OUT/hb_1_staged.txt" '^slot') record(s)"
grep -a "^slot\|desc v" "$OUT/hb_1_staged.txt" | sed 's/^/    /' | cut -c1-200
staged_gone=$([ "$(grep -ac "node=$PNODE " "$OUT/hb_1_staged.txt")" = 0 ] && echo 1 || echo 0)
staged_desc=$(grep -a 'desc v' "$OUT/hb_1_staged.txt" | grep -a 'stage=FENCING' | grep -ac "prover=$PNODE/")
ck "STAGED: A1's record is gone from the table (its slot published: all-zero)" "$staged_gone" 1
ck "STAGED: B1's slot still carries the FENCING attempt naming A1 as prover" "$staged_desc" 1
if [ "$staged_gone" != 1 ] || [ "$staged_desc" != 1 ]; then
    echo "RESULT: VACUOUS label=$LABEL the s562 state was not staged; the judge would measure nothing wall=$(el)s evidence=$OUT"
    exit 3
fi

# ---- 4. THE JUDGE: a fresh mount, knob at 0.  The v5 context, its node id
# and its dead set are per mount, so a remount on the loaded module is a fresh
# judge; the module is kept loaded because rmmod after an aborted mount is not
# the path under test.
JMARK=$(date +%s)
rsx $((JOIN_BOUND + 60)) "$B" "echo 0 > $DECLP; echo DECLINE=\$(cat $DECLP); T0=\$(date +%s%N); timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/B_judge.txt"
mountcap "$OUT/B_judge.txt" "the judge mount on $B"
echo "STAGE judge mount rc=$(field "$OUT/B_judge.txt" MOUNT_RC) wall=$(field "$OUT/B_judge.txt" WALL_MS)ms $(grep -ao '^MOUNTED\|^NOT_MOUNTED' "$OUT/B_judge.txt") at +$(el)s"
rsx 60 "$B" "journalctl -k --since @$JMARK --no-pager | cut -c1-600" > "$OUT/B_judge_journal.txt"
journalcap "$OUT/B_judge_journal.txt" "the kernel journal on $B across the judge mount"
dump "$OUT/hb_2_after_judge.txt" dump2
J=$OUT/B_judge_journal.txt
echo "--- judge: verdict=REVOKED=$(cnt "$J" 'verdict=REVOKED') verdict=UNKNOWN=$(cnt "$J" 'verdict=UNKNOWN') TAKEOVER=$(cnt "$J" 'P238-FENCE-TAKEOVER ') NOKEY=$(cnt "$J" 'P238-FENCE-TAKEOVER-NOKEY') REFUSED=$(cnt "$J" 'P238-FENCE-TAKEOVER-REFUSED') DECLINED=$(cnt "$J" 'P238-FENCE-TAKEOVER-DECLINED') CERTIFIED=$(cnt "$J" 'P236-FENCE-CERTIFIED') COMPLETE=$(cnt "$J" 'P163-RECOVERY-COMPLETE') P-DEAD-INC=$(cnt "$J" 'P-DEAD-INC')"
grep -ah 'verdict=REVOKED\|P238-FENCE-TAKEOVER\|P236-FENCE-CERTIFIED\|P163-RECOVERY-COMPLETE\|P-DEAD-INC\|P238-FENCE-HOLDER-STATE' "$J" | sed 's/.*mxfs: /    /' | cut -c1-230 | sort -u | head -10
# THE LINE THIS RECORD HAS BEEN OPEN FOR: the platter judged A1's tuple revoked.
ckge "JUDGE: v5_holder_slot_state answered REVOKED for A1's tuple from the platter" "$(grep -a 'verdict=REVOKED' "$J" | grep -ac "holder=$PNODE/")" 1
ckge "JUDGE: the verdict rested on the published slot (all-zero, or no record carries the tuple)" "$(grep -a 'verdict=REVOKED' "$J" | grep -a "holder=$PNODE/" | grep -ac 'all-zero\|no heartbeat record carries')" 1
ck   "JUDGE: the membership view had no answer of its own (no P-DEAD-INC for A1 before the verdict)" "$(grep -a 'P-DEAD-INC' "$J" | grep -ac "node=$PNODE ")" 0
ckge "JUDGE: the standing attempt was TAKEN OVER (only reachable once the holder is proved REVOKED)" "$(cnt "$J" 'P238-FENCE-TAKEOVER ')" 1
ck   "JUDGE: no takeover refused for want of a victim key (P238-FENCE-TAKEOVER-NOKEY)" "$(cnt "$J" 'P238-FENCE-TAKEOVER-NOKEY')" 0
ck   "JUDGE: no takeover refused as not abandoned (P238-FENCE-TAKEOVER-REFUSED)" "$(cnt "$J" 'P238-FENCE-TAKEOVER-REFUSED')" 0
ck   "JUDGE: the knob was off (no P238-FENCE-TAKEOVER-DECLINED)" "$(cnt "$J" 'P238-FENCE-TAKEOVER-DECLINED')" 0
ckge "JUDGE: a NEW fence of B1 was proved and certified under the taken-over attempt" "$(grep -a 'P236-FENCE-CERTIFIED' "$J" | grep -ac "victim=$VNODE ")" 1
ckge "JUDGE: B1's recovery completed (P163-RECOVERY-COMPLETE for B1)" "$(grep -a 'P163-RECOVERY-COMPLETE' "$J" | grep -ac "node=$VNODE ")" 1
ck   "JUDGE: the mount completed" "$(grep -ac '^MOUNTED' "$OUT/B_judge.txt")" 1
ck   "JUDGE: zero 'lock request failed after'" "$(cnt "$J" 'lock request failed after')" 0
ck   "JUDGE: zero shutdown / BUG / Oops on $B" "$(( $(cnt "$J" 'hutting down filesystem') + $(cnt "$J" 'BUG:\|Oops') ))" 0
echo "STAGE hb after judge: $(cnt "$OUT/hb_2_after_judge.txt" '^slot') record(s), $(cnt "$OUT/hb_2_after_judge.txt" 'RECOVERY_GUARD') guarded"
grep -a "^slot\|desc v" "$OUT/hb_2_after_judge.txt" | sed 's/^/    /' | cut -c1-200
ck   "after the judge: no recovery descriptor stands on the platter" "$(cnt "$OUT/hb_2_after_judge.txt" 'RECOVERY_GUARD')" 0

# ---- 5. A's host returns and joins the judge.
$VIRSH start "$A" > /dev/null 2>&1
waitboot "$A"
deploy_ko "$A"
RMARK=$(date +%s)
rsx $((JOIN_BOUND + 60)) "$A" "lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/A_join.txt"
mountcap "$OUT/A_join.txt" "the rejoin of $A"
echo "STAGE A join rc=$(field "$OUT/A_join.txt" MOUNT_RC) wall=$(field "$OUT/A_join.txt" WALL_MS)ms $(grep -ao '^MOUNTED\|^NOT_MOUNTED' "$OUT/A_join.txt") at +$(el)s"
rsx 60 "$A" "journalctl -k --since @$RMARK --no-pager | cut -c1-600" > "$OUT/A_join_journal.txt"
journalcap "$OUT/A_join_journal.txt" "the kernel journal on $A across its rejoin"
rsx 60 "$B" "journalctl -k --since @$RMARK --no-pager | cut -c1-600" > "$OUT/B_after_join_journal.txt"
journalcap "$OUT/B_after_join_journal.txt" "the kernel journal on $B across $A's rejoin"
ck "A rejoined the cluster (mounted)" "$(grep -ac '^MOUNTED' "$OUT/A_join.txt")" 1
ck "A: zero shutdown / BUG / Oops" "$(( $(cnt "$OUT/A_join_journal.txt" 'hutting down filesystem') + $(cnt "$OUT/A_join_journal.txt" 'BUG:\|Oops') ))" 0
ck "B: zero shutdown / BUG / Oops across A's join" "$(( $(cnt "$OUT/B_after_join_journal.txt" 'hutting down filesystem') + $(cnt "$OUT/B_after_join_journal.txt" 'BUG:\|Oops') ))" 0
# -A, not -a: '..' is each node's LOCAL parent directory and its mtime differs
# per node (s608b scored 'differ' on exactly that); the entries of the shared
# root are what must agree.
rsx 30 "$A" "ls -A -l --time-style=+%s $MNT | md5sum | cut -c1-32" > "$OUT/A_rootls.txt"
capture_require "$OUT/A_rootls.txt" '^[0-9a-f]{32}$' "the root listing digest on $A"
rsx 30 "$B" "ls -A -l --time-style=+%s $MNT | md5sum | cut -c1-32" > "$OUT/B_rootls.txt"
capture_require "$OUT/B_rootls.txt" '^[0-9a-f]{32}$' "the root listing digest on $B"
lsA=$(head -1 "$OUT/A_rootls.txt"); lsB=$(head -1 "$OUT/B_rootls.txt")
ck "both nodes see the same root listing (A=$lsA B=$lsB)" "$([ "$lsA" = "$lsB" ] && echo same || echo differ)" same

echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
