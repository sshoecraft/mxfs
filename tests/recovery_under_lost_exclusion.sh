#!/bin/bash
# recovery_under_lost_exclusion.sh — does a recovery in flight fail CLOSED when
# every persistent reservation on the LUN vanishes, or does its durable FENCED
# descriptor carry it on to write images with no exclusion in force?
#
# THE REQUIREMENT (docs/rulings/fence-crash-matrix-cuts.md, Target restart,
# D-FENCE-CRASH-MATRIX-UNTESTED): "without APTPL the loss of exclusion fails
# closed for ordinary clustered writes as well as recovery writes — a durable
# FENCED descriptor does not authorise continued I/O because its sector
# survived."  The ordinary-writes half is measured (tests/resv_selfgone_withdraw.sh,
# tests/resv_health_detect.sh).  This is the recovery-writes half.
#
# THE SHAPE.  A target that restarts without APTPL comes back with no
# registrations and no reservation while every initiator's session is re-
# established.  A PERSISTENT RESERVE OUT with the CLEAR service action from the
# one registered initiator produces the same PR state on a live target with no
# restart at all: every registration and the reservation are gone, the
# sessions stay up.  This rig's appliance cannot be restarted from here, so the
# CLEAR is how the PR-state loss is produced; what it cannot measure is
# persistence across a real restart, which stays owed to the appliance.
#
# THE WINDOW.  dbg_replay_hold_ms parks the survivor's foreign replay AFTER the
# recovery execution lease is claimed and the certificate sealed, BEFORE any
# image is applied (P-FREPLAY-HOLD; tests/fence_rejoin_barrier.sh uses the same
# window).  The hold loop re-reads xfs_is_shutdown every second.  The CLEAR is
# issued inside that window, so the only thing standing between the recovery
# and its image writes is what the module does about the lost exclusion.
#
# PREDICTION (the design): the survivor is the elected reservation maintainer
# (lowest live slot), its health tick runs every V5_RESV_HEALTH_LEAD_MS (5 s),
# its own key is gone so it reads SELF_GONE, launches the fenced-self
# inspection (P305-RESV-SELF-GONE-INSPECT), which re-asks the target and
# withdraws the mount (P277-FENCED-SELF-WITHDRAW); the hold then ends with
# shutdown=1 (P-FREPLAY-HOLD-END) and NO image is applied: no
# P163-RECOVERY-COMPLETE after the CLEAR, the victim's descriptor still below
# IMAGES_REPLAYED on the platter.  FAIL: the hold ends with shutdown=0 and the
# recovery completes after the CLEAR (images written with no reservation on
# the LUN), or no withdrawal within the bound (a FENCED descriptor and a
# mounted node with no exclusion).
#
# BUDGET (derived): prep <=240 (57-225 measured) + B's files 30 + arm 10 + the
# dead window 62 + fence to seal ~90 (FENCE_BOUND 200 covers both) + the CLEAR
# and the PR reads 20 + the withdrawal (5 s tick + <=5 re-asks) bound 40 + the
# hold's own end <= HOLD_MS/1000 (60) + captures 40 = ~560 s.  Caller bound 700.
#
# Cleanup: B (destroyed) is started; A is left withdrawn with no PR state on
# the LUN; the next lap's prep re-formats and re-registers.
#
# Usage: tests/recovery_under_lost_exclusion.sh <label> [hold_ms]
# Env:   MXFS_NODE_LIST (test1,test2), NFILES (32), FENCE_BOUND (200)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
HOLD_MS=${2:-60000}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the survivor / prover; holds the replay, loses its exclusion
B=${MXFS_NODE_LIST##*,}          # the victim; power-cut
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
NFILES=${NFILES:-32}
FENCE_BOUND=${FENCE_BOUND:-200}
PARM=/sys/module/mxfs/parameters
DUMP=/src/mxfs/tools/disklock_hb_dump.py
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_rule_${LABEL}
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="RULE-MARK-$LABEL"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
waitboot() {
    local n w=0 st
    for n in "$@"; do
        st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
        [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
    done
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 48 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
CLEANED=0
cleanup() {
    [ "$CLEANED" = 1 ] && return 0
    CLEANED=1
    $VIRSH start "$B" >/dev/null 2>&1
    echo "STAGE cleanup: $B started; $A is left as the lap left it (withdrawn, the LUN with no PR state); the caller must prep_cluster before the next lap at +$(el)s"
}
trap cleanup EXIT

echo "=== recovery_under_lost_exclusion label=$LABEL A(survivor)=$A B(victim)=$B hold_ms=$HOLD_MS $(date -u +%FT%TZ) ==="

# ---- 1. the fleet on the tree build, and that build must carry the hold
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
if [ "$(strings -a mxfs.ko | grep -c 'P-FREPLAY-HOLD')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no P-FREPLAY-HOLD replay hold (build the tree first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
waitboot "$A" "$B"
MXFS_FORCE_PREP=1 timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV
for n in "$A" "$B"; do
    value_now_into cl "$n" 30 "$OUT/${n}_claim.txt" '^claimed heartbeat slot [0-9]+' "the slot claim line on $n" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1"
    printf -v "slot_$n" '%s' "${cl##* }"
done
eval "ASLOT=\$slot_$A; BSLOT=\$slot_$B"
echo "STAGE identities: $A slot $ASLOT (survivor), $B slot $BSLOT (victim) at +$(el)s"

# ---- 2. the victim's dirty slice: fsynced files the replay would bring back
measure "$B" 90 "$OUT/B_files.txt" '^FILES_END$' "B's fsynced files" \
    "d=$MNT/rule_$LABEL; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'rule %s file %s\n' $LABEL \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"
ck "B fsynced $NFILES files before the cut" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/B_files.txt")" "$NFILES"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=files evidence=$OUT"; exit 2; }

# ---- 3. arm the hold on the survivor, read it back
measure "$A" 30 "$OUT/A_arm.txt" '^ARMED hold_ms=[0-9]+$' "the replay hold on $A" \
    "echo $MARK > /dev/kmsg; echo $HOLD_MS > $PARM/dbg_replay_hold_ms; echo ARMED hold_ms=\$(cat $PARM/dbg_replay_hold_ms)"
ck "A armed the replay hold for this lap" "$(grep -a '^ARMED' "$OUT/A_arm.txt")" "ARMED hold_ms=$HOLD_MS"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }

# ---- 4. the power cut, the fence, the seal, the claim — and the hold
$VIRSH destroy "$B" > "$OUT/destroy.txt" 2>&1
echo "STAGE $B destroyed at +$(el)s — the survivor must fence it, seal, claim, and then hold"
wait_for_into held "$A" "$FENCE_BOUND" "$MARK" "P-FREPLAY-HOLD slot"
window_into "$OUT/A_fence.txt" "$A" 60 "$MARK"
SEALED=$(cnt "$OUT/A_fence.txt" 'P236-FENCE-SEALED')
HELD=$(cnt "$OUT/A_fence.txt" 'P-FREPLAY-HOLD slot')
CLAIMED=$(cnt "$OUT/A_fence.txt" 'P236-RECOV-CLAIMED')
echo "STAGE the survivor reached the hold at +$(el)s: waited=${held}s sealed=$SEALED claimed=$CLAIMED held=$HELD"
if [ "$HELD" = 0 ]; then
    echo "  VACUOUS the replay hold never fired: there is no sealed-but-unreplayed window to lose the exclusion in"
    echo "RESULT: VACUOUS label=$LABEL reason=nohold wall=$(el)s evidence=$OUT"; exit 3
fi
ck "the certificate was sealed before the hold" "$([ "$SEALED" -ge 1 ] && echo yes || echo no)" yes
ck "the survivor holds the recovery execution lease" "$([ "$CLAIMED" -ge 1 ] && echo yes || echo no)" yes
ck "the slice is NOT replayed while the hold is in force" "$(cnt "$OUT/A_fence.txt" 'P163-RECOVERY-COMPLETE')" 0

# ---- 5. THE SUBJECT: every reservation on the LUN vanishes while the recovery
#         stands claimed and sealed.  The survivor's key is the only one left
#         after the fence (the victim's was preempted); the CLEAR is issued
#         with it and the PR state is read back empty.
measure "$A" 40 "$OUT/A_pr_before.txt" '^PR_END$' "the PR state on $A before the CLEAR" \
    "sg_persist --in --read-keys \$(readlink -f $MXFS_DEV) 2>&1; sg_persist --in --read-reservation \$(readlink -f $MXFS_DEV) 2>&1; echo PR_END"
mapfile -t KEYS < <(grep -aoE '^ +0x[0-9a-f]+$' "$OUT/A_pr_before.txt" | tr -d ' ')
# A reservation line reads "scope: LU_SCOPE,  type: Write Exclusive, ...";
# 'type:' alone also matches sg_persist's "Peripheral device type: disk"
# banner, which s154a counted as two reservations after a CLEAR the target
# had accepted.
echo "STAGE PR state before the CLEAR: keys=${#KEYS[@]} [${KEYS[*]:-none}] reservation: $(grep -a 'scope:' "$OUT/A_pr_before.txt" | head -1 | tr -s ' ' | cut -c1-80)"
if [ "${#KEYS[@]}" -ne 1 ]; then
    echo "  VACUOUS the LUN carries ${#KEYS[@]} registered key(s) at the hold, not the survivor's one: the CLEAR could not be attributed to the survivor's own nexus"
    echo "RESULT: VACUOUS label=$LABEL reason=keys-${#KEYS[@]} wall=$(el)s evidence=$OUT"; exit 3
fi
AKEY=${KEYS[0]}
measure "$A" 40 "$OUT/A_clear.txt" '^CLEAR_RC=' "the CLEAR from $A" \
    "echo $MARK-CLEAR > /dev/kmsg; sg_persist --out --clear --param-rk=$AKEY \$(readlink -f $MXFS_DEV) 2>&1; echo CLEAR_RC=\$?"
CRC=$(field "$OUT/A_clear.txt" CLEAR_RC)
measure "$A" 40 "$OUT/A_pr_after.txt" '^PR_END$' "the PR state on $A after the CLEAR" \
    "sg_persist --in --read-keys \$(readlink -f $MXFS_DEV) 2>&1; sg_persist --in --read-reservation \$(readlink -f $MXFS_DEV) 2>&1; echo PR_END"
KEYS_AFTER=$(grep -acE '^ +0x[0-9a-f]+$' "$OUT/A_pr_after.txt")
RESV_AFTER=$(grep -ac 'scope:' "$OUT/A_pr_after.txt")
echo "STAGE CLEAR rc=$CRC at +$(el)s; PR state after: keys=$KEYS_AFTER reservations=$RESV_AFTER [$(grep -a 'reservation\|keys follow\|no registered' "$OUT/A_pr_after.txt" | tr -s ' ' | tr '\n' '|' | cut -c1-160)]"
ck "the CLEAR was accepted by the target" "$CRC" 0
ck "no registration is left on the LUN" "$KEYS_AFTER" 0
ck "no reservation is left on the LUN" "$RESV_AFTER" 0
if [ "$KEYS_AFTER" != 0 ] || [ "$RESV_AFTER" != 0 ]; then
    echo "  VACUOUS the exclusion was not lost, so nothing below measures the recovery under its loss"
    echo "RESULT: VACUOUS label=$LABEL reason=exclusion-kept wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- 6. what the survivor does about it, and what its recovery does
wait_for_into gone "$A" 40 "$MARK-CLEAR" "P305-RESV-SELF-GONE-INSPECT"
wait_for_into wd   "$A" 40 "$MARK-CLEAR" "P277-FENCED-SELF-WITHDRAW"
wait_for_into hend "$A" $(( HOLD_MS / 1000 + 20 )) "$MARK-CLEAR" "P-FREPLAY-HOLD-END"
echo "STAGE after the CLEAR: self-gone inspection after ${gone}s, withdrawal after ${wd}s, hold end after ${hend}s at +$(el)s"
sleep 5
window_into "$OUT/A_window.txt" "$A" 60 "$MARK-CLEAR"
count_file_into inspect  "$OUT/A_window.txt" 'P305-RESV-SELF-GONE-INSPECT'
count_file_into withdrew "$OUT/A_window.txt" 'P277-FENCED-SELF-WITHDRAW'
count_file_into hends    "$OUT/A_window.txt" 'P-FREPLAY-HOLD-END'
count_file_into complete "$OUT/A_window.txt" 'P163-RECOVERY-COMPLETE'
count_file_into replayed "$OUT/A_window.txt" 'MXFS foreign replay slot=.*replayed\|IMAGES_REPLAYED'
count_file_into shut     "$OUT/A_window.txt" 'hutting down filesystem'
count_file_into oops     "$OUT/A_window.txt" 'BUG:\|Oops\|kernel NULL pointer'
HSHUT=$(grep -ao 'P-FREPLAY-HOLD-END slot=[0-9]* held_ms=[0-9]* shutdown=[01]' "$OUT/A_window.txt" | tail -1 | sed -n 's/.*shutdown=//p')
echo "STAGE window on $A from the CLEAR: self-gone-inspect=$inspect withdraw=$withdrew hold-end=$hends (shutdown='${HSHUT:-none}') recovery-complete=$complete replay-lines=$replayed shutdowns=$shut oops=$oops"
grep -a 'P305-RESV\|P277-\|P-FREPLAY-HOLD-END\|P163-RECOVERY-COMPLETE\|MXFS foreign replay\|hutting down' "$OUT/A_window.txt" | head -n 10 | cut -c1-230 | sed 's/^/    /'
measure "$A" 60 "$OUT/hb_after.txt" '^slot +[0-9]+ magic=' "the disklock table after the lap" "python3 $DUMP $MXFS_DEV"
echo "  platter slot $BSLOT: $(grep -aE "^slot +$BSLOT " "$OUT/hb_after.txt" | head -1 | cut -c1-140)"
echo "  platter desc     : $(awk -v s="$BSLOT" '$1=="slot" && $2==s {f=1; next} f && /^    desc/ {print; exit} /^slot/ {f=0}' "$OUT/hb_after.txt" | cut -c1-200)"

ck   "no BUG/Oops on the survivor" "$oops" 0
ckge "the survivor noticed its own registration was gone (P305-RESV-SELF-GONE-INSPECT)" "$inspect" 1
ckge "the survivor withdrew the mount rather than staying a registrant-less member (P277-FENCED-SELF-WITHDRAW)" "$withdrew" 1
ck   "the replay hold ended on the shutdown, not on its timer (P-FREPLAY-HOLD-END shutdown=1)" "${HSHUT:-none}" 1
ck   "the recovery did NOT complete after the exclusion was lost (P163-RECOVERY-COMPLETE after the CLEAR)" "$complete" 0
if [ "${HSHUT:-none}" = 0 ] && [ "$complete" -ge 1 ]; then
    echo "  FAIL the recovery wrote its images and completed with NO reservation on the LUN: a durable FENCED descriptor authorised continued I/O"
    fails=$((fails+1))
fi
echo "=== recovery_under_lost_exclusion $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
if [ $fails -eq 0 ]; then
    echo "RESULT: PASS label=$LABEL fails=0 inspect_s=$gone withdraw_s=$wd hold_end_s=$hend hold_shutdown=${HSHUT:-none} complete=$complete evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL fails=$fails inspect_s=$gone withdraw_s=$wd hold_end_s=$hend hold_shutdown=${HSHUT:-none} complete=$complete evidence=$OUT"; exit 1
