#!/bin/bash
# fence_kind_matrix.sh — make the consuming side MEET a durable fence
# certificate of every class, including the ones this build has revoked, and
# grade what it does about each.
#
# WHY THIS EXISTS.  0.89.16 made a fence KIND the durable identifier of a proof
# contract: one classifier answers "can this build classify this record into a
# contract it still supports", every reader that did not mint the certificate
# asks it, and refusal is the default.  Nothing in the tree can test that.  A
# build only ever MINTS the kinds it still supports, so the revoked classes —
# the retired code point 16, kind 19, the absent-registration kinds 20 and 21,
# and a kind from a build that does not exist yet — are branches no lap can
# reach by running the software.  They are exactly the records an OLDER build
# left on the platter, which is the whole subject of the defect.
#
# tools/recov_forge writes them.  It puts a complete recovery-guard record in
# an unused heartbeat slot, with the certificate fields filled in and the crc
# and identity binding recomputed, so the record is indistinguishable from one
# the kernel wrote except for the one field under test.  A node then mounts:
# its admission sweep picks the slot up as requires-recovery, tries to claim
# it, and has to classify the certificate to decide whether anything on that
# slice may be replayed.
#
# WHAT IS GRADED, per arm
#   1. the claim was REFUSED — P236-CLAIM-UNCERTIFIED — and the refusal names
#      the class in words, not just "no";
#   2. the refusal names the kind that is actually on the platter;
#   3. NOTHING was replayed: no recovery completed on the forged slice;
#   4. the refusing path did not REWRITE the record it refused — the sector is
#      byte-identical to what was forged.  A refusal that relabels the record
#      would launder the very ambiguity the class was retired for;
#   5. nothing crashed, hung or shut a filesystem down on either node, and the
#      survivor is still serving throughout.
#
# NON-VACUITY, and this is the part that makes the matrix worth running.  A
# refusal is easy to get for the wrong reason: a descriptor the gate rejects
# for a missing field refuses just as loudly as one it rejects for its class,
# and a matrix that only counts refusals cannot tell them apart.  So an arm
# carries a kind this build still SUPPORTS — 23 — with one supporting field
# left empty.  It must refuse with a DIFFERENT reason, naming the missing
# field, and must NOT name any revoked class.  That is a positive
# measurement of the classifier: it passed the kind through and something later
# stopped the record.  Until 0.89.18 kind 17 was the second such arm; it is
# revoked now, and the four binding arms below carry the supported kind 23,
# so the discriminator is not weakened by losing it.
# It is also why no arm here presents a fully valid
# certificate: an accepted one would authorise replaying a journal slice that
# belongs to a live filesystem, and the arm that proves acceptance works is a
# real fence on a real victim (tests/fence_strong_basis.sh), not a forgery.
#
# THE ARMS
#   retired16   kind 16, the retired code point: two producers, one of which
#               ran no operation.  Must refuse naming the retirement.
#   revoked19   kind 19, self-succession.  Must refuse naming the revocation.
#   gate20      kind 20, the sole-survivor exclusive-write gate, under the
#               single-holder reservation type it rests on.
#   boot21      kind 21, boot succession with the victim's key already absent.
#   unknown99   a kind this build has never heard of.  Refusal is the DEFAULT,
#               not a case someone remembered to write.
#   oldversion  a descriptor whose VERSION is not this build's.  It is refused
#               earlier, at the shape gate, before any certificate is read —
#               so this arm asserts the refusal happened and that no class was
#               ever named, which is a different fact from the others.
#   single17    kind 17, the operator's single-node topology assertion,
#               REVOKED in 0.89.18 because an operator parameter may select an
#               operating mode and may not create a retirement witness.  Must
#               refuse naming the revocation.
#   proven23    kind 23 with no prover incarnation — the current profile, with
#               one supporting field missing.  This is the discriminator: it
#               must refuse NAMING THAT FIELD and name no revoked class, which
#               is what says the classifier passed a supported kind through.
#
# AND THE BINDING ARMS, which ask the other half of the question.  A kind that
# classifies says the certificate was CONSTRUCTED under a contract this build
# supports.  It says nothing about whether it authorises THIS recovery.  So
# four arms forge a supported class with a correct CRC and one binding wrong —
#   bind_slot   the descriptor names a heartbeat slot other than its own
#   bind_fsgen  it claims a recovery from a different mkfs generation, while
#               the heartbeat stays on the live one so no sweep skips it
#   bind_key    it names no victim key
#   bind_term   it carries no fencing-attempt term
# — and each must refuse NAMING THAT FIELD.  A recomputed CRC is not a licence:
# the forge seals every one of these correctly, so nothing here is caught by
# the checksum.
#
# Budget, and it is DERIVED FROM THE BARRIER'S OWN CONSTANTS rather than from
# an estimate — a first pass guessed 90 s from the observation windows and
# failed all seven classifying arms at 96 s on a mount that was still inside
# its documented bound.  The number that governs is the mount barrier's
# admission wait in xfs/xfs_mxfs_dlm.c: MXFS_BARRIER_ADMISSION_WAIT_MS is
# 30 s, and a barrier that sees a frozen record not yet declared dead — which
# a forged guard slot is — extends ONCE to
# MXFS_BARRIER_ADMISSION_WAIT_MS + dead window + MXFS_BARRIER_ADMISSION_WAIT_MS.
# The dead window is MXFS_DISKLOCK_DEAD_THRESHOLD (31) heartbeats at 2 s = 62 s,
# so the barrier's maximum is 30 + 62 + 30 = 122 s.  Add a clean mount's
# measured 8-15 s of infrastructure either side: 137 s, so the mount budget is
# 140 s.  A mount still running at 140 s is past the bound the code sets for
# itself and IS a failure — a refusal that never returns is a hang.  Per arm:
# umount 5 + build and forge 15 + mount 140 + two kernel-log windows 20 +
# restore 5 + remount 25 = 210 s; caller bound 240 s.
#
# Usage: tests/fence_kind_matrix.sh <arm> [label] [slot]
# Env:   MXFS_NODE_LIST (test1,test2), MOUNT_BUDGET (140), SLOT (40)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
ARM=${1:?usage: fence_kind_matrix.sh <arm> [label] [slot]}
LABEL=${2:-$ARM}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the survivor; stays mounted throughout
B=${MXFS_NODE_LIST##*,}          # the reader; unmounts, meets the record, mounts
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
SLOT=${3:-${SLOT:-40}}
MOUNT_BUDGET=${MOUNT_BUDGET:-140}
FORGE=$PWD/tools/recov_forge
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_fkm_${LABEL}_$ARM
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
MARK="FKM-MARK-$LABEL-$ARM"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

# arm -> the forged record, and what the reader must say about it.
#   KIND      desc.fence_kind
#   RESV      desc.fence_resv_type (the type that kind's exclusion rests on)
#   PROVER    desc.fence_prover_node; 0 leaves the certificate one field short
#   DESCVER   desc.version
#   GATE      class  = refused AT the classifier, naming the class
#             shape  = refused BEFORE it, at the descriptor shape gate
#   CLASS     the words the refusal must carry
DESCVER=3
PROVER=1
EXTRA=
case "$ARM" in
  retired16)  KIND=16; RESV=0x07; GATE=class; CLASS='RETIRED code point 16' ;;
  revoked19)  KIND=19; RESV=0x07; GATE=class; CLASS='REVOKED kind 19' ;;
  gate20)     KIND=20; RESV=0x01; GATE=class; CLASS='REVOKED absent-registration kind' ;;
  boot21)     KIND=21; RESV=0x07; GATE=class; CLASS='REVOKED absent-registration kind' ;;
  unknown99)  KIND=99; RESV=0x07; GATE=class; CLASS='no fence kind this build can classify' ;;
  oldversion) KIND=23; RESV=0x07; GATE=shape; CLASS=''; DESCVER=4 ;;
  # 0.89.18 moved this arm from the supported side to the revoked side, and the
  # move IS the measurement.  Kind 17 was the operator's single-node topology
  # assertion; that assertion bounds which INITIATORS may write and says nothing
  # about the writes the target had already accepted from the incarnation being
  # recovered, so it never carried a retirement proof.  It is revoked, nothing
  # mints one, and every reader must now refuse it by class — including the
  # untagged-replay authority in dlm/v5_mount.c, which read the kind directly
  # and was the last reader that would still have honoured an older build's
  # record.  The arm keeps PROVER=0 so that a build which somehow passed the
  # class would still be stopped at the missing field: the assertion below
  # requires the REVOCATION to be named, so a refusal for the missing prover
  # incarnation is a FAIL here, not a pass.
  single17)   KIND=17; RESV=0x07; GATE=class; CLASS='REVOKED kind 17'; PROVER=0 ;;
  proven23)   KIND=23; RESV=0x07; GATE=class; CLASS='certificate names no prover incarnation'; PROVER=0 ;;
  # THE BINDING ARMS.  A certificate whose CLASS this build supports and whose
  # CRC recomputes correctly, pointed at the wrong recovery.  Each must refuse
  # NAMING THE FIELD, which is what says the binding is checked rather than
  # merely present.  Two of them (slot, mkfs generation) are refused BEFORE the
  # class is ever looked at, and that ordering is itself the finding: a record
  # that does not belong to this recovery never reaches the classifier.
  # The slot binding is NOT enforced at the claim gate, and asserting it there
  # failed a refusal that was working.  Read from the code rather than fitted to
  # the output: recov_outcome_structural() in dlm/disklock.c takes the heartbeat
  # slot the sector was READ FROM and compares it with the descriptor's own
  # victim_slot, returning -EPROTO — "misplaced/copied record: names another
  # slot" — before the certificate is looked at at all.  Its comment states why
  # that comparison has to exist: the descriptor crc binds the SECTOR's
  # {fs_gen, node_id, epoch}, and those bytes travel with a byte-copied record,
  # so victim_slot is the ONLY binding to the slot it was found in.
  #
  # The consuming side turns that -EPROTO into a fail-closed FSWIDE quarantine
  # and refuses admission, so this arm's refusal is terminal and earlier than
  # every other arm's.  Its discriminator is proven23, which forges the same
  # kind, the same reservation type and the same correct crc with victim_slot
  # equal to the slot it is written in: that record passes this gate and is
  # stopped later, at the claim, for its missing prover incarnation.  The pair
  # isolates victim_slot as the field doing the work — one gate, one field.
  bind_slot)  KIND=23; RESV=0x07; GATE=structural
              CLASS='verdict state UNREADABLE'
              EXTRA="--victim-slot $(( (SLOT + 1) % 64 ))" ;;
  # Moving the descriptor's victim mkfs generation cannot produce a record
  # that validates under ANY crc, and that is the finding rather than a
  # limitation of the forge.  recov_desc_of() verifies the checksum against the
  # identity in the record HEADER (dlm/disklock.c:1631); the claim gate
  # recomputes the same checksum from the descriptor's OWN victim_fs_gen /
  # victim_node / victim_epoch (:8164).  One seal cannot satisfy both unless
  # they agree, so the victim identity triple is unforgeable, not merely
  # compared.  The later 'different mkfs generation' field test is second line
  # of defence and is unreachable from a forgery.
  bind_fsgen) KIND=23; RESV=0x07; GATE=class; CLASS='crc / descriptor-vs-header identity mismatch'
              EXTRA="--victim-fsgen 0xdeadbeef" ;;
  bind_key)   KIND=23; RESV=0x07; GATE=class; CLASS='certificate names no victim key'
              EXTRA="--fence-key 0" ;;
  bind_term)  KIND=23; RESV=0x07; GATE=class; CLASS='certificate carries no fencing-attempt term'
              EXTRA="--fence-term 0" ;;
  *) echo "ABORT: unknown arm '$ARM'"; exit 2 ;;
esac
# The revoked classes, as one pattern.  A supported-kind arm must show NONE of
# them: that is what says the classifier passed the kind through.
REVOKED='RETIRED code point 16\|REVOKED kind 17\|REVOKED kind 19\|REVOKED absent-registration kind\|no fence kind this build can classify'
case "$ARM" in
  proven23|bind_*) EXPECT_REVOKED_TEXT=0 ;;
  *)               EXPECT_REVOKED_TEXT=1 ;;
esac

echo "=== fence_kind_matrix label=$LABEL arm=$ARM kind=$KIND resv=$RESV prover=$PROVER desc_ver=$DESCVER slot=$SLOT A(survivor)=$A B(reader)=$B $(date -u +%FT%TZ) ==="

# ---- 1. the forge must be THIS source, and its descriptor version must be the
# kernel's or every arm measures the shape gate under a fence-kind name.  The
# checked-in binary is not built by any Makefile, so build it here rather than
# trusting a file whose age nobody tracks.
cc -O2 -Wall -Wextra -I include -o "$FORGE" tools/recov_forge.c 2> "$OUT/forge_build.txt"
crc=$?
echo "STAGE built recov_forge rc=$crc $(head -2 "$OUT/forge_build.txt" | tr '\n' ' ' | cut -c1-160)"
[ $crc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=forgebuild evidence=$OUT"; exit 2; }
KVER=$(sed -n 's/^#define MXFS_RECOV_DESC_VERSION[[:space:]]*\([0-9]*\).*/\1/p' dlm/disklock.h | head -1)
FVER=$(sed -n 's/^#define RECOV_DESC_VERSION[[:space:]]*\([0-9]*\).*/\1/p' tools/recov_forge.c | head -1)
ck "the forge mirrors the kernel's descriptor version" "${FVER:-?}" "${KVER:-?}"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=descver evidence=$OUT"; exit 2; }

# ---- 2. both nodes mounted on the tree build, or this arm grades wreckage
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' \
        "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "the tree build is loaded on $n" "$sv" "$SV"
    value_now_into mnt "$n" 30 "$OUT/${n}_mounted_before.txt" '^MOUNTED=[0-9]+$' \
        "$n's mount before the arm" "echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts)"
    ck "$n is mounted before the arm" "${mnt#MOUNTED=}" 1
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=fleet evidence=$OUT"; exit 2; }
# The device is an IDENTITY, not a path, and the path for the same LUN can
# differ per node — the forge runs on the survivor and the mount happens on the
# reader, so each gets its own resolution rather than one node's path used on
# the other.
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV
mxfs_dev_resolve "$B"; DEV_B=$MXFS_DEV_RESOLVED
echo "STAGE the LUN resolves to $MXFS_DEV on $A and $DEV_B on $B"

# ---- 3. the slot must be unused.  Forging over a live node's heartbeat is a
# different and destructive experiment.
measure "$A" 40 "$OUT/slot_before.txt" 'slot=' "the target slot's contents before the forge" \
    "$FORGE $MXFS_DEV dump $SLOT"
if grep -qa 'flags=ACTIVE' "$OUT/slot_before.txt"; then
    echo "  FAIL <slot $SLOT carries a LIVE heartbeat; pick an unused slot>"
    echo "RESULT: ABORT label=$LABEL stage=slotbusy evidence=$OUT"; exit 2
fi
SAVE=/tmp/fkm_slot${SLOT}_${LABEL}.bin
measure "$A" 40 "$OUT/slot_save.txt" '^saved slot=' "the saved baseline sector" \
    "$FORGE $MXFS_DEV save $SLOT $SAVE"
BASE_CRC=$(sed -n 's/.*sector_crc32c=\(0x[0-9a-f]*\).*/\1/p' "$OUT/slot_save.txt" | head -1)
echo "STAGE saved slot $SLOT at +$(el)s: baseline sector_crc32c=$BASE_CRC"

# The sector is restored on EVERY exit: a forged guard record left behind holds
# admission shut on every later mount of this filesystem.
#
# And the reader is put back on EVERY exit too.  A lap that ends early — VACUOUS
# or ABORT — used to return with the reader still unmounted, because the remount
# lived at the bottom of the happy path.  The next arm then failed its "the
# reader is mounted before the arm" precondition and ABORTed without measuring
# anything, so one early exit cost two laps (measured s85a: bind_fsgen exited
# VACUOUS on a busy mount, and the retry aborted on the fleet check).  Restoring
# the platter but not the fleet leaves the rig in a state no later arm can use.
RESTORE_NEEDED=0
restore_slot() {
    [ "$RESTORE_NEEDED" = 1 ] || return 0
    timeout 40 $SSH "$A" "$FORGE $MXFS_DEV restore $SLOT $SAVE" > "$OUT/slot_restore.txt" 2>&1
    echo "STAGE restored slot $SLOT at +$(el)s: $(grep -a 'restored slot' "$OUT/slot_restore.txt" | cut -c1-90)"
}
remount_reader() {
    grep -qa '^UMOUNT_RC=0$' "$OUT/B_umount.txt" 2>/dev/null || return 0
    timeout 200 $SSH "$B" \
        "grep -q ' $MNT ' /proc/mounts || mount -t mxfs $DEV_B $MNT; \
         echo BACK=\$(grep -c ' $MNT ' /proc/mounts)" \
        > "$OUT/B_remount_exit.txt" 2>&1
    echo "STAGE the reader is back at +$(el)s: $(grep -ao 'BACK=[0-9]*' "$OUT/B_remount_exit.txt" | tail -1)"
}
on_exit() { restore_slot; remount_reader; }
trap on_exit EXIT

# ---- 4. the reader leaves, the record lands, the reader comes back
measure "$B" 60 "$OUT/B_umount.txt" '^UMOUNT_RC=[0-9]+$' "the reader's unmount" \
    "echo $MARK > /dev/kmsg; umount $MNT; echo UMOUNT_RC=\$?"
ck "the reader unmounted cleanly" "$(field "$OUT/B_umount.txt" UMOUNT_RC)" 0
measure "$A" 30 "$OUT/A_mark.txt" '^MARKED$' "the survivor's lap mark" \
    "echo $MARK > /dev/kmsg; echo MARKED"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=umount evidence=$OUT"; exit 2; }

FA="--live --node 4242 --epoch 7 --stage 3 --desc-version $DESCVER"
FA="$FA --fence-kind $KIND --fence-resv $RESV --fence-prover $PROVER $EXTRA"
measure "$A" 40 "$OUT/forge.txt" '^forged slot=' "the forged certificate" \
    "$FORGE $MXFS_DEV mkguard $SLOT $FA"
RESTORE_NEEDED=1
FORGED_CRC=$(sed -n 's/.*sector_crc32c=\(0x[0-9a-f]*\).*/\1/p' "$OUT/forge.txt" | head -1)
grep -a 'forged slot=\|        cert:\|        desc: ver=' "$OUT/forge.txt" | sed 's/^/    /' | cut -c1-200
ck "the forge wrote a record that is not the baseline" \
   "$([ -n "$FORGED_CRC" ] && [ "$FORGED_CRC" != "$BASE_CRC" ] && echo yes || echo no)" yes
ck "the record on the platter carries the arm's kind" \
   "$(grep -ac "^        cert: kind=$KIND " "$OUT/forge.txt")" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=forge evidence=$OUT"; exit 2; }

# ---- 5. the reader mounts and meets the record
t0=$(date +%s)
timeout "$MOUNT_BUDGET" $SSH "$B" \
    "mount -t mxfs $DEV_B $MNT > /tmp/fkm_mount.log 2>&1; echo MOUNT_RC=\$?" \
    > "$OUT/B_mount.txt" 2>&1
trc=$?
MRC=$(field "$OUT/B_mount.txt" MOUNT_RC)
wall=$(( $(date +%s) - t0 ))
[ "$trc" = 124 ] && MRC=TIMEOUT
echo "STAGE the reader's mount answered at +$(el)s: rc=${MRC:-?} wall=${wall}s (budget ${MOUNT_BUDGET}s)"
if [ "$MRC" = TIMEOUT ]; then
    echo "  FAIL <the mount was still running at its ${MOUNT_BUDGET}s budget: a refusal that never returns is a hang, not a refusal>"
    fails=$((fails+1))
fi
# The mount's DISPOSITION is recorded, not graded.  What this matrix is about
# is classification: whether the reader can tell the certificate's class and
# refuses to act on a revoked one.  Whether an unreplayable foreign slice
# should also hold admission shut is a different question with its own record,
# and grading it here would make this harness fail for a reason it did not
# measure.  A mount still running at its budget IS graded, above: a refusal
# that never returns is a hang.
echo "FINDING the reader's mount disposition: rc=${MRC:-?} ($([ "$MRC" = 0 ] && echo "admitted beside the unreplayable slice" || echo "held shut"))"
# ---- 6. what the reader said about the certificate
#
# The kernel window is taken BEFORE the lap is classified, and that ordering is
# the whole point.  mount(8) prints "already mounted or mount point busy" for
# EVERY -EBUSY the syscall returns, and two entirely different things return it
# here:
#
#   a leftover holder of the mountpoint    the kernel never saw a mount, the
#   (measured s84i: ~15 s, rc=32 at 2 s)   forged record was never met, and
#                                          every assertion below is vacuous;
#
#   the admission barrier REFUSING         the kernel ran the whole mount, met
#   (measured s85a/bind_fsgen: rc=32        the record, spent its full bound and
#    after 123 s of a 140 s budget)        declined — which is the measurement.
#
# Keying vacuity on the message alone cannot tell them apart, and the earlier
# version of this gate exited on the message and threw the kernel window away,
# grading a 123 s refusal as a lap that did not happen.  So the discriminator is
# the kernel's own record of having started a mount at all in THIS lap's window.
window_into "$OUT/B_window.txt" "$B" 90 "$MARK"
rs 30 "$B" "tail -5 /tmp/fkm_mount.log 2>/dev/null" > "$OUT/B_mount_log.txt" 2>&1
KERNEL_SAW_MOUNT=$(cnt "$OUT/B_window.txt" \
    'P304-PREOBSERVE\|P-BARRIER-CLOCK\|P240-QUAR-IMPORT\|Mounting Filesystem')
if grep -qa 'already mounted or mount point busy\|is busy' "$OUT/B_mount_log.txt" &&
   [ "$KERNEL_SAW_MOUNT" = 0 ]; then
    echo "  FAIL <the mount was refused before the kernel began one — the device"
    echo "        or mount point was held by something else, so the reader never"
    echo "        met the forged record>"
    sed 's/^/    /' "$OUT/B_mount_log.txt" | cut -c1-160
    echo "RESULT: VACUOUS label=$LABEL arm=$ARM stage=busy wall=$(el)s evidence=$OUT"; exit 3
fi
echo "FINDING the kernel logged $KERNEL_SAW_MOUNT mount-path marker(s) in this lap's window, so the reader did meet the record"
UNCERT=$(cnt "$OUT/B_window.txt" 'P236-CLAIM-UNCERTIFIED')
REPLAYED=$(cnt "$OUT/B_window.txt" 'P163-RECOVERY-COMPLETE')
grep -a 'P236-CLAIM-UNCERTIFIED' "$OUT/B_window.txt" | sed 's/.*mxfs: /    /' | cut -c1-260 | tail -2
echo "STAGE the reader logged $UNCERT claim refusal(s) and $REPLAYED recovery completion(s)"

case "$GATE" in
class)
    ck "the reader REFUSED the claim" \
       "$([ "$UNCERT" -ge 1 ] && echo yes || echo no)" yes
    ck "the refusal names the kind that is on the platter" \
       "$([ "$(grep -ac "P236-CLAIM-UNCERTIFIED.*kind=$KIND " "$OUT/B_window.txt")" -ge 1 ] && echo yes || echo no)" yes
    ck "the refusal says WHY in words: $CLASS" \
       "$([ "$(grep -ac "$CLASS" "$OUT/B_window.txt")" -ge 1 ] && echo yes || echo no)" yes
    if [ "$EXPECT_REVOKED_TEXT" = 0 ]; then
        ck "no revoked class was named, so the classifier passed kind $KIND through" \
           "$(cnt "$OUT/B_window.txt" "$REVOKED")" 0
    fi
    ;;
shape)
    ck "no class was named: the record was refused before its certificate was read" \
       "$(cnt "$OUT/B_window.txt" "$REVOKED")" 0
    ;;
structural)
    # The record never reaches the certificate: the slot binding is checked
    # while the verdict state is read, so the refusal names the SLOT and the
    # errno, not a fence class.  -71 is -EPROTO, and asserting the number as
    # well as the words is what keeps this arm from passing on an unrelated
    # unreadable-verdict failure that happens to print the same sentence.
    ck "the reader refused the record structurally, naming this slot" \
       "$([ "$(cnt "$OUT/B_window.txt" "foreign replay slot=$SLOT: verdict state UNREADABLE")" -ge 1 ] && echo yes || echo no)" yes
    ck "the refusal carries -EPROTO, the misplaced-record errno" \
       "$([ "$(cnt "$OUT/B_window.txt" 'verdict state UNREADABLE (-71)')" -ge 1 ] && echo yes || echo no)" yes
    ck "the slice was quarantined fail-closed rather than interpreted" \
       "$([ "$(cnt "$OUT/B_window.txt" "P240-QUAR-IMPORT victim_slot=$SLOT fswide=1")" -ge 1 ] && echo yes || echo no)" yes
    ck "admission was DENIED rather than granted beside a record nobody could read" \
       "$([ "$(cnt "$OUT/B_window.txt" "P240-QUAR-ADMIT-DENY victim_slot=$SLOT")" -ge 1 ] && echo yes || echo no)" yes
    ck "the mount was held shut" \
       "$([ "$MRC" != 0 ] && echo yes || echo no)" yes
    ck "no fence class was named: the certificate was never reached" \
       "$(cnt "$OUT/B_window.txt" "$REVOKED")" 0
    ck "the claim gate was never consulted, so this refusal is the earlier one" \
       "$UNCERT" 0
    ;;
esac
ck "nothing on the forged slice was replayed" "$REPLAYED" 0

# ---- 7. the refusing path must not have RELABELLED what it refused.
# The grade is on the CERTIFICATE, not on the whole sector: a node that marks a
# slot recovery-pending legitimately stamps bytes outside the certificate, and
# grading the sector crc would turn that into a failure about relabelling.
# What must never change is the proof contract on the platter — if a refused
# class could acquire a supported one by being read, the retirement would be
# undone by the very readers enforcing it.
measure "$A" 40 "$OUT/slot_after.txt" 'slot=' "the sector after the refusal" \
    "$FORGE $MXFS_DEV dump $SLOT"
AFTER_CRC=$(sed -n 's/.*sector_crc32c=\(0x[0-9a-f]*\).*/\1/p' "$OUT/slot_after.txt" | head -1)
grep -a '^        cert:' "$OUT/forge.txt"      | head -1 > "$OUT/cert_before.txt"
grep -a '^        cert:' "$OUT/slot_after.txt" | head -1 > "$OUT/cert_after.txt"
ck "the certificate on the platter was not relabelled" \
   "$(diff -q "$OUT/cert_before.txt" "$OUT/cert_after.txt" > /dev/null && echo same || echo changed)" same
echo "FINDING the sector as a whole: forged=$FORGED_CRC after=$AFTER_CRC ($([ "$AFTER_CRC" = "$FORGED_CRC" ] && echo "untouched" || echo "bytes outside the certificate moved"))"

# ---- 8. and nothing crashed, hung or shut a filesystem down
window_into "$OUT/A_window.txt" "$A" 90 "$MARK"
# The survivor's own monitor sweeps the same slot and is a second consumer of
# the same record.  It must have replayed nothing either.
ck "the survivor replayed nothing on the forged slice" \
   "$(cnt "$OUT/A_window.txt" 'P163-RECOVERY-COMPLETE')" 0
echo "FINDING the survivor's monitor logged $(cnt "$OUT/A_window.txt" 'P236-CLAIM-UNCERTIFIED') claim refusal(s) of its own"
for n in "$A" "$B"; do
    f="$OUT/${n}_window.txt"
    [ "$n" = "$B" ] && f="$OUT/B_window.txt"
    [ "$n" = "$A" ] && f="$OUT/A_window.txt"
    ck "no BUG or Oops on $n" "$(cnt "$f" 'BUG:\|Oops')" 0
    ck "no filesystem shutdown on $n" "$(cnt "$f" 'Filesystem has been shut down')" 0
done
value_now_into am "$A" 30 "$OUT/A_mounted_after.txt" '^MOUNTED=[0-9]+$' \
    "the survivor's mount after the arm" "echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts)"
ck "the survivor served throughout" "${am#MOUNTED=}" 1

# ---- 9. put the rig back: restore the sector, then bring the reader up on it
restore_slot
RESTORE_NEEDED=0
measure "$A" 40 "$OUT/slot_restored.txt" 'slot=' "the restored sector" \
    "$FORGE $MXFS_DEV dump $SLOT"
RESTORED_CRC=$(sed -n 's/.*sector_crc32c=\(0x[0-9a-f]*\).*/\1/p' "$OUT/slot_restored.txt" | head -1)
ck "the baseline sector is back" "$RESTORED_CRC" "$BASE_CRC"
timeout 120 $SSH "$B" \
    "grep -qs ' $MNT mxfs ' /proc/mounts || mount -t mxfs $DEV_B $MNT > /tmp/fkm_remount.log 2>&1; \
     echo REMOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts)" > "$OUT/B_remount.txt" 2>&1
ck "the reader mounts again once the record is gone" \
   "$(field "$OUT/B_remount.txt" REMOUNTED)" 1

echo "--- arm=$ARM kind=$KIND refusals=$UNCERT replays=$REPLAYED mount_rc=${MRC:-?}"
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL arm=$ARM fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL arm=$ARM fails=$fails wall=$(el)s evidence=$OUT"; exit 1
