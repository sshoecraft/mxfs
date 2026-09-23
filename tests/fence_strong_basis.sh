#!/bin/bash
# fence_strong_basis.sh — the withdrawal must not have broken the fence that
# actually runs an operation.
#
# WHY THIS EXISTS.  0.89.16 removed the deployment's retirement clause as a
# basis for certifying a fence, leaving exactly one: a COMPLETED TARGET
# OPERATION whose own abort scope covered the victim's tasks.  Two harnesses
# grade the refusal (tests/fence_retire_basis.sh, tests/fence_gate_basis.sh).
# Neither can tell you whether the path that SHOULD still certify still does,
# and "nothing is certified any more" is also what a build that certifies
# nothing at all looks like.  This is the other direction.
#
# THE STIMULUS, and it is the one thing that makes this different from its two
# siblings: the victim is NOT power-cut.  Its heartbeat thread is parked with
# dl_inject_hb_pause_ms while its iSCSI session, its mount and its writer stay
# up — so its PR registration is STILL IN THE TARGET'S TABLE when the prover
# declares it dead.  That is the case the surviving basis is written for: the
# prover's PERSISTENT RESERVE OUT / PREEMPT AND ABORT can NAME that
# registration, and a completed preempt's abort scope is the one the standard
# defines for it.  On a target that purges a registration with its session — as
# the shipping LUN does, 30-46 s after a power cut, while death is not declared
# for ~66 s — a power cut can never produce this case, which is exactly why a
# clause was invented for the other one and why this arm has to inject.
#
# WHAT IS GRADED
#   1. the prover certified, and the certificate is kind
#      PREEMPT_ABORT_PROVEN_V1 — the versioned proof profile a completed
#      operation earns, never the retired code point 16 it replaced;
#   2. it names retire_basis=completed-target-op — not "none", and not the
#      withdrawn clause under a new spelling;
#   3. the victim's journal slice was REPLAYED;
#   4. every file the victim fsynced before it went silent is readable FROM THE
#      SURVIVOR, byte-identical.  This is the integrity assertion: the
#      certificate authorises the replay, and the replay has to bring the
#      acknowledged data back;
#   5. nothing crashed, hung or shut a filesystem down on either node, and no
#      LOGICAL UNIT RESET was issued (MXFS has no path to one).
#
# NON-VACUITY.  A lap that never reached the fence grades nothing, so the
# injection must be observed to have fired on the victim, and the prover must
# have logged a fence outcome of some kind.  A certificate of kind 20 or 21
# would mean the lap measured the absent-registration path instead and is a
# FAIL here, not a pass by another name.
#
# THE VICTIM IS LEFT WITHDRAWN.  A preempted live node loses its key, audits
# SELF_GONE and withdraws its mount — that is the designed behaviour for a node
# that has been fenced, and it is not a defect of this lap.  The injection is
# cleared on exit whether the lap passes or fails: a heartbeat park left armed
# stalls the NEXT prep's unmount.  Run prep_cluster after this harness.
#
# Budget (derived, then re-derived from what the rig actually charges): prep
# + the victim's files 60 + arming 10 + the death window 62 + fence, certify
# and replay 40 + the survivor's verify 60 + clearing the injections 10.
# PREP IS THE VARIABLE ONE and it is the previous lap's bill, not this lap's:
# this harness FENCES A LIVE NODE, so the victim loses its key, self-withdraws
# and has to be power-cycled before the next lap can form a cluster — measured
# 51-63 s after a healthy lap and 344 s after a lap that fenced the peer, which
# is a VM boot plus a re-prep.  Take the pessimistic one: 360 + 242 ~= 600 s,
# caller bound 700 s.  A legacy arm additionally waits up to 150 s for the
# consuming side, which the proven arm spends on the replay instead.
#
# THE ARMS
#   proven    (default) nothing is injected: the fence certifies the profile it
#             actually proved, the slice is replayed and the data comes back.
#   legacy16  the certificate is written with the RETIRED code point 16, and
#   legacy19  ... with the REVOKED kind 19, through the constructor's TEST-ONLY
#             dl_fence_cert_kind_inject.  Everything the attempt proved is
#             unchanged and every constructor check still runs against it; only
#             the value that lands on the platter is replaced.  That produces
#             the one state this build cannot otherwise reach — a durable
#             certificate carrying a proof contract this build has revoked,
#             which is what an older build left behind — and the assertion is
#             that the CONSUMING side refuses it, names the class, and replays
#             nothing.  Without this arm that refusal is a branch nobody has
#             seen fire.
#
# Usage: tests/fence_strong_basis.sh <label> [proven|legacy16|legacy19]
# Env:   MXFS_NODE_LIST (test1,test2), NFILES (32), PAUSE_MS (180000),
#        FENCE_BOUND (170)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
ARM=${2:-proven}
case "$ARM" in
    proven)   INJ_KIND=0 ;;
    legacy16) INJ_KIND=16 ;;
    legacy19) INJ_KIND=19 ;;
    *) echo "ABORT: unknown arm '$ARM' (proven|legacy16|legacy19)"; exit 2 ;;
esac
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the prover; stays alive throughout
B=${MXFS_NODE_LIST##*,}          # the victim; silenced, not cut
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
NFILES=${NFILES:-32}
PAUSE_MS=${PAUSE_MS:-180000}
FENCE_BOUND=${FENCE_BOUND:-170}
PARM=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_fsb_${LABEL}_$ARM
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
MARK="FSB-MARK-$LABEL-$ARM"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

# A parked heartbeat that outlives this lap stalls the next prep's unmount,
# because the unmount waits on the sleeping thread.  Clear it on every exit.
ARMED=0
clear_injections() {
    [ "$ARMED" = 1 ] || return 0
    timeout 30 $SSH "$B" "echo 0 > $PARM/dl_inject_hb_pause_ms 2>/dev/null; \
        echo CLEARED=\$(cat $PARM/dl_inject_hb_pause_ms 2>/dev/null)" \
        > "$OUT/B_clear.txt" 2>&1
    timeout 30 $SSH "$A" "echo 0 > $PARM/dl_fence_cert_kind_inject 2>/dev/null; \
        echo CLEARED=\$(cat $PARM/dl_fence_cert_kind_inject 2>/dev/null)" \
        > "$OUT/A_clear.txt" 2>&1
    echo "STAGE cleared the injections at +$(el)s: park=$(cat "$OUT/B_clear.txt" | tr '\n' ' ' | cut -c1-40) certkind=$(cat "$OUT/A_clear.txt" | tr '\n' ' ' | cut -c1-40)"
}
trap clear_injections EXIT

echo "=== fence_strong_basis label=$LABEL arm=$ARM inject_kind=$INJ_KIND A(prover)=$A B(victim, silenced not cut) $(date -u +%FT%TZ) ==="

# ---- 1. the fleet on the tree build, with NO contract: the point of this lap
# is that the surviving basis needs none.
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
if [ "$(strings -a mxfs.ko | grep -c 'P303-RETIRE-CONTRACT-REJECTED')" = 0 ]; then
    echo "ABORT: mxfs.ko is not a build that withdrew the retirement clause (no P303-RETIRE-CONTRACT-REJECTED); build the tree first"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
MXFS_RETIRE_CONTRACT="" MXFS_FORCE_PREP=1 timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV

# ---- 2. what the replay must bring back
measure "$B" 90 "$OUT/B_files.txt" '^FILES_END$' "B's fsynced files" \
    "d=$MNT/fsb_$LABEL; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'fsb %s file %s\n' $LABEL \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"
grep -av '^FILES_END' "$OUT/B_files.txt" > "$OUT/B_files_sha.txt"
ck "B fsynced $NFILES files before it went silent" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/B_files_sha.txt")" "$NFILES"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=files evidence=$OUT"; exit 2; }

# ---- 3. the victim's registration must be PRESENT, read from the prover, or
# this lap is about the wrong case entirely.  Count only the indented key
# lines: sg_persist's header carries "PR generation=0x..", so a bare '0x' match
# counts one registration too many.
value_now_into keys "$A" 40 "$OUT/A_keys_before.txt" '^KEYS=[0-9]+$' "the registration count before the silence" \
    "echo KEYS=\$(sg_persist -n -i -k $MXFS_DEV 2>/dev/null | grep -ac '^ *0x')"
ck "the target holds both nodes' registrations before the silence" "${keys#KEYS=}" 2

# ---- 4. silence B without cutting it: its session, its mount and its
# registration all stay up, which is what makes the preempt able to name it.
measure "$B" 30 "$OUT/B_arm.txt" '^PAUSE=[0-9]+$' "the heartbeat park on $B" \
    "echo $MARK > /dev/kmsg; echo $PAUSE_MS > $PARM/dl_inject_hb_pause_ms; echo PAUSE=\$(cat $PARM/dl_inject_hb_pause_ms)"
ARMED=1
ck "B's heartbeat is parked for the lap" "$(field "$OUT/B_arm.txt" PAUSE)" "$PAUSE_MS"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }
measure "$A" 30 "$OUT/A_mark.txt" '^CERTKIND=[0-9]+$' "the prover's lap mark and certificate-kind injection" \
    "echo $MARK > /dev/kmsg; echo $INJ_KIND > $PARM/dl_fence_cert_kind_inject; echo CERTKIND=\$(cat $PARM/dl_fence_cert_kind_inject)"
ck "the prover holds this arm's certificate-kind injection" "$(field "$OUT/A_mark.txt" CERTKIND)" "$INJ_KIND"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=inject evidence=$OUT"; exit 2; }
T_ARM=$(date +%s)

# ---- 5. the prover declares B dead, finds its key PRESENT, and preempts it
wait_for_into decided "$A" "$FENCE_BOUND" "$MARK" \
    "P236-FENCE-CERTIFIED\|P238-FENCE-NO-RETIREMENT\|P236-FENCE-NO-RETIREMENT\|P238-FENCE-BLOCKED"
window_into "$OUT/A_fence.txt" "$A" 60 "$MARK"
CERT=$(cnt "$OUT/A_fence.txt" 'P236-FENCE-CERTIFIED')
STRONG=$(grep -ac 'P236-FENCE-CERTIFIED.*kind=PREEMPT_ABORT_PROVEN_V1' "$OUT/A_fence.txt")
RETIRED16=$(grep -ac 'P236-FENCE-CERTIFIED.*kind=PREEMPT_ABORT_DONE_RETIRED16' "$OUT/A_fence.txt")
WEAKKIND=$(grep -ac 'P236-FENCE-CERTIFIED.*kind=\(EXCLUSIVE_WRITE_GATE\|BOOT_SUCCESSION_ABSENT\)' "$OUT/A_fence.txt")
NORETIRE=$(cnt "$OUT/A_fence.txt" 'FENCE-NO-RETIREMENT')
grep -a 'P236-FENCE-CERTIFIED\|FENCE-NO-RETIREMENT\|P236-FENCEKIND' "$OUT/A_fence.txt" \
    | sed 's/.*mxfs: /    /' | cut -c1-240 | tail -4
echo "STAGE the prover decided at +$(el)s (+$(( $(date +%s) - T_ARM ))s from the silence): waited=${decided}s certificates=$CERT strong=$STRONG refusals=$NORETIRE"

# non-vacuity: the injection must have fired and the prover must have reached a
# fence outcome, or this lap graded nothing.
if [ "$(cnt "$OUT/A_fence.txt" 'P236-FENCE-CERTIFIED\|FENCE-NO-RETIREMENT\|P238-FENCE-BLOCKED')" = 0 ]; then
    echo "  FAIL <the prover reached no fence outcome at all within ${FENCE_BOUND}s>"
    echo "RESULT: VACUOUS label=$LABEL stage=nofence wall=$(el)s evidence=$OUT"; exit 3
fi

INJECTED=$(cnt "$OUT/A_fence.txt" 'P236-FENCE-CERT-KIND-INJECTED')
ck "a certificate became durable" "$([ "$CERT" -ge 1 ] && echo yes || echo no)" yes
ck "no certificate of an absent-registration kind was minted" "$WEAKKIND" 0
ck "nothing was refused for want of a retirement basis" "$NORETIRE" 0
# EVERY certificate, not just the first: a lap that mints two must not pass on
# one of them carrying the basis.
ck "every certificate names the completed target operation as its basis" \
   "$(grep -ac 'P236-FENCE-CERTIFIED.*retire_basis=completed-target-op' "$OUT/A_fence.txt")" \
   "$CERT"
ck "no certificate carries the withdrawn clause or no basis at all" \
   "$(grep -ac 'P236-FENCE-CERTIFIED.*retire_basis=\(none\|qualified-contract\)' "$OUT/A_fence.txt")" 0

case "$ARM" in
proven)
    ck "nothing was injected on this arm" "$INJECTED" 0
    ck "the certificate is the one a completed operation earns (PREEMPT_ABORT_PROVEN_V1)" \
       "$([ "$STRONG" -ge 1 ] && echo yes || echo no)" yes
    ck "no certificate was minted under the retired code point" "$RETIRED16" 0

    # ---- 6. the replay, and the data it has to bring back
    wait_for_into replayed "$A" 120 "$MARK" "P163-RECOVERY-COMPLETE"
    window_into "$OUT/A_replay.txt" "$A" 60 "$MARK"
    ck "the victim's journal slice was replayed" \
       "$([ "$(cnt "$OUT/A_replay.txt" 'P163-RECOVERY-COMPLETE')" -ge 1 ] && echo yes || echo no)" yes
    measure "$A" 120 "$OUT/A_verify.txt" '^VERIFY_END$' "B's files read from the survivor" \
        "cd $MNT/fsb_$LABEL && sha256sum f* | sort; echo VERIFY_END"
    grep -av '^VERIFY_END' "$OUT/A_verify.txt" > "$OUT/A_verify_sha.txt"
    ck "every file B fsynced before the fence is readable from the survivor, byte-identical" \
       "$(diff -q "$OUT/B_files_sha.txt" "$OUT/A_verify_sha.txt" > /dev/null && echo same || echo differs)" same
    ;;
legacy16|legacy19)
    # ---- 6. THE CONSUMING SIDE MEETS A REVOKED PROOF CONTRACT.
    # Non-vacuity first: if the substitution never happened the platter holds
    # the sound profile and this arm is grading the proven lap under another
    # name.
    if [ "$INJECTED" = 0 ]; then
        echo "  FAIL <the certificate-kind injection never fired, so no revoked contract reached the platter>"
        echo "RESULT: VACUOUS label=$LABEL arm=$ARM stage=noinject wall=$(el)s evidence=$OUT"; exit 3
    fi
    ck "the certificate on the platter carries the injected revoked kind" \
       "$(grep -ac "P236-FENCE-CERT-KIND-INJECTED.*written=.*($INJ_KIND)" "$OUT/A_fence.txt")" \
       "$INJECTED"
    # WHICH refusal fires is not for this arm to predict.  The certificate is
    # classified at the CLAIM gate (P236-CLAIM-UNCERTIFIED), before anything
    # reaches the replay gate (P236-REPLAY-REFUSED) — measured s83n/s83o, where
    # an assertion written for the replay gate alone FAILED a refusal that was
    # working perfectly.  Accept either, and assert on what matters: a refusal
    # happened, it names the revoked class, and the slice is untouched.
    REFUSAL='P236-CLAIM-UNCERTIFIED\|P236-REPLAY-REFUSED'
    wait_for_into refused "$A" 150 "$MARK" "$REFUSAL"
    window_into "$OUT/A_replay.txt" "$A" 60 "$MARK"
    REPLAY_REFUSED=$(cnt "$OUT/A_replay.txt" "$REFUSAL")
    grep -a "$REFUSAL" "$OUT/A_replay.txt" | sed 's/.*mxfs: /    /' | cut -c1-260 | tail -2
    echo "STAGE the consuming side answered at +$(el)s: waited=${refused}s refusals=$REPLAY_REFUSED"
    ck "the corrected reader REFUSED the revoked certificate" \
       "$([ "$REPLAY_REFUSED" -ge 1 ] && echo yes || echo no)" yes
    case "$ARM" in
      legacy16) CLASS='RETIRED code point 16' ;;
      legacy19) CLASS='REVOKED kind 19' ;;
    esac
    ck "the refusal names the revoked class rather than just saying no" \
       "$([ "$(grep -ac "$CLASS" "$OUT/A_replay.txt")" -ge 1 ] && echo yes || echo no)" yes
    ck "the refusal names the kind that was actually on the platter" \
       "$([ "$(grep -ac "\\($REFUSAL\\).*kind=$INJ_KIND " "$OUT/A_replay.txt")" -ge 1 ] && echo yes || echo no)" yes
    ck "the victim's journal slice was NOT replayed" \
       "$(cnt "$OUT/A_replay.txt" 'P163-RECOVERY-COMPLETE')" 0
    ;;
esac

# ---- 7. and nothing crashed, hung or reached for an operation we have no path to
for n in "$A" "$B"; do
    window_into "$OUT/${n}_final.txt" "$n" 90 "$MARK"
    ck "no BUG or Oops on $n" "$(cnt "$OUT/${n}_final.txt" 'BUG:\|Oops')" 0
    ck "MXFS issued no LOGICAL UNIT RESET on $n during the lap" \
       "$(cnt "$OUT/${n}_final.txt" 'iscsi_eh_device_reset\|LU Reset\|Logical Unit Reset')" 0
done
# The survivor must still be serving; a fenced victim withdrawing its own mount
# is the designed outcome and is recorded rather than graded.
measure "$A" 30 "$OUT/A_mounted.txt" '^AMOUNTED=' "the survivor's mount at the end" \
    "echo AMOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts)"
ck "the survivor is still mounted" "$(field "$OUT/A_mounted.txt" AMOUNTED)" 1
echo "FINDING the fenced victim's own mount: $(cnt "$OUT/${B}_final.txt" 'P277-FENCED-SELF-WITHDRAW') self-withdrawal line(s) on $B (a preempted live node withdrawing is the designed behaviour, not a defect of this lap)"

echo "--- certificates=$CERT strong=$STRONG refusals=$NORETIRE"
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"; exit 1
