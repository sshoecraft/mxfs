#!/bin/bash
# fence_gate_basis.sh — the sole-survivor exclusive-write gate must not certify
# without a retirement basis either.
#
# WHY THIS KIND NEEDS THE SAME GATE BOOT SUCCESSION GOT.
# The gate issues PERSISTENT RESERVE OUT / PREEMPT AND ABORT with rk=own,
# **sark=0**, type=WRITE EXCLUSIVE(1).  Per SPC that removes every OTHER
# registration and aborts THEIR task sets — which is a real completed target
# operation and a genuine retirement witness for a victim whose registration
# still EXISTS.
#
# It is never reached in that case.  The gate is attempted only from the
# KEY_ABSENT_UNPROVEN classification, and its own log line says so on every
# lap: "P238-FENCE-GATE-TRY ... victim key already absent".  Measured across
# 20 laps on 2026-09-20, every single occurrence carried that phrase.  So in
# its ONLY reachable case the sark=0 preempt aborts nothing belonging to the
# victim — the registration it would have named is already gone — and the
# reservation it installs excludes FUTURE commands, while a command the target
# already accepted has passed its reservation check.
#
# ADMISSION, therefore, and not RETIREMENT.  Those are separate facts and a
# certificate authorising replay of a foreign journal slice needs both: if the
# target can still execute a write it accepted from the dead incarnation, that
# write lands under the replay as an unordered logical write into metadata the
# replay is rewriting.  Silent corruption, not a refusal.
#
# The basis this kind can have is the deployment's clause, and a clause is a
# CONDITIONAL whose premise is an observation.  What an initiator can state is
# that the registration is gone and MXFS did not replace it; it can never state
# WHY the target removed it, because the target does not report that.  So the
# clause is written about the observation, the gate records which observation
# it made, and a key one of our own mounts replaced is refused here exactly as
# it is refused where the replacement is detected.
#
# 0.89.16 WITHDREW THAT CLAUSE.  An environmental assertion is not a witness:
# the module cannot detect a target that breaks it, and the shipped clause's
# entire support was four probe laps that observed no late write inside a
# bounded window.  So there is no longer ANY basis this kind can have, and the
# gate is never installed from the absent-key case.  Both arms below refuse;
# what they prove is that the refusal is in the CODE and not in a deployment
# value somebody can put back.
#
# THE ARMS, one invocation each.  Identical in shape to
# tests/fence_retire_basis.sh, which is the template, except that this one
# forces the GATE to be the operative path instead of boot succession:
# fence_bootsucc_inject_refuse holds boot succession off, so the only route to
# a certificate is the gate.
#   declared   the module is loaded WITH the exact string this rig used to
#              declare (data/rigs.json task_retirement_contract_withdrawn).
#              ZERO certificates of kind 20, the gate is not even attempted,
#              the slice is not replayed and the returning peer is refused —
#              with the module holding the assertion that used to certify.
#   none       no contract at all.  The same outcome by the other branch, and
#              nothing may report a rejected contract when none is set.
#   snexcl     THE MINT BARRIER (0.89.18).  No contract, and the operator's
#              single_node_exclusive assertion set on the prover instead.
#              Until 0.89.18 that assertion was the last route by which a
#              fence proving nothing could still certify: the unproven leg
#              converted the outcome to kind 17 and the slice was replayed.
#              The assertion is about ADMISSION — that no second INITIATOR can
#              be holding writes — and the victim here is a previous
#              INCARNATION whose already-accepted writes the target may still
#              be finishing, so it never carried the retirement half.  Kind 17
#              is revoked; this arm requires that setting the parameter changes
#              NOTHING about the outcome: the same refusal, no certificate of
#              any kind, no replay, and specifically no P238-FENCE-SINGLENODE.
#              An operator parameter may select an operating mode; it may not
#              create a retirement witness, and this arm is how that is
#              measured rather than argued.
#
# Lost availability is the intended price: certifying on the assertion risks
# silent corruption, refusing costs only the recovery route.
#
# NON-VACUITY, because every one of these arms can pass for the wrong reason:
#   - the module must be holding THIS arm's contract, read back out of sysfs
#     before the lap is graded (a value with a space in it arrives truncated
#     unless the insmod argv carries literal quotes — that bug produced a
#     refusal the module had invented against itself);
#   - the certifying arm must show P238-FENCE-GATE-TRY, or the gate was never
#     the path and the lap graded something else; a refusing arm must show the
#     refusal instead and must NOT show the try, because the basis is checked
#     before the command and an exclusion we cannot certify is never taken;
#   - boot succession must have been held off, or a certificate of kind 21
#     could satisfy an assertion written about kind 20.
#
# Usage: tests/fence_gate_basis.sh <label> <declared|none>
# Env:   MXFS_NODE_LIST (test1,test2), NFILES (32), FENCE_BOUND (200),
#        BOOT_BOUND (240), MOUNT_BOUND (150)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
#
# Budget (derived from the fence_retire_basis measurements it mirrors):
# prep <=240 (measured 55-62) + B's 32 fsynced files 30 + the arm and its
# read-back 10 + the dead window 62 + the registration purge and the gate ~90 +
# the certificate or the refusal ~10 + B's boot 150 + its re-prep and mount 200
# (the refusing arms spend the full mount bound before rc=32) + final captures
# 60 ~= 560 s.  Caller bound 560 s, the same as its template, whose measured
# walls are 328 s qualified and 445-446 s refusing.
set -u
LABEL=${1:?label}
ARM=${2:?arm: declared|none|snexcl}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the prover / survivor
B=${MXFS_NODE_LIST##*,}          # the victim; power-cut, then returns
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
NFILES=${NFILES:-32}
OBSINJ=0
OBSNAME=
SNEXCL=0                         # the snexcl arm sets the operator assertion
FENCE_BOUND=${FENCE_BOUND:-200}
BOOT_BOUND=${BOOT_BOUND:-240}
MOUNT_BOUND=${MOUNT_BOUND:-150}
PARM=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_fgb_${LABEL}_$ARM
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="FGB-MARK-$LABEL-$ARM"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
waitboot() {
    local n w=0
    for n in "$@"; do
        # A node that is POWERED OFF will never become ready, and polling ssh
        # for four minutes to discover that spends the lap's whole budget on
        # the previous lap's leftovers.  Ask the hypervisor first.
        if [ "$($VIRSH domstate "$n" 2>/dev/null | head -1)" != running ]; then
            echo "STAGE $n is not running — starting it at +$(el)s"
            $VIRSH start "$n" >/dev/null 2>&1
        fi
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 48 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}

# THE VICTIM IS POWERED BACK ON WHATEVER ENDS THIS LAP.  A FAIL, a VACUOUS or
# a caller's timeout between the destroy and the restart otherwise leaves the
# node off, and the NEXT lap pays for it: its boot-wait polls a corpse and its
# prep power-cycles the node, which is how a harness manufactures a budget
# failure for whatever it runs next.
DESTROYED=0
restore_victim() {
    [ "$DESTROYED" = 1 ] || return 0
    if [ "$($VIRSH domstate "$B" 2>/dev/null | head -1)" != running ]; then
        echo "STAGE restoring $B at +$(el)s (this lap destroyed it)"
        $VIRSH start "$B" >/dev/null 2>&1
    fi
}
trap restore_victim EXIT

echo "=== fence_gate_basis label=$LABEL arm=$ARM A(prover)=$A B(victim)=$B $(date -u +%FT%TZ) ==="

# ---- 1. the fleet on the tree build, and that build must carry the gate basis
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
if [ "$(strings -a mxfs.ko | grep -c 'P238-GATE-NO-RETIRE-BASIS')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no P238-GATE-NO-RETIRE-BASIS refusal (build the tree first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
# The arm's contract.  The DECLARED arm loads the exact string this rig used to
# declare, so the only thing that differs from the build that certified is the
# code itself.  Exactly the derivation tests/fence_retire_basis.sh uses.
WITHDRAWN_CONTRACT=$(mxfs_rig_retirement_contract_withdrawn)
case "$ARM" in
    declared)
        CONTRACT=$WITHDRAWN_CONTRACT
        [ -n "$CONTRACT" ] || {
            echo "ABORT: this rig records no task_retirement_contract_withdrawn in data/rigs.json, so the declared arm has no contract to be refused"
            echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; } ;;
    none)
        CONTRACT="" ;;
    snexcl)
        CONTRACT=""; SNEXCL=1 ;;
    *) echo "ABORT: unknown arm '$ARM' (declared|none|snexcl)"
       echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2 ;;
esac
ACTIVE_CONTRACT=$(MXFS_RETIRE_CONTRACT= mxfs_rig_retirement_contract)
if [ -n "$ACTIVE_CONTRACT" ]; then
    echo "ABORT: data/rigs.json still declares an ACTIVE task_retirement_contract ($ACTIVE_CONTRACT); the qualification is withdrawn and no rig may ship one"
    echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2
fi
echo "=== arm contract=[${CONTRACT:-<none>}] withdrawn=[${WITHDRAWN_CONTRACT:-<none>}] ==="
waitboot "$A" "$B"
MXFS_RETIRE_CONTRACT="$CONTRACT" MXFS_FORCE_PREP=1 timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV

# ---- 2. the contract the MODULE is actually holding, read back
# A lap whose module does not hold this arm's contract grades nothing, and the
# failure is silent: the value is a module parameter and the shell, the ssh
# layer and insmod's argv each get a chance to mangle it.
value_now_into ctr "$A" 30 "$OUT/A_contract.txt" '^CONTRACT=' "the retirement contract $A is holding" \
    "echo CONTRACT=\$(cat $PARM/target_retire_contract 2>/dev/null)"
HELD=${ctr#CONTRACT=}
case "$ARM" in
    none|snexcl) ck "the module holds NO contract for this arm" "${HELD:-<empty>}" "<empty>" ;;
    *)           ck "the module holds this arm's contract verbatim" "$HELD" "$CONTRACT" ;;
esac
echo "STAGE $A holds contract: ${HELD:-<empty>}"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=contract evidence=$OUT"; exit 2; }

# ---- 3. what the replay must bring back
measure "$B" 90 "$OUT/B_files.txt" '^FILES_END$' "B's fsynced files" \
    "d=$MNT/fgb_$LABEL; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'fgb %s file %s\n' $LABEL \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"
grep -av '^FILES_END' "$OUT/B_files.txt" > "$OUT/B_files_sha.txt"
ck "B fsynced $NFILES files before the cut" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/B_files_sha.txt")" "$NFILES"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=files evidence=$OUT"; exit 2; }

# ---- 4. hold boot succession off so the GATE is the only route
# Without this a kind-21 certificate could satisfy an assertion written about
# kind 20 and the lap would pass having measured the wrong path entirely.
# single_node_exclusive is written on EVERY arm, not only the one that wants
# it: the parameter is live and persists across laps, so a value left behind by
# an earlier run is exactly the contamination that would make a refusing arm
# pass while the assertion was silently in force.  It is read back with the
# others and graded, so the lap knows which side of the barrier it is on.
measure "$A" 30 "$OUT/A_arm.txt" '^ARMED bootsucc_refuse=[0-9]+ obsinj=[0-9]+ snexcl=[0-9]+$' "the boot-succession hold-off on $A" \
    "echo $MARK > /dev/kmsg; echo 99 > $PARM/fence_bootsucc_inject_refuse; echo $OBSINJ > $PARM/fence_retire_obs_inject; echo $SNEXCL > $PARM/single_node_exclusive; echo ARMED bootsucc_refuse=\$(cat $PARM/fence_bootsucc_inject_refuse) obsinj=\$(cat $PARM/fence_retire_obs_inject) snexcl=\$(cat $PARM/single_node_exclusive)"
ck "A held boot succession off so the gate is the operative path" \
   "$(grep -a '^ARMED' "$OUT/A_arm.txt")" "ARMED bootsucc_refuse=99 obsinj=$OBSINJ snexcl=$SNEXCL"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }

# ---- 5. the power cut, and the gate it forces
$VIRSH destroy "$B" > "$OUT/destroy.txt" 2>&1
DESTROYED=1
echo "STAGE $B destroyed at +$(el)s (rc=$?) — the target purges its registration with the session, so the gate is the route"
wait_for_into decided "$A" "$FENCE_BOUND" "$MARK" \
    "P236-FENCE-CERTIFIED\|P238-GATE-NO-RETIRE-BASIS"
window_into "$OUT/A_fence.txt" "$A" 60 "$MARK"
GATETRY=$(cnt "$OUT/A_fence.txt" 'P238-FENCE-GATE-TRY')
GATECERT=$(grep -ac 'P236-FENCE-CERTIFIED.*kind=EXCLUSIVE_WRITE_GATE' "$OUT/A_fence.txt")
ANYCERT=$(cnt "$OUT/A_fence.txt" 'P236-FENCE-CERTIFIED')
REFUSALS=$(cnt "$OUT/A_fence.txt" 'P238-GATE-NO-RETIRE-BASIS')
echo "STAGE the prover decided at +$(el)s: waited=${decided}s gate_try=$GATETRY gate_certs=$GATECERT any_certs=$ANYCERT refusals=$REFUSALS"

# NON-VACUITY, and it is not the same question for the two outcomes.
#
# A lap that certifies must have ATTEMPTED the gate, or it graded some other
# kind.  A lap that refuses must NOT have attempted it — the basis is checked
# before the command precisely so a gate that cannot be certified is never
# installed, since a single-holder Write Exclusive nothing can release locks a
# returning incarnation out of the LUN entirely.  So for a refusing arm the
# evidence that the gate path was the one under test is the refusal itself,
# which is printed from inside that branch with the sole-survivor conditions
# already true.
if [ "$REFUSALS" = 0 ]; then
    echo "  FAIL <neither the gate nor its refusal was reached: this lap did not exercise kind 20>"
    echo "RESULT: VACUOUS label=$LABEL arm=$ARM stage=nogate wall=$(el)s evidence=$OUT"; exit 3
fi

ck "the gate refused to certify without a basis" \
   "$([ "$REFUSALS" -ge 1 ] && echo yes || echo no)" yes
ck "ZERO certificates of the gate kind were written" "$GATECERT" 0
ck "no certificate of ANY kind was written for the slice" "$ANYCERT" 0
# An exclusion we cannot certify must never be TAKEN: the gate is a
# single-holder reservation and nothing would be left to release it.
ck "the gate was not even attempted, so no reservation was installed" "$GATETRY" 0
case "$ARM" in
    declared)
        ck "the refusal says the configured clause was REJECTED, not missing" \
           "$(grep -a 'P238-GATE-NO-RETIRE-BASIS' "$OUT/A_fence.txt" | grep -ac 'WITHDRAWN')" \
           "$REFUSALS"
        ck "the deployment is told WHICH contract was rejected, verbatim" \
           "$([ "$(grep -a 'P303-RETIRE-CONTRACT-REJECTED' "$OUT/A_fence.txt" | grep -acF "$CONTRACT")" -ge 1 ] && echo yes || echo no)" yes
        ;;
    none)
        ck "the refusal names the missing operation, not a missing contract" \
           "$(grep -a 'P238-GATE-NO-RETIRE-BASIS' "$OUT/A_fence.txt" | grep -ac 'UNAVAILABLE')" \
           "$REFUSALS"
        ck "nothing reports a rejected contract when none is configured" \
           "$(cnt "$OUT/A_fence.txt" 'P303-RETIRE-CONTRACT-REJECTED')" 0
        ;;
    snexcl)
        # The mint barrier.  The refusal must be the SAME one the `none` arm
        # gets: the operator's assertion must not have moved the outcome at
        # all.  Its own former route is named explicitly, because a regression
        # here would show up as that line and nothing else.
        ck "the refusal names the missing operation, exactly as with no assertion" \
           "$(grep -a 'P238-GATE-NO-RETIRE-BASIS' "$OUT/A_fence.txt" | grep -ac 'UNAVAILABLE')" \
           "$REFUSALS"
        ck "the operator's assertion minted NOTHING: no single-node certificate leg ran" \
           "$(cnt "$OUT/A_fence.txt" 'P238-FENCE-SINGLENODE')" 0
        ck "no kind-17 certificate was written for the slice" \
           "$(cnt "$OUT/A_fence.txt" 'kind=SINGLE_NODE_EXCLUSIVE')" 0
        # NON-VACUITY FOR THIS ARM, and it needs no extra probe.  The barrier
        # is only tested if the prover was in the state the old conversion
        # required: the assertion in force, membership single-node, and a
        # fence outcome that proved nothing.  All three are already
        # established by assertions above, and the third one establishes the
        # second.  The assertion in force is read back out of sysfs at arming
        # (snexcl=1) rather than assumed.  The gate branch in dlm/v5_mount.c
        # is entered ONLY from KEY_ABSENT_UNPROVEN with this node the lowest
        # and only live slot, so P238-GATE-NO-RETIRE-BASIS cannot be printed
        # by a prover that was not sole survivor over a victim whose key was
        # gone — which is exactly the unproven, single-node state the old code
        # turned into a kind-17 certificate.  Asserting sole survivorship
        # again from a second source would be restating that, and a check that
        # cannot fail is not a check.
        ;;
esac

# ---- 6. the consequence the cluster feels
$VIRSH start "$B" > "$OUT/start.txt" 2>&1
DESTROYED=0
waitboot "$B"
KO_MD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}')
measure "$B" "$BOOT_BOUND" "$OUT/B_rejoin.txt" '^PREP_RC=' "the re-prep of $B" \
    "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; mountpoint -q /src || echo SRC_NOT_MOUNTED; echo $MARK > /dev/kmsg; MXFS_DEV='$MXFS_DEV' MXFS_KO_MD5='$KO_MD5' timeout $(( BOOT_BOUND - 40 )) bash /src/mxfs/tests/setup/prep_node.sh tcp > /tmp/fgb_prep.log 2>&1; echo PREP_RC=\$?; tail -2 /tmp/fgb_prep.log"
measure "$B" "$(( MOUNT_BOUND + 60 ))" "$OUT/B_mount.txt" '^MOUNT_RC=' "the decisive mount attempt on $B" \
    "if mountpoint -q $MNT; then echo MOUNT_RC=0; else timeout $MOUNT_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; fi; echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts)"
MOUNT_RC=$(field "$OUT/B_mount.txt" MOUNT_RC)
MOUNTED=$(field "$OUT/B_mount.txt" MOUNTED)
echo "STAGE $B returned at +$(el)s: MOUNT_RC=$MOUNT_RC MOUNTED=$MOUNTED"
# Refusing costs the peer its filesystem, and that is the POINT: without a
# witnessed retirement this recovery route is not available.  Assert it rather
# than tolerate it, so a silent regression to "certify anyway" cannot pass.
ck "the peer is refused, which is the price of having no basis" "$MOUNT_RC" 32
ck "the peer is not mounted" "$MOUNTED" 0
ck "the victim's slice was NOT replayed" \
   "$(cnt "$OUT/A_fence.txt" 'P163-RECOVERY-COMPLETE')" 0

# ---- 7. and nothing was corrupted or crashed on the way
for n in "$A" "$B"; do
    window_into "$OUT/${n}_final.txt" "$n" 60 ""
    ck "no shutdown or BUG on $n" \
       "$(( $(cnt "$OUT/${n}_final.txt" 'hutting down filesystem') + $(cnt "$OUT/${n}_final.txt" 'BUG:\|Oops') ))" 0
done

echo "--- arm=$ARM gate_try=$GATETRY gate_certs=$GATECERT refusals=$REFUSALS mount_rc=$MOUNT_RC"
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL arm=$ARM fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL arm=$ARM fails=$fails wall=$(el)s evidence=$OUT"; exit 1
