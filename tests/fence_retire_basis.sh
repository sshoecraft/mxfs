#!/bin/bash
# tests/fence_retire_basis.sh — a boot-succession certificate may not be minted
# from identity and admission alone, and no deployment assertion may supply the
# missing half.
#
# WHAT THIS GRADES.  v5_boot_succession_consume (dlm/v5_mount.c) certifies
# BOOT_SUCCESSION_ABSENT from three identity facts — the victim's frozen
# (host, boot), that host live again under a DIFFERENT boot, no record of the
# victim's boot still advancing — plus one ADMISSION fact, the reservation and
# the victim key's absence from the registration table.  All four together say
# the dead incarnation cannot obtain permission for a NEW write.  None of them
# says the target has finished with the writes it ALREADY ACCEPTED from that
# incarnation's nexus, and the certificate is what authorises replaying the
# victim's journal slice — so a command still executable from the old nexus
# lands under the replay as an unordered write into metadata the replay is
# rewriting.  No SPC command reports that retirement after the fact.
#
# 0.89.13 and 0.89.15 let the DEPLOYMENT supply it: a five-field contract for
# the exact target, firmware level and LUN designator it had been qualified
# against, and a matching contract certified.  0.89.16 WITHDREW THAT.  An
# environmental assertion is not a witness — the module cannot detect a target
# that breaks it, and the shipped clause's entire support was four probe laps
# that saw no late write inside a bounded window, which characterises one
# appliance under one workload rather than bounding what it may still execute.
# The only basis left is a COMPLETED TARGET OPERATION whose own abort scope
# covered the victim's tasks, and a registration that is already gone leaves
# nothing for one to name.  So this path refuses, always, and the returning
# victim does not get its filesystem back.  That lost availability is the
# intended price: it costs availability, where certifying on the assertion
# risks silent corruption.
#
# THE TWO ARMS, one invocation each.  Both must refuse; they differ in what the
# module was CONFIGURED with, which is the whole point:
#   declared  the module is loaded WITH the string this rig used to declare
#             (data/rigs.json task_retirement_contract_withdrawn).  This is the
#             arm that proves the withdrawal is in the CODE: the deployment
#             asserts exactly what it used to assert, the LUN is exactly the
#             one it was qualified against, and the module refuses anyway and
#             names the configured contract as rejected.
#   none      no contract at all.  The same refusal, reached by the other
#             branch, naming that none is configured.
#
# Neither arm may mint a certificate, replay the slice or let the victim mount.
# Both additionally require that the refusal is TERMINAL AND BOUNDED rather
# than a hang — the mount returns a real failure inside its own bound, not a
# timeout kill — that the surviving prover keeps serving its own filesystem
# across the whole lap, and that MXFS issued no LOGICAL UNIT RESET (it has no
# path to one, and a bystander initiator is destroyed by one: measured in
# tests/lu_reset_probe.sh, D state in blk_io_schedule with no error and no
# timeout).
#
# WHY THE SOLE-SURVIVOR GATE IS HELD OFF.  With the victim's registration
# purged and the prover the only live member, the exclusive-write gate (kind
# 20) would consume the absence long before the victim returns, and boot
# succession would never be reached.  fence_gate_inject_refuse=1 holds it for
# the lap, which is the same instrument tests/fence_lost_response.sh uses.
# Boot succession is tried BEFORE the gate, so nothing else is perturbed.  The
# gate's own refusal — it needs the same basis and no longer gets it either —
# is graded by tests/fence_gate_basis.sh.
#
# WHAT A REFUSAL ARM MAY NOT BE GRADED FROM.  "Nothing was certified" is also
# what a lap that never reached the path looks like.  Every arm therefore
# requires, as a non-vacuity gate, that the prover logged a P238-BOOTSUCC line
# at all — the certificate or the refusal — and that the module on both nodes
# actually holds the arm's contract.  A lap that fails either is ABORT/VACUOUS,
# never a verdict.
#
# Budget (derived): prep <=300 (measured 45-90) + identities and the victim's
# files 60 + the arm 15 + the dead window 62 + the registration purge and the
# blocked-fence observation 90 + the victim's boot 120 + its re-prep and mount
# attempt 180 (a refusal arm spends the mount's own 30 s barrier bound here)
# + the certificate/refusal observation OBSERVE_S (150) + final captures 60
# ~= 1040 s.  Caller bound 1100 s per arm.
#
# Usage: tests/fence_retire_basis.sh <label> <declared|none>
# Env:   MXFS_NODE_LIST (test1,test2), NFILES (32), OBSERVE_S (150),
#        BOOT_BOUND (240), MOUNT_BOUND (150)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
ARM=${2:?arm: declared|none}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the prover; stays alive throughout
B=${MXFS_NODE_LIST##*,}          # the victim; power-cut, then returns
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
NFILES=${NFILES:-32}
OBSERVE_S=${OBSERVE_S:-150}
BOOT_BOUND=${BOOT_BOUND:-240}
MOUNT_BOUND=${MOUNT_BOUND:-150}
PARM=/sys/module/mxfs/parameters
CONTRACT_PARM=$PARM/target_retire_contract
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_frb_${LABEL}_$ARM
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="FRB-MARK-$LABEL-$ARM"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
waitboot() {
    local n w=0
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 48 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}

# ---- 0. the arm's contract.  The DECLARED arm loads the exact string this rig
# used to declare, so the only difference from the build that certified is the
# code; the NONE arm loads nothing.  Both must refuse.
WITHDRAWN_CONTRACT=$(mxfs_rig_retirement_contract_withdrawn)
case "$ARM" in
    declared)
        CONTRACT=$WITHDRAWN_CONTRACT
        [ -n "$CONTRACT" ] || {
            echo "ABORT: this rig records no task_retirement_contract_withdrawn in data/rigs.json, so the declared arm has no contract to be refused"
            echo "RESULT: ABORT label=$LABEL stage=declaration evidence=$OUT"; exit 2; }
        ;;
    none)
        CONTRACT=""
        ;;
    *) echo "ABORT: unknown arm '$ARM' (declared|none)"
       echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2 ;;
esac
# No rig may still declare an ACTIVE contract: if one did, prep would ship it
# and this harness would be grading a configuration nobody meant to keep.
ACTIVE_CONTRACT=$(MXFS_RETIRE_CONTRACT= mxfs_rig_retirement_contract)
if [ -n "$ACTIVE_CONTRACT" ]; then
    echo "ABORT: data/rigs.json still declares an ACTIVE task_retirement_contract ($ACTIVE_CONTRACT); the qualification is withdrawn and no rig may ship one"
    echo "RESULT: ABORT label=$LABEL stage=declaration evidence=$OUT"; exit 2
fi
echo "=== fence_retire_basis label=$LABEL arm=$ARM A(prover)=$A B(victim)=$B contract=[${CONTRACT:-<none>}] $(date -u +%FT%TZ) ==="

# ---- 1. the fleet on the tree build, loaded with THIS arm's contract
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
if [ "$(strings -a mxfs.ko | grep -c 'P238-BOOTSUCC-NO-RETIRE-BASIS')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no P238-BOOTSUCC-NO-RETIRE-BASIS refusal (build the tree first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
waitboot "$A" "$B"
MXFS_RETIRE_CONTRACT="$CONTRACT" MXFS_FORCE_PREP=1 timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
    measure "$n" 30 "$OUT/${n}_contract.txt" '^CONTRACT=' "the loaded retirement contract on $n" \
        "printf 'CONTRACT=%s\n' \"\$(cat $CONTRACT_PARM 2>/dev/null)\""
    ck "the module on $n holds this arm's contract" \
       "$(sed -n 's/^CONTRACT=//p' "$OUT/${n}_contract.txt" | head -1)" "$CONTRACT"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=armcheck evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV

# ---- 2. the dirty-death oracle: B fsyncs NFILES files before it is cut
measure "$B" 90 "$OUT/B_files.txt" '^FILES_END$' "B's fsynced files" \
    "d=$MNT/frb_$LABEL; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'frb %s file %s\n' $LABEL \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"
grep -av '^FILES_END' "$OUT/B_files.txt" > "$OUT/B_files_sha.txt"
ck "B fsynced $NFILES files before the cut" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/B_files_sha.txt")" "$NFILES"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=files evidence=$OUT"; exit 2; }
# A takes a domain of its OWN before the cut, so section 7b can ask what the
# survivor can still do with metadata the dead node never owned.
measure "$A" 60 "$OUT/A_own_before.txt" '^AOWN_RC=' "A's own pre-cut file" \
    "d=$MNT/frb_a_$LABEL; mkdir -p \$d && dd if=/dev/zero of=\$d/a bs=4096 count=16 oflag=direct status=none && sync -f $MNT; echo AOWN_RC=\$?"
ck "A created and fsynced its own file before the cut" "$(field "$OUT/A_own_before.txt" AOWN_RC)" 0
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=afiles evidence=$OUT"; exit 2; }


# ---- 3. hold the sole-survivor gate so boot succession is the operative path
measure "$A" 30 "$OUT/A_arm.txt" '^GATE=[01]$' "the gate hold on $A" \
    "echo $MARK > /dev/kmsg; echo 1 > $PARM/fence_gate_inject_refuse; echo GATE=\$(cat $PARM/fence_gate_inject_refuse)"
ck "A holds the sole-survivor exclusive-write gate off for the lap" "$(field "$OUT/A_arm.txt" GATE)" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=gatehold evidence=$OUT"; exit 2; }

# ---- 4. the power cut.  Not a shutdown: whatever B had submitted is left in
# the target's queue with nobody to answer to, which is the state the whole
# retirement question is about.
$VIRSH destroy "$B" > "$OUT/destroy.txt" 2>&1
echo "STAGE $B destroyed at +$(el)s (rc=$?) — the prover must now find the key absent and have no gate"
T_CUT=$(date +%s)

# ---- 5. the prover reaches the absent key with no proof.  While B's host is
# DOWN, boot succession must also refuse — for a different reason (the host is
# not live again), which is the shipped behaviour and not this arm's subject.
wait_for_into blocked "$A" 180 "$MARK" "P238-BOOTSUCC-HOST-NOT-LIVE\|KEY_ABSENT_UNPROVEN\|P238-BOOTSUCC"
window_into "$OUT/A_while_down.txt" "$A" 40 "$MARK"
echo "STAGE the prover's state while $B is down: waited=${blocked}s bootsucc_lines=$(cnt "$OUT/A_while_down.txt" 'P238-BOOTSUCC') certificates=$(cnt "$OUT/A_while_down.txt" 'P238-FENCE-BOOT-SUCCESSION')"
ck "no certificate was minted while the victim's host was still down" \
   "$(cnt "$OUT/A_while_down.txt" 'P238-FENCE-BOOT-SUCCESSION')" 0

# ---- 6. the boot boundary: B returns and rejoins, which is what makes the
# host live again under a different boot.  Its mount is also the arm's visible
# consequence: with no basis nothing replays its predecessor's slice, so the
# mount does not complete.
$VIRSH start "$B" > "$OUT/start.txt" 2>&1
waitboot "$B"
KO_MD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}')
measure "$B" "$BOOT_BOUND" "$OUT/B_rejoin.txt" '^PREP_RC=' "the re-prep of $B" \
    "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; mountpoint -q /src || echo SRC_NOT_MOUNTED; echo $MARK > /dev/kmsg; MXFS_DEV='$MXFS_DEV' MXFS_KO_MD5='$KO_MD5' MXFS_RETIRE_CONTRACT='$CONTRACT' timeout $(( BOOT_BOUND - 40 )) bash /src/mxfs/tests/setup/prep_node.sh tcp > /tmp/frb_prep.log 2>&1; echo PREP_RC=\$?; grep -a 'MXFS_RETIRE_CONTRACT=' /tmp/frb_prep.log | head -1; tail -2 /tmp/frb_prep.log"
PREP_RC=$(field "$OUT/B_rejoin.txt" PREP_RC)
# THE DECISIVE MOUNT.  The prep script's own mount gives up at the admission
# barrier's bound, and on a healthy lap the certificate lands within a second
# of that — B's mount is itself the stimulus, because the prover cannot see the
# host live again under a new boot until B is heartbeating.  So the verdict is
# taken from a mount that is given the bound the recovery actually needs:
# A's revisit is rate-bounded to 15 s, the fence re-drive, certificate and the
# replay of a 32-file slice run in well under a minute, and the mount's own
# barrier polling adds up to 30 s — MOUNT_BOUND is twice that sum.  A refusal
# arm spends the whole bound and still does not mount, which IS its verdict.
measure "$B" "$(( MOUNT_BOUND + 60 ))" "$OUT/B_mount.txt" '^MOUNT_RC=' "the decisive mount attempt on $B" \
    "if mountpoint -q $MNT; then echo MOUNT_RC=0; else timeout $MOUNT_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; fi; echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts)"
MOUNT_RC=$(field "$OUT/B_mount.txt" MOUNT_RC)
MOUNTED=$(field "$OUT/B_mount.txt" MOUNTED)
echo "STAGE $B returned and attempted to rejoin at +$(el)s: PREP_RC=$PREP_RC MOUNT_RC=$MOUNT_RC MOUNTED=$MOUNTED"

# ---- 7. what the prover did once the boot boundary existed
wait_for_into decided "$A" "$OBSERVE_S" "$MARK" "P238-FENCE-BOOT-SUCCESSION\|P238-BOOTSUCC-NO-RETIRE-BASIS"
window_into "$OUT/A_after_return.txt" "$A" 60 "$MARK"
CERT=$(cnt "$OUT/A_after_return.txt" 'P238-FENCE-BOOT-SUCCESSION')
REFUSED=$(cnt "$OUT/A_after_return.txt" 'P238-BOOTSUCC-NO-RETIRE-BASIS')
BOOTSUCC_ANY=$(cnt "$OUT/A_after_return.txt" 'P238-BOOTSUCC\|P238-FENCE-BOOT-SUCCESSION')
grep -a 'P238-BOOTSUCC-NO-RETIRE-BASIS\|P238-FENCE-BOOT-SUCCESSION' "$OUT/A_after_return.txt" \
    | sed 's/.*mxfs: /    /' | cut -c1-260 | tail -4
echo "STAGE the prover decided at +$(el)s: waited=${decided}s certificates=$CERT refusals=$REFUSED"

# non-vacuity: the lap must have REACHED the boot-succession path at all
if [ "$BOOTSUCC_ANY" = 0 ]; then
    echo "  FAIL <the prover never reached the boot-succession path: no P238-BOOTSUCC line of any kind>"
    echo "RESULT: VACUOUS label=$LABEL arm=$ARM stage=unreached wall=$(el)s evidence=$OUT"; exit 3
fi

# THE VERDICT.  Both arms refuse; they differ only in the reason the module
# gives, and the DECLARED arm is the one that proves the withdrawal is not a
# configuration default somebody can put back.
ck "the prover refused for want of a retirement basis" "$([ "$REFUSED" -ge 1 ] && echo yes || echo no)" yes
ck "NO certificate was minted" "$CERT" 0
ck "the victim's slice was not replayed, so its mount did not complete" \
   "$([ "$MOUNT_RC" = 0 ] && echo mounted || echo refused)" refused
ck "the victim is not mounted" "$MOUNTED" 0
# A refusal that hangs fails the operational bar as surely as a wrong
# certificate: 124 is the timeout kill, and it is not an acceptable outcome.
ck "the refusal is bounded — the mount returned a real failure, not a timeout kill" \
   "$([ "$MOUNT_RC" = 124 ] && echo hung || echo returned)" returned
case "$ARM" in
    declared)
        ck "the refusal says the configured clause was REJECTED, not missing" \
           "$(grep -a 'P238-BOOTSUCC-NO-RETIRE-BASIS' "$OUT/A_after_return.txt" | grep -ac 'WITHDRAWN')" \
           "$REFUSED"
        ck "the deployment is told WHICH contract was rejected, verbatim" \
           "$([ "$(grep -a 'P303-RETIRE-CONTRACT-REJECTED' "$OUT/A_after_return.txt" | grep -acF "$CONTRACT")" -ge 1 ] && echo yes || echo no)" yes
        ;;
    none)
        ck "the refusal names the missing operation, not a missing contract" \
           "$(grep -a 'P238-BOOTSUCC-NO-RETIRE-BASIS' "$OUT/A_after_return.txt" | grep -ac 'UNAVAILABLE')" \
           "$REFUSED"
        ck "nothing reports a rejected contract when none is configured" \
           "$(cnt "$OUT/A_after_return.txt" 'P303-RETIRE-CONTRACT-REJECTED')" 0
        ;;
esac

# ---- 7b. THE SURVIVOR'S OWN OPERATIONAL STATE AFTER THE REFUSAL.
# The refusal costs availability by design, and HOW MUCH is a finding rather
# than a verdict: metadata in the dead node's domain is deliberately
# unreachable while its recovery is blocked, and an operation that touches it
# is refused with an error before any transaction.  What IS graded is the
# operational bar — the survivor must fail FAST and stay up: never hang, never
# crash, never shut its filesystem down.  A timeout kill (124) is a hang.
measure "$A" 120 "$OUT/A_alive.txt" '^ALIVE_RC=' "the prover's own I/O after the refusal" \
    "d=$MNT/frb_a_$LABEL; s=\$(date +%s); timeout 45 dd if=/dev/zero of=\$d/a bs=4096 count=16 oflag=direct status=none; r=\$?; timeout 45 sync -f $MNT; echo ALIVE_WALL=\$(( \$(date +%s) - s )); echo ALIVE_RC=\$r"
ALIVE_RC=$(field "$OUT/A_alive.txt" ALIVE_RC)
ALIVE_WALL=$(field "$OUT/A_alive.txt" ALIVE_WALL)
echo "FINDING the prover's own O_DIRECT write after the refusal: rc=$ALIVE_RC wall=${ALIVE_WALL}s (a non-zero rc is the designed fail-fast inside a blocked domain; a hang would be the defect)"
ck "the prover's own I/O RETURNED rather than hanging" \
   "$([ "$ALIVE_RC" = 124 ] && echo hung || echo returned)" returned
measure "$A" 30 "$OUT/A_mounted.txt" '^AMOUNTED=' "the prover's mount after the refusal" \
    "echo AMOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts)"
ck "the prover is still mounted after refusing" "$(field "$OUT/A_mounted.txt" AMOUNTED)" 1
# MXFS has no path to a task-management function, and a LOGICAL UNIT RESET
# would strand any other initiator's in-flight command (measured in
# tests/lu_reset_probe.sh: D state in blk_io_schedule, no error, no timeout).
# Scoped to THIS lap's mark: the ring holds earlier probes that did issue one.
for n in "$A" "$B"; do
    window_into "$OUT/${n}_tmf.txt" "$n" 90 "$MARK"
    ck "MXFS issued no LOGICAL UNIT RESET on $n during the lap" \
       "$(cnt "$OUT/${n}_tmf.txt" 'iscsi_eh_device_reset\|LU Reset\|Logical Unit Reset')" 0
done

# ---- 8. neither arm may have corrupted or crashed anything
for n in "$A" "$B"; do
    window_into "$OUT/${n}_final.txt" "$n" 60 ""
    ck "no shutdown or BUG on $n" \
       "$(( $(cnt "$OUT/${n}_final.txt" 'hutting down filesystem') + $(cnt "$OUT/${n}_final.txt" 'BUG:\|Oops') ))" 0
done

echo "--- arm=$ARM certificates=$CERT refusals=$REFUSED mount_rc=$MOUNT_RC"
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL arm=$ARM fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL arm=$ARM fails=$fails wall=$(el)s evidence=$OUT"; exit 1
