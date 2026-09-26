#!/bin/bash
# tests/fence_cert_publish.sh — a PROVED exclusion whose certificate does not
# commit must not lose the proof.
#
# WHAT THIS GRADES.  The fencing sequence is: lay a durable attempt, prove
# exclusion against the target, then WRITE the certificate that authorises
# replaying the victim's journal slice.  The proof of exclusion exists, between
# the second and third steps, only in the prover's memory.  Until 0.89.13 the
# first failure of that write was recorded TERMINALLY — "the victim key is
# consumed, so no successor can prove it again: this slice is BLOCKED and needs
# operator action" — so a single transient error on the certificate CAS cost the
# cluster its ability to replay that slice, and on two nodes that means the peer
# can never rejoin.  It is the same lockout class as the ambiguous-attempt leg,
# reached by a different door (ledger
# D-FENCE-POSTSUBMIT-AMBIGUITY-NO-RECONCILIATION-381).
#
# The fix retries the PUBLICATION of the proof already held, five times with
# doubling backoff.  It issues no new PREEMPT, re-derives nothing from a fresh
# READ KEYS (a key's absence now is not the completed command's receipt), and
# never clears the durable arm to make ordinary retry legal.  Reconciliation is
# the disklock primitive's own: it re-reads the descriptor on every call and
# answers 0 when this attempt's certificate is already standing under our lease.
#
# THE THREE ARMS, one invocation each (the injectors are module parameters and
# are named in the evidence, so a lap cannot be graded without them firing):
#   retry   dbg_cert_fail_n=3 — three CAS attempts reported failed without
#           being issued, inside the window of five.  The certificate MUST
#           appear anyway, the slice MUST be replayed, and the peer MUST get
#           its filesystem back.
#   lost    dbg_cert_lost=1 — the CAS COMPLETES and its result is withheld, the
#           case a failed write cannot be distinguished from.  The next attempt
#           must RECONCILE that commit rather than write a second certificate:
#           exactly one certificate, recovery completes.
#   spent   dbg_cert_fail_n=99 — the whole window is spent.  Blocking is
#           correct here and is asserted; what is ALSO asserted is that it is
#           not terminal.  The injected write fault is then CLEARED — it is a
#           transient fault, and an injector left armed fails the recovery's
#           certificate too, which would make the second half of this arm
#           unreachable rather than merely unmet.  Once it clears, the prover
#           republishes the proof it still holds (the exclusive-write gate it
#           installed is still in force under its own key) without re-proving
#           anything, and the peer gets its filesystem back.  That is the half
#           the old terminal record denied.
#
# WHY THE VICTIM IS POWER-CUT AND NOTHING ELSE IS INJECTED.  A destroyed peer
# on this target leaves its registration to be purged with the session, so the
# prover reaches the certificate through the sole-survivor exclusive-write gate
# — a proved kind, which is all this test needs.  The publication path is shared
# by every kind, so the cheapest route to it is the right one.
#
# Budget (derived): prep <=300 (measured 45-90) + the victim's files 30 + the
# arm 15 + the dead window 62 + the registration purge and the fence 90 + the
# certificate window (five tries, ~6 s) and the replay 40 + the victim's boot
# 150 + its re-prep and mount 200 + final captures 60 ~= 950 s.  Caller bound
# 1000 s per arm.
#
# Usage: tests/fence_cert_publish.sh <label> <retry|lost|spent>
# Env:   MXFS_NODE_LIST (test1,test2), NFILES (32), FENCE_BOUND (200),
#        BOOT_BOUND (240), MOUNT_BOUND (150)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
ARM=${2:?arm: retry|lost|spent}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the prover; stays alive throughout
B=${MXFS_NODE_LIST##*,}          # the victim; power-cut, then returns
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
NFILES=${NFILES:-32}
FENCE_BOUND=${FENCE_BOUND:-200}
BOOT_BOUND=${BOOT_BOUND:-240}
MOUNT_BOUND=${MOUNT_BOUND:-150}
PARM=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_fcp_${LABEL}_$ARM
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="FCP-MARK-$LABEL-$ARM"
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

case "$ARM" in
    retry) FAIL_N=3;  LOST_N=0 ;;
    lost)  FAIL_N=0;  LOST_N=1 ;;
    spent) FAIL_N=99; LOST_N=0 ;;
    *) echo "ABORT: unknown arm '$ARM' (retry|lost|spent)"
       echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2 ;;
esac
echo "=== fence_cert_publish label=$LABEL arm=$ARM A(prover)=$A B(victim)=$B fail_n=$FAIL_N lost_n=$LOST_N $(date -u +%FT%TZ) ==="

# ---- 1. the fleet on the tree build, with THESE injectors in it
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
if [ "$(strings -a mxfs.ko | grep -c 'P238-FENCE-CERT-RETRY')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no P238-FENCE-CERT-RETRY publication retry (build the tree first)"
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

# ---- 2. the dirty-death oracle
measure "$B" 90 "$OUT/B_files.txt" '^FILES_END$' "B's fsynced files" \
    "d=$MNT/fcp_$LABEL; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'fcp %s file %s\n' $LABEL \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"
grep -av '^FILES_END' "$OUT/B_files.txt" > "$OUT/B_files_sha.txt"
ck "B fsynced $NFILES files before the cut" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/B_files_sha.txt")" "$NFILES"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=files evidence=$OUT"; exit 2; }

# ---- 3. arm the certificate injectors on the prover
measure "$A" 30 "$OUT/A_arm.txt" '^ARMED fail_n=[0-9]+ lost=[0-9]+$' "the certificate injectors on $A" \
    "echo $MARK > /dev/kmsg; echo $FAIL_N > $PARM/dbg_cert_fail_n; echo $LOST_N > $PARM/dbg_cert_lost; echo ARMED fail_n=\$(cat $PARM/dbg_cert_fail_n) lost=\$(cat $PARM/dbg_cert_lost)"
ck "A armed the certificate injectors for this arm" \
   "$(grep -a '^ARMED' "$OUT/A_arm.txt")" "ARMED fail_n=$FAIL_N lost=$LOST_N"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }

# ---- 4. the power cut, and the fence it forces
$VIRSH destroy "$B" > "$OUT/destroy.txt" 2>&1
echo "STAGE $B destroyed at +$(el)s (rc=$?) — the prover must fence it and then publish the certificate"
wait_for_into decided "$A" "$FENCE_BOUND" "$MARK" \
    "P236-FENCE-CERTIFIED\|P238-FENCE-UNRECORDED"
window_into "$OUT/A_fence.txt" "$A" 60 "$MARK"
CERT=$(cnt "$OUT/A_fence.txt" 'P236-FENCE-CERTIFIED')
RETRIES=$(cnt "$OUT/A_fence.txt" 'P238-FENCE-CERT-RETRY')
UNREC=$(cnt "$OUT/A_fence.txt" 'P238-FENCE-UNRECORDED')
INJ_FAIL=$(cnt "$OUT/A_fence.txt" 'P-DBG-CERT-FAIL')
INJ_LOST=$(cnt "$OUT/A_fence.txt" 'P-DBG-CERT-LOST')
grep -a 'P238-FENCE-CERT-RETRY\|P238-FENCE-UNRECORDED\|P236-FENCE-CERTIFIED' "$OUT/A_fence.txt" \
    | sed 's/.*mxfs: /    /' | cut -c1-240 | tail -5
echo "STAGE the prover decided at +$(el)s: waited=${decided}s certificates=$CERT retries=$RETRIES unrecorded=$UNREC injected(fail=$INJ_FAIL lost=$INJ_LOST)"

# non-vacuity: the injector must have fired, or this lap graded the shipped
# path rather than the one under test
if [ "$ARM" = lost ]; then
    if [ "$INJ_LOST" = 0 ]; then
        echo "  FAIL <the withheld-result injector never fired: nothing exercised reconciliation>"
        echo "RESULT: VACUOUS label=$LABEL arm=$ARM stage=noinject wall=$(el)s evidence=$OUT"; exit 3
    fi
elif [ "$INJ_FAIL" = 0 ]; then
    echo "  FAIL <the certificate-failure injector never fired: nothing exercised the publication window>"
    echo "RESULT: VACUOUS label=$LABEL arm=$ARM stage=noinject wall=$(el)s evidence=$OUT"; exit 3
fi

case "$ARM" in
    retry|lost)
        ck "the publication was retried rather than recorded terminal" \
           "$([ "$RETRIES" -ge 1 ] && echo yes || echo no)" yes
        ck "the certificate was published" "$([ "$CERT" -ge 1 ] && echo yes || echo no)" yes
        ck "exactly one certificate was written for the slice" "$CERT" 1
        ck "no terminal unrecorded verdict" "$UNREC" 0
        ;;
    spent)
        ck "the publication window was spent and the slice left blocked" \
           "$([ "$UNREC" -ge 1 ] && echo yes || echo no)" yes
        ck "the whole window was used before blocking" \
           "$([ "$RETRIES" -ge 4 ] && echo yes || echo no)" yes
        ck "the blocked verdict does not claim the slice is permanently uncertifiable" \
           "$(grep -a 'P238-FENCE-UNRECORDED' "$OUT/A_fence.txt" | grep -ac 'needs operator action')" 0
        # THE INJECTED FAULT IS TRANSIENT, AND IT HAS TO END SOMEWHERE.
        #
        # dbg_cert_fail_n=99 fails EVERY certificate CAS, not just the window's.
        # Left armed, it also fails the certificate the recovery below depends
        # on, so "the peer gets its filesystem back" is not merely unmet, it is
        # unreachable — the lap would be asserting a fantasy.  Measured s81e:
        # the prover republished the proof it still held six times
        # (P238-FENCE-REPUBLISH, zero NOGATE) and every one of those CAS
        # attempts was injected-failed, with the injector still reporting
        # left=64 at the end of the lap.  A slice that cannot be written CANNOT
        # be certified, and blocking forever is the CORRECT behaviour for as
        # long as that is true.
        #
        # So disarm it here, which is the fault clearing.  What the arm asserts
        # either side of this line is the real claim: while the write fault
        # persists the slice stays blocked and nothing is invented, and once it
        # clears the slice recovers WITHOUT re-proving anything — the peer gets
        # its filesystem back.
        measure "$A" 30 "$OUT/A_disarm.txt" '^DISARMED fail_n=[0-9]+$' "clearing the injected write fault on $A" \
            "echo 0 > $PARM/dbg_cert_fail_n; echo DISARMED fail_n=\$(cat $PARM/dbg_cert_fail_n)"
        ck "the injected certificate-write fault was cleared before the recovery" \
           "$(grep -a '^DISARMED' "$OUT/A_disarm.txt")" "DISARMED fail_n=0"
        ;;
esac

# ---- 5. the consequence the cluster actually feels: does the peer come back?
# In every arm it must.  Where the certificate published, its own slice is
# replayed under it; where the window was spent, the victim returns under a new
# boot and an INDEPENDENT proof must recertify the slice — that is the half the
# terminal record denied.
$VIRSH start "$B" > "$OUT/start.txt" 2>&1
waitboot "$B"
KO_MD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}')
measure "$B" "$BOOT_BOUND" "$OUT/B_rejoin.txt" '^PREP_RC=' "the re-prep of $B" \
    "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; mountpoint -q /src || echo SRC_NOT_MOUNTED; echo $MARK > /dev/kmsg; MXFS_DEV='$MXFS_DEV' MXFS_KO_MD5='$KO_MD5' timeout $(( BOOT_BOUND - 40 )) bash /src/mxfs/tests/setup/prep_node.sh tcp > /tmp/fcp_prep.log 2>&1; echo PREP_RC=\$?; tail -2 /tmp/fcp_prep.log"
measure "$B" "$(( MOUNT_BOUND + 60 ))" "$OUT/B_mount.txt" '^MOUNT_RC=' "the decisive mount attempt on $B" \
    "if mountpoint -q $MNT; then echo MOUNT_RC=0; else timeout $MOUNT_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; fi; echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts)"
MOUNT_RC=$(field "$OUT/B_mount.txt" MOUNT_RC)
MOUNTED=$(field "$OUT/B_mount.txt" MOUNTED)
echo "STAGE $B returned at +$(el)s: MOUNT_RC=$MOUNT_RC MOUNTED=$MOUNTED"
ck "the peer got its filesystem back" "$MOUNT_RC" 0
ck "the peer is mounted again" "$MOUNTED" 1
if [ "$MOUNT_RC" = 0 ]; then
    measure "$B" 90 "$OUT/B_verify.txt" '^VERIFY_END$' "B's files after the recovery" \
        "cd $MNT/fcp_$LABEL && sha256sum f* | sort; echo VERIFY_END"
    grep -av '^VERIFY_END' "$OUT/B_verify.txt" > "$OUT/B_verify_sha.txt"
    ck "every file B fsynced before the cut survived byte-identical" \
       "$(diff -q "$OUT/B_files_sha.txt" "$OUT/B_verify_sha.txt" > /dev/null && echo same || echo differs)" same
fi

# ---- 6. and nothing was corrupted or crashed on the way
for n in "$A" "$B"; do
    window_into "$OUT/${n}_final.txt" "$n" 60 ""
    ck "no shutdown or BUG on $n" \
       "$(( $(cnt "$OUT/${n}_final.txt" 'hutting down filesystem') + $(cnt "$OUT/${n}_final.txt" 'BUG:\|Oops') ))" 0
done
ckge "at least one recovery completed for the slice" \
   "$(( $(cnt "$OUT/${A}_final.txt" 'P163-RECOVERY-COMPLETE') + $(cnt "$OUT/${B}_final.txt" 'P163-RECOVERY-COMPLETE') ))" 1

echo "--- arm=$ARM certificates=$CERT retries=$RETRIES unrecorded=$UNREC mount_rc=$MOUNT_RC"
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL arm=$ARM fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL arm=$ARM fails=$fails wall=$(el)s evidence=$OUT"; exit 1
