#!/bin/bash
# fence_rejoin_barrier.sh — is a rejoining node admitted on the SEAL, or on the
# slice actually being RECOVERED?
#
# THE HAZARD.  A fence certificate is sealed some time BEFORE the dead peer's
# journal slice is replayed: the seal happens on the prover's proof path
# (P236-FENCE-SEALED, stage FENCED) and the replay is dispatched afterwards.
# Sealing freezes the LIST of the dead node's journal work; it does not perform
# it.  If a returning incarnation were admitted on the seal alone, this would
# destroy data and nothing would report it:
#
#   the survivor seals the list of B's journal work;
#   B+1 observes the seal and mounts;
#   B+1 modifies shared metadata block M;
#   the survivor replays B's OLDER update to M;
#   B+1's newer state is overwritten.
#
# The design-consult ruling this arm exists for is explicit that a barrier
# DEMONSTRATED is not a barrier SUFFICIENT: "SEALED is not, by its name alone,
# a sufficient release condition", and the release milestone has to be recovery
# complete, or recovery locks installed such that the joiner cannot touch
# conflicting metadata.  Reading the code says the joiner's barrier refuses
# while any slot "still requires recovery"; that is a claim about behaviour and
# this harness is the measurement of it.
#
# WHY A KNOB AND NOT TIMING.  Measured on this rig, P236-FENCE-SEALED to
# P163-RECOVERY-COMPLETE is about 8.6 s.  A returning node cannot be steered
# into an 8.6 s window, so the module holds the window open on purpose:
# dbg_replay_hold_ms parks the foreign-replay worker AFTER the recovery
# execution lease is claimed and BEFORE the slice is replayed.  The hold is
# taken after the claim deliberately — held before it, the returning node could
# simply claim the slice and replay it itself, which is also correct behaviour
# but is not the case under test.
#
# WHAT A PASS MEANS.  While the survivor holds a sealed, claimed, UNREPLAYED
# slice, the returning peer asks for its filesystem and is REFUSED.  When the
# hold releases, the slice is replayed, the peer mounts, and every file it
# fsynced before the cut comes back byte-identical.  A mount that succeeds
# during the hold is the defect, and it is graded as a FAIL, not as speed.
#
# Usage: tests/fence_rejoin_barrier.sh <label> [hold_ms]
# Env:   MXFS_NODE_LIST (test1,test2), NFILES (32), FENCE_BOUND (200),
#        BOOT_BOUND (240), MOUNT_BOUND (150)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
#
# Budget (derived, not rounded): prep <=240 (measured 57-225) + B's files 30 +
# the arm 10 + the dead window 62 + the fence to the seal ~90 + the hold itself
# HOLD_MS/1000 (200) + the release and the replay ~15 + B's decisive remount
# ~90 + final captures 40 ~= 780 s.  Caller bound 800 s.  B's boot (~150 s) and
# its refused mount attempt run INSIDE the hold, which is the whole point, so
# they are not added on top.
set -u
LABEL=${1:?label}
HOLD_MS=${2:-200000}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the survivor / prover; holds the replay
B=${MXFS_NODE_LIST##*,}          # the victim; power-cut, then returns
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
NFILES=${NFILES:-32}
FENCE_BOUND=${FENCE_BOUND:-200}
BOOT_BOUND=${BOOT_BOUND:-240}
MOUNT_BOUND=${MOUNT_BOUND:-150}
PARM=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_frjb_${LABEL}
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="FRJB-MARK-$LABEL"
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

echo "=== fence_rejoin_barrier label=$LABEL A(survivor)=$A B(victim)=$B hold_ms=$HOLD_MS $(date -u +%FT%TZ) ==="

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

# ---- 2. what the replay must bring back
measure "$B" 90 "$OUT/B_files.txt" '^FILES_END$' "B's fsynced files" \
    "d=$MNT/frjb_$LABEL; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'frjb %s file %s\n' $LABEL \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"
grep -av '^FILES_END' "$OUT/B_files.txt" > "$OUT/B_files_sha.txt"
ck "B fsynced $NFILES files before the cut" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/B_files_sha.txt")" "$NFILES"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=files evidence=$OUT"; exit 2; }

# ---- 3. arm the hold on the survivor, and read it back
# The knob is one-shot and self-clears when it fires, so it is read back HERE,
# before the cut — a lap whose module does not hold the value grades nothing.
measure "$A" 30 "$OUT/A_arm.txt" '^ARMED hold_ms=[0-9]+$' "the replay hold on $A" \
    "echo $MARK > /dev/kmsg; echo $HOLD_MS > $PARM/dbg_replay_hold_ms; echo ARMED hold_ms=\$(cat $PARM/dbg_replay_hold_ms)"
ck "A armed the replay hold for this lap" \
   "$(grep -a '^ARMED' "$OUT/A_arm.txt")" "ARMED hold_ms=$HOLD_MS"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }

# ---- 4. the power cut, the fence, the seal — and then the hold
$VIRSH destroy "$B" > "$OUT/destroy.txt" 2>&1
echo "STAGE $B destroyed at +$(el)s (rc=$?) — the survivor must fence it, seal, claim, and then hold"
wait_for_into held "$A" "$FENCE_BOUND" "$MARK" "P-FREPLAY-HOLD slot"
window_into "$OUT/A_fence.txt" "$A" 60 "$MARK"
SEALED=$(cnt "$OUT/A_fence.txt" 'P236-FENCE-SEALED')
HELD=$(cnt "$OUT/A_fence.txt" 'P-FREPLAY-HOLD slot')
CLAIMED=$(cnt "$OUT/A_fence.txt" 'P236-RECOV-CLAIMED')
echo "STAGE the survivor reached the hold at +$(el)s: waited=${held}s sealed=$SEALED claimed=$CLAIMED held=$HELD"

# non-vacuity: without the hold in force there is no window and nothing below
# grades the barrier.  This is the harness refusing, not failing.
if [ "$HELD" = 0 ]; then
    echo "  FAIL <the replay hold never fired: there was no sealed-but-unreplayed window to admit into>"
    echo "RESULT: VACUOUS label=$LABEL stage=nohold wall=$(el)s evidence=$OUT"; exit 3
fi
ck "the certificate was sealed before the hold" \
   "$([ "$SEALED" -ge 1 ] && echo yes || echo no)" yes
ck "the survivor holds the recovery execution lease" \
   "$([ "$CLAIMED" -ge 1 ] && echo yes || echo no)" yes
ck "the slice is NOT replayed while the hold is in force" \
   "$(cnt "$OUT/A_fence.txt" 'P163-RECOVERY-COMPLETE')" 0

# ---- 5. the returning peer meets the window
$VIRSH start "$B" > "$OUT/start.txt" 2>&1
waitboot "$B"
KO_MD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}')
measure "$B" "$BOOT_BOUND" "$OUT/B_rejoin.txt" '^PREP_RC=' "the re-prep of $B" \
    "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; mountpoint -q /src || echo SRC_NOT_MOUNTED; echo $MARK > /dev/kmsg; MXFS_DEV='$MXFS_DEV' MXFS_KO_MD5='$KO_MD5' timeout $(( BOOT_BOUND - 40 )) bash /src/mxfs/tests/setup/prep_node.sh tcp > /tmp/frjb_prep.log 2>&1; echo PREP_RC=\$?; tail -2 /tmp/frjb_prep.log"
measure "$B" "$(( MOUNT_BOUND + 60 ))" "$OUT/B_mount_held.txt" '^MOUNT_RC=' "the mount attempt made DURING the hold on $B" \
    "if mountpoint -q $MNT; then echo MOUNT_RC=0; else timeout $MOUNT_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; fi; echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts)"
HELD_RC=$(field "$OUT/B_mount_held.txt" MOUNT_RC)
HELD_MOUNTED=$(field "$OUT/B_mount_held.txt" MOUNTED)

# Was that attempt actually INSIDE the window?  Read the survivor the instant
# the attempt returns: if the hold has already released, this lap proves
# nothing about admission during it and must say so rather than pass.
window_into "$OUT/A_window.txt" "$A" 60 "$MARK"
ENDED=$(cnt "$OUT/A_window.txt" 'P-FREPLAY-HOLD-END')
echo "STAGE $B asked for its filesystem at +$(el)s: MOUNT_RC=$HELD_RC MOUNTED=$HELD_MOUNTED hold_released=$ENDED"
if [ "$ENDED" != 0 ]; then
    echo "  FAIL <the hold released before the mount attempt returned: the attempt did not meet the window>"
    echo "RESULT: VACUOUS label=$LABEL stage=windowclosed wall=$(el)s evidence=$OUT"; exit 3
fi

# THE ASSERTION THIS HARNESS EXISTS FOR.
ck "the peer was REFUSED while the slice was sealed but unreplayed" \
   "$([ "$HELD_RC" = 0 ] && echo admitted || echo refused)" refused
ck "the peer is not mounted while the slice is unreplayed" "$HELD_MOUNTED" 0

# ---- 6. and when the hold releases, recovery finishes and the peer returns
wait_for_into released "$A" 120 "$MARK" "P-FREPLAY-HOLD-END"
wait_for_into replayed "$A" 120 "$MARK" "P163-RECOVERY-COMPLETE"
echo "STAGE the hold released at +$(el)s: released_after=${released}s replayed_after=${replayed}s"
measure "$B" "$(( MOUNT_BOUND + 60 ))" "$OUT/B_mount.txt" '^MOUNT_RC=' "the decisive mount attempt on $B" \
    "if mountpoint -q $MNT; then echo MOUNT_RC=0; else timeout $MOUNT_BOUND mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; fi; echo MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts)"
MOUNT_RC=$(field "$OUT/B_mount.txt" MOUNT_RC)
MOUNTED=$(field "$OUT/B_mount.txt" MOUNTED)
echo "STAGE $B returned at +$(el)s: MOUNT_RC=$MOUNT_RC MOUNTED=$MOUNTED"
ck "the peer got its filesystem back once the slice was replayed" "$MOUNT_RC" 0
ck "the peer is mounted again" "$MOUNTED" 1
if [ "$MOUNT_RC" = 0 ]; then
    measure "$B" 90 "$OUT/B_verify.txt" '^VERIFY_END$' "B's files after the recovery" \
        "cd $MNT/frjb_$LABEL && sha256sum f* | sort; echo VERIFY_END"
    grep -av '^VERIFY_END' "$OUT/B_verify.txt" > "$OUT/B_verify_sha.txt"
    ck "every file B fsynced before the cut survived byte-identical" \
       "$(diff -q "$OUT/B_files_sha.txt" "$OUT/B_verify_sha.txt" > /dev/null && echo same || echo differs)" same
fi

# ---- 7. and nothing was corrupted or crashed on the way
for n in "$A" "$B"; do
    window_into "$OUT/${n}_final.txt" "$n" 60 ""
    ck "no shutdown or BUG on $n" \
       "$(( $(cnt "$OUT/${n}_final.txt" 'hutting down filesystem') + $(cnt "$OUT/${n}_final.txt" 'BUG:\|Oops') ))" 0
done
ckge "at least one recovery completed for the slice" \
   "$(( $(cnt "$OUT/${A}_final.txt" 'P163-RECOVERY-COMPLETE') + $(cnt "$OUT/${B}_final.txt" 'P163-RECOVERY-COMPLETE') ))" 1

echo "--- hold_ms=$HOLD_MS sealed=$SEALED claimed=$CLAIMED refused_rc=$HELD_RC final_rc=$MOUNT_RC"
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"; exit 1
