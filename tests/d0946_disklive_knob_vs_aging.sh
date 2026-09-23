#!/bin/bash
# d0946_disklive_knob_vs_aging.sh — does the inode double-allocation depend on
# the unpub_publish_owned_meta knob, or only on how aged the filesystem is?
#
# D-0946.  xfs_dialloc handed out inode 132 whose platter dinode was still LIVE
# (incore_gen == disk_gen + 1, disk mode 0100644), the create path's fail-safe
# refused with EFSCORRUPTED while the transaction was dirty, and the filesystem
# shut down.  Seen twice, both times in the FIX arm of the D-0944 A/B.
#
# THAT ASYMMETRY IS CONFOUNDED AND THIS HARNESS EXISTS TO BREAK THE CONFOUND.
# Every control lap of that A/B re-prepped (fresh mkfs) because its victim kept
# failing to rejoin; the fix arm ran five consecutive laps on ONE aged
# filesystem.  So "only in the fix arm" and "only on an aged filesystem" are the
# same observation in that data, and neither the knob's guilt nor its innocence
# follows from it.
#
# The confound is removable for free: unpub_publish_owned_meta is a 0644 module
# parameter, so it can be flipped IN PLACE between rounds.  Both arms then run
# on the SAME filesystem, at the same age, in interleaved order — no mkfs, no
# remount, no death, no rejoin.  Nothing differs between the arms except the
# knob, which is what an A/B is supposed to mean.
#
# ORDER IS ALTERNATED, not blocked.  A fixed order (all of arm A, then all of
# arm B) confounds the knob with elapsed age all over again — the second block
# always runs on an older filesystem than the first.  Rounds alternate 1,0,1,0
# and the driver also reports the per-round sequence so a monotone trend in age
# is visible as a trend rather than as an arm difference.
#
# WHAT IS COUNTED.  P-CR62 ... verdict=DISK-LIVE is the fail-safe firing;
# P-CR63-DEFER-DISKLIVE is the deferred deadshell check finding a live platter
# image.  Both are counted per round from a dmesg window opened at the round's
# own marker, because an evidence file named after a round is not windowed to
# that round unless someone windows it (that mistake cost this campaign a wrong
# reading once already).
#
# A SHUTDOWN ENDS THE RUN AND IS THE RESULT, NOT AN ERROR.  If the filesystem
# dies the harness stops, reports which arm and which round killed it, and
# leaves the evidence — it does not re-prep and carry on, because a run that
# repairs the condition it is measuring measures nothing.
#
# derived time budget: 400 creates+deletes per round, measured on this rig at
# ~3 ms per create -> ~1.2 s of create, ~1.2 s of delete, ~4 s with sync and
# ssh overhead.  8 rounds bounds at 32 s of work; the per-round ssh timeout is
# 90 s and the whole run is bounded at 420 s.  A round that takes longer than
# its bound is itself a budget failure and is reported as one.
#
# Usage: tests/d0946_disklive_knob_vs_aging.sh <label> [ROUNDS=8] [FILES=400] [MODE=peer|local]
set -u
LABEL=${1:?label}
ROUNDS=${2:-8}
FILES=${3:-400}
# peer  = node B frees what A created, then A recreates into the same numbers.
# local = same-node create/delete only.
# tight = same-node, NO SYNC ANYWHERE, free and re-allocate interleaved, and
#         every churn file carries ALLOCATED BLOCKS.
# dirchurn = same, but the thing freed and immediately re-allocated is a
#         DIRECTORY with enough entries to own several blocks.
#
# WHY dirchurn.  tight makes the pubob arm fire freely but never reaches the
# deferred-deadshell classification (DEADSHELL=0 in every round), which is the
# gate that actually produces the shutdown.  Its entry condition, in
# xfs_icache.c, is an in-core shell that is XFS_IRECLAIMABLE with nlink==0 and
# `i_mode != 0 || i_nblocks != 0`.  The one captured failure's shell was
# `P-CR63-SHELL ino=0x84 mode=00 nlink=0 nblk=11` -- mode already zeroed by the
# free, but ELEVEN BLOCKS still attached.  Eleven blocks is not an 8M file
# (that would be 2048); it is a directory.  So the object to churn is a
# multi-block directory removed and immediately re-created, with no sync in
# between -- which needs no death, no rejoin and no injected fault.
#
# WHY tight EXISTS.  peer and local were both run for 8 rounds each on 0.75.116
# (evidence 20260910T070641Z_d0946disklive_s574b and ...s574peer) and scored
# DISKLIVE=0 DEFERLIVE=0 in 16 of 16 rounds -- but they also scored ZERO
# P-FREEOB-CHAIN-LIVE and ZERO P946-VALIDATE-ALLOW, which means the pubob arm of
# the candidate validator never ran.  Those rounds were VACUOUS, not clean: they
# proved nothing about the defect because they never reached the code that has
# it.  The cause is in the harness, not the filesystem -- `sync -f` between the
# create pass and the delete pass publishes every owed free before the next
# round can re-allocate the number, which closes the exact window D-0946 lives
# in.  tight removes every sync and interleaves the free with the re-allocation
# one inode at a time, which is what the failing workload did.
#
# AND THE FILES MUST HAVE BLOCKS.  The first cut of tight mode used `: > f`,
# i.e. zero-length files, and scored 0 in 12 rounds while the gate itself fired
# 40 times -- the arm ran and the defect still could not happen.  The reason is
# in the entry condition of the path that fails: xfs_icache.c classifies an
# in-core shell as a deferred deadshell only when `i_mode != 0 || i_nblocks != 0`,
# and the shell in the captured failure was `mode=00 nblk=11`.  A zero-length
# file leaves mode 0 AND nblocks 0, so the create never reaches the recycle gate
# that produces the shutdown.  The failing workload's file was `fallocate -l 8M`.
TIGHT_SZ=${MXFS_D0946_TIGHT_SZ:-1M}
# entries per churned directory in dirchurn mode: enough that the directory
# outgrows shortform and owns real blocks, which is the entry condition above.
DIRENTS=${MXFS_D0946_DIRENTS:-40}
MODE=${4:-tight}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
# THE MARKER KNOWS WHICH DEVICE THIS RIG IS ON; A HARDCODED DEFAULT DOES NOT.
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; DEV=$MXFS_DEV_RESOLVED
# WHICH KNOB IS UNDER TEST IS AN ARGUMENT, NOT A CONSTANT.  This harness was
# written to break the unpub_publish_owned_meta / aging confound; from 0.75.117
# it is also the A/B for the D-0946 FIX itself, whose control arm is
# dialloc_pubpend_refuse=0 (the allocator's pre-fix "an open obligation of ours
# means the live image at home is ours, allow it" inference).  Same rounds, same
# filesystem, same alternation -- only the parameter name changes.
KNOBNAME=${MXFS_D0946_KNOB:-dialloc_pubpend_refuse}
KNOB=/sys/module/mxfs/parameters/$KNOBNAME
# The module default of the knob under test, so a lap can start from it.
# partial_iwrite_sole defaults to 1 from 0.83.3 (the D-0955 fix); the
# allocator knobs this harness was written for are left as the rig has them.
case "$KNOBNAME" in
  partial_iwrite_sole) KNOB_DEFAULT=${MXFS_D0946_KNOB_DEFAULT:-1} ;;
  *)                   KNOB_DEFAULT=${MXFS_D0946_KNOB_DEFAULT:-} ;;
esac
# THE SOLE-SURVIVOR PRE-PHASE (opt-in, MXFS_D0946_SOLE=umount|death).
#
# The candidate validator that D-0946 turns on is gated off entirely when the
# mount is single-node -- and mxfs_v5_dlm_is_single_node() is DYNAMIC
# membership, so the instant a two-node cluster's peer leaves, the survivor
# stops validating candidates.  That is the same shape as D-0949: the guard
# asks "am I alone now" when the question it has to answer is "has anybody
# else ever had a view of this volume".
#
# Reaching that state costs one departure and nothing else: once A is a sole
# survivor it stays one for the rest of the mount, so every round after the
# pre-phase runs in the condition under test and the knob still alternates in
# place with no remount.  B is removed AFTER an aging pass in which BOTH nodes
# create and delete, so the numbers the survivor is later handed include ones
# the departed peer freed -- the residue whose platter image the validator
# exists to check.
#
#   umount  clean departure: B publishes everything it owes on the way out.
#           The cheap arm.  A refusal here still proves the guard is off.
#   death   virsh destroy: B's owed writes are whatever replay reconstructs.
#           The sharp arm, and the one a production 2-node cluster meets.
SOLE=${MXFS_D0946_SOLE:-}
AGE_FILES=${MXFS_D0946_AGE_FILES:-600}
# The aging directories are named here for EVERY mode: the round's remote
# command carries the touch/stalesrc branches whatever MODE is, and it is
# built in this shell under `set -u`, so a name defined only inside the
# sole-survivor pre-phase killed every plain tight lap at line 542 with
# "AD: unbound variable" (s602a) — and the empty round line then read as a
# dead filesystem.
AD=$MNT/d0946age_$LABEL.A
BD=$MNT/d0946age_$LABEL.B
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0946disklive_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it

SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0946_disklive label=$LABEL rounds=$ROUNDS files=$FILES mode=$MODE knob=$KNOBNAME sv=$SV $(date -u +%FT%TZ) ==="

# PRECONDITION.  Both nodes mounted, running THIS tree's build, and the knob
# present and writable.  A run against a stale module is not this build's run.
fails=0
for n in $A $B; do
    st=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) mnt=\$(grep -c ' $MNT mxfs ' /proc/mounts)" | tr -d '\n')
    echo "  INFO $n $st"
    case "$st" in
        "sv=$SV mnt=1") ;;
        *) echo "  FAIL $n precondition (want sv=$SV mnt=1)"; fails=$((fails+1)) ;;
    esac
done
kn=$(rs 25 "$A" "cat $KNOB 2>/dev/null || echo missing")
echo "  INFO knob starts at $kn"
# THE PRE-PHASE RUNS ON THE MODULE DEFAULT.  Round 8 of the previous lap is
# the knob=0 arm, so without this a second lap on the same module load would
# age, depart and wait with the knob still at 0 — and the survivor's first
# flushes after the departure would run on the pre-fix arm, unrecorded.
if [ -n "$SOLE" ] && [ "$KNOB_DEFAULT" != "" ]; then
    kn=$(rs 25 "$A" "echo $KNOB_DEFAULT > $KNOB 2>/dev/null; cat $KNOB 2>/dev/null || echo missing")
    echo "  INFO knob reset to its default $KNOB_DEFAULT for the pre-phase (now $kn)"
fi
[ "$kn" = "0" ] || [ "$kn" = "1" ] || { echo "  FAIL knob not readable at $KNOB (got '$kn')"; fails=$((fails+1)); }
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL precondition fails=$fails"; exit 2; }

# A MOUNT IN /proc/mounts IS NOT A WORKING MOUNT.  A filesystem that has been
# shut down still appears there and answers EIO to everything; a harness that
# only counts the mount line runs its whole workload against it and reports a
# clean or vacuous result instead of a broken precondition.  That has already
# cost this campaign one whole run.
wprobe=$(rs 40 "$A" "mkdir -p $MNT/.d0946probe.$$ 2>&1 && rmdir $MNT/.d0946probe.$$ 2>&1 && echo WRITABLE || echo NOTWRITABLE")
case "$wprobe" in
  *WRITABLE*) ;;
  *) echo "RESULT: FAIL label=$LABEL $A mounted but NOT writable (shut down?): $wprobe"; exit 2 ;;
esac

# ---- sole-survivor pre-phase ------------------------------------------------
SOLEFIRED=0
if [ -n "$SOLE" ] && [ "$MODE" = peer ]; then
    echo "RESULT: FAIL label=$LABEL MODE=peer needs a live peer and MXFS_D0946_SOLE removes it"
    exit 2
fi
if [ "$MODE" = touch -o "$MODE" = stalesrc ] && [ -z "$SOLE" ]; then
    echo "RESULT: FAIL label=$LABEL MODE=$MODE is a sole-survivor lap and needs MXFS_D0946_SOLE=umount|death"
    exit 2
fi
if [ -n "$SOLE" ]; then
    AD=$MNT/d0946age_$LABEL.A
    BD=$MNT/d0946age_$LABEL.B
    # Age BOTH nodes so the free inode numbers the survivor is later handed
    # include ones the DEPARTED peer freed.  Files carry blocks on purpose:
    # a zero-length file leaves mode 0 and nblocks 0 and never reaches the
    # recycle gate whose refusal is the defect's downstream consequence.
    ta=$(date +%s)
    if [ "$MODE" = touch ]; then
        # THE STALE-CACHE PRIME (D-0955).  A create workload cannot publish a
        # stale image: a survivor allocating over the peer's freed numbers
        # reads them fresh (s582i: 11 whole-cluster writes over freed images,
        # every slot a NEW incarnation, zero behind the platter; s582j death:
        # the frees never landed, fresh chunks, probe silent).  The hazard the
        # record names needs the survivor's cache to hold the peer's LIVE
        # image of a slot the peer then FREES, in a cluster the survivor
        # later flushes for an inode of its own.  So: both nodes allocate
        # CONCURRENTLY into one AG so their inodes interleave within
        # clusters; B publishes its creates; A reads every B file, which
        # pulls B's live images into A's cluster buffers; B frees and
        # publishes the frees (its own slots, partial writes); B departs.
        # The rounds then re-dirty A's OWN files only, so every cluster A
        # flushes carries B's freed slots from A's pre-free cache.
        # ONE shared directory: a file is allocated in its parent's AG and
        # separate directories rotate across AGs.  Concurrent creates by two
        # nodes do NOT interleave either (s582k: MIXED_CLUSTERS=0 over 600+600
        # files — each node is handed whole chunks of its own).  A cluster
        # becomes MIXED when the peer reuses numbers this node freed, so the
        # prime is: A creates a<i>, publishes, frees every odd a<i> and
        # publishes the frees; B then creates b<i> into the same directory
        # and takes the lowest free numbers — A's — and publishes.  A's
        # cluster buffers stay cached for its surviving even files, carrying
        # A's OWN FREE image of every slot B has since brought to life.  A
        # must NOT look at B's files (an iget would refresh the buffer), so
        # mixing is read from readdir's d_ino (os.scandir) without a stat.
        # B departs with its files LIVE.  The rounds re-dirty A's even files:
        # a whole-cluster flush then publishes 'free' over B's live inodes.
        SD=$MNT/d0946age_$LABEL
        rs 60 "$A" "mkdir -p $SD; sync -f $MNT; echo SD_OK" > "$OUT/age_mkdir.txt" 2>&1
        # A's freed numbers are 'not the peer's to take yet' while A still
        # holds their deferred-free grants cached (s582l: B_IN_MIXED=0 with
        # 300 numbers free), so A evicts them first (drop_caches releases the
        # grants and drops the clean buffers), then re-dirties its even files
        # ONCE so every cluster is re-read fresh — odd slots FREE — and sits
        # in A's cache again before B allocates into them.  A's copy of those
        # slots is then a pre-B free image, and nothing A does afterwards
        # reads B's inodes to refresh it.
        rs 300 "$A" "for i in \$(seq 1 $AGE_FILES); do fallocate -l 64k $SD/a\$i 2>/dev/null; done; sync -f $MNT; for i in \$(seq 1 2 $AGE_FILES); do rm -f $SD/a\$i; done; sync -f $MNT; sync; echo 2 > /proc/sys/vm/drop_caches; sleep 2; for i in \$(seq 2 2 $AGE_FILES); do touch $SD/a\$i; done; sync -f $MNT; echo A_MADE=$AGE_FILES A_LEFT=\$(ls $SD | grep -c '^a') A_RETOUCHED=1" > "$OUT/age_a.txt" 2>&1
        rs 300 "$B" "for i in \$(seq 1 $((AGE_FILES / 2))); do fallocate -l 64k $SD/b\$i 2>/dev/null; done; sync -f $MNT; echo B_MADE=\$(ls $SD | grep -c '^b')" > "$OUT/age_b.txt" 2>&1
        rs 120 "$A" "python3 - <<'PY'
import os
ents=[(e.inode(), e.name) for e in os.scandir('$SD')]
cl={}
for ino,name in ents: cl.setdefault(ino//32, set()).add(name[0])
mixed=[c for c,s in cl.items() if 'a' in s and 'b' in s]
print('MIXED_CLUSTERS=%d CLUSTERS=%d B_IN_MIXED=%d' % (len(mixed), len(cl), sum(1 for ino,n in ents if n[0]=='b' and ino//32 in mixed)))
PY" > "$OUT/age_a_walk.txt" 2>&1
        echo "B_RM_RC=none (B keeps its files live)" > "$OUT/age_b_rm.txt"
        AD=$SD
        echo "  AGE $(cat "$OUT/age_a.txt" "$OUT/age_b.txt" "$OUT/age_a_walk.txt" "$OUT/age_b_rm.txt" 2>/dev/null | tr -d '\r' | tr '\n' ' ') wall=$(( $(date +%s) - ta ))s"
    elif [ "$MODE" = stalesrc ]; then
        # THE STALE-SOURCE PRIME (design consult, sess583).  The consult's
        # counterexample to 'logged this round is authorised while single':
        # A caches directory S; B takes ownership and publishes S+b; B
        # leaves cleanly; A modifies its cached S.  If A's acquire does not
        # refresh S from the platter first, A logs and publishes S+a and
        # B's names are gone -- a same-generation directory revert that no
        # incarnation test can see.  So: A creates S with a-files and reads
        # it (the listing pulls S into A's cache); B adds b-files and
        # publishes; B departs; the rounds have A add r-files to S.  The
        # readback at the end wants a, b and r all present from both nodes.
        SD=$MNT/d0946age_$LABEL
        rs 300 "$A" "mkdir -p $SD; for i in \$(seq 1 $AGE_FILES); do fallocate -l 64k $SD/a\$i 2>/dev/null; done; sync -f $MNT; echo A_MADE=\$(ls $SD | grep -c '^a') A_LISTED=1" > "$OUT/age_a.txt" 2>&1
        rs 300 "$B" "for i in \$(seq 1 $((AGE_FILES / 2))); do fallocate -l 64k $SD/b\$i 2>/dev/null; done; sync -f $MNT; echo B_MADE=\$(ls $SD | grep -c '^b')" > "$OUT/age_b.txt" 2>&1
        echo "B_RM_RC=none (B keeps its names live)" > "$OUT/age_b_rm.txt"
        AD=$SD
        echo "  AGE $(cat "$OUT/age_a.txt" "$OUT/age_b.txt" "$OUT/age_b_rm.txt" 2>/dev/null | tr -d '\r' | tr '\n' ' ') wall=$(( $(date +%s) - ta ))s"
    else
    rs 300 "$A" "mkdir -p $AD; for i in \$(seq 1 $AGE_FILES); do fallocate -l 64k $AD/f\$i 2>/dev/null; done; echo A_MADE=\$(ls $AD | wc -l)" > "$OUT/age_a.txt" 2>&1
    rs 300 "$B" "mkdir -p $BD; for i in \$(seq 1 $AGE_FILES); do fallocate -l 64k $BD/f\$i 2>/dev/null; done; echo B_MADE=\$(ls $BD | wc -l)" > "$OUT/age_b.txt" 2>&1
    # B frees ITS OWN inodes.  No sync: the owed dinode writes are the point.
    rs 300 "$B" "rm -rf $BD; echo B_RM_RC=\$?" > "$OUT/age_b_rm.txt" 2>&1
    echo "  AGE $(cat "$OUT/age_a.txt" "$OUT/age_b.txt" "$OUT/age_b_rm.txt" 2>/dev/null | tr -d '\r' | tr '\n' ' ') wall=$(( $(date +%s) - ta ))s"
    fi

    # WINDOW THE DETECTION.  P-SOLE-SURVIVOR is printed once per episode and
    # survives in the ring buffer across mounts, so a whole-dmesg grep is
    # satisfied by ANY earlier run on this boot -- it would report the
    # transition as already seen before the peer has even left.  Mark kmsg
    # first and read only what follows the mark.
    SOLEMK="D0946-SOLEMARK-$LABEL-$$"
    rs 30 "$A" "echo '$SOLEMK' > /dev/kmsg"
    case "$SOLE" in
      umount)
        rs 180 "$B" "umount $MNT; echo B_UMOUNT_RC=\$?" > "$OUT/depart.txt" 2>&1 ;;
      death)
        # virsh destroy is a power cut: nothing is flushed, nothing published.
        timeout 60 sudo virsh -c qemu:///system destroy "$B" > "$OUT/depart.txt" 2>&1
        echo "B_DESTROY_RC=$?" >> "$OUT/depart.txt" ;;
      *) echo "RESULT: FAIL label=$LABEL unknown MXFS_D0946_SOLE='$SOLE' (want umount|death)"; exit 2 ;;
    esac
    echo "  DEPART $(cat "$OUT/depart.txt" 2>/dev/null | tr -d '\r' | tr '\n' ' ')"

    # WAIT FOR THE MEMBERSHIP TRANSITION, DO NOT ASSUME IT.  A death has to be
    # detected, fenced and replayed before the survivor is single-node; a run
    # that starts its rounds before that measures the multi-node path and
    # reports it as the sole-survivor path.  Bounded, and a timeout is a
    # failed precondition, never something to widen.
    solewait=$(rs 240 "$A" "
        for i in \$(seq 1 40); do
            ls $MNT >/dev/null 2>&1; stat -f $MNT >/dev/null 2>&1
            if dmesg | sed -n '/$SOLEMK/,\$p' | grep -aq 'P-SOLE-SURVIVOR'; then
                echo SOLE_SEEN_AT=\$i; break
            fi
            sleep 5
        done
        echo SOLE=\$(dmesg | sed -n '/$SOLEMK/,\$p' | grep -ac 'P-SOLE-SURVIVOR') MOUNTED=\$(grep -c ' $MNT mxfs ' /proc/mounts) MARKSEEN=\$(dmesg | grep -ac '$SOLEMK')")
    echo "  SOLEWAIT $(echo "$solewait" | tr '\n' ' ')"
    SOLEFIRED=$(echo "$solewait" | sed -n 's/.*SOLE=\([0-9]*\).*/\1/p'); SOLEFIRED=${SOLEFIRED:-0}
    # AND THE MARK ITSELF HAS TO BE THERE.  If the ring buffer rolled past it
    # the window is the whole buffer again and the count means nothing.
    MARKSEEN=$(echo "$solewait" | sed -n 's/.*MARKSEEN=\([0-9]*\).*/\1/p'); MARKSEEN=${MARKSEEN:-0}
    if [ "$MARKSEEN" = 0 ]; then
        echo "RESULT: FAIL label=$LABEL the kmsg mark $SOLEMK is not in $A's ring buffer"
        echo "        so the P-SOLE-SURVIVOR count below is unwindowed and proves nothing"
        exit 2
    fi
    if [ "$SOLEFIRED" = 0 ]; then
        echo "RESULT: FAIL label=$LABEL the sole-survivor state was NEVER reached (P-SOLE-SURVIVOR=0 since the mark)"
        echo "        every round below would measure the multi-node path; not run"
        exit 2
    fi
    # And the survivor must still be usable, or the rounds are vacuous again.
    wprobe=$(rs 60 "$A" "mkdir -p $MNT/.d0946sole.$$ 2>&1 && rmdir $MNT/.d0946sole.$$ 2>&1 && echo WRITABLE || echo NOTWRITABLE")
    case "$wprobe" in
      *WRITABLE*) echo "  SOLE_OK $A is a sole survivor and writable" ;;
      *) echo "RESULT: FAIL label=$LABEL $A is not writable after the departure: $wprobe"; exit 2 ;;
      esac
    # WHETHER A PASSENGER SLOT IS STALE IS A PLATTER QUESTION, NOT AN
    # AUTHORITY QUESTION.  P218 says which slots this node has no tenure for;
    # only mxfs_dino_clobber_probe (a FUA read of the platter at submission,
    # changecount compared per slot) says whether the cached image being
    # published is BEHIND what the departed peer last wrote.  It costs one
    # synchronous read per cluster write, so it lives behind
    # mxfs.dino_clobber_check, which the sole-survivor measurement turns on
    # for its rounds and off again at the end.  P-DINO-CLOBBER#N is a
    # regressed slot IN the I/O (a landed revert); P-DINO-CLOBBER-MASKED is
    # one the authority mask dropped.  On the whole-buffer arm nothing is
    # masked, so every regression there landed on the platter.
    if [ "$KNOBNAME" = partial_iwrite_sole ]; then
        cc=$(rs 25 "$A" "echo 1 > /sys/module/mxfs/parameters/dino_clobber_check 2>/dev/null; cat /sys/module/mxfs/parameters/dino_clobber_check 2>/dev/null || echo missing")
        echo "  INFO dino_clobber_check on $A = $cc (the platter-regression probe for every cluster write in the rounds)"
        [ "$cc" = 1 ] || { echo "RESULT: FAIL label=$LABEL could not enable dino_clobber_check on $A (got '$cc'): the rounds could count passengers but never say whether they are stale"; exit 2; }
    fi
fi

tot1=0; tot0=0; hits1=0; hits0=0; gate1=0; gate0=0; died=""
p951a=0; p951b=0; vref1=0; vref0=0; auth1=0; auth0=0; pass1=0; pass0=0; storm1=0; storm0=0; clob1=0; clob0=0; real1=0; real0=0
skip1=0; skip0=0; declined=0; operrs=0
s=$(date +%s)
# AN ALL-FIXED-PATH CAMPAIGN NEEDS NO RESCUE ARM.  Alternating with knob=0
# (the pre-fix whole-buffer write) lets a knob=0 round land what a knob=1
# round left unpublished -- s583c's root directory only reached the platter
# that way.  MXFS_D0946_ARM=1 pins every round to the fixed path so an
# omission has nothing to hide behind; unset keeps the A/B alternation.
ARMFIX=${MXFS_D0946_ARM:-}
for r in $(seq 1 "$ROUNDS"); do
    arm=$(( r % 2 ))          # alternate 1,0,1,0 — never blocked by arm
    [ -n "$ARMFIX" ] && arm=$ARMFIX
    MK="D0946-R$r-$(date +%s%N)"
    D=$MNT/d0946_${LABEL}_$r

    # PEER MODE IS THE ONE THE EVIDENCE NAMES.  The observed failure logged
    # 'P-CR63-SHELL ... src=7' and 'peer-freed dead shell': the inode whose
    # dinode was still live on the platter had been freed by the OTHER node, so
    # the write that would have made the free durable was the peer's to issue.
    # A same-node create/delete loop cannot produce that and, run alone, says
    # nothing — the first cut of this harness did exactly that and reported
    # NOT REPRODUCED in 8 rounds.
    if [ "$MODE" = dirchurn ] || [ "$MODE" = touch ] || [ "$MODE" = stalesrc ]; then
        : # everything happens in the measured block below
    elif [ "$MODE" = tight ]; then
        # PRIME then INTERLEAVE.  Each rm frees a number whose dinode image is
        # still owed to the platter; the very next create asks the allocator for
        # a number and the freed one is the lowest free agino, so it comes
        # straight back -- inside the publication window, which is the whole
        # condition.  No sync, by construction: a sync here would publish the
        # frees and there would be nothing left to test.
        rs 180 "$A" "mkdir -p $D 2>/dev/null; for i in \$(seq 1 $FILES); do fallocate -l $TIGHT_SZ $D/f\$i 2>/dev/null; done" >/dev/null
    elif [ "$MODE" = peer ]; then
        rs 90 "$A" "mkdir -p $D 2>/dev/null; for i in \$(seq 1 $FILES); do : > $D/f\$i 2>/dev/null; done; sync -f $MNT 2>/dev/null" >/dev/null
        # B frees them.  B must SEE them first — the lookup is what pulls the
        # peer's committed dirents over, and removing what you cannot see is a
        # no-op that would make the round silently vacuous.
        pf=$(rs 90 "$B" "ls $D 2>/dev/null | wc -l; for i in \$(seq 1 $FILES); do rm -f $D/f\$i 2>/dev/null; done; sync -f $MNT 2>/dev/null; echo peer_left=\$(ls $D 2>/dev/null | wc -l)")
        echo "     PEERFREE $(echo "$pf" | tr '\n' ' ')"
    fi

    out=$(rs 90 "$A" "
        echo '$MK' > /dev/kmsg 2>/dev/null
        echo $arm > $KNOB 2>/dev/null; krc=\$?
        knob=\$(cat $KNOB)
        # D-0948: the sparse-record hole counters are exact and resettable
        # (P-DIALLOC-HOLEMASK is ratelimited, so its line count is not a
        # measurement).  Zero them at the round start, read them at the end.
        echo 0 > /sys/module/mxfs/parameters/dialloc_holemask_n 2>/dev/null
        echo 0 > /sys/module/mxfs/parameters/dialloc_holepick_n 2>/dev/null
        t0=\$(date +%s%N)
        mkdir -p $D 2>/dev/null || echo MKDIR_FAIL
        cerr=0; derr=0
        if [ '$MODE' = dirchurn ]; then
            # Each iteration: build a directory big enough to own several
            # blocks, remove it, and IMMEDIATELY re-create one -- so the
            # allocator is asked for an inode while the removed directory's
            # own free is still unpublished and its in-core shell still
            # carries its blocks.
            for i in \$(seq 1 $FILES); do
                d=$D/sub\$i
                mkdir -p \$d 2>/dev/null || cerr=\$((cerr+1))
                for j in \$(seq 1 $DIRENTS); do : > \$d/e\$j 2>/dev/null; done
                rm -rf \$d 2>/dev/null || derr=\$((derr+1))
                mkdir -p \$d 2>/dev/null || cerr=\$((cerr+1))
                rm -rf \$d 2>/dev/null || derr=\$((derr+1))
            done
            srch=0
        elif [ '$MODE' = touch ]; then
            # Re-dirty A's OWN aged files only (a timestamp change logs the
            # inode); the sync flushes them, and every cluster write carries
            # whatever A's cache holds for the peer's slots beside them.
            for i in \$(seq 2 2 $AGE_FILES); do
                touch $AD/a\$i 2>/dev/null || cerr=\$((cerr+1))
            done
            sync -f $MNT 2>/dev/null; srch=\$?
        elif [ '$MODE' = stalesrc ]; then
            # Add names to the directory the departed peer modified after
            # A cached it.  Every add is a directory modification from A's
            # cached image; the readback at the end says whether B's names
            # survived it.
            for i in \$(seq 1 $FILES); do
                fallocate -l 64k $AD/r${r}_\$i 2>/dev/null || cerr=\$((cerr+1))
            done
            sync -f $MNT 2>/dev/null; srch=\$?
        elif [ '$MODE' = tight ]; then
            for i in \$(seq 1 $FILES); do
                rm -f $D/f\$i 2>/dev/null || derr=\$((derr+1))
                fallocate -l $TIGHT_SZ $D/g\$i 2>/dev/null || cerr=\$((cerr+1))
            done
            for i in \$(seq 1 $FILES); do
                rm -f $D/g\$i 2>/dev/null || derr=\$((derr+1))
                fallocate -l $TIGHT_SZ $D/f\$i 2>/dev/null || cerr=\$((cerr+1))
            done
            srch=0
        else
            for i in \$(seq 1 $FILES); do : > $D/f\$i 2>/dev/null || cerr=\$((cerr+1)); done
            sync -f $MNT 2>/dev/null
            for i in \$(seq 1 $FILES); do rm -f $D/f\$i 2>/dev/null || derr=\$((derr+1)); done
            rmdir $D 2>/dev/null
            sync -f $MNT 2>/dev/null; srch=\$?
        fi
        t1=\$(date +%s%N)
        echo ROUND r=$r knob=\$knob krc=\$krc cerr=\$cerr derr=\$derr syncrc=\$srch ms=\$(( (t1-t0)/1000000 )) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)
        dmesg | sed -n '/$MK/,\$p' > /tmp/d0946_win.txt
        echo DISKLIVE=\$(grep -ac 'P-CR62 .*verdict=DISK-LIVE' /tmp/d0946_win.txt) \
             DEFERLIVE=\$(grep -ac 'P-CR63-DEFER-DISKLIVE' /tmp/d0946_win.txt) \
             CR3=\$(grep -ac 'P-CR3-CANCEL' /tmp/d0946_win.txt) \
             SHUT=\$(grep -ac 'Shutting down filesystem\|P-WITHDRAW ' /tmp/d0946_win.txt)
        # A SUBSTRING GREP COUNTED THE SUMMARY LINE AS A REFUSAL.  VQUAR was
        # 'P-DIALLOC-DISKLIVE', which also matches P-DIALLOC-DISKLIVE-STORM --
        # the per-allocation summary printed once per 64 rejected candidates.
        # A run that stormed reported 72833 'validator refusals' that were
        # overwhelmingly storm lines, which reads as an enormous find and is
        # an artefact of the grep.  They are counted separately now, and
        # VSTORM is the one to watch: a storm means the allocator restarted
        # past its cap and FAILED THE CREATE, which is a different event from
        # a candidate being refused.
        # THE SOLE-SURVIVOR GATE, counted per round in the round's own window.
        # P951 counts allocations that took the UNVALIDATED path because the
        # mount is single-node NOW; VREFUSE counts candidates the validator
        # actually refused.  A round with P951>0 and VREFUSE=0 says the guard
        # was off and found nothing; P951=0 with VREFUSE>0 says it ran and did.
        echo P951=\$(grep -ac 'P951-VALIDATE-OFF-SOLE' /tmp/d0946_win.txt) \
             VEIO=\$(grep -ac 'P-DIALLOC-VALIDATE-EIO' /tmp/d0946_win.txt) \
             VQUAR=\$(grep -ac 'P-DIALLOC-DISKLIVE agno' /tmp/d0946_win.txt) \
             VSTORM=\$(grep -ac 'P-DIALLOC-DISKLIVE-STORM' /tmp/d0946_win.txt) \
             VNOMAGIC=\$(grep -ac 'P947-VALIDATE-NOMAGIC' /tmp/d0946_win.txt) \
             SOLEP=\$(grep -ac 'P-SOLE-SURVIVOR' /tmp/d0946_win.txt)
        # THE CENSUS.  P952-SOLE-SKIP names every single-node fast path this
        # survivor actually reaches, first hit per site.  Which guards a sole
        # survivor takes has never been observed -- it has only ever been
        # reasoned about from the source, and the class has already survived
        # one closure that way.
        echo P952=\$(grep -ac 'P952-SOLE-SKIP' /tmp/d0946_win.txt) \\
             P952SITES=\$(grep -ao 'P952-SOLE-SKIP site=[a-z_]*' /tmp/d0946_win.txt | sed 's/.*site=//' | sort -u | tr '\\n' ',')
        # THE INODE-CLUSTER AUTHORITY DETECTOR.  P218 is always-on but lives
        # INSIDE mxfs_submit_partial_inode_write, which a single-node mount
        # never enters -- so for a sole survivor it is silent by construction,
        # not by health.  With partial_iwrite_sole=1 it runs; PASSENGER counts
        # writes carrying slots this node neither logged nor holds, and WHOLE
        # says the shipped path would have published them anyway.
        echo P218=\$(grep -ac 'P218-CLUSTER-AUTHORITY' /tmp/d0946_win.txt) \
             P218WHOLE=\$(grep -ac 'P218-CLUSTER-AUTHORITY .*-> WHOLE' /tmp/d0946_win.txt) \
             P218PART=\$(grep -ac 'P218-CLUSTER-AUTHORITY .*-> PARTIAL' /tmp/d0946_win.txt) \
             PASSPR=\$(grep -a 'P218-CLUSTER-AUTHORITY' /tmp/d0946_win.txt | sed -n 's/.*no_write_tenure=\\([0-9]*\\).*/\\1/p' | awk '{s+=\$1} END{print s+0}') \
             PASSGEN=\$(grep -a 'P218-CLUSTER-AUTHORITY' /tmp/d0946_win.txt | sed -n 's/.*gen_mismatch=\\([0-9]*\\).*/\\1/p' | awk '{s+=\$1} END{print s+0}') \
             PASSNOC=\$(grep -a 'P218-CLUSTER-AUTHORITY' /tmp/d0946_win.txt | sed -n 's/.*no_incore=\\([0-9]*\\).*/\\1/p' | awk '{s+=\$1} END{print s+0}') \
             PASSWR=\$(grep -a 'P218-CLUSTER-AUTHORITY' /tmp/d0946_win.txt | sed -n 's/.*unlogged_written=\\([0-9]*\\).*/\\1/p' | awk '{s+=\$1} END{print s+0}')
        # THE GATE UNDER TEST HAS TO BE SHOWN TO HAVE RUN.  A round with zero
        # PUBPEND and zero ALLOW did not exercise the pubob arm at all, and its
        # clean result means nothing -- a silent instrument and a clean system
        # read identically otherwise.
        # THE PLATTER VERDICT PER ROUND (see the pre-phase): regressions in
        # the I/O, regressions the mask dropped, and the passenger lines
        # themselves so each unauthorised slot is named (ino, image mode and
        # generation, whether an in-core inode existed, whether it was
        # skipped) rather than summed.
        # PASSSKIP is the mask itself: P218-PASSENGER-SKIP is printed when the
        # un-logged slots this node has no write tenure for are DROPPED from
        # the write.  On the fixed arm (partial_iwrite_sole=1, the 0.83.3
        # default) a passenger line without a skip line would mean the
        # detector saw the slot and the write carried it anyway.
        echo CLOB=\$(grep -ac 'P-DINO-CLOBBER#' /tmp/d0946_win.txt) \
             CLOBMASK=\$(grep -ac 'P-DINO-CLOBBER-MASKED' /tmp/d0946_win.txt) \
             CLOBREALLOC=\$(grep -ac 'P-DINO-CLOBBER-REALLOC' /tmp/d0946_win.txt) \
             PASSLINES=\$(grep -ac 'P218-CLUSTER-PASSENGER' /tmp/d0946_win.txt) \
             PASSSKIP=\$(grep -ac 'P218-PASSENGER-SKIP' /tmp/d0946_win.txt) \
             SKIPDECLINED=\$(grep -ac 'P218-SKIP-DECLINED' /tmp/d0946_win.txt)
        grep -a 'P218-CLUSTER-PASSENGER\|P-DINO-CLOBBER#\|P-DINO-CLOBBER-MASKED\|P-DINO-CLOBBER-REALLOC\|P218-CLUSTER-AUTHORITY' /tmp/d0946_win.txt | head -12
        echo PUBPEND=\$(grep -ac 'P946-VALIDATE-PUBPEND' /tmp/d0946_win.txt) \
             PUBALLOW=\$(grep -ac 'P946-VALIDATE-ALLOW' /tmp/d0946_win.txt) \
             DRIVEOK=\$(grep -ac 'P946-PUBDRIVE-OK' /tmp/d0946_win.txt) \
             DRIVETO=\$(grep -ac 'P946-PUBDRIVE-TIMEOUT' /tmp/d0946_win.txt) \
             PSTORM=\$(grep -ac 'P946-DIALLOC-PUBPEND-STORM' /tmp/d0946_win.txt) \
             PYIELD=\$(grep -ac 'P946-DIALLOC-PUBPEND-YIELD' /tmp/d0946_win.txt) \
             CHAINLIVE=\$(grep -ac 'P-FREEOB-CHAIN-LIVE' /tmp/d0946_win.txt) \
             DEADSHELL=\$(grep -ac 'P-CR63-DEADSHELL-DEFER' /tmp/d0946_win.txt) \
             CR63SHELL=\$(grep -ac 'P-CR63-SHELL' /tmp/d0946_win.txt) \
             CR63LINK=\$(grep -ac 'P-CR63-DEADSHELL ' /tmp/d0946_win.txt) \
             CR63GRAB=\$(grep -ac 'P-CR63-IGRAB-FAIL' /tmp/d0946_win.txt)
        # ALLOCATOR EXHAUSTION SIGNALS, per round and inside the round's own
        # window.  A whole-dmesg count of these is worthless on this workload:
        # the ring buffer rolls over inside a single round, so both a marker
        # and the early lines are gone by the time anything reads them.
        # SWEPT/GROW say whether the AG was declared spent and a fresh inode
        # chunk carved -- the cost of tallying our own owed writes as peer
        # contention, and the supply of fresh carves D-0948 feeds on.
        echo SWEPT=\$(grep -ac 'P-DIALLOC-RESV-SWEPT' /tmp/d0946_win.txt) \
             GROW=\$(grep -ac 'P-DIALLOC-RESV-GROW' /tmp/d0946_win.txt) \
             CARVE=\$(grep -ac 'P-AGIFC-MOD site=ag_alloc' /tmp/d0946_win.txt) \
             P36=\$(grep -ac 'P36-STACK' /tmp/d0946_win.txt) \
             RBOK=\$(grep -ac 'P948-SYNCINIT-READBACK-OK' /tmp/d0946_win.txt) \
             RBBAD=\$(grep -ac 'P948-SYNCINIT-READBACK agno' /tmp/d0946_win.txt) \
             COOLMAX=\$(grep -a 'P-DIALLOC-RESV-SWEPT' /tmp/d0946_win.txt | sed -n 's/.*cool=\\([0-9]*\\).*/\\1/p' | sort -n | tail -1)
        # D-0948: SPARSE records with holes BELOW a free inode.  HOLEMASK is
        # the exact count of picks that met such a record (the fixed walk
        # masked the holes; the control arm, dbg_dialloc_pick_holes=1, did
        # not); HOLEPICK is the exact count of candidates taken from inside a
        # hole, which only the control arm can produce.  Both are the module
        # counters zeroed at the round start, not dmesg line counts.
        echo HOLEMASK=\$(cat /sys/module/mxfs/parameters/dialloc_holemask_n 2>/dev/null || echo NA) \
             HOLEPICK=\$(cat /sys/module/mxfs/parameters/dialloc_holepick_n 2>/dev/null || echo NA) \
             HOLEPICKLINES=\$(grep -ac 'P-DIALLOC-HOLEPICK' /tmp/d0946_win.txt) \
             HOLEKNOB=\$(cat /sys/module/mxfs/parameters/dbg_dialloc_pick_holes 2>/dev/null || echo NA)
        grep -a 'P-DIALLOC-HOLEMASK\|P-DIALLOC-HOLEPICK' /tmp/d0946_win.txt | head -4
        grep -a 'P-CR62 \|P-RECYCLE-GATE \|P-CR3-CANCEL' /tmp/d0946_win.txt | head -6
    ")
    echo "$out" > "$OUT/round_$r.txt"

    line=$(echo "$out" | grep -a '^ROUND ' | head -1)
    # NO ROUND LINE IS A HARNESS FAILURE, NOT A DEATH.  The remote command
    # did not run to its summary (a local expansion error, an ssh failure,
    # the 90 s bound); reading its absence as mounted=0 reported "the
    # filesystem died" on a healthy rig (s602a).
    [ -n "$line" ] || { echo "ABORT: round $r produced no ROUND line — the remote command failed or timed out; a harness failure, not a result (captured: $(echo "$out" | head -c 200 | tr '\n' ' '))"; exit 2; }
    # A FAILED CREATE OR DELETE IS A RESULT.  s583c round 1 reported cerr=799
    # and the run's own verdict lines read clean, because nothing summed the
    # field: the survivor's new directory had been poisoned ESTALE.
    ncerr=$(echo "$line" | sed -n 's/.*cerr=\([0-9]*\).*/\1/p'); ncerr=${ncerr:-0}
    nderr=$(echo "$line" | sed -n 's/.*derr=\([0-9]*\).*/\1/p'); nderr=${nderr:-0}
    operrs=$((operrs+ncerr+nderr))
    [ $((ncerr+nderr)) -gt 0 ] && echo "     OPERATION FAILURES round $r arm=$arm cerr=$ncerr derr=$nderr — the workload could not run; this round is a FAIL whatever the probes say"
    cnt=$(echo "$out" | grep -a '^DISKLIVE=' | head -1)
    gate=$(echo "$out" | grep -a '^PUBPEND=' | head -1)
    alloc=$(echo "$out" | grep -a '^SWEPT=' | head -1)
    solec=$(echo "$out" | grep -a '^P951=' | head -1)
    authc=$(echo "$out" | grep -a '^P218=' | head -1)
    censc=$(echo "$out" | grep -a '^P952=' | head -1)
    dl=$(echo "$cnt" | sed -n 's/.*DISKLIVE=\([0-9]*\).*/\1/p')
    sh=$(echo "$cnt" | sed -n 's/.*SHUT=\([0-9]*\).*/\1/p')
    mnt=$(echo "$line" | sed -n 's/.*mounted=\([0-9]*\).*/\1/p')
    ms=$(echo "$line" | sed -n 's/.*ms=\([0-9]*\).*/\1/p')
    dl=${dl:-0}; sh=${sh:-0}; mnt=${mnt:-0}; ms=${ms:-0}
    echo "  R$r arm=$arm $line"
    echo "     $cnt"
    echo "     ${gate:-PUBPEND=? (gate counters missing — the round proves nothing)}"
    echo "     ${alloc:-SWEPT=? (allocator counters missing)}"
    holec=$(echo "$out" | grep -a '^HOLEMASK=' | head -1)
    echo "     ${holec:-HOLEMASK=? (sparse-hole counters missing — this build predates the D-0948 pick fix)}"
    nhm=$(echo "$holec" | sed -n 's/.*HOLEMASK=\([0-9]*\).*/\1/p'); nhm=${nhm:-0}
    nhp=$(echo "$holec" | sed -n 's/.*HOLEPICK=\([0-9]*\).*/\1/p'); nhp=${nhp:-0}
    holemask_total=$((${holemask_total:-0}+nhm)); holepick_total=$((${holepick_total:-0}+nhp))
    [ "$nhp" -gt 0 ] && echo "     HOLE PICK round $r arm=$arm holepick=$nhp — a candidate inside a sparse record's hole was handed out (D-0948's mechanism; expected ONLY under dbg_dialloc_pick_holes=1)"
    [ -n "$SOLE" ] && echo "     ${solec:-P951=? (sole-survivor counters missing — this build predates the probe)}"
    [ -n "$SOLE" ] && echo "     ${authc:-P218=? (authority counters missing — this build predates the probe)}"
    [ -n "$SOLE" ] && echo "     ${censc:-P952=? (census counters missing — this build predates the probe)}"
    [ -n "$SOLE" ] && echo "$out" | grep -a 'P952-SOLE-SKIP' | cut -c1-150 | sed 's/^/       /'
    if [ -n "$SOLE" ] && [ "$KNOBNAME" = partial_iwrite_sole ]; then
        clobc=$(echo "$out" | grep -a '^CLOB=' | head -1)
        echo "     ${clobc:-CLOB=? (clobber counters missing)}"
        echo "$out" | grep -a 'P218-CLUSTER-PASSENGER\|P-DINO-CLOBBER#\|P-DINO-CLOBBER-MASKED\|P-DINO-CLOBBER-REALLOC' | cut -c1-230 | sed 's/^/       /'
        nclob=$(echo "$clobc" | sed -n 's/.*CLOB=\([0-9]*\).*/\1/p'); nclob=${nclob:-0}
        nreal=$(echo "$clobc" | sed -n 's/.*CLOBREALLOC=\([0-9]*\).*/\1/p'); nreal=${nreal:-0}
        nskip=$(echo "$clobc" | sed -n 's/.*PASSSKIP=\([0-9]*\).*/\1/p'); nskip=${nskip:-0}
        ndecl=$(echo "$clobc" | sed -n 's/.*SKIPDECLINED=\([0-9]*\).*/\1/p'); ndecl=${ndecl:-0}
        declined=$((declined+ndecl))
        if [ "$arm" = 1 ]; then clob1=$((clob1+nclob)); real1=$((real1+nreal)); skip1=$((skip1+nskip)); else clob0=$((clob0+nclob)); real0=$((real0+nreal)); skip0=$((skip0+nskip)); fi
    fi
    echo "$out" | grep -a 'P-CR62 \|P-RECYCLE-GATE ' | head -3 | cut -c1-180 | sed 's/^/       /'

    pp=$(echo "$gate" | sed -n 's/.*PUBPEND=\([0-9]*\).*/\1/p'); pp=${pp:-0}
    pa=$(echo "$gate" | sed -n 's/.*PUBALLOW=\([0-9]*\).*/\1/p'); pa=${pa:-0}
    n951=$(echo "$solec" | sed -n 's/.*P951=\([0-9]*\).*/\1/p'); n951=${n951:-0}
    nveio=$(echo "$solec" | sed -n 's/.*VEIO=\([0-9]*\).*/\1/p'); nveio=${nveio:-0}
    nvq=$(echo "$solec" | sed -n 's/.*VQUAR=\([0-9]*\).*/\1/p'); nvq=${nvq:-0}
    nvnm=$(echo "$solec" | sed -n 's/.*VNOMAGIC=\([0-9]*\).*/\1/p'); nvnm=${nvnm:-0}
    nvst=$(echo "$solec" | sed -n 's/.*VSTORM=\([0-9]*\).*/\1/p'); nvst=${nvst:-0}
    nvref=$((nveio+nvq+nvnm))
    [ "$nvst" -gt 0 ] && echo "     NOTE round $r stormed ($nvst P-DIALLOC-DISKLIVE-STORM): the allocator exhausted its candidate retries and FAILED CREATES — that is not a refusal count, and D-0947 (a chunk this mount logged but has not destaged reads as unvalidatable) produces it on a healthy filesystem"
    if [ "$arm" = 1 ]; then storm1=$((storm1+nvst)); else storm0=$((storm0+nvst)); fi
    for f in P218 PASSPR PASSGEN PASSNOC PASSWR; do
        v=$(echo "$authc" | sed -n "s/.*$f=\([0-9]*\).*/\1/p"); v=${v:-0}
        eval "n$f=$v"
    done
    npass=$((nPASSPR+nPASSGEN+nPASSNOC))
    if [ "$arm" = 1 ]; then tot1=$((tot1+1)); hits1=$((hits1+dl)); gate1=$((gate1+pp));
                            p951a=$((p951a+n951)); vref1=$((vref1+nvref));
                            auth1=$((auth1+nP218)); pass1=$((pass1+npass));
                       else tot0=$((tot0+1)); hits0=$((hits0+dl)); gate0=$((gate0+pa));
                            p951b=$((p951b+n951)); vref0=$((vref0+nvref));
                            auth0=$((auth0+nP218)); pass0=$((pass0+npass)); fi
    # budget: the per-round bound is an assertion, not a safety net.
    [ "$ms" -gt 30000 ] && echo "     the budget rule round wall ${ms}ms exceeds the 30000ms derived bound"
    if [ "$sh" != "0" ] || [ "$mnt" != "1" ]; then
        died="round $r arm $arm (shut=$sh mounted=$mnt)"
        echo "  STOP — the filesystem died; that is the result, not an error to recover from"
        break
    fi
done
wall=$(( $(date +%s) - s ))

echo "D0946-DISKLIVE label=$LABEL mode=$MODE knob=$KNOBNAME sv=$SV rounds_knob1=$tot1 disklive_knob1=$hits1 gatefire_knob1=$gate1 rounds_knob0=$tot0 disklive_knob0=$hits0 gatefire_knob0=$gate0 died='${died:-no}' operation_failures=$operrs sparse_holemask_picks=${holemask_total:-0} hole_picks=${holepick_total:-0} wall=${wall}s evidence=$OUT"
# D-0948's own verdict, in terms of what the rounds met.  A pick that met a
# sparse record with holes below a free inode is the only situation in which
# the fixed walk and the pre-fix walk differ; a lap that met none says
# nothing about the fix.
if [ "${holepick_total:-0}" -gt 0 ]; then
    echo "  HOLE-READ: FAIL — ${holepick_total} candidate(s) were taken from inside a sparse inode record's hole (a block never carved for inodes); on the control arm (dbg_dialloc_pick_holes=1) that is the D-0948 chain reproduced, on the fixed arm it is a regression"
elif [ "${holemask_total:-0}" -gt 0 ]; then
    echo "  HOLE-READ: ${holemask_total} pick(s) met a sparse inode record with holes below a free inode and walked only its carved inodes (dialloc_holemask_n); no candidate came from a hole"
else
    echo "  HOLE-READ: VACUOUS for D-0948 — no pick met a sparse inode record with holes below a free inode, so the fixed and the pre-fix walk were indistinguishable on this lap"
fi
if [ -n "$SOLE" ]; then
    # THE SURVIVOR'S OWN DURABILITY, over the WHOLE sole-survivor phase (from
    # the departure mark), not per round: the round prime (mkdir + creates)
    # runs before the round marker, and s583c's stranded directory was
    # created, skipped and poisoned entirely inside that prime.
    #   P56-NL-LOGGED-DIR-SKIP  a logged directory image dropped from a
    #                           cluster write (never reaches the platter)
    #   P34H-INCARN-POISON      the survivor disowned one of its own live
    #                           inodes after reading the platter (ESTALE)
    #   P-SURVIVOR-RELOAD       the sole-survivor entry point re-read an
    #                           inode from the platter for a pending mark
    solewin=$(rs 60 "$A" "dmesg | sed -n '/$SOLEMK/,\$p' > /tmp/d0946_sole.txt; echo MARK=\$(grep -ac '$SOLEMK' /tmp/d0946_sole.txt) NLDIRSKIP=\$(grep -ac 'P56-NL-LOGGED-DIR-SKIP' /tmp/d0946_sole.txt) POISON=\$(grep -ac 'P34H-INCARN-POISON' /tmp/d0946_sole.txt) POISONED_INOS=\$(grep -a 'P34H-INCARN-POISON' /tmp/d0946_sole.txt | grep -ao 'ino=[0-9]*' | sort -u | wc -l) SURVRELOAD=\$(grep -ac 'P-SURVIVOR-RELOAD' /tmp/d0946_sole.txt); grep -a 'P56-NL-LOGGED-DIR-SKIP' /tmp/d0946_sole.txt | head -4 | cut -c1-200; grep -a 'P34H-INCARN-POISON' /tmp/d0946_sole.txt | head -2 | cut -c1-200")
    echo "  SOLEWIN $(echo "$solewin" | head -1)"
    echo "$solewin" | tail -n +2 | sed 's/^/       /'
    smark=$(echo "$solewin" | head -1 | sed -n 's/.*MARK=\([0-9]*\).*/\1/p'); smark=${smark:-0}
    nldirskip=$(echo "$solewin" | head -1 | sed -n 's/.*NLDIRSKIP=\([0-9]*\).*/\1/p'); nldirskip=${nldirskip:-0}
    npoison=$(echo "$solewin" | head -1 | sed -n 's/.*POISON=\([0-9]*\).*/\1/p'); npoison=${npoison:-0}
    if [ "$smark" = 0 ]; then
        echo "  SOLE-DURABILITY-READ: UNREADABLE — the departure mark has rolled out of $A's ring buffer, so the skip and poison counts above are unwindowed"
    elif [ "$nldirskip" -gt 0 ] || [ "$npoison" -gt 0 ]; then
        echo "  SOLE-DURABILITY-READ: FAIL — $nldirskip logged directory image(s) were dropped from the survivor's cluster writes and $npoison poison line(s) fired; a directory change on the survivor did not reach the platter (s583c: ino 8463296, ESTALE, 799 failed creates)"
    else
        echo "  SOLE-DURABILITY-READ: no logged directory image was dropped and nothing was poisoned on the survivor since the departure"
    fi
    # PUT THE PEER BACK.  A harness that leaves the rig one node short makes
    # every later run on this fleet a different experiment than it claims to
    # be, and the next session inherits a cluster it did not break.
    case "$SOLE" in
      umount) rs 180 "$B" "mount -t mxfs $DEV $MNT; echo B_REMOUNT_RC=\$?" > "$OUT/restore.txt" 2>&1 ;;
      death)  timeout 120 sudo virsh -c qemu:///system start "$B" > "$OUT/restore.txt" 2>&1
              echo "B_START_RC=$?" >> "$OUT/restore.txt"
              echo "NOTE a virsh-destroyed node comes back without the NFS /src mount; it needs scripts/module_swap_deploy.sh before it can rejoin" >> "$OUT/restore.txt" ;;
    esac
    echo "  RESTORE $(cat "$OUT/restore.txt" 2>/dev/null | tr -d '\r' | tr '\n' ' ')"
    if [ "$KNOBNAME" = partial_iwrite_sole ]; then
        cc=$(rs 25 "$A" "echo 0 > /sys/module/mxfs/parameters/dino_clobber_check 2>/dev/null; cat /sys/module/mxfs/parameters/dino_clobber_check 2>/dev/null")
        echo "  INFO dino_clobber_check restored on $A = ${cc:-?}"
    fi
    # WHO CAN READ COLD.  After a clean departure the peer remounts and its
    # empty cache is the cold reader.  After a death the peer comes back
    # unmounted (it needs a prep before it can rejoin), so a readback from
    # it is NO OUTPUT, and s583k scored that vacuity as a FAIL.  The cold
    # reader for a death lap is the survivor itself after an unmount and
    # remount, which empties its cache the same way.
    RBNODES="$A $B"
    COLDNODE=$B
    if [ "$SOLE" = death ]; then
        arm_rm=$(rs 180 "$A" "umount $MNT; echo A_UMOUNT_RC=\$?; mount -t mxfs $DEV $MNT; echo A_REMOUNT_RC=\$?" | tr '\n' ' ')
        echo "  COLDREMOUNT $arm_rm"
        case "$arm_rm" in
          *A_UMOUNT_RC=0*A_REMOUNT_RC=0*) ;;
          *) echo "  COLD-READ: FAIL — the survivor could not be unmounted and remounted for a cold readback ($arm_rm)" ;;
        esac
        RBNODES="$A"
        COLDNODE=$A
    fi
    # THE SURVIVOR'S NAMESPACE, READ COLD.  B's cache was empty when it came
    # back, so what it sees of the survivor's round directories is what the
    # platter holds: every round directory with every file the survivor
    # created in it (tight/local leave FILES f-files per round; stalesrc
    # leaves the a-files and b-files it names).  A directory the survivor
    # created but never published reads as missing or ESTALE here.
    if [ "$MODE" = tight -o "$MODE" = local ]; then
        cold=$(rs 120 "$COLDNODE" "okd=0; badd=0; for r in \$(seq 1 $ROUNDS); do n=\$(ls $MNT/d0946_${LABEL}_\$r 2>/dev/null | grep -c '^f'); if [ \"\$n\" = $FILES ]; then okd=\$((okd+1)); else badd=\$((badd+1)); echo COLD_DIR r=\$r files=\$n want=$FILES; fi; done; echo COLD_READBACK node=$COLDNODE dirs_ok=\$okd dirs_bad=\$badd")
        echo "  $(echo "$cold" | tr '\n' ' ')"
        cbad=$(echo "$cold" | sed -n 's/.*dirs_bad=\([0-9]*\).*/\1/p'); cbad=${cbad:-0}
        cok=$(echo "$cold" | sed -n 's/.*dirs_ok=\([0-9]*\).*/\1/p'); cok=${cok:-0}
        if [ "$cbad" -gt 0 ] || [ "$cok" = 0 ]; then
            echo "  COLD-READ: FAIL — $cbad of the survivor's round directories are not on the platter as the survivor left them (ok=$cok)"
        else
            echo "  COLD-READ: all $cok round directories read back complete from $COLDNODE's cold cache"
        fi
    fi
    if [ "$MODE" = stalesrc ]; then
        # THE STALE-SOURCE COUNTEREXAMPLE (design consult, sess583): A cached
        # S, B modified S and left, A modified S again.  Both changes must
        # survive; a survivor that modified its stale cached image would
        # have published S+a over S+b and lost B's names.
        for n in $RBNODES; do
            rb=$(rs 120 "$n" "na=\$(ls $SD 2>/dev/null | grep -c '^a'); nb=\$(ls $SD 2>/dev/null | grep -c '^b'); nr=\$(ls $SD 2>/dev/null | grep -c '^r'); echo STALESRC_READBACK node=$n cold=\$([ $n = $COLDNODE ] && echo 1 || echo 0) a=\$na want_a=$AGE_FILES b=\$nb want_b=$((AGE_FILES / 2)) r=\$nr want_r=$((ROUNDS * FILES))")
            echo "  ${rb:-STALESRC_READBACK node=$n NO OUTPUT}"
            echo "$rb" | grep -q "a=$AGE_FILES want_a=$AGE_FILES b=$((AGE_FILES / 2)) want_b=$((AGE_FILES / 2)) r=$((ROUNDS * FILES)) want_r" || echo "  STALESRC-READ: FAIL on $n — a name set is short: B's additions to the directory A had cached, or A's later additions, did not both survive"
        done
    fi
    if [ "$MODE" = touch ]; then
        # THE USER-VISIBLE CONSEQUENCE.  B's files were live when it left.
        # If a survivor flush published a free image over them, reading them
        # now fails (a free dinode under an allocated number).  Read from
        # BOTH nodes: the survivor's own cache may still answer from core.
        for n in $RBNODES; do
            rb=$(rs 120 "$n" "ok=0; bad=0; for i in \$(seq 1 $((AGE_FILES / 2))); do if cat $SD/b\$i > /dev/null 2>&1; then ok=\$((ok+1)); else bad=\$((bad+1)); fi; done; echo READBACK_B node=$n cold=\$([ $n = $COLDNODE ] && echo 1 || echo 0) ok=\$ok bad=\$bad")
            echo "  ${rb:-READBACK_B node=$n NO OUTPUT}"
        done
    fi
    echo "D0946-SOLE label=$LABEL depart=$SOLE sole_probe=$SOLEFIRED unvalidated_knob1=$p951a unvalidated_knob0=$p951b validator_refusals_knob1=$vref1 validator_refusals_knob0=$vref0 storms_knob1=$storm1 storms_knob0=$storm0 authority_lines_knob1=$auth1 authority_lines_knob0=$auth0 passenger_slots_knob1=$pass1 passenger_slots_knob0=$pass0 platter_regressions_in_io_knob1=$clob1 platter_regressions_in_io_knob0=$clob0 passenger_skips_knob1=$skip1 passenger_skips_knob0=$skip0 skip_declined=$declined"
    if [ "$KNOBNAME" = partial_iwrite_sole ]; then
        # THE MASK ASSERTION (D-0955 fix, 0.83.3).  On the knob=1 arm a sole
        # survivor stays on the partial path: every write that carried
        # passengers must also have dropped them.  knob=0 is the pre-fix
        # whole-buffer arm and masks nothing by construction.
        if [ "$skip1" -gt 0 ] && [ "$declined" = 0 ]; then
            echo "  MASK-READ: $skip1 sole-survivor cluster write(s) on the knob=1 arm dropped their"
            echo "        un-logged no-tenure slots (P218-PASSENGER-SKIP); knob=0 dropped $skip0. No"
            echo "        write was declined back to whole-buffer (P218-SKIP-DECLINED=0)."
        elif [ "$declined" -gt 0 ]; then
            echo "  MASK-READ: $declined write(s) hit P218-SKIP-DECLINED — the mask emptied a write"
            echo "        that still owed a sector and it fell back to whole-buffer. That is a"
            echo "        should-never-happen assertion firing, not a pass."
        elif [ "$pass1" -gt 0 ]; then
            echo "  MASK-READ: $pass1 passenger slot(s) on the knob=1 arm and NO P218-PASSENGER-SKIP"
            echo "        line — the detector saw them and the write carried them anyway."
        else
            echo "  MASK-READ: no passenger reached the knob=1 arm, so the mask had nothing to drop"
            echo "        (vacuous for the mask; the shape did not produce a no-tenure slot)."
        fi
        if [ $((clob1+clob0)) -gt 0 ]; then
            echo "  PLATTER-READ: $((clob1+clob0)) slot(s) whose cached image was BEHIND the platter were"
            echo "        in a sole survivor's cluster write I/O (knob1 $clob1, knob0 $clob0): a landed"
            echo "        revert of the departed peer's last durable inode image."
        elif [ $((real1+real0)) -gt 0 ]; then
            echo "  PLATTER-READ: no cluster write in any round carried a slot behind the platter,"
            echo "        and the probe was live: $((real1+real0)) write(s) carried new incarnations over"
            echo "        the peer's freed images (knob1 $real1, knob0 $real0). The passengers above"
            echo "        were unauthorised but not stale on this workload."
        else
            echo "  PLATTER-READ: VACUOUS — the probe never reported a regression OR a reallocation"
            echo "        in any round, so nothing shows the FUA-read compare ran on these writes."
        fi
    fi
    if [ $((pass1+pass0)) -gt 0 ]; then
        echo "  AUTHORITY-READ: $((pass1+pass0)) inode slot(s) with NO write authority rode a"
        echo "        sole survivor's inode-cluster write (knob1 $pass1, knob0 $pass0) across"
        echo "        $((auth1+auth0)) detector line(s) — the shipped path publishes these unchecked."
    elif [ $((auth1+auth0)) -gt 0 ]; then
        echo "  AUTHORITY-READ: the detector ran ($((auth1+auth0)) line(s)) and found no unauthorised"
        echo "        passenger slot in any sole-survivor cluster write."
    else
        echo "  AUTHORITY-READ: the detector never produced a line — either no inode-cluster"
        echo "        write happened in the arm that enters the path, or the build predates it."
    fi
    # WHAT EACH SHAPE MEANS.  The knob under test is dialloc_validate_sole:
    # arm 1 keeps the candidate validator running for a sole survivor, arm 0
    # is the shipped behaviour that turns it off the instant the peer leaves.
    if [ $((p951a+p951b)) = 0 ] && [ $((vref1+vref0)) = 0 ]; then
        echo "  SOLE-READ: VACUOUS — neither the unvalidated path nor the validator was"
        echo "        reached in any round, so this run says nothing about the gate."
    elif [ $((storm1+storm0)) -gt 0 ]; then
        echo "  SOLE-READ: INCONCLUSIVE — the validator STORMED ($((storm1+storm0)) summary lines): it"
        echo "        exhausted its candidate retries and failed creates. While D-0947 is open a"
        echo "        chunk this mount logged but has not destaged reads as unvalidatable, so a"
        echo "        storm does NOT distinguish real residue from that false positive."
    elif [ $((vref1+vref0)) -gt 0 ]; then
        echo "  SOLE-READ: the validator REFUSED $((vref1+vref0)) candidate(s) while the node was a"
        echo "        sole survivor (knob1 $vref1, knob0 $vref0) — residue the shipped gate"
        echo "        would have allocated over unchecked."
    else
        echo "  SOLE-READ: $((p951a+p951b)) allocation(s) took the unvalidated sole-survivor path and the"
        echo "        validator refused nothing in the arm that ran it — the guard is off,"
        echo "        and on this workload there was nothing for it to catch."
    fi
fi
# ---- the cold structural check: THIS DEFECT'S OWN ORACLE -------------------
# D-0957: a directory the survivor created under the partial-write filter
# without a grant (the withdrawn first D-0955 fix, and the s574iwr knob arm
# on 0.75.128) was dropped from every cluster write (P56-NL-LOGGED-DIR-SKIP),
# its log item completed without a re-arm, and its core never reached the
# platter -- the inode btree said allocated, the dinode at its home was still
# the chunk-initialisation image.  Nothing in this harness could see that:
# the round summaries count probes, and the cold readback (above) walks names,
# not inode records.  Only chk_mxfs on a QUIESCED device compares the two
# records of every allocated inode, so the lap ends with one.  Both nodes are
# unmounted for it (the audit must not read a live mount), then put back.
# The line to assert on is P-ALLOC-FREE-CORE; a non-clean verdict of any
# other shape is reported as itself.
# derived time budget: the cold check read a 12000-inode volume in well under
# its 300 s bound on this rig (d0949, s614/s615); unmount and remount of two
# nodes measured 5-80 s each (a cold mount that meets a frozen slot is the
# 80 s case).
if [ "${MXFS_D0946_COLDCHK:-1}" = 1 ]; then
    rs 180 "$A" "umount $MNT; echo CC_UMOUNT_A_RC=\$?" > "$OUT/coldchk_umount_a.txt" 2>&1
    rs 180 "$B" "umount $MNT; echo CC_UMOUNT_B_RC=\$?" > "$OUT/coldchk_umount_b.txt" 2>&1
    ccm=$(rs 30 "$A" "grep -c ' $MNT mxfs ' /proc/mounts"; rs 30 "$B" "grep -c ' $MNT mxfs ' /proc/mounts")
    if [ "$(echo "$ccm" | tr -d '\r' | tr '\n' ' ')" = "0 0 " ]; then
        rs 300 "$A" "/src/mxfs/tools/chk_mxfs -v $DEV 2>&1 | tail -60" > "$OUT/chk.txt" 2>&1
        ccfree=$(grep -ac 'P-ALLOC-FREE-CORE' "$OUT/chk.txt"); ccfree=${ccfree:-0}
        ccerr=$(grep -a '^chk_mxfs: ' "$OUT/chk.txt" | tail -1 | tr -d '\r')
        echo "  COLDCHK $(cat "$OUT/coldchk_umount_a.txt" "$OUT/coldchk_umount_b.txt" | tr -d '\r' | tr '\n' ' ')alloc_free_core=$ccfree verdict='${ccerr:-NO VERDICT LINE}'"
        grep -a 'ERROR' "$OUT/chk.txt" | head -6 | cut -c1-220 | sed 's/^/       /'
        if [ "$ccfree" -gt 0 ]; then
            echo "  COLDCHK-READ: FAIL — $ccfree inobt-allocated inode(s) with a FREE core on the quiesced volume (D-0957's shape: a creation whose core never reached the platter)"
        elif [ -z "$ccerr" ]; then
            echo "  COLDCHK-READ: UNREADABLE — chk_mxfs printed no verdict line; the check did not complete"
        elif echo "$ccerr" | grep -q 'filesystem clean'; then
            echo "  COLDCHK-READ: the quiesced volume checks clean after the sole-survivor lap"
        else
            echo "  COLDCHK-READ: FAIL — $ccerr (not D-0957's shape; read the ERROR lines above)"
        fi
    else
        echo "  COLDCHK-READ: UNREADABLE — a node is still mounted (mounts: $(echo "$ccm" | tr '\n' ' ')); the audit does not read a live mount"
    fi
    rs 180 "$A" "mount -t mxfs $DEV $MNT; echo CC_REMOUNT_A_RC=\$?" > "$OUT/coldchk_remount_a.txt" 2>&1
    rs 180 "$B" "mount -t mxfs $DEV $MNT; echo CC_REMOUNT_B_RC=\$?" > "$OUT/coldchk_remount_b.txt" 2>&1
    echo "  COLDCHK restore $(cat "$OUT/coldchk_remount_a.txt" "$OUT/coldchk_remount_b.txt" | tr -d '\r' | tr '\n' ' ')"
fi
# The verdict this run can support, stated in terms of what it measured.
if [ -n "$died" ]; then
    echo "  READ: the condition reproduced and killed the filesystem at $died"
elif [ $((gate1+gate0)) = 0 ]; then
    echo "  READ: VACUOUS — the pubob arm of the candidate validator never fired in"
    echo "        $ROUNDS rounds (gatefire 0 in both arms), so a clean result here is"
    echo "        indistinguishable from an instrument that cannot fire. Not a result."
elif [ $((hits1+hits0)) = 0 ]; then
    echo "  READ: NOT REPRODUCED in $ROUNDS rounds — the gate DID fire"
    echo "        (knob1 $gate1 PUBPEND, knob0 $gate0 ALLOW), so the arm was exercised;"
    echo "        the DISK-LIVE verdict simply did not occur in either arm."
else
    echo "  READ: knob=1 $hits1 hit(s) in $tot1 rounds; knob=0 $hits0 hit(s) in $tot0 rounds."
    echo "        Comparable rates disprove a knob role and leave aging as the variable."
fi
exit 0
