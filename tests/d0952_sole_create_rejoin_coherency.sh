#!/bin/bash
# d0952_sole_create_rejoin_coherency.sh — are inodes a SOLE SURVIVOR created
# coherent to the peer that comes back?
#
# THE HAZARD, IN THE CODE'S OWN WORDS.  mxfs_dlm_publish_inode()
# (xfs/xfs_mxfs_dlm.c) exists to give a newly created inode a real on-disk DLM
# slot, and its comment says exactly why:
#
#     "After this returns, a peer reaching the new inode by name will find a
#      real slot, send us a proper BAST, and we will drain+release coherently
#      — closing the sess107 'peer acquires empty slot cleanly, never BASTs'
#      window."
#
# Its first test is
#
#     if (mxfs_v5_dlm_is_single_node(dlm))
#             return;         /* "nothing to publish, no peers to coordinate" */
#
# and mxfs_v5_dlm_is_single_node() is DYNAMIC MEMBERSHIP.  "No peers to
# coordinate" is true of a mount that has never had one.  It is NOT true of the
# sole survivor of a departure in a two-node cluster, because in that cluster
# THE PEER COMES BACK — and every inode the survivor created while it was alone
# was created without the slot that is the peer's only way to make the survivor
# drain.
#
# WHAT THIS MEASURES, AND WHY IT NEEDS NO PROBE.  Coherency is observable from
# userspace: after the peer rejoins and overwrites a file, the survivor must
# read what the peer wrote.  If the survivor serves its own cached image
# instead, that is a stale read, and no interpretation of a kernel counter is
# needed to see it.  Each file carries its own identity and generation in its
# contents, so a wrong read names both what was expected and what was served.
#
# THE CONTROL ARM IS THE WHOLE POINT.  The same files, the same overwrites, the
# same reads — but created while BOTH nodes are mounted, so publish_inode did
# its job.  Run both arms and the difference is attributable to the publication
# gap and to nothing else.  Run only the treatment arm and a clean result is
# indistinguishable from a workload that never exercised the window.
#
#   sole     B unmounts, A creates, B remounts, both directions verified.
#   control  B stays mounted throughout; A creates; same verification.
#   lone     BOTH unmount, A mounts ALONE (a mount with no in-core memory of
#            a peer: ever_multi false, so every guard keyed on the sole-survivor
#            predicate is off and the never-multi write-without-grants path is
#            on), A creates, B mounts for the first time in A's life, both
#            directions verified, then the cold structural check.  This is the
#            D-0956 scenario: a volume that carried two writers, quiesced, then
#            written by one node that cannot know that history.  P-SOLE-SURVIVOR
#            must stay 0 on A for the whole lap or the arm measured the sole
#            case again.
#
# derived time budget, measured on this rig 2026-09-10 (2-node TCP, QNAP LUN):
# empty-file creates run ~7 ms each once the inode chunks exist, and the first
# ~11 s of any create burst is fixed cost, not per-file.  200 files is
# therefore ~13 s of create; a mount is ~10 s and an unmount ~5 s.  Per-step
# timeouts below are twice the measured step, and the whole lap is bounded at
# roughly four minutes.  A step that hits its bound is a FAILURE, reported as
# one, never re-run with a larger number.
#
# Usage: tests/d0952_sole_create_rejoin_coherency.sh <label> [ARM=sole|control|lone] [NFILES=200]
set -u
LABEL=${1:?label}
ARM=${2:-sole}
NFILES=${3:-200}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; DEV=$MXFS_DEV_RESOLVED
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0952coh_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it

SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
D=$MNT/d0952_$LABEL
MK="D0952-MARK-$LABEL-$$"
echo "=== d0952_sole_create_rejoin_coherency label=$LABEL arm=$ARM nfiles=$NFILES sv=$SV $(date -u +%FT%TZ) ==="
case "$ARM" in sole|control|lone) ;; *) echo "RESULT: FAIL unknown arm '$ARM' (want sole|control|lone)"; exit 2 ;; esac

# ---- preconditions ---------------------------------------------------------
# A LAP ON A DIFFERENT MODULE IS NOT THIS BUILD'S LAP, and a mount that is in
# /proc/mounts but shut down answers EIO to everything while still looking
# healthy to a grep.  Both are checked, on both nodes, before anything runs.
fails=0
for n in $A $B; do
    st=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) mnt=\$(grep -c ' $MNT mxfs ' /proc/mounts)" | tr -d '\n')
    echo "  INFO $n $st"
    [ "$st" = "sv=$SV mnt=1" ] || { echo "  FAIL $n precondition (want sv=$SV mnt=1)"; fails=$((fails+1)); }
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL precondition fails=$fails"; exit 2; }
for n in $A $B; do
    w=$(rs 40 "$n" "mkdir -p $MNT/.d0952probe.$$.$n 2>&1 && rmdir $MNT/.d0952probe.$$.$n 2>&1 && echo WRITABLE || echo NOTWRITABLE")
    case "$w" in *WRITABLE*) ;; *) echo "RESULT: FAIL label=$LABEL $n mounted but NOT writable: $w"; exit 2 ;; esac
done
rs 25 "$A" "rm -rf $D" >/dev/null 2>&1
rs 20 "$A" "echo '$MK' > /dev/kmsg"
echo "PRECOND_OK both nodes on $SV, both writable"

# ---- phase 1: the peer leaves (sole arm only) ------------------------------
SOLEFIRED=0
if [ "$ARM" = sole ]; then
    rs 120 "$B" "sync; umount $MNT; echo B_UMOUNT_RC=\$?" > "$OUT/umount_b.txt" 2>&1
    echo "PHASE1 $(tr -d '\r' < "$OUT/umount_b.txt" | tr '\n' ' ')"
    # The transition has to be OBSERVED, windowed to this run's own mark: the
    # note is printed once per episode and survives in the ring buffer, so an
    # unwindowed grep is satisfied by any earlier run on this boot.
    sw=$(rs 120 "$A" "
        for i in \$(seq 1 20); do
            ls $MNT >/dev/null 2>&1; stat -f $MNT >/dev/null 2>&1
            dmesg | sed -n '/$MK/,\$p' | grep -aq 'P-SOLE-SURVIVOR' && break
            sleep 3
        done
        echo SOLE=\$(dmesg | sed -n '/$MK/,\$p' | grep -ac 'P-SOLE-SURVIVOR') MARK=\$(dmesg | grep -ac '$MK')")
    echo "PHASE1 $(echo "$sw" | tr '\n' ' ')"
    SOLEFIRED=$(echo "$sw" | sed -n 's/.*SOLE=\([0-9]*\).*/\1/p'); SOLEFIRED=${SOLEFIRED:-0}
    MARK=$(echo "$sw" | sed -n 's/.*MARK=\([0-9]*\).*/\1/p'); MARK=${MARK:-0}
    [ "$MARK" = 0 ] && { echo "RESULT: FAIL label=$LABEL kmsg mark rolled out of $A's ring buffer; nothing below is windowed"; exit 2; }
    [ "$SOLEFIRED" = 0 ] && { echo "RESULT: FAIL label=$LABEL $A never became a sole survivor; the arm did not run"; exit 2; }
    echo "PHASE1 $A is a SOLE SURVIVOR (P-SOLE-SURVIVOR=$SOLEFIRED since the mark)"
elif [ "$ARM" = lone ]; then
    # Both out, then A alone.  A's unmount with B already gone is the cheap one;
    # B's unmount with A live pays the per-page authority handoff (35-80 s,
    # D-A-CLEAN-UNMOUNT-OF-ONE-NODE-WHILE-ITS-PEER), so B goes first.
    t1a=$(date +%s)
    rs 120 "$B" "sync; umount $MNT; echo B_UMOUNT_RC=\$?" > "$OUT/umount_b.txt" 2>&1
    rs 120 "$A" "sync; umount $MNT; echo A_UMOUNT_RC=\$?" > "$OUT/umount_a.txt" 2>&1
    rs 180 "$A" "mount -t mxfs $DEV $MNT; echo A_MOUNT_RC=\$?" > "$OUT/mount_a.txt" 2>&1
    echo "PHASE1 wall=$(( $(date +%s) - t1a ))s $(cat "$OUT/umount_b.txt" "$OUT/umount_a.txt" "$OUT/mount_a.txt" 2>/dev/null | tr -d '\r' | tr '\n' ' ')"
    # B's departure made A a sole survivor of the PREVIOUS mount, and that note
    # sits in the ring after the first mark.  Everything from here is windowed
    # to a second mark written after the lone mount, so the survivor count
    # below speaks only for the mount under test.
    MK="$MK-LONE"
    rs 20 "$A" "echo '$MK' > /dev/kmsg"
    lw=$(rs 60 "$A" "
        echo MNT=\$(grep -c ' $MNT mxfs ' /proc/mounts) \
             SOLE=\$(dmesg | sed -n '/$MK/,\$p' | grep -ac 'P-SOLE-SURVIVOR') \
             MARK=\$(dmesg | grep -ac '$MK') \
             MEMB=\$(dmesg | sed -n '/$MK/,\$p' | grep -a 'MXFS-MEMBERSHIP' | tail -1 | sed -n 's/.*active_count=\([0-9]*\).*/\1/p')")
    echo "PHASE1 $(echo "$lw" | tr '\n' ' ')"
    parse1() { echo "$lw" | sed -n "s/.*$1=\([0-9]*\).*/\1/p" | head -1; }
    LMNT=$(parse1 MNT); LMNT=${LMNT:-0}
    MARK=$(parse1 MARK); MARK=${MARK:-0}
    SOLEFIRED=$(parse1 SOLE); SOLEFIRED=${SOLEFIRED:-0}
    [ "$MARK" = 0 ] && { echo "RESULT: FAIL label=$LABEL kmsg mark rolled out of $A's ring buffer; nothing below is windowed"; exit 2; }
    [ "$LMNT" = 1 ] || { echo "RESULT: FAIL label=$LABEL $A did not come back alone (mounted=$LMNT); the arm did not run"; exit 2; }
    # A mount that comes up with a peer's ghost in the slot table can fence it
    # and still be alone; what disqualifies the arm is A OBSERVING a live peer.
    [ "$SOLEFIRED" = 0 ] || { echo "RESULT: FAIL label=$LABEL $A printed P-SOLE-SURVIVOR=$SOLEFIRED after its lone mount: it observed a peer, so this is not the no-memory-of-a-peer case"; exit 2; }
    w=$(rs 40 "$A" "mkdir -p $MNT/.d0952probe.$$.$A 2>&1 && rmdir $MNT/.d0952probe.$$.$A 2>&1 && echo WRITABLE || echo NOTWRITABLE")
    case "$w" in *WRITABLE*) ;; *) echo "RESULT: FAIL label=$LABEL $A remounted alone but NOT writable: $w"; exit 2 ;; esac
    echo "PHASE1 $A is mounted ALONE with no memory of a peer (P-SOLE-SURVIVOR=0 since the mark)"
else
    echo "PHASE1 control arm: $B stays mounted, so every create below is published normally"
fi

# ---- phase 2: A creates the files -----------------------------------------
# Each file carries its own name and generation, so a stale read names itself.
t0=$(date +%s)
rs 90 "$A" "mkdir -p $D && i=0; while [ \$i -lt $NFILES ]; do echo A-v1-\$i > $D/f\$i || break; i=\$((i+1)); done; sync; echo MADE=\$i SYNC_RC=\$?" > "$OUT/create.txt" 2>&1
t1=$(date +%s)
MADE=$(sed -n 's/.*MADE=\([0-9]*\).*/\1/p' "$OUT/create.txt" | tr -d '\r'); MADE=${MADE:-0}
echo "PHASE2 made=$MADE wall=$((t1-t0))s $(tr -d '\r' < "$OUT/create.txt" | tr '\n' ' ')"
[ "$MADE" = "$NFILES" ] || { echo "RESULT: FAIL label=$LABEL only $MADE of $NFILES files were created; the lap measured nothing"; exit 2; }

# ---- phase 2a: RECYCLE, because a fresh create is the easy case ------------
# THE FIRST CUT OF THIS HARNESS ONLY CREATED FRESH FILES AND PASSED, and that
# pass was narrower than it looked.  mxfs_dlm_rearm_unpublished() exists for a
# create satisfied from the inode CACHE: a recycled IRECLAIMABLE incarnation
# keeps the prior incarnation's i_dlm_mode=EX with i_dlm_unpublished false,
# while the prior incarnation's on-disk slot was RELEASED at free time.  Without
# the re-arm the create runs on a PHANTOM in-core EX -- no slot is acquired, a
# rejoining peer's acquire of the reused number grants CLEAN with no BAST, the
# creator is never forced to flush the new dinode, and the peer adopts it at a
# size=0 image.  Readers see an existing file as EMPTY.
#
# That function is one of the single-node fast paths, so a sole survivor skips
# it -- and a workload of fresh creates in a fresh directory never reaches it at
# all.  So: delete half the files and recreate them, in place, with no sync
# between, so the allocator hands the same numbers straight back while the
# in-core shells are still reclaimable.  The recreated half carries the same
# A-v1-<i> contents as the rest, so every later check covers both populations
# and a failure names which one it was.
t2a=$(date +%s)
rs 120 "$A" "
    cd $D || exit 1
    n=0
    for i in \$(seq 0 2 \$(( $NFILES - 1 ))); do
        rm -f f\$i 2>/dev/null
        echo A-v1-\$i > f\$i 2>/dev/null && n=\$((n+1))
    done
    sync
    echo RECYCLED=\$n" > "$OUT/recycle.txt" 2>&1
echo "PHASE2a wall=$(( $(date +%s) - t2a ))s $(tr -d '\r' < "$OUT/recycle.txt" | tr '\n' ' ')"

# ---- phase 2b: the operations that actually reach publish_inode ------------
# A PLAIN CREATE DOES NOT PUBLISH.  mxfs_dlm_publish_inode() was REMOVED from
# xfs_create (xfs/xfs_inode.c: "it cost one read_slot under..."); publication
# on that path is lazy, via the backstop in mxfs_dlm_ilock_begin and the
# BAST-side scoped drain.  The only callers left are LINK (xfs_inode.c:3914),
# cross-directory RENAME (7617/7619) and SYMLINK (pal/linux/xfs_symlink.c:224),
# and each of those publishes SYNCHRONOUSLY because the recorded parent must
# not go stale.
#
# So a create-only workload never reaches that guard at all, and its silence
# says nothing about it -- the first cut of this harness scored
# publish_inode_skips=0 and that zero was vacuous, not clean.  These three
# operations are here to make the site reachable, and P952-SOLE-SKIP
# site=publish_inode in the summary is the proof that it was reached.
t2b=$(date +%s)
rs 120 "$A" "
    cd $D || exit 1
    lerr=0; serr=0; rerr=0
    for i in \$(seq 0 \$(( $NFILES - 1 ))); do
        ln f\$i l\$i 2>/dev/null || lerr=\$((lerr+1))
        ln -s f\$i s\$i 2>/dev/null || serr=\$((serr+1))
    done
    mkdir -p sub 2>/dev/null
    for i in \$(seq 0 \$(( $NFILES / 4 ))); do
        mv f\$i sub/r\$i 2>/dev/null || rerr=\$((rerr+1))
        mv sub/r\$i f\$i 2>/dev/null || rerr=\$((rerr+1))
    done
    sync
    echo PUB link_err=\$lerr symlink_err=\$serr rename_err=\$rerr links=\$(ls l* 2>/dev/null | wc -l) syms=\$(ls s* 2>/dev/null | wc -l)" > "$OUT/publish.txt" 2>&1
echo "PHASE2b wall=$(( $(date +%s) - t2b ))s $(tr -d '\r' < "$OUT/publish.txt" | tr '\n' ' ')"

# ---- phase 3: the peer comes back (sole) or joins for the first time (lone) --
if [ "$ARM" = sole ] || [ "$ARM" = lone ]; then
    t2=$(date +%s)
    rs 180 "$B" "mount -t mxfs $DEV $MNT; echo B_MOUNT_RC=\$?" > "$OUT/mount_b.txt" 2>&1
    t3=$(date +%s)
    echo "PHASE3 wall=$((t3-t2))s $(tr -d '\r' < "$OUT/mount_b.txt" | tr '\n' ' ')"
    m=$(rs 30 "$B" "grep -c ' $MNT mxfs ' /proc/mounts")
    [ "$m" = 1 ] || { echo "RESULT: FAIL label=$LABEL $B did not rejoin (mounted=$m); the coherency check below cannot run"; exit 2; }
fi

# ---- phase 4: B reads what A wrote -----------------------------------------
# The peer must see every file and its v1 contents.  A file the peer cannot
# see, or sees with the wrong contents, is the failure.  "Seen" counts the
# f<N> entries only: phase 2b added a hard link and a symlink per file and a
# subdirectory, and a whole-listing count against NFILES scored every lap
# INCOHERENT on a clean read (s616a/s616b).
bread=$(rs 200 "$B" "
    seen=\$(ls $D 2>/dev/null | grep -c '^f[0-9]'); bad=0; miss=0; eio=0
    for i in \$(seq 0 \$(( $NFILES - 1 ))); do
        c=\$(cat $D/f\$i 2>/dev/null); rc=\$?
        if [ \$rc != 0 ]; then eio=\$((eio+1)); continue; fi
        if [ -z \"\$c\" ]; then miss=\$((miss+1)); continue; fi
        [ \"\$c\" = \"A-v1-\$i\" ] || { bad=\$((bad+1)); [ \$bad -le 5 ] && echo BADREAD i=\$i got=\"\$c\" want=A-v1-\$i; }
    done
    lbad=0; sbad=0
    for i in \$(seq 0 \$(( $NFILES - 1 ))); do
        c=\$(cat $D/l\$i 2>/dev/null)
        [ \"\$c\" = \"A-v1-\$i\" ] || lbad=\$((lbad+1))
        c=\$(cat $D/s\$i 2>/dev/null)
        [ \"\$c\" = \"A-v1-\$i\" ] || sbad=\$((sbad+1))
    done
    echo BREAD seen=\$seen bad=\$bad empty=\$miss err=\$eio linkbad=\$lbad symbad=\$sbad")
echo "PHASE4 $(echo "$bread" | tr '\n' ' ')"

# ---- phase 5: B overwrites, A must see it ----------------------------------
# THIS IS THE DISCRIMINATING STEP.  If A created these inodes with no on-disk
# slot, B acquires them cleanly and A is never told to drain, so A can serve
# its own v1 image for a file B has already rewritten.  A read of A-v1 here is
# a stale read on a healthy filesystem with nothing killed.
rs 90 "$B" "i=0; while [ \$i -lt $NFILES ]; do echo B-v2-\$i > $D/f\$i || break; i=\$((i+1)); done; sync; echo BWROTE=\$i" > "$OUT/bwrite.txt" 2>&1
echo "PHASE5 $(tr -d '\r' < "$OUT/bwrite.txt" | tr '\n' ' ')"
aread=$(rs 200 "$A" "
    stale=0; bad=0; eio=0; ok=0
    for i in \$(seq 0 \$(( $NFILES - 1 ))); do
        c=\$(cat $D/f\$i 2>/dev/null); rc=\$?
        if [ \$rc != 0 ]; then eio=\$((eio+1)); continue; fi
        if [ \"\$c\" = \"B-v2-\$i\" ]; then ok=\$((ok+1))
        elif [ \"\$c\" = \"A-v1-\$i\" ]; then
            stale=\$((stale+1)); [ \$stale -le 5 ] && echo STALEREAD i=\$i got=\"\$c\" want=B-v2-\$i
        else
            bad=\$((bad+1)); [ \$bad -le 5 ] && echo GARBAGE i=\$i got=\"\$c\" want=B-v2-\$i
        fi
    done
    echo AREAD ok=\$ok stale=\$stale garbage=\$bad err=\$eio")
echo "PHASE6 $(echo "$aread" | tr '\n' ' ')"

# ---- phase 6: and the other direction --------------------------------------
rs 90 "$A" "i=0; while [ \$i -lt $NFILES ]; do echo A-v3-\$i > $D/f\$i || break; i=\$((i+1)); done; sync; echo AWROTE=\$i" > "$OUT/awrite.txt" 2>&1
bread2=$(rs 200 "$B" "
    stale=0; bad=0; eio=0; ok=0
    for i in \$(seq 0 \$(( $NFILES - 1 ))); do
        c=\$(cat $D/f\$i 2>/dev/null); rc=\$?
        if [ \$rc != 0 ]; then eio=\$((eio+1)); continue; fi
        if [ \"\$c\" = \"A-v3-\$i\" ]; then ok=\$((ok+1))
        elif [ \"\$c\" = \"B-v2-\$i\" ]; then
            stale=\$((stale+1)); [ \$stale -le 5 ] && echo STALEREAD2 i=\$i got=\"\$c\" want=A-v3-\$i
        else
            bad=\$((bad+1)); [ \$bad -le 5 ] && echo GARBAGE2 i=\$i got=\"\$c\" want=A-v3-\$i
        fi
    done
    echo BREAD2 ok=\$ok stale=\$stale garbage=\$bad err=\$eio")
echo "PHASE7 $(echo "$bread2" | tr '\n' ' ')"

# ---- harvest ---------------------------------------------------------------
rs 60 "$A" "dmesg | sed -n '/$MK/,\$p'" > "$OUT/dmesg_A.txt" 2>&1
cnt() { local c; c=$(grep -ac -- "$1" "$OUT/dmesg_A.txt" 2>/dev/null | head -1); echo "${c:-0}"; }
P952=$(cnt 'P952-SOLE-SKIP')
REARM=$(grep -ac 'P952-SOLE-SKIP site=rearm_unpublished' "$OUT/dmesg_A.txt" 2>/dev/null | head -1); REARM=${REARM:-0}
PUBSKIP=$(grep -ac 'P952-SOLE-SKIP site=publish_inode' "$OUT/dmesg_A.txt" 2>/dev/null | head -1); PUBSKIP=${PUBSKIP:-0}
SHUT=$(cnt 'Shutting down filesystem')
SITES=$(grep -ao 'P952-SOLE-SKIP site=[a-z_]*' "$OUT/dmesg_A.txt" 2>/dev/null | sed 's/.*site=//' | sort -u | tr '\n' ',')

parse() { echo "$1" | sed -n "s/.*$2=\([0-9]*\).*/\1/p" | head -1; }
BSEEN=$(parse "$bread" seen);   BBAD=$(parse "$bread" bad);   BERR=$(parse "$bread" err)
BLBAD=$(parse "$bread" linkbad); BSBAD=$(parse "$bread" symbad)
ASTALE=$(parse "$aread" stale); AGARB=$(parse "$aread" garbage); AERR=$(parse "$aread" err); AOK=$(parse "$aread" ok)
B2STALE=$(parse "$bread2" stale); B2GARB=$(parse "$bread2" garbage); B2ERR=$(parse "$bread2" err); B2OK=$(parse "$bread2" ok)
for v in BSEEN BBAD BERR BLBAD BSBAD ASTALE AGARB AERR AOK B2STALE B2GARB B2ERR B2OK; do
    eval "[ -n \"\$$v\" ] || $v=0"
done

BAD=$(( BBAD + BERR + BLBAD + BSBAD + ASTALE + AGARB + AERR + B2STALE + B2GARB + B2ERR ))
[ "$BSEEN" = "$NFILES" ] || BAD=$((BAD+1))

# ---- every arm: the cold structural check ---------------------------------
# A lap that ran a survivor's or a lone mount's write path and a join must end
# with the platter audited offline: a stranded image or an inode with a free
# core is invisible to every read above and shows only here (D-0957 taught
# that).  B goes out first (A's unmount with B gone is the cheap one),
# chk_mxfs on the quiesced device, then both remount.  MXFS_D0952_COLDCHK=0
# skips it.
COLD=notrun; COLDERR=0; COLDCORE=0; COLDALIAS=notrun
if [ "${MXFS_D0952_COLDCHK:-1}" = 1 ]; then
    tc=$(date +%s)
    SOLE2=$(rs 30 "$A" "dmesg | sed -n '/$MK/,\$p' | grep -ac 'P-SOLE-SURVIVOR'"); SOLE2=${SOLE2:-0}
    rs 120 "$B" "sync; umount $MNT; echo CC_UMOUNT_B_RC=\$?" > "$OUT/cc_umount_b.txt" 2>&1
    rs 180 "$A" "sync; umount $MNT; echo CC_UMOUNT_A_RC=\$?" > "$OUT/cc_umount_a.txt" 2>&1
    rs 300 "$A" "/src/mxfs/tools/chk_mxfs -v $DEV 2>&1 | tail -45" > "$OUT/chk.txt" 2>&1
    COLD=$(grep -a '^chk_mxfs: ' "$OUT/chk.txt" | tail -1 | tr -d '\r')
    COLDERR=$(grep -ac 'ERROR' "$OUT/chk.txt" 2>/dev/null | head -1); COLDERR=${COLDERR:-0}
    COLDCORE=$(grep -ac 'P-ALLOC-FREE-CORE\|has a FREE core' "$OUT/chk.txt" 2>/dev/null | head -1); COLDCORE=${COLDCORE:-0}
    COLDALIAS=$(grep -a 'Chunk/free-space aliasing' "$OUT/chk.txt" | sed -n 's/.*aliasing[ .]*\([A-Z]*\).*/\1/p' | head -1); COLDALIAS=${COLDALIAS:-missing}
    rs 180 "$A" "mount -t mxfs $DEV $MNT; echo CC_REMOUNT_A_RC=\$?" > "$OUT/cc_remount_a.txt" 2>&1
    rs 180 "$B" "mount -t mxfs $DEV $MNT; echo CC_REMOUNT_B_RC=\$?" > "$OUT/cc_remount_b.txt" 2>&1
    echo "COLDCHK wall=$(( $(date +%s) - tc ))s $(cat "$OUT/cc_umount_b.txt" "$OUT/cc_umount_a.txt" "$OUT/cc_remount_a.txt" "$OUT/cc_remount_b.txt" 2>/dev/null | tr -d '\r' | tr '\n' ' ') verdict='$COLD' errors=$COLDERR free_core=$COLDCORE aliasing=$COLDALIAS sole_after_join=$SOLE2"
    [ "$COLD" = "chk_mxfs: filesystem clean" ] || BAD=$((BAD+1))
    [ "$COLDALIAS" = OK ] || BAD=$((BAD+1))
    # A P-SOLE-SURVIVOR after the join would mean B left again mid-lap.  The
    # count is since the lap's mark, so on the sole arm it already holds the
    # phase-1 departure that the arm exists to produce (SOLEFIRED); only a
    # count ABOVE that one is a second departure.  (s617a-c scored every
    # clean sole lap INCOHERENT by demanding zero here.)
    [ "$SOLE2" = "$SOLEFIRED" ] || BAD=$((BAD+1))
fi

if [ "$ARM" = sole ] && [ "$SOLEFIRED" = 0 ]; then
    VERDICT=VACUOUS
elif [ "$BAD" = 0 ] && [ "$SHUT" = 0 ]; then
    VERDICT=CLEAN
else
    VERDICT=INCOHERENT
fi

echo "D0952 label=$LABEL arm=$ARM verdict=$VERDICT sv=$SV files=$NFILES sole=$SOLEFIRED b_saw=$BSEEN b_wrongv1=$BBAD b_err=$BERR b_link_wrong=$BLBAD b_symlink_wrong=$BSBAD a_saw_v2=$AOK a_stale_v1=$ASTALE a_garbage=$AGARB a_err=$AERR b_saw_v3=$B2OK b_stale_v2=$B2STALE b_garbage=$B2GARB b_err=$B2ERR shutdown=$SHUT p952=$P952 publish_inode_skips=$PUBSKIP rearm_skips=$REARM sites=$SITES cold='$COLD' cold_aliasing=$COLDALIAS cold_free_core=$COLDCORE evidence=$OUT"
echo "$bread$aread$bread2" | grep -a 'BADREAD\|STALEREAD\|GARBAGE' | head -12 | sed 's/^/   /'
case "$VERDICT" in
  CLEAN)
    echo "  READ: every file the survivor created was visible to the rejoined peer,"
    echo "        and both nodes read each other's writes. On the sole arm this also"
    echo "        means the missing publication did not cost coherency in THIS shape."
    ;;
  INCOHERENT)
    echo "  READ: a node served a value the other node had already overwritten, or could"
    echo "        not read a file at all, on a healthy filesystem with nothing killed."
    echo "        Run the other arm before attributing it: only the difference between"
    echo "        arms attributes this to the create-while-alone publication gap."
    ;;
  *)
    echo "  READ: VACUOUS — the sole-survivor state was never reached, so this lap says"
    echo "        nothing about the condition it was written to test."
    ;;
esac
exit 0
