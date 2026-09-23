#!/bin/bash
# d0949_sole_survivor_chunkfree.sh — does a SOLE SURVIVOR delete inode chunks
# and return their blocks to the AG free pool?
#
# D-0949.  xfs_difree_inobt keeps a fully-free inode chunk instead of deleting
# it, so its blocks can never re-enter the AG free pool and directory data can
# never alias an inode cluster.  The guard is
#
#     !(mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
#
# and is_single_node() is DYNAMIC MEMBERSHIP.  From the moment a two-node
# cluster's peer leaves until it returns, the survivor takes the upstream
# branch and frees the chunk.  Nothing has ever measured that, because the only
# probe on the path was unreachable (its condition was the complement of the
# branch it sat in) until 0.75.124 made it fire.
#
# WHY THIS HARNESS EXISTS AND d0944_death_rejoin_ab.sh DOES NOT ANSWER IT.
# That harness reaches the sole-survivor state (P-SOLE-SURVIVOR fired 6 times
# in 13 laps on 0.75.124) and still scores P103-CHUNKFREE=0 — but so does
# P133-ICLUSTER-SYNCINIT, which means its 8-second churn NEVER CARVES AN INODE
# CHUNK AT ALL.  A chunk that is never carved can never become fully free, so
# its zero is a vacuous measurement, not a negative result.  The gate has to be
# counted, not the outcome.
#
# THE SHAPE.  A chunk is deleted only when EVERY inode in it is free, so the
# workload has to carve chunks and then empty them completely:
#   1. both nodes mounted — create N files on A, in their own directory, until
#      new chunks are carved (positive control: P133-ICLUSTER-SYNCINIT > 0);
#   2. B unmounts cleanly — A is now single-node but ever_multi, i.e. a SOLE
#      SURVIVOR (positive control: P-SOLE-SURVIVOR).  A clean unmount is used
#      deliberately: it produces the same membership state as a death for a
#      fraction of the cost and with no fencing or replay to disentangle;
#   3. A removes the whole directory — whole chunks go fully free while A is
#      the sole survivor, which is the condition under test;
#   4. report whether P103-CHUNKFREE fired and with sole=1, plus the unbudgeted
#      P103-CHUNKFREE-SOLE alert;
#   5. optionally re-fill with directory data to see whether the freed blocks
#      are handed straight back out, then run the cross-tree audit in chk_mxfs
#      (a block inside an allocated inode chunk must never also be free).
#
# A ZERO HERE IS ONLY MEANINGFUL IF STEP 1 AND STEP 2 BOTH FIRED.  The summary
# prints all three counts so a vacuous run is visible as a vacuous run.
#
# derived time budget: creates measured in-line and printed; the whole lap is bounded
# by its own per-step timeouts and should complete in ~5 minutes.
#
# Usage: tests/d0949_sole_survivor_chunkfree.sh <label> [NFILES=12000]
set -u
LABEL=${1:?label}
NFILES=${2:-12000}
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
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0949chunkfree_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it

SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
MARK="D0949-MARK-$LABEL-$$"
echo "=== d0949_sole_survivor_chunkfree label=$LABEL nfiles=$NFILES sv=$SV $(date -u +%FT%TZ) ==="

# THE BUILD IS PART OF READINESS.  A lap on an older module is not this
# build's lap, and the probes under test only exist from 0.75.124.
for n in $A $B; do
    nsv=$(rs 20 "$n" "cat /sys/module/mxfs/srcversion 2>/dev/null || echo none")
    [ "$nsv" = "$SV" ] || { echo "PRECOND_FAIL $n sv=$nsv want=$SV"; exit 2; }
    m=$(rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts")
    [ "$m" = "1" ] || { echo "PRECOND_FAIL $n not mounted (m=$m)"; exit 2; }
done
# A MOUNTED FILESYSTEM IS NOT NECESSARILY A WORKING ONE.  A mount that has
# been shut down (EIO on every operation) still appears in /proc/mounts, and a
# harness that only greps /proc/mounts will run its whole workload against it
# and report a vacuous result rather than a broken precondition.
wprobe=$(rs 40 "$A" "mkdir -p $MNT/.d0949probe.$$ 2>&1 && rmdir $MNT/.d0949probe.$$ 2>&1 && echo WRITABLE || echo NOTWRITABLE")
case "$wprobe" in
  *WRITABLE*) : ;;
  *) echo "PRECOND_FAIL $A mounted but NOT writable (shut down?): $wprobe"; exit 2 ;;
esac
echo "PRECOND_OK both nodes mounted on $SV and $A is writable"

rs 20 "$A" "echo '$MARK' > /dev/kmsg"

# THE PRIMARY INSTRUMENT IS NOT A PROBE.  P133-ICLUSTER-SYNCINIT prints only
# its first 20 occurrences per module load and P45-INIT its first 40, so a
# carve count taken from either is a print budget, not a measurement — that
# mistake has already cost this campaign one wrong conclusion.  df -i's
# "Inodes" column IS the allocated-inode count (sb_icount), and MXFS recomputes
# the lazy counters from AGF/AGI at every mount, so:
#     Inodes rises  => inode chunks were CARVED
#     Inodes falls  => inode chunks were DELETED and their blocks freed
# which is the defect's on-disk effect measured directly, with no budget, no
# rate limit and no ring buffer in the path.
# df --output=itotal reports XFS's dynamic MAXIMUM inode count (maxicount),
# not sb_icount: measured unchanged at 25991808 across 12000 creates AND the
# removes, so it cannot see carving or deletion at all.  chk_mxfs prints the
# real allocated-inode count and works against a mounted device.
# AND chk_mxfs READS THE PLATTER SUPERBLOCK, WHICH LAGS A LIVE MOUNT.  MXFS
# keeps sb_icount lazily and only writes it at unmount, so a sample taken
# while the workload is in flight reports the value from the LAST unmount, not
# the current one.  Measured on 0.75.125: STEP0/1/3 all read 64 while the
# cold read after the unmount in step 4 said 12032 -- the run carved 187
# chunks and every mid-flight sample missed all of them, which is exactly how
# a decisive lap gets reported as VACUOUS.
#
# So the mid-flight samples stay (they are cheap and they show the lag) but
# NOTHING IS GATED ON THEM.  The carve gate is the count of files the workload
# actually created, and the post-state is the COLD read taken in step 4 with
# both nodes unmounted.
icount() { rs 90 "$1" "sync; /src/mxfs/tools/chk_mxfs -v $DEV 2>/dev/null | sed -n 's/.*Superblock icount: *//p' | tail -1 | tr -d ' \r'"; }
IC0=$(icount "$A")
echo "STEP0 icount_before=$IC0"

# ---- step 1: carve chunks -------------------------------------------------
D=$MNT/d0949.$LABEL
t0=$(date +%s)
# the budget rule BUDGET, DERIVED AND MEASURED, NOT ROUNDED.  12000 empty files into a
# fresh directory on this two-node TCP rig, with the chunks already carved:
# 85.5 s measured (tools/mxfs_sshpass.sh test1, 2026-09-10, sv 0F560095).  The
# bound is 2x that.  Carving new chunks costs far more -- the first cut of this
# harness ran the same loop on a filesystem with icount=64, needed to carve 187
# chunks, and was still going at 400 s -- so this lap deliberately runs on a
# filesystem that ALREADY HOLDS the chunks it is going to empty.  That is the
# condition under test anyway: the defect is in the DELETE of a fully-free
# chunk, not in its carve.
rs 180 "$A" "mkdir -p $D && i=0; while [ \$i -lt $NFILES ]; do : > $D/f\$i || break; i=\$((i+1)); done; echo CREATED=\$i" > "$OUT/create.txt" 2>&1
t1=$(date +%s)
CREATED=$(sed -n 's/.*CREATED=//p' "$OUT/create.txt" | tr -d '\r')
IC1=$(icount "$A")
echo "STEP1 created=${CREATED:-0} wall=$((t1-t0))s icount_after_create=$IC1"

# ---- step 2: B leaves; A becomes a SOLE SURVIVOR ---------------------------
rs 120 "$B" "umount $MNT; echo UMOUNT_RC=\$?" > "$OUT/umount_b.txt" 2>&1
sleep 5
rs 20 "$A" "echo '$MARK-SOLE' > /dev/kmsg"
# a read touches the membership predicate so P-SOLE-SURVIVOR is emitted
rs 30 "$A" "ls $D >/dev/null 2>&1; stat -f $MNT >/dev/null 2>&1; echo TOUCH_OK"
echo "STEP2 $(cat "$OUT/umount_b.txt" | tr -d '\r' | tr '\n' ' ')"

# ---- step 3: empty the chunks while sole survivor --------------------------
t2=$(date +%s)
rs 400 "$A" "rm -rf $D; echo RM_RC=\$?; sync; echo SYNC_RC=\$?" > "$OUT/remove.txt" 2>&1
# inactivation is deferred to inodegc, and the chunk delete happens inside it,
# so the count is not final the instant rm returns.  Settle, then sample.
sleep 15
IC2=$(icount "$A")
t3=$(date +%s)
echo "STEP3 $(cat "$OUT/remove.txt" | tr -d '\r' | tr '\n' ' ') wall=$((t3-t2))s icount_after_rm=$IC2"

# ---- harvest ---------------------------------------------------------------
rs 60 "$A" "dmesg | awk '/$MARK/{f=1} f'" > "$OUT/dmesg_A.txt" 2>&1
cnt() { local c; c=$(grep -ac -- "$1" "$OUT/dmesg_A.txt" 2>/dev/null | head -1); echo "${c:-0}"; }
CARVE=$(cnt 'P133-ICLUSTER-SYNCINIT')
SOLE=$(cnt 'P-SOLE-SURVIVOR')
CF=$(cnt 'P103-CHUNKFREE')
CFSOLE=$(cnt 'P103-CHUNKFREE-SOLE')
CF1=$(grep -ac 'P103-CHUNKFREE sole=1' "$OUT/dmesg_A.txt" 2>/dev/null | head -1); CF1=${CF1:-0}
NOMAGIC=$(cnt 'P947-VALIDATE-NOMAGIC')
FOREIGN=$(cnt 'P949-HOME-FOREIGN')
STALE=$(cnt 'P949-PLAIN-STALE')

grep -a 'P103-CHUNKFREE' "$OUT/dmesg_A.txt" 2>/dev/null | head -20 > "$OUT/chunkfree_lines.txt"

# ---- step 4: cross-tree audit, ON A QUIESCED FILESYSTEM --------------------
# The audit compares two btrees against each other, so it must not read a live
# mount: in-flight allocation would show up as a disagreement between the trees
# and this check would announce a corruption that is really just a snapshot
# skew.  Unmount A as well (B is already out from step 2), audit the device
# cold, then bring both nodes back.  This is also the first real use of the
# check, so a false ERROR here would be worse than no check at all.
rs 180 "$A" "umount $MNT; echo UMOUNT_A_RC=\$?" > "$OUT/umount_a.txt" 2>&1
rs 300 "$A" "/src/mxfs/tools/chk_mxfs -v $DEV 2>&1 | tail -45" > "$OUT/chk.txt" 2>&1
ALIAS=$(grep -a 'Chunk/free-space aliasing' "$OUT/chk.txt" | head -1 | tr -d '\r')
# THE ONLY TRUSTWORTHY icount IN THE WHOLE LAP: both nodes are unmounted, so
# the platter superblock has been written and says what is actually there.
ICCOLD=$(sed -n 's/.*Superblock icount: *//p' "$OUT/chk.txt" | tail -1 | tr -d ' \r')
CHKVERDICT=$(grep -a '^chk_mxfs: ' "$OUT/chk.txt" | tail -1 | tr -d '\r')
rs 180 "$A" "mount -t mxfs $DEV $MNT; echo REMOUNT_A_RC=\$?" > "$OUT/remount_a.txt" 2>&1
rs 180 "$B" "mount -t mxfs $DEV $MNT; echo REMOUNT_B_RC=\$?" > "$OUT/remount_b.txt" 2>&1
echo "STEP4 $(cat "$OUT/umount_a.txt" "$OUT/remount_a.txt" "$OUT/remount_b.txt" 2>/dev/null | tr -d '\r' | tr '\n' ' ')"

# ---- step 5: THE ACROSS-MOUNT ARM -----------------------------------------
# THE FIRST FIX PASSED ITS LAP AND STILL HAD A HOLE, AND THIS ARM IS THE HOLE.
#
# Moving the guard from "am I alone now" to "has this MOUNT had a peer" was
# verified by everything above -- and mxfs_v5_dlm_sole_survivor() rests on
# ever_multi, a per-mount in-core bool with no durable backing.  Every node has
# just unmounted for the cold audit in step 4.  Mount ONE node now and it comes
# up with ever_multi false: to that mount the volume looks exactly like one that
# has never been clustered, even though the 187 chunks it is about to empty were
# filled while a peer was live.
#
# So this arm is the same measurement as the main lap, run against a mount that
# has no memory of the peer.  P103-CHUNKFREE must still be 0.  If the primary
# lap passes and this one does not, the fix is scoped to a mount and the defect
# is intact across a remount -- which is exactly what happened once already.
#
# derived time budget: the chunks already exist and were KEPT by step 3, so these
# creates carve nothing and run at the measured ~7 ms each; 4000 files is ~30 s.
# A single cold mount was measured at up to 80 s when it meets a frozen slot.
if [ "${MXFS_D0949_REMOUNT_ARM:-1}" = 1 ]; then
    RN=${MXFS_D0949_REMOUNT_FILES:-4000}
    D2=$MNT/d0949x.$LABEL
    MARK2="$MARK-XMOUNT"
    # B is already out from step 2; A was unmounted for the cold audit and then
    # remounted by step 4.  Take A out again so the next mount is genuinely
    # cold, with no peer and no in-core memory of one.
    rs 180 "$A" "umount $MNT; echo X_UMOUNT_A_RC=\$?" > "$OUT/x_umount_a.txt" 2>&1
    rs 180 "$A" "mount -t mxfs $DEV $MNT; echo X_MOUNT_A_RC=\$?" > "$OUT/x_mount_a.txt" 2>&1
    xm=$(rs 30 "$A" "grep -c ' $MNT mxfs ' /proc/mounts")
    echo "STEP5 $(cat "$OUT/x_umount_a.txt" "$OUT/x_mount_a.txt" 2>/dev/null | tr -d '\r' | tr '\n' ' ') mounted=$xm"
    if [ "$xm" != 1 ]; then
        echo "D0949-XMOUNT PRECOND_FAIL $A did not come back alone; the across-mount arm did not run"
        XVERDICT=NOTRUN; XCF=0; XCREATED=0; XSOLE=0
    else
        rs 20 "$A" "echo '$MARK2' > /dev/kmsg"
        rs 200 "$A" "mkdir -p $D2 && i=0; while [ \$i -lt $RN ]; do : > $D2/f\$i || break; i=\$((i+1)); done; echo XCREATED=\$i" > "$OUT/x_create.txt" 2>&1
        XCREATED=$(sed -n 's/.*XCREATED=//p' "$OUT/x_create.txt" | tr -d '\r'); XCREATED=${XCREATED:-0}
        rs 300 "$A" "rm -rf $D2; sync; echo X_RM_RC=\$?" > "$OUT/x_remove.txt" 2>&1
        sleep 15
        rs 60 "$A" "dmesg | awk '/$MARK2/{f=1} f'" > "$OUT/x_dmesg_A.txt" 2>&1
        XCF=$(grep -ac 'P103-CHUNKFREE' "$OUT/x_dmesg_A.txt" 2>/dev/null | head -1); XCF=${XCF:-0}
        XSOLE=$(grep -ac 'P-SOLE-SURVIVOR' "$OUT/x_dmesg_A.txt" 2>/dev/null | head -1); XSOLE=${XSOLE:-0}
        XFILLED=$(( XCREATED / 64 ))
        if [ "$XFILLED" -le 0 ]; then
            XVERDICT=VACUOUS
        elif [ "$XCF" -gt 0 ]; then
            XVERDICT=CONFIRMED-ACROSS-MOUNT
        else
            XVERDICT=KEPT-FIXED
        fi
        echo "D0949-XMOUNT verdict=$XVERDICT created=$XCREATED chunks_filled=$XFILLED chunkfree=$XCF sole_probe=$XSOLE"
        # P-SOLE-SURVIVOR MUST BE ZERO HERE, and that is the point of the arm:
        # this mount never saw a peer, so the predicate the first fix relied on
        # is false throughout.  A non-zero count means the mount somehow did
        # observe multi-node membership and the arm tested the easy case again.
        [ "$XSOLE" != 0 ] && echo "D0949-XMOUNT-NOTE sole_probe=$XSOLE is NOT 0 — this mount observed a peer, so it did not exercise the no-memory-of-a-peer case this arm exists for"
    fi
    rs 180 "$B" "mount -t mxfs $DEV $MNT; echo X_REMOUNT_B_RC=\$?" > "$OUT/x_remount_b.txt" 2>&1
    echo "STEP5 restore $(tr -d '\r' < "$OUT/x_remount_b.txt" | tr '\n' ' ')"
fi

# THE GATE IS (whole chunks were filled and then emptied) AND (the node was a
# sole survivor while that happened).  "Filled" is the count of files the
# workload actually created -- an unbudgeted, unlagged number that comes from
# the workload itself -- converted to whole chunks.  "Emptied" is the drop in
# the COLD icount, which is the only sample in this lap that is not a stale
# platter read.  Neither number comes from a rate-limited probe and neither
# comes from a live-mount superblock.
INOPERCHUNK=64
FILLED=$(( ${CREATED:-0} / INOPERCHUNK ))
DELETED=$(( ${IC0:-0} - ${ICCOLD:-0} ))
[ "$DELETED" -lt 0 ] && DELETED=0
VERDICT=VACUOUS
if [ "$FILLED" -gt 0 ] && [ "${SOLE:-0}" -gt 0 ]; then
    if [ "$DELETED" -gt 0 ] || [ "${CFSOLE:-0}" -gt 0 ] || [ "${CF1:-0}" -gt 0 ]; then
        # chunks went away, or the unbudgeted sole-survivor alert fired
        VERDICT=CONFIRMED
    else
        # chunks carved, node was a sole survivor, and the chunks were KEPT
        VERDICT=KEPT-FIXED
    fi
fi
echo "D0949 label=$LABEL verdict=$VERDICT created=${CREATED:-0} chunks_filled=$FILLED icount_live_samples=$IC0->$IC1->$IC2 icount_cold_after=${ICCOLD:-?} chunk_inodes_deleted=$DELETED carve_probe=$CARVE sole=$SOLE chunkfree=$CF chunkfree_sole1=$CF1 chunkfree_sole_alert=$CFSOLE nomagic=$NOMAGIC home_foreign=$FOREIGN plain_stale=$STALE"
echo "D0949-CHK $ALIAS"
echo "D0949-CHKVERDICT $CHKVERDICT"
echo "D0949 evidence=$OUT"
[ "$VERDICT" = VACUOUS ] && echo "D0949-NOTE the gate did not fire (chunks_filled=$FILLED sole=$SOLE) — this run measured NOTHING about the defect; raise NFILES or fix the sole-survivor step before reading the other counters"
exit 0
