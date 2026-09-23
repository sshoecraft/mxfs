#!/bin/bash
# d0959_first_join_drain.sh — does a mount that has never had a peer lose the
# directory changes it holds dirty at NL when its first peer joins?
#
# D-0959.  On single-node membership mxfs_dlm_ilock_begin takes the
# never-multi bypass: no DLM grant, i_dlm_mode stays NL.  When a peer joins,
# the DLM master purges its table and advances the epoch, but nothing lands
# the incumbent's dirty NL images first, and the newcomer's acquires find no
# holder to BAST.  From that moment the incumbent is a multi-node member, and
# mxfs_submit_partial_inode_write refuses to publish a LOGGED DIRECTORY at NL
# without the release-drain token (P56-NL-LOGGED-DIR-SKIP) -- the rule that
# stranded the sole survivor's directory in s583c.  So a directory the
# incumbent created or modified before the join, still dirty at the join,
# may never reach the platter.
#
# The shape: both nodes start mounted (a normal prep).  B unmounts, A
# unmounts, A mounts ALONE (a fresh mount: never multi).  A creates a
# directory tree with no sync.  B mounts (the first join).  Both nodes wait
# for active_count=2.  A syncs.  The verdict is read from three places:
#   P56-NL-LOGGED-DIR-SKIP on A since the join mark  (the omission, if any)
#   B's cold listing of A's tree                     (what the platter holds)
#   a fresh mount of A after both unmount            (the durable truth)
# A tree that B cannot see, or that is gone after the remount, is the loss.
#
# derived budget: two unmounts and three mounts at ~5 s each on this rig,
# 400 creates at ~3 ms, a membership settle of up to 20 s, two cold listings.
# 120 s of work; the whole run is bounded at 240 s and any single ssh step at
# the number written beside it.
#
# Usage: tests/d0959_first_join_drain.sh <label> [FILES=400]
set -u
LABEL=${1:?label}
FILES=${2:-400}
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
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0959joindrain_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0959_first_join_drain label=$LABEL files=$FILES sv=$SV $(date -u +%FT%TZ) ==="

fails=0
for n in $A $B; do
    st=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) mnt=\$(grep -c ' $MNT mxfs ' /proc/mounts)" | tr -d '\n')
    echo "  INFO $n $st"
    [ "$st" = "sv=$SV mnt=1" ] || { echo "  FAIL $n precondition (want sv=$SV mnt=1)"; fails=$((fails+1)); }
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL precondition fails=$fails"; exit 2; }

D=$MNT/d0959_$LABEL
t0=$(date +%s)
# Leave the cluster in reverse join order, then bring A back alone.
echo "  LEAVE B=$(rs 120 "$B" "umount $MNT; echo rc=\$?" | tr '\n' ' ') A=$(rs 120 "$A" "umount $MNT; echo rc=\$?" | tr '\n' ' ')"
amt=$(rs 120 "$A" "mount -t mxfs $DEV $MNT; echo A_SOLO_MOUNT_RC=\$?; sleep 2; dmesg | grep -a 'MXFS-MEMBERSHIP' | tail -1 | grep -ao 'active_count=[0-9]*'")
echo "  SOLO $(echo "$amt" | tr '\n' ' ')"
case "$amt" in *A_SOLO_MOUNT_RC=0*) ;; *) echo "RESULT: FAIL label=$LABEL $A could not mount alone: $amt"; exit 2 ;; esac

# THE DIRTY STATE HAS TO EXIST AT THE MOMENT OF THE FLIP.  The first cut of
# this harness made one directory tree and then mounted B: xfsaild wrote the
# directory blocks 0.7 s after they were created, on the single-node whole
# path, before the membership line -- the join found nothing dirty and the
# lap read NOT REPRODUCED (s583o).  So A keeps creating directories, each
# with ten files and no sync, until its own log shows active_count=2, and
# stops.  The directories made in the last second before the flip are the
# ones whose images are dirty at NL when A becomes a multi-node member.
# AND IT HAS TO BE A MODIFICATION OF A DIRECTORY THAT ALREADY REACHED THE
# PLATTER.  The second cut created new directories up to the flip and still
# read NOT REPRODUCED (s583p): a freshly carved inode chunk is written WHOLE
# on its first flush by design (XFS_BLI_INODE_ALLOC_BUF), so a brand-new
# directory's dinode never meets the partial path's NL rule.  A directory
# that was created and flushed while alone, then given new names just before
# the flip, is the exposed state: its dinode is logged at NL, its cluster is
# an ordinary buffer, and the flush after the flip takes the partial path.
# Twenty shortform directories are made and synced first; the loop then adds
# one name per iteration round-robin until it sees the second member.
NPRE=20
JOINMK="D0959-JOINMARK-$LABEL-$$"
rs 60 "$A" "mkdir -p $D; for j in \$(seq 1 $NPRE); do mkdir -p $D/j\$j; for k in 1 2 3 4 5 6 7 8 9 10; do : > $D/j\$j/x\$k; done; done; sync -f $MNT; sleep 2; echo PRE dirs=\$(ls $D | grep -c '^j') files=\$(find $D -type f | wc -l)" | tr '\n' ' '
echo
rs 30 "$A" "echo '$JOINMK' > /dev/kmsg; rm -f /tmp/d0959_loop.txt; nohup bash -c 'i=0; while [ \$i -lt 20000 ]; do i=\$((i+1)); : > $D/j\$((i % $NPRE + 1))/y\$i; if [ \$((i % 10)) = 0 ] && dmesg | sed -n \"/$JOINMK/,\\\$p\" | grep -aq \"active_count=2\"; then echo JOIN_SEEN_AT_ADD=\$i; break; fi; done; echo LOOP_DONE adds=\$i' > /tmp/d0959_loop.txt 2>&1 &
sleep 1; echo LOOP_STARTED adds_so_far=\$(find $D -name 'y*' | wc -l)" | tr '\n' ' '
echo

# The first join.  B mounts; both nodes must reach active_count=2 before A
# syncs, or the flush measures the never-multi path and not the join.
bmt=$(rs 180 "$B" "mount -t mxfs $DEV $MNT; echo B_JOIN_MOUNT_RC=\$?")
echo "  JOIN $(echo "$bmt" | tr '\n' ' ')"
case "$bmt" in *B_JOIN_MOUNT_RC=0*) ;; *) echo "RESULT: FAIL label=$LABEL $B could not join: $bmt"; exit 2 ;; esac
conv=$(rs 120 "$A" "for i in \$(seq 1 60); do grep -aq LOOP_DONE /tmp/d0959_loop.txt 2>/dev/null && { echo LOOP_ENDED_AT=\$i; break; }; sleep 1; done; cat /tmp/d0959_loop.txt | tr '\n' ' '; echo; echo A_VIEW=\$(dmesg | grep -a 'MXFS-MEMBERSHIP' | tail -1 | grep -ao 'active_count=[0-9]*') A_FILES=\$(find $D -type f | wc -l)")
echo "  CONVERGE $(echo "$conv" | tr '\n' ' ')"
case "$conv" in *JOIN_SEEN_AT_ADD=*) ;; *) echo "RESULT: FAIL label=$LABEL $A's add loop never saw active_count=2 after the join: $conv"; exit 2 ;; esac
NADDS=$(echo "$conv" | sed -n 's/.*LOOP_DONE adds=\([0-9]*\).*/\1/p' | head -1); NADDS=${NADDS:-0}
NDIRS=$NPRE
WANTFILES=$((NPRE * 10 + NADDS))

# A flushes everything it holds; then the incumbent's own log says whether a
# logged directory at NL was refused, and whether a skipped inode was re-armed.
fl=$(rs 120 "$A" "sync -f $MNT; echo SYNC_RC=\$?; sleep 3; dmesg | sed -n '/$JOINMK/,\$p' > /tmp/d0959_win.txt; echo MARK=\$(grep -ac '$JOINMK' /tmp/d0959_win.txt) NLDIRSKIP=\$(grep -ac 'P56-NL-LOGGED-DIR-SKIP' /tmp/d0959_win.txt) NLINKREV=\$(grep -ac 'P186-NLINK-REVERT' /tmp/d0959_win.txt) POISON=\$(grep -ac 'P34H-INCARN-POISON' /tmp/d0959_win.txt) SHUT=\$(grep -ac 'Shutting down filesystem\|P-WITHDRAW ' /tmp/d0959_win.txt) P218=\$(grep -ac 'P218-CLUSTER-AUTHORITY' /tmp/d0959_win.txt) SKIPPED_INOS=\$(grep -a 'P56-NL-LOGGED-DIR-SKIP' /tmp/d0959_win.txt | grep -ao 'ino=[0-9]*' | sort -u | tr '\n' ','); grep -a 'P56-NL-LOGGED-DIR-SKIP' /tmp/d0959_win.txt | head -3 | cut -c1-220")
echo "  FLUSH $(echo "$fl" | head -1 | tr '\n' ' ')"
echo "$fl" | tail -n +2 | sed 's/^/       /'
nskip=$(echo "$fl" | sed -n 's/.*NLDIRSKIP=\([0-9]*\).*/\1/p' | head -1); nskip=${nskip:-0}
smark=$(echo "$fl" | sed -n 's/.*MARK=\([0-9]*\).*/\1/p' | head -1); smark=${smark:-0}

# What the platter holds, read by the newcomer whose cache never held A's tree.
# Every j-directory must be present with its ten files.  COUNT reports
# dirs, files and the first few short directories by name.
COUNT="dirs=\$(ls $D 2>/dev/null | grep -c '^j'); files=\$(find $D -type f 2>/dev/null | wc -l); ys=\$(find $D -name 'y*' 2>/dev/null | wc -l); echo dirs=\$dirs files=\$files ys=\$ys want_dirs=$NDIRS want_files=$WANTFILES want_ys=$NADDS"
cold=$(rs 120 "$B" "echo B_COLD \$($COUNT)")
echo "  $(echo "$cold" | tr '\n' ' ')"

# The durable truth: both leave, A comes back cold.
lv=$(rs 120 "$B" "umount $MNT; echo B_UMOUNT_RC=\$?")
lv2=$(rs 120 "$A" "umount $MNT; echo A_UMOUNT_RC=\$?; mount -t mxfs $DEV $MNT; echo A_REMOUNT_RC=\$?; echo A_COLD \$($COUNT)")
echo "  DURABLE $(echo "$lv" "$lv2" | tr '\n' ' ')"
# Put B back so the rig is left as it was found.
rb=$(rs 180 "$B" "mount -t mxfs $DEV $MNT; echo B_REMOUNT_RC=\$?")
echo "  RESTORE $(echo "$rb" | tr '\n' ' ')"
wall=$(( $(date +%s) - t0 ))

bd=$(echo "$cold" | sed -n 's/.*B_COLD dirs=\([0-9]*\).*/\1/p'); bd=${bd:-0}
bf=$(echo "$cold" | sed -n 's/.*B_COLD dirs=[0-9]* files=\([0-9]*\).*/\1/p'); bf=${bf:-0}
ad=$(echo "$lv2" | sed -n 's/.*A_COLD dirs=\([0-9]*\).*/\1/p'); ad=${ad:-0}
af=$(echo "$lv2" | sed -n 's/.*A_COLD dirs=[0-9]* files=\([0-9]*\).*/\1/p'); af=${af:-0}
echo "D0959-JOINDRAIN label=$LABEL sv=$SV dirs=$NDIRS adds_before_flip=$NADDS nl_dir_skips=$nskip b_cold_dirs=$bd b_cold_files=$bf a_cold_dirs=$ad a_cold_files=$af want_files=$WANTFILES mark_seen=$smark wall=${wall}s evidence=$OUT"
if [ "$smark" = 0 ]; then
    echo "  READ: UNREADABLE — the join mark rolled out of $A's ring buffer; the skip count is unwindowed"
elif [ "$NADDS" = 0 ]; then
    echo "  READ: VACUOUS — the add loop made no modification before the flip"
elif [ "$ad" != "$NDIRS" ] || [ "$af" != "$WANTFILES" ]; then
    echo "  READ: LOST — after both nodes left, a fresh mount of $A finds dirs=$ad/$NDIRS files=$af/$WANTFILES of what it wrote alone up to the join (P56 skips=$nskip)"
elif [ "$nskip" -gt 0 ]; then
    echo "  READ: REFUSED-THEN-LANDED — $nskip logged directory image(s) were refused at NL after the join, yet the tree is durable; something else published them (read the P56 lines and the re-arm path before calling this clean)"
elif [ "$bd" != "$NDIRS" ] || [ "$bf" != "$WANTFILES" ]; then
    echo "  READ: NOT VISIBLE TO THE NEWCOMER — $B saw dirs=$bd/$NDIRS files=$bf/$WANTFILES while A's tree was durable; a coherency gap, not a loss"
else
    echo "  READ: NOT REPRODUCED — no logged directory at NL was refused after the join, the newcomer saw every directory cold, and all survived both nodes leaving"
fi
[ "$wall" -gt 120 ] && echo "  the budget rule: wall ${wall}s exceeds the 120 s derived bound"
exit 0
