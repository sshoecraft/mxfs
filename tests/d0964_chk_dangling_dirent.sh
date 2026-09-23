#!/bin/bash
# d0964_chk_dangling_dirent.sh — chk_mxfs's directory-entry walk names a
# dangling entry, counts what it walked, and stays CLEAN on a healthy volume.
#
# D-CHK-MXFS-DOES-NOT-WALK-DIRECTORY-ENTRIES-SO-A-DIRENT-NAMING-A-FREE-INODE-
# PASSES-CLEAN-0964: before the walk existed the checker parsed no name, so
# the durable outcome of D-0963 (a published dirent naming a freed inode,
# listed on every node, resolved on none, unremovable) reported CLEAN.
#
# Phase 1 (formats, healthy): A creates four directories that land in each
# on-disk directory format — shortform (3 names), block (100), leaf (300) and
# node (1500) — and syncs.  Both nodes unmount so the platter is the only
# view.  chk_mxfs -v run offline on A must report, per directory, exactly the
# entries created plus the two dots (the shortform parent counts as its '..'),
# an OK directory-entry pass with zero dangling, and a clean volume (rc 0).
# Phase 2 (the defect's fixture): both nodes remount and the D-0963 control
# arm (tests/d0963_sf_lagging_flush.sh MODE=control, one lap) publishes a
# dangling entry V in a directory D; its own verdict proves the fixture (V
# lists on both nodes and resolves on neither).  Both nodes unmount again and
# chk_mxfs must name D and V as a dangling entry with rc 4; under -a the
# entry is reported and retained (report only), and a further plain run still
# names it.
#
# The fleet is left UNMOUNTED on a volume carrying the control arm's
# directory: the caller preps afterwards.
#
# Usage: tests/d0964_chk_dangling_dirent.sh <label> [nodeA] [nodeB]  (default test1 test2)
# Exit 0 = every check held, 1 = a check failed, 2 = ABORT (nothing measured).
#
# derived time budget: identity + srcgate ~6 s; phase 1 creates 1903 names
# (native XFS ~0.5 s; ×2 and the cluster's per-create DLM ~4 ms => ~10 s) +
# sync 1 s + two unmounts ~2 s + chk offline ~15 s (1903 dinode reads) + two
# mounts ~10 s => ~40 s; phase 2 control arm one lap ~18 s + two unmounts +
# three chk runs ~45 s => ~70 s.  Total ~125 s; caller bound 300 s.
set -u
LABEL=${1:?label}; A=${2:-test1}; B=${3:-test2}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0964chk_$LABEL
mkdir -p "$OUT"
fails=0
# rsx/measure/capture_require/value_now_into (tests/lib/rig.sh): every
# capture a verdict is read from crosses the boundary in the parent shell
# first; a failed acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
fld() { echo "$1" | grep -ao "$2=[0-9-]*" | head -1 | cut -d= -f2; }

echo "=== d0964_chk_dangling_dirent label=$LABEL A=$A B=$B out=$OUT $(date -u +%FT%TZ) ==="
export MXFS_NODE_LIST="$A,$B"
mxfs_dev_same "$A" "$B"
DEV=$MXFS_DEV_RESOLVED
ensure_src_or_abort "$A" "$B"
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $A $B; do
    value_now_into nsv "$n" 15 "$OUT/rv_nsv_$n.txt" '^[0-9A-F]+$' "srcversion on $n" "cat /sys/module/mxfs/srcversion"
    [ "$nsv" = "$want" ] || { echo "ABORT: $n runs $nsv, the tree is $want"; echo "RESULT: ABORT label=$LABEL stage=srcgate evidence=$OUT"; exit 2; }
done
CHK=/src/mxfs/tools/chk_mxfs
value_now_into cv "$A" 15 "$OUT/rv_chk_present.txt" '^CHK ' "chk_mxfs on the share from $A" "test -x $CHK && echo CHK ok=1 || echo CHK ok=0"
[ "$(fld "$cv" ok)" = 1 ] || { echo "ABORT: $CHK is not executable on $A (make tools)"; echo "RESULT: ABORT label=$LABEL stage=tools evidence=$OUT"; exit 2; }

umount_both() {   # $1 = phase tag
    local n urc
    for n in $A $B; do
        value_now_into urc "$n" 90 "$OUT/rv_umount_$1_$n.txt" '^UM rc=' "umount on $n ($1)" "timeout 60 umount $MNT; echo UM rc=\$? mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)"
        echo "  $n $1: $urc"
        [ "$(fld "$urc" rc)" = 0 ] && [ "$(fld "$urc" mounted)" = 0 ] || { echo "ABORT: $n did not unmount for the offline check ($urc)"; echo "RESULT: ABORT label=$LABEL stage=umount-$1 evidence=$OUT"; exit 2; }
    done
}
mount_both() {
    local n mrc
    for n in $A $B; do
        value_now_into mrc "$n" 120 "$OUT/rv_mount_$1_$n.txt" '^RM rc=' "mount on $n ($1)" "timeout 90 mount -t mxfs $DEV $MNT; echo RM rc=\$? mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)"
        echo "  $n $1: $mrc"
        [ "$(fld "$mrc" rc)" = 0 ] && [ "$(fld "$mrc" mounted)" = 1 ] || { echo "ABORT: $n did not remount ($mrc)"; echo "RESULT: ABORT label=$LABEL stage=mount-$1 evidence=$OUT"; exit 2; }
    done
}
# chk_offline <file> <args>: the checker's whole output is the result, so its
# own status line is the shape; the ssh's status is what ABORTs.
chk_offline() {
    mxfs_dev_check "$A"
    rsx 150 "$A" "$CHK $2 $DEV 2>&1; printf '\nCHK_RC=%s\n' \$?" > "$1"
    capture_require "$1" '^CHK_RC=[0-9]+$' "chk_mxfs $2 offline on $A"
}
dirline() { grep -a "^  dirents: directory $1 " "$2" | head -1; }

# ---------------- phase 1: every directory format, healthy ----------------
BASE=$MNT/d0964_$LABEL
echo "--- phase 1: format fixtures at +$(el)s ---"
value_now_into mk "$A" 120 "$OUT/rv_mk.txt" '^MK ' "creating the format fixtures on $A" \
  "mkdir -p $BASE/sf $BASE/blk $BASE/leaf $BASE/node && \
   for i in \$(seq 1 3); do : > $BASE/sf/f\$i; done && \
   for i in \$(seq 1 100); do : > $BASE/blk/f\$i; done && \
   for i in \$(seq 1 300); do : > $BASE/leaf/f\$i; done && \
   for i in \$(seq 1 1500); do : > $BASE/node/f\$i; done && sync && \
   echo MK sf=\$(stat -c %i $BASE/sf) blk=\$(stat -c %i $BASE/blk) leaf=\$(stat -c %i $BASE/leaf) node=\$(stat -c %i $BASE/node) sfsz=\$(stat -c %s $BASE/sf) blksz=\$(stat -c %s $BASE/blk) leafsz=\$(stat -c %s $BASE/leaf) nodesz=\$(stat -c %s $BASE/node)"
echo "  $mk"
SF=$(fld "$mk" sf); BLK=$(fld "$mk" blk); LEAF=$(fld "$mk" leaf); NODE=$(fld "$mk" node)
umount_both p1
chk_offline "$OUT/chk_p1.txt" -v
rc1=$(sed -n 's/^CHK_RC=//p' "$OUT/chk_p1.txt" | tail -1)
pass1=$(grep -a '^Directory entries' "$OUT/chk_p1.txt" | head -1)
echo "  $pass1"
echo "--- verdict phase 1 ---"
ck "p1: the directory-entry pass ran and is OK" "$(echo "$pass1" | grep -ac '^Directory entries ....... OK')" "1"
ck "p1: zero dangling entries on the healthy volume" "$(echo "$pass1" | grep -ao 'dangling=[0-9]*' | head -1)" "dangling=0"
ck "p1: shortform directory $SF walked with 3 names + parent" "$(dirline "$SF" "$OUT/chk_p1.txt" | grep -ao 'format=shortform entries=[0-9]*')" "format=shortform entries=4"
ck "p1: block directory $BLK walked with 100 names + dots in one block" "$(dirline "$BLK" "$OUT/chk_p1.txt" | grep -ao 'entries=[0-9]* blocks=[0-9]*')" "entries=102 blocks=1"
ck "p1: leaf directory $LEAF walked with 300 names + dots" "$(dirline "$LEAF" "$OUT/chk_p1.txt" | grep -ao 'entries=[0-9]*')" "entries=302"
# ' blocks=' with its leading space: 'bad_blocks=' on the same line also
# contains 'blocks=' (s62b: two matches, an unjudgeable two-line value)
ckge "p1: leaf directory $LEAF spans more than one data block" "$(dirline "$LEAF" "$OUT/chk_p1.txt" | grep -ao ' blocks=[0-9]*' | cut -d= -f2)" "2"
ck "p1: node directory $NODE walked with 1500 names + dots" "$(dirline "$NODE" "$OUT/chk_p1.txt" | grep -ao 'entries=[0-9]*')" "entries=1502"
ckge "p1: node directory $NODE spans many data blocks" "$(dirline "$NODE" "$OUT/chk_p1.txt" | grep -ao ' blocks=[0-9]*' | cut -d= -f2)" "5"
ck "p1: no directory was skipped and no block was bad" "$(echo "$pass1" | grep -ao 'bad_blocks=[0-9]* dirs_skipped=[0-9]*')" "bad_blocks=0 dirs_skipped=0"
ck "p1: the unmounted healthy volume is clean (chk_mxfs rc)" "$rc1" "0"
[ "$rc1" = 0 ] || grep -a '^  ERROR' "$OUT/chk_p1.txt" | head -6 | sed 's/^/     /'
mount_both p1

# ---------------- phase 2: the D-0963 control arm's dangling entry ---------
echo "--- phase 2: control arm at +$(el)s ---"
MODE=control MXFS_NODE_LIST="$A,$B" tests/d0963_sf_lagging_flush.sh "$LABEL-ctl" 1 64 > "$OUT/d0963_control.log" 2>&1
crc=$?
CO=$(grep -ao ' out=tests/evidence/[^ ]*' "$OUT/d0963_control.log" | head -1 | sed 's/^ out=//')
echo "  control arm rc=$crc out=$CO"
grep -a '^  FAIL\|^ABORT\|^=== d0963' "$OUT/d0963_control.log" | head -8 | sed 's/^/     /'
[ "$crc" = 0 ] || { echo "ABORT: the control arm did not publish its dangling entry (rc=$crc): no fixture to check"; echo "RESULT: ABORT label=$LABEL stage=fixture evidence=$OUT"; exit 2; }
[ -r "$CO/lap1.txt" ] || { echo "ABORT: the control arm's lap record $CO/lap1.txt is missing"; echo "RESULT: ABORT label=$LABEL stage=fixture evidence=$OUT"; exit 2; }
DINO=$(grep -a '^CA ' "$CO/lap1.txt" | grep -ao 'ino=[0-9]*' | head -1 | cut -d= -f2)
K=$(grep -a '^RB ' "$CO/lap1.txt" | grep -ao 'removed=[0-9]*' | head -1 | cut -d= -f2)
[ -n "$DINO" ] && [ -n "$K" ] || { echo "ABORT: the control arm's lap record names no directory inode or removal count"; echo "RESULT: ABORT label=$LABEL stage=fixture evidence=$OUT"; exit 2; }
V=nodeB_file$((K+1))
echo "  fixture: directory ino=$DINO dangling name=$V"
umount_both p2
chk_offline "$OUT/chk_p2.txt" -v
rc2=$(sed -n 's/^CHK_RC=//p' "$OUT/chk_p2.txt" | tail -1)
pass2=$(grep -a '^Directory entries' "$OUT/chk_p2.txt" | head -1)
echo "  $pass2"
grep -a "ERROR: directory $DINO:" "$OUT/chk_p2.txt" | head -3 | sed 's/^/     /'
echo "--- verdict phase 2 ---"
dang() { grep -ac "ERROR: directory $DINO: entry '$V' names inode [0-9]* .*(dangling entry)" "$1"; }
ck "p2: chk_mxfs names the dangling entry (directory $DINO, name $V)" "$(dang "$OUT/chk_p2.txt")" "1"
ck "p2: the directory-entry pass reports ERRORS" "$(echo "$pass2" | grep -ac '^Directory entries ....... ERRORS')" "1"
ck "p2: the walk of $DINO counted its dangling entry" "$(dirline "$DINO" "$OUT/chk_p2.txt" | grep -ao 'dangling=[0-9]*')" "dangling=1"
ck "p2: the volume is not clean (chk_mxfs rc 4)" "$rc2" "4"
chk_offline "$OUT/chk_p2_repair.txt" "-a -v"
rc3=$(sed -n 's/^CHK_RC=//p' "$OUT/chk_p2_repair.txt" | tail -1)
ck "p2: under -a the dangling entry is still reported (report only)" "$(dang "$OUT/chk_p2_repair.txt")" "1"
ck "p2: under -a nothing claims to have repaired a directory entry" "$(grep -ac 'REPAIRED: directory' "$OUT/chk_p2_repair.txt")" "0"
chk_offline "$OUT/chk_p2_after.txt" -v
rc4=$(sed -n 's/^CHK_RC=//p' "$OUT/chk_p2_after.txt" | tail -1)
ck "p2: after -a the entry is retained and named again" "$(dang "$OUT/chk_p2_after.txt")" "1"
ck "p2: after -a the volume still reports rc 4" "$rc4" "4"
echo "  INFO rc: plain=$rc2 repair=$rc3 after=$rc4"
echo "  INFO the fleet is left unmounted on the fixture volume; prep before the next lap"
echo "=== d0964_chk_dangling_dirent $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
if [ "$fails" -eq 0 ]; then echo "RESULT: PASS label=$LABEL fails=0 wall=$(el)s evidence=$OUT"; exit 0; fi
echo "RESULT: FAIL label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"; exit 1
