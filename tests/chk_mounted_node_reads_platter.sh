#!/bin/bash
# chk_mounted_node_reads_platter.sh — the offline checker refuses a node whose
# module holds the shared device, and on a node that merely has the device
# held open by another process it reads the platter, not the block device's
# page cache.
#
# Measured s67e (ledger D-A-TEST-HARNESS-CAN-REPORT-A-VERDICT-ABOUT-MXFS,
# buffered-reader class): the module writes the LUN with bios that never
# touch the block device inode's page cache, and the kernel drops that cache
# only at the device's LAST close.  So a buffered read from a node where any
# opener still holds the device returns whatever image the first buffered
# read cached — a peer's later writes are invisible to it.  Every Python and
# shell instrument moved to O_DIRECT at 0.89.4; tools/chk_mxfs's main check
# descriptor stayed buffered.  At 0.89.6 (design consult banked in
# docs/rulings/checker-page-cache-and-exclusion.md) it opens O_EXCL, so a
# node whose own mount holds the device is refused, and it drops the
# device's cached pages (BLKFLSBUF) before its first read, so the leftovers
# of any plain opener on the node are not what it reads.
#
# SHAPE.  Both nodes are mounted (the capture gate's ensure).  A = creator,
# B = the checker's node.
#   arm 1, B mounted: tools/chk_mxfs on B is REFUSED (rc 4, the EBUSY text,
#      no "Superblock icount" line).  A verdict from a node whose module
#      holds the device would be read through that mount's page cache.
#   arm 2, B unmounted but the device held open by a plain process:
#      2a. On B: unmount; start a background holder (a sleep with the device
#          open read-only); read the XFS superblock sector once BUFFERED
#          (seeds B's cache, which the holder keeps alive) and once DIRECT;
#          both carry the same sb_icount or the lap ABORTs (a precondition).
#      2b. On A: create NFILES files, then unmount — the unmount writes the
#          platter superblock with the new inode count.
#      2c. On B: the direct read shows the new count (vacuity gate: the
#          platter moved) and the buffered read still shows the OLD one
#          (the hazard is live; if the buffered read followed the platter
#          the fix's mechanism was not exercised and the lap is VACUOUS).
#      2d. On B: tools/chk_mxfs -v.  Its "Superblock icount" must equal the
#          direct read's, and it must report the dropped pages.
#      2e. On B: the buffered read now shows the new count too — the
#          checker's invalidation dropped the stale page for every later
#          buffered reader on the node.
# Then the holder is stopped and both nodes are remounted.  The files stay
# (a few hundred inodes of residue).
#
# the budget rule (derived, not rounded): device resolve ~5 s + the refused
# check ~3 s + B's unmount ~10 s + four superblock reads ~8 s + NFILES
# creates at ~14 ms each (200 → ~3 s) + A's unmount ~10 s + the checker on
# a small filesystem (bounded 120 s, measured and tightened after the first
# PASS) + two remounts ~30 s ≈ 190 s.  Caller bound 380 s (2×).
#
# Usage: tests/chk_mounted_node_reads_platter.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, NFILES (default 200).
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}          # creates, then unmounts
B=${MXFS_NODE_LIST##*,}          # the checker runs here
MNT=/mnt/shared
NFILES=${NFILES:-200}
CHK=/src/mxfs/tools/chk_mxfs
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_chkmounted_$LABEL
mkdir -p "$OUT"
fails=0
echo "=== chk_mounted_node_reads_platter label=$LABEL A(creates,unmounts)=$A B(checker)=$B dev=$MXFS_DEV nfiles=$NFILES $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }

# The XFS superblock's byte offset is the envelope's xfs_data_offset (byte 88
# of sector 0, a mkfs-time constant, read direct); sb_icount is the
# big-endian u64 at byte 0x80 of that superblock.  The mode selects the
# reader: direct (the platter) or buffered (the page cache).  One line:
#   ICOUNT mode=<m> off=<bytes> icount=<n>
sbread() {   # <node> <mode> <file> <what>
    local flag=
    [ "$2" = direct ] && flag=iflag=direct
    measure "$1" 20 "$3" '^ICOUNT mode=[a-z]+ off=[0-9]+ icount=[0-9]+$' "$4" \
        "off=\$(dd if=$MXFS_DEV bs=4096 count=1 iflag=direct 2>/dev/null | od -An -tu8 -j88 -N8 -v | tr -d ' '); \
         h=\$(dd if=$MXFS_DEV bs=512 skip=\$((off/512)) count=1 $flag 2>/dev/null | od -An -tx1 -j128 -N8 -v | tr -d ' \\n'); \
         echo ICOUNT mode=$2 off=\$off icount=\$((16#\$h))"
}
icount_of() { sed -n 's/^ICOUNT .* icount=\([0-9]*\)$/\1/p' "$1" | head -1; }
mounted_into() {   # <var> <node> <file> <what>
    value_now_into "$1" "$2" 20 "$3" '^mounted=[01]$' "$4" "mountpoint -q $MNT && echo mounted=1 || echo mounted=0"
}
# the checker on <node>, its own timing and rc on the last line
chk_run() {   # <node> <file> <what> <shape>
    measure "$1" 120 "$2" "$4" "$3" \
        "s=\$(date +%s%N); $CHK -v $MXFS_DEV 2>&1; rc=\$?; e=\$(date +%s%N); echo CHK_RC=\$rc ms=\$(( (e-s)/1000000 ))"
}
chk_rc() { grep -ao '^CHK_RC=[0-9]*' "$1" | head -1 | cut -d= -f2; }

# precondition: both mounted
mounted_into am "$A" "$OUT/A_mounted_before.txt" "A's mount state before"
mounted_into bm "$B" "$OUT/B_mounted_before.txt" "B's mount state before"
ck "A is mounted before the arms" "$am" "mounted=1"
ck "B is mounted before the arms" "$bm" "mounted=1"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=precondition fails=$fails wall=$(el)s evidence=$OUT"; exit 2; }

# ---- arm 1: the checker on a node whose module holds the device is refused
chk_run "$B" "$OUT/B_chk_mounted.txt" "tools/chk_mxfs on $B while $B is mounted" '^CHK_RC=[0-9]+ ms=[0-9]+$'
echo "STAGE arm 1 (B mounted): $(grep -a '^CHK_RC=' "$OUT/B_chk_mounted.txt") at +$(el)s"
grep -a 'held open exclusively\|Superblock icount\|dropped the block' "$OUT/B_chk_mounted.txt" | sed 's/^/    /' | cut -c1-200
ck   "the checker refused the mounted node (rc 4)" "$(chk_rc "$OUT/B_chk_mounted.txt")" 4
ckge "it said why (held open exclusively on this node)" "$(cnt "$OUT/B_chk_mounted.txt" 'held open exclusively on this node')" 1
ck   "it printed no superblock verdict" "$(cnt "$OUT/B_chk_mounted.txt" '^  Superblock icount:')" 0
mounted_into bm "$B" "$OUT/B_mounted_after_arm1.txt" "B's mount state after arm 1"
ck   "B is still mounted after the refusal" "$bm" "mounted=1"

# ---- arm 2: B unmounted, the device held open by a plain process
measure "$B" 60 "$OUT/B_umount.txt" '^B_UMOUNT_RC=[0-9]+$' "B's unmount" "umount $MNT; echo B_UMOUNT_RC=\$?"
ck "B unmounted before the holder arm" "$(grep -ao '^B_UMOUNT_RC=[0-9]*' "$OUT/B_umount.txt" | cut -d= -f2)" 0
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=B_umount fails=$fails wall=$(el)s evidence=$OUT"; exit 2; }
# the holder: keeps bd_openers above zero so the page cache outlives every
# short-lived reader, exactly as a mount would, without being a mount
measure "$B" 20 "$OUT/B_holder.txt" '^HOLDER_PID=[0-9]+$' "the device holder on $B" \
    "nohup sh -c 'exec 3<$MXFS_DEV; exec sleep 600' </dev/null >/dev/null 2>&1 & echo HOLDER_PID=\$!"
holder=$(grep -ao '^HOLDER_PID=[0-9]*' "$OUT/B_holder.txt" | cut -d= -f2)
stop_holder() { rs 20 "$B" "kill $holder 2>/dev/null; sleep 1; echo holder_stopped" >/dev/null; }
sbread "$B" buffered "$OUT/B_sb_buffered_0.txt" "B's buffered superblock read (seeds the cache)"
sbread "$B" direct   "$OUT/B_sb_direct_0.txt"   "B's direct superblock read before the arm"
b0=$(icount_of "$OUT/B_sb_buffered_0.txt"); d0=$(icount_of "$OUT/B_sb_direct_0.txt")
echo "STAGE seed (B unmounted, holder pid $holder): buffered icount=$b0 direct icount=$d0 at +$(el)s"
if [ "$b0" != "$d0" ]; then
    stop_holder
    echo "ABORT: B's page cache already disagrees with the platter before the arm (buffered=$b0 direct=$d0); the A/B needs a clean seed"
    echo "RESULT: ABORT label=$LABEL stage=seed evidence=$OUT"; exit 2
fi

# the arm: A creates and leaves; the platter superblock moves
measure "$A" 120 "$OUT/A_create_unmount.txt" '^A_UMOUNT_RC=[0-9]+ ms=[0-9]+$' "A's creates and unmount" \
    "d=$MNT/chkmounted_$LABEL; mkdir -p \$d && for i in \$(seq $NFILES); do : > \$d/f\$i; done; sync; s=\$(date +%s%N); umount $MNT; rc=\$?; e=\$(date +%s%N); echo A_UMOUNT_RC=\$rc ms=\$(( (e-s)/1000000 ))"
echo "STAGE A: $(grep -a '^A_UMOUNT_RC=' "$OUT/A_create_unmount.txt") at +$(el)s"
ck "A unmounted cleanly after its creates" "$(grep -ao '^A_UMOUNT_RC=[0-9]*' "$OUT/A_create_unmount.txt" | head -1 | cut -d= -f2)" 0

sbread "$B" direct   "$OUT/B_sb_direct_1.txt"   "B's direct superblock read after A's unmount"
sbread "$B" buffered "$OUT/B_sb_buffered_1.txt" "B's buffered superblock read after A's unmount"
d1=$(icount_of "$OUT/B_sb_direct_1.txt"); b1=$(icount_of "$OUT/B_sb_buffered_1.txt")
echo "STAGE after A's unmount: direct icount=$d1 buffered icount=$b1 (seed was $d0) at +$(el)s"
if [ "$d1" = "$d0" ]; then
    stop_holder
    echo "VACUOUS: the platter superblock's icount did not move across A's unmount ($d0 -> $d1); nothing distinguishes a cached image from the platter"
    echo "RESULT: VACUOUS label=$LABEL stage=platter_moved wall=$(el)s evidence=$OUT"; exit 3
fi
if [ "$b1" != "$b0" ]; then
    stop_holder
    echo "VACUOUS: B's buffered read followed the platter ($b0 -> $b1) while the holder kept the device open; the stale-cache hazard the checker's invalidation exists for was not present, so the arm exercised nothing"
    echo "RESULT: VACUOUS label=$LABEL stage=hazard_live wall=$(el)s evidence=$OUT"; exit 3
fi
echo "STAGE hazard live: B's buffered read still returns the seeded image ($b1) while the platter says $d1"

# the measurement: the checker on B, the device held open by the holder
chk_run "$B" "$OUT/B_chk.txt" "tools/chk_mxfs -v on $B (unmounted, device held open)" '^  Superblock icount: +[0-9]+$'
echo "STAGE checker: $(grep -a '^CHK_RC=' "$OUT/B_chk.txt") at +$(el)s"
grep -a '^  Superblock icount:\|dropped the block\|error(s) found' "$OUT/B_chk.txt" | sed 's/^/    /' | cut -c1-200
chk_icount=$(sed -n 's/^  Superblock icount: *\([0-9]*\)$/\1/p' "$OUT/B_chk.txt" | head -1)
ck   "the checker's superblock icount is the platter's, not the cached image's" "$chk_icount" "$d1"
ckge "the checker reported that it dropped the device's cached pages" "$(cnt "$OUT/B_chk.txt" 'dropped the block device')" 1
# Both nodes are unmounted here, so the platter is quiescent and the check
# must be clean.  s69a (0.89.6) PASSed the two assertions above while the
# checker reported 10 errors: its interior-node btree walk read the child
# pointers at the wrong byte and judged the superblock as a corrupt inobt
# block (fixed 0.89.7).  A verifier that misreports a clean platter is this
# ledger record's own class, so its verdict is asserted, not just its icount.
ck   "the checker found no errors on the quiescent platter (rc 0)" "$(chk_rc "$OUT/B_chk.txt")" 0
ck   "it reported no error lines" "$(cnt "$OUT/B_chk.txt" '^  ERROR:')" 0

# the checker's open dropped the stale page: a later buffered reader sees the platter
sbread "$B" buffered "$OUT/B_sb_buffered_2.txt" "B's buffered superblock read after the checker"
b2=$(icount_of "$OUT/B_sb_buffered_2.txt")
echo "STAGE after the checker: buffered icount=$b2 at +$(el)s"
ck "B's buffered read now returns the platter's icount (the checker's invalidation dropped the stale page)" "$b2" "$d1"
stop_holder

# leave the fleet as found: both remounted (B first, then A)
for n in "$B" "$A"; do
    m=$(rs 180 "$n" "s=\$(date +%s%N); mount -t mxfs $MXFS_DEV $MNT; rc=\$?; e=\$(date +%s%N); echo MOUNT_RC=\$rc ms=\$(( (e-s)/1000000 ))")
    echo "  INFO $n's remount: ${m:-no result} at +$(el)s"
done
mounted_into am2 "$A" "$OUT/A_mounted_after.txt" "A's mount state after"
mounted_into bm2 "$B" "$OUT/B_mounted_after.txt" "B's mount state after"
ck "A is mounted again at the end" "$am2" "mounted=1"
ck "B is mounted again at the end" "$bm2" "mounted=1"
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
