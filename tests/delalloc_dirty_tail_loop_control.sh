#!/bin/bash
# tests/delalloc_dirty_tail_loop_control.sh — the same reproducer as
# tests/delalloc_dirty_tail_durability.sh, run on ONE spare node against a loop
# device, in two arms: native XFS of the node's own kernel, then a single-node
# MXFS mount of the tree's module.  Same program, same seconds, same
# unmount/remount, same oracle.
# (ledger D-THE-DELALLOC-RELEASE-SHIM-PUNCHES-UNDER-DIRTY-FOLIOS-BELOW-6-12)
#
# WHY THIS EXISTS.  s138b2 on the 2-node rig FAILed with EVERY mmap-dirtied
# (odd) page reading back as zero after a remount while every write()-dirtied
# (even) page survived, and P313-DELALLOC-KEEP had fired 60 times.  That
# verdict has two readings that nothing in the lap discriminates:
#   (a) MXFS loses the mmap-dirtied pages — a data-loss defect in this fork;
#   (b) the reproducer's own oracle is wrong on this kernel — the odd pages
#       never reach the platter on native XFS either, so the lap measured the
#       program, not the filesystem.
# Native XFS on the same kernel is the control that separates them: 6.8's own
# xfs_buffered_write_delalloc_release() already scans for dirty folios, so if
# the odd pages are lost THERE the oracle is at fault; if they survive there
# and are lost under MXFS, the defect is MXFS's.
#
# WHY A LOOP DEVICE ON A SPARE NODE.  The 2-node rig is busy with a lap queue
# that must not be disturbed, and the question is single-node anyway — the
# subject is one node's own page cache against its own delalloc.  A loop-backed
# MXFS with its own volume uuid is invisible to the running cluster (discovery
# filters on volume_uuid, dlm/discovery.c), and the vergate loop arm has run
# exactly this shape before (tests/vergate.sh, fence_capability_override=1).
#
# BOUND, derived, every term a number this lap spends:
#   NFS /src mount + module load       60 s
#   loop setup + mkfs (2 GiB image)    40 s per arm  (mkfs.xfs on a sparse
#                                                    2 GiB file is ~1 s; mkfs_mxfs
#                                                    writes a 65536-slot table)
#   gcc of one file                    60 s
#   the race itself                    RACE_S s per arm, default 10
#   msync+fsync of 16 MiB              20 s per arm
#   unmount + remount                  60 s per arm
#   the verify pass                    60 s per arm  (4032 page reads, cold)
#   dmesg reads                        40 s
#                                     ------
#                                    160 s + 2 x (240 + RACE_S)  (= 660 at the default)
#
# Usage: [RACE_S=10] [REQ_KB=256] tests/delalloc_dirty_tail_loop_control.sh <label> <node>
set -u
LABEL=${1:?label}
NODE=${2:?spare node, e.g. test3 — NEVER a node of a running queue}
cd "$(dirname "$0")/.." || exit 2
RACE_S=${RACE_S:-10}
REQ_KB=${REQ_KB:-256}
IMG=/var/tmp/ddtl_$LABEL.img
DEV=/dev/loop6
MNT=/mnt/ddtl
BIN=/tmp/ddtl_$LABEL
SRC=/src/mxfs/tests/delalloc_dirty_tail_race.c
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ddtl_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }

case "$NODE" in
    test1|test2) echo "ABORT: $NODE is a queue node; this lap runs only on a spare"; exit 2 ;;
esac
if [ ! -f mxfs.ko ]; then
    echo "ABORT: no mxfs.ko in the tree (build it first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== delalloc_dirty_tail_loop_control label=$LABEL node=$NODE race_s=$RACE_S req_kb=$REQ_KB sv=$SV $(date -u +%FT%TZ) ==="

# The node must see the tree (module, tools, the reproducer) and hold no MXFS
# mount of its own: this lap loads the tree's module itself.
rsx 60 "$NODE" "mountpoint -q /src || { mkdir -p /src && mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }; mountpoint -q /src && echo SRC_OK; uname -r; grep -c ' mxfs ' /proc/mounts; echo end=1" > "$OUT/node.txt" 2>&1
capture_require "$OUT/node.txt" '^SRC_OK$' "the /src export on $NODE"
KREL=$(grep -a '^[0-9]' "$OUT/node.txt" | head -1)
NMX=$(grep -aoE '^[0-9]+$' "$OUT/node.txt" | tail -1)
echo "NODE $NODE kernel=$KREL mxfs_mounts=$NMX"
[ "$NMX" = 0 ] || { echo "ABORT: $NODE already has $NMX mxfs mount(s); refusing to disturb them"; echo "RESULT: ABORT label=$LABEL stage=node evidence=$OUT"; exit 2; }

rsx 60 "$NODE" "gcc -O2 -pthread -o $BIN $SRC 2>&1 && echo CC_OK" > "$OUT/cc.txt" 2>&1
capture_require "$OUT/cc.txt" 'CC_OK' "the compile of the reproducer on $NODE"
echo "  PASS the reproducer compiled on $NODE"

# verify <arm>: read the file back from the FRESH mount into $OUT/verify_<arm>.txt
# with tests/ddtr_verify.py (the manifest-aware check the 2-node lap uses) and
# print the CHECKED/BAD line plus up to 12 bad pages.
verify() {
    local arm=$1 vhi=$2 f=$3
    rsx 60 "$NODE" "python3 /src/mxfs/tests/ddtr_verify.py $f $vhi 12" > "$OUT/verify_$arm.txt" 2>&1
    capture_require "$OUT/verify_$arm.txt" '^CHECKED=[0-9]+ BAD=[0-9]+ BAD_WRITER=[0-9]+ BAD_TOUCHER=[0-9]+ TOUCHED=[0-9]+ UNTOUCHED=[0-9]+$' "the post-remount content check ($arm) on $NODE"
    echo "STAGE $arm post-remount content: $(grep -a '^CHECKED=' "$OUT/verify_$arm.txt" | head -1)"
    grep -a '^  page=' "$OUT/verify_$arm.txt" | head -12 | sed 's/^/    /'
}

# race <arm> <file>: run the reproducer and print its summary; sets SUM VHI SHORTN ERRN
race() {
    local arm=$1 f=$2
    rsx $(( RACE_S + 40 )) "$NODE" "$BIN $f $RACE_S $REQ_KB" > "$OUT/race_$arm.txt" 2>&1
    capture_require "$OUT/race_$arm.txt" '^SHORT=[0-9]+ ' "the reproducer's summary line ($arm) on $NODE"
    SUM=$(grep -aoE '^SHORT=.*ERR=[0-9]+' "$OUT/race_$arm.txt" | head -1)
    echo "STAGE $arm reproducer: $SUM"
    VHI=$(echo "$SUM" | grep -ao 'VERIFY_HI=[0-9]*' | cut -d= -f2)
    SHORTN=$(echo "$SUM" | grep -ao 'SHORT=[0-9]*' | cut -d= -f2)
    ERRN=$(echo "$SUM" | grep -ao 'ERR=[0-9]*' | cut -d= -f2)
    ck "$arm: the reproducer reported no errors of its own" "${ERRN:-x}" 0
    ckge "$arm: the reproducer produced short writes (its whole premise)" "${SHORTN:-0}" 1
}

# ---------------------------------------------------------------- arm 1: native XFS
rsx 40 "$NODE" "umount $MNT 2>/dev/null; umount $DEV 2>/dev/null; losetup -d $DEV 2>/dev/null; rm -f $IMG; mkdir -p $MNT; truncate -s 2G $IMG && losetup $DEV $IMG && mkfs.xfs -f -q $DEV && mount -t xfs $DEV $MNT && grep ' $MNT ' /proc/mounts | awk '{print \$3}'" > "$OUT/setup_xfs.txt" 2>&1
capture_require "$OUT/setup_xfs.txt" '^xfs$' "the native XFS loop mount on $NODE"
echo "STAGE xfs: $DEV ($IMG) mounted at $MNT as $(grep -a '^xfs$' "$OUT/setup_xfs.txt") at +$(el)s"
race xfs "$MNT/ddtl.dat"
rsx 60 "$NODE" "umount $MNT && mount -t xfs $DEV $MNT && echo REMOUNT_OK" > "$OUT/remount_xfs.txt" 2>&1
capture_require "$OUT/remount_xfs.txt" 'REMOUNT_OK' "the xfs unmount/remount on $NODE"
verify xfs "$VHI" "$MNT/ddtl.dat"
XFS_BADT=$(grep -ao 'BAD_TOUCHER=[0-9]*' "$OUT/verify_xfs.txt" | head -1 | cut -d= -f2)
XFS_BADW=$(grep -ao 'BAD_WRITER=[0-9]*' "$OUT/verify_xfs.txt" | head -1 | cut -d= -f2)
ck "xfs: every write()-page the filesystem accepted is on the platter" "${XFS_BADW:-x}" 0
ck "xfs: every mmap-page the filesystem accepted is on the platter" "${XFS_BADT:-x}" 0
rsx 40 "$NODE" "umount $MNT && losetup -d $DEV && rm -f $IMG && echo TEARDOWN_OK" > "$OUT/teardown_xfs.txt" 2>&1
capture_require "$OUT/teardown_xfs.txt" 'TEARDOWN_OK' "the xfs teardown on $NODE"

# ---------------------------------------------------------------- arm 2: MXFS, single node
# MXFS_ARM=0 skips it.  s139b measured that a loop device cannot host this arm
# at all on 0.89.60: even on the TCP transport the page-authority ledger writes
# its records with COMPARE AND WRITE (P304-CAS-NOCAW, rc=-95), the first inode
# lock fails and the mount shuts itself down.  The MXFS side of this question is
# answered on the real LUN by tests/delalloc_dirty_tail_durability.sh.
if [ "${MXFS_ARM:-1}" = 0 ]; then
    echo "STAGE mxfs arm skipped (MXFS_ARM=0)"
    echo "STAGE done at +$(el)s"
    if [ "$fails" = 0 ]; then
        echo "RESULT: PASS label=$LABEL fails=0 xfs_bad_toucher=$XFS_BADT arms=xfs wall=$(el)s evidence=$OUT"
    else
        echo "RESULT: FAIL label=$LABEL fails=$fails xfs_bad_toucher=$XFS_BADT arms=xfs wall=$(el)s evidence=$OUT"
    fi
    exit $(( fails > 0 ))
fi
# The tree's module, loaded from node-local disk (an NFS view can be a mixed
# image), with the rig's own tcp modargs.  A loop device can produce no fencing
# evidence, and the admission gate (dlm/v5_mount.c v5_fence_capability_admit)
# admits such a device read-write only on BOTH operator statements together:
# fence_capability_override=1 (this rig cannot fence) AND single_node_exclusive=1
# (no other initiator can write it) — both literally true of a file on this
# node's own root disk.  s139a set only the first and was refused with
# P303-FENCECAP-OVERRIDE-REFUSED-CLUSTERED.
rsx 60 "$NODE" "lsmod | grep -q '^mxfs' && { rmmod mxfs || exit 9; }; cp -f /src/mxfs/mxfs.ko /root/mxfs.ko.ddtl && modprobe libcrc32c 2>/dev/null; insmod /root/mxfs.ko.ddtl force_transport=1 target_cache_protected=1 && echo 1 > /sys/module/mxfs/parameters/fence_capability_override && echo 1 > /sys/module/mxfs/parameters/single_node_exclusive && cat /sys/module/mxfs/srcversion" > "$OUT/load.txt" 2>&1
capture_require "$OUT/load.txt" "^$SV\$" "the load of the tree's module on $NODE"
echo "  PASS the tree's module ($SV) is loaded on $NODE"
rsx 40 "$NODE" "echo DDTL-MARK-$LABEL > /dev/kmsg; rm -f $IMG; truncate -s 2G $IMG && losetup $DEV $IMG && /src/mxfs/tools/mkfs_mxfs -f $DEV > /dev/null 2>&1 && mount -t mxfs $DEV $MNT && grep ' $MNT ' /proc/mounts | awk '{print \$3}'" > "$OUT/setup_mxfs.txt" 2>&1
capture_require "$OUT/setup_mxfs.txt" '^mxfs$' "the MXFS loop mount on $NODE"
echo "STAGE mxfs: $DEV ($IMG) mounted at $MNT as $(grep -a '^mxfs$' "$OUT/setup_mxfs.txt") at +$(el)s"

rsx 20 "$NODE" "dmesg | grep -ac 'P313-DELALLOC-KEEP'; echo end=1" > "$OUT/keep_pre.txt" 2>&1
capture_require "$OUT/keep_pre.txt" '^end=1$' "the pre-run P313 count on $NODE"
pre=$(grep -aoE '^[0-9]+$' "$OUT/keep_pre.txt" | head -1)
race mxfs "$MNT/ddtl.dat"
rsx 20 "$NODE" "dmesg | grep -ac 'P313-DELALLOC-KEEP'; echo end=1" > "$OUT/keep_post.txt" 2>&1
capture_require "$OUT/keep_post.txt" '^end=1$' "the post-run P313 count on $NODE"
post=$(grep -aoE '^[0-9]+$' "$OUT/keep_post.txt" | head -1)
kept=$(( ${post:-0} - ${pre:-0} ))
echo "STAGE mxfs P313-DELALLOC-KEEP: pre=$pre post=$post delta=$kept"
rsx 60 "$NODE" "umount $MNT && mount -t mxfs $DEV $MNT && echo REMOUNT_OK" > "$OUT/remount_mxfs.txt" 2>&1
capture_require "$OUT/remount_mxfs.txt" 'REMOUNT_OK' "the mxfs unmount/remount on $NODE"
verify mxfs "$VHI" "$MNT/ddtl.dat"
MX_BADT=$(grep -ao 'BAD_TOUCHER=[0-9]*' "$OUT/verify_mxfs.txt" | head -1 | cut -d= -f2)
MX_BADW=$(grep -ao 'BAD_WRITER=[0-9]*' "$OUT/verify_mxfs.txt" | head -1 | cut -d= -f2)
ck "mxfs: every write()-page the filesystem accepted is on the platter" "${MX_BADW:-x}" 0
ck "mxfs: every mmap-page the filesystem accepted is on the platter" "${MX_BADT:-x}" 0

# Everything the module said from the mark on, for the reader: refusals,
# probes, anything that names the inode.  Kept whole in the evidence dir; the
# console gets the count and the distinct probe names.
rsx 40 "$NODE" "dmesg | sed -n '/DDTL-MARK-$LABEL/,\$p'" > "$OUT/dmesg_mxfs.txt" 2>&1
capture_require "$OUT/dmesg_mxfs.txt" "DDTL-MARK-$LABEL" "the kernel log window on $NODE"
echo "STAGE mxfs kernel log: $(grep -ac 'mxfs' "$OUT/dmesg_mxfs.txt") mxfs lines; probes: $(grep -aoE 'P[0-9A-Z-]+[0-9A-Z]' "$OUT/dmesg_mxfs.txt" | sort | uniq -c | sort -rn | head -8 | awk '{printf "%s=%s ", $2, $1}')"
ck "mxfs: the node logged no BUG or Oops" "$(grep -ac 'BUG:\|Oops' "$OUT/dmesg_mxfs.txt")" 0

rs 60 "$NODE" "umount $MNT; losetup -d $DEV; rm -f $IMG $BIN; rmmod mxfs; echo 0 > /sys/module/mxfs/parameters/fence_capability_override 2>/dev/null; true" >/dev/null 2>&1 || true
echo "STAGE done at +$(el)s"
if [ "$fails" = 0 ]; then
    echo "RESULT: PASS label=$LABEL fails=0 xfs_bad_toucher=$XFS_BADT mxfs_bad_toucher=$MX_BADT kept=$kept wall=$(el)s evidence=$OUT"
else
    echo "RESULT: FAIL label=$LABEL fails=$fails xfs_bad_toucher=$XFS_BADT mxfs_bad_toucher=$MX_BADT kept=$kept wall=$(el)s evidence=$OUT"
fi
