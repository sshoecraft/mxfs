#!/bin/bash
# tests/delayed_write_across_fence.sh — a write that LEFT the authority gate
# while this node's lease was live, was held on its way to the LUN, and
# arrives at the target only after a successor has fenced this node and
# replayed its journal slice.
# (ledger D-OLD-EPOCH-IO-BELOW-THE-AUTHORITY-GATE-IS-UNBOUNDED, schedule (B):
# the command below the gate, in transit, not the submission parked above it.)
#
# HOW THIS DIFFERS FROM tests/admitted_write_parked_across_fence.sh.  That lap
# parks the submission INSIDE the module, between the gate's "yes" and the
# layer below it, with a debug knob; when the hold ends the module hands a
# fresh bio down and the target sees a post-fence submission.  This lap holds
# the request BELOW the module, inside the block layer: the module has
# submitted it, the module has no knob on it, and nothing MXFS decides can
# call it back.  From the target's side the two arrive the same way — after
# the PREEMPT AND ABORT, on a preempted nexus — and the record says so; what
# this lap adds is the demonstration that a command already handed to the
# block layer meets the target's exclusion rather than the platter, with no
# help from the module that issued it.
#
# THE HOLD IS A SINGLE-PATH dm-multipath MAP WITH queue_if_no_path.  B is
# mounted through /dev/mapper/mxfsmp, whose one path is the LUN.  Failing that
# path (dmsetup message ... fail_path) makes multipath requeue every request
# it receives — the request sits on the dm device's blk-mq requeue list,
# visible in /sys/kernel/debug/block/dm-N/requeue_list — and reinstating the
# path releases them to the LUN.  The delay is on the initiator side because
# the target is a closed appliance (data/rigs.json: no host image, no target
# source), so nothing can be delayed AT the target.
#
# WHY NOT dm-delay (s147c, tests/evidence/20260922T044107Z_dlywrite_s147c).
# The module's REGISTER goes through the stacked device's pr_ops
# (pal/linux/kern.c mxfs_pal_scsi_pr_register -> dm_pr_register), and dm-delay's
# iterate_devices hands dm_pr_register the SAME backing device three times
# (its read, write and flush classes).  The first REGISTER succeeds, the second
# answers RESERVATION CONFLICT because the nexus is now registered, and
# dm_pr_register rolls the first one back — so the mount reads a predecessor
# key on its own nexus and refuses, and the LUN is left with the key removed.
# Multipath lists each path once, which is the shape dm_pr_register was built
# for and the shape a production deployment has.  The fence path is untouched
# by the hold: dm_pr_register and the PR-IN reads call the path's own pr_ops
# directly, whatever state multipath holds the path in, and the module's
# passthrough resolver (P-MPATH-RESOLVE) finds the backing SCSI disk by content
# identity and issues its passthroughs to that sdev.  multipathd ignores a map
# created without the mpath- uuid prefix, so its checker cannot reinstate the
# path under the lap (verified 2026-09-22 on test2: multipath -ll shows nothing
# while the map exists).
#
# THE ORDER, and why it is not negotiable.
#   1. B is remounted through the multipath map, the probe target is made
#      durable and the control proves the oracle.  If B cannot mount through a
#      stacked device at all, the lap ABORTs there and the ABORT is itself the
#      answer the record asked for first.
#   2. B's heartbeat is PARKED by the module's own one-shot knob and its two
#      detectors are held off (the same blinding as the park lap), and the
#      lap waits for P-HB-INJECT-PAUSE — because the heartbeat write is a bio
#      and would otherwise be the first thing the hold swallowed, silently,
#      with the knob's own line never landing.
#   3. Only then is the path failed.
#   4. The writer submits ONE write of the chosen class, inside the lease
#      (the deadline is on the P-HB-INJECT-PAUSE line since 0.89.66), and the
#      lap confirms it is held below the module: the writer has not returned,
#      the LUN's completed-write count has not moved, the path is still
#      failed, and the dm device's requeue list is printed.
#   5. A declares B dead from heartbeat silence, fences it, certifies and
#      replays B's slice; R1 is read.  The writer must still be inside the
#      kernel at that instant or the lap is VACUOUS.
#   6. The path is reinstated under a kernel-log mark: the request reaches the
#      target, the writer returns; R2.
#   7. A unmounts and mounts again; R3.
#
# THE VERDICT IS THE PLATTER, NEVER THE RETURN CODE, exactly as in the park
# lap, with the same two oracles (ORACLE=block for dio and data, ORACLE=slice
# for log) and the same control.  The writer's errno is REPORTED — the
# expected shape is a reservation conflict surfacing as EBADE or EIO — and a
# write that returned 0 is not by itself a FAIL: the platter decides.
#
# VACUOUS IF: the write was not held when A's recovery completed; the
# heartbeat pause never confirmed; A completed no recovery inside the bound;
# or B withdrew on its own (P290-AUTH-WITHDRAW) BEFORE the release mark —
# the record's own vacuity clause, because then the release is not an
# old-epoch arrival but a shut-down node's leftover.  A withdrawal AFTER the
# release is the conflict's own consequence and is reported, not graded.
#
# CLEANUP: before the blinding, an exit unmounts B and removes the map so the
# next prep finds /dev/sda free; from the blinding onwards B is destroyed and
# restarted (the parked heartbeat thread is what an unmount waits for, and
# the map goes with the boot).
#
# THE BUDGET (derived, a timeout is a failure): boot-wait 200 (infra) + prep
# 300 + B's unmount and remount through the map 120 + probe and control 60 +
# the blinding and the path failure 60 + the writer and its hold proof 30 +
# A's fence and recovery 180 (dead window 62 + fence + replay, measured
# 77-120 s on this rig) + R1 20 + the release and the writer's return 30,
# waited to 60 and then graded stuck with its stack and B's ring captured 40
# + R2 20 + windows 60 + A's unmount and remount 300 + R3 20 = 1470.  Caller
# bound 1470 s for the block arms.  The slice arm adds five scans at FIND_T
# 90 = 450: caller bound 1920 s.
#
# Usage: tests/delayed_write_across_fence.sh <label>
# Env:   MXFS_NODE_LIST (test1,test2) — FIRST is A, the prover that fences B
#        and replays its slice; SECOND is B, whose write is held.
#        SITE (dio; data, log), PAUSE_MS (1710000), HEALTH_PAUSE_MS (1710000),
#        AUTHPUMP (1710000), RECOV_BOUND (180), FIND_T (90), DMNAME (mxfsmp).
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
[ "$A" = "$B" ] && { echo "ABORT: this lap needs two distinct nodes (MXFS_NODE_LIST=$MXFS_NODE_LIST)"; exit 2; }
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
PARM=/sys/module/mxfs/parameters
SLICETOOL=/src/mxfs/tools/slice_image.py
SITE=${SITE:-dio}
FIND_T=${FIND_T:-90}
DMNAME=${DMNAME:-mxfsmp}
DMDEV=/dev/mapper/$DMNAME
# the blinding outlasts the lap, never merely the hold (see the park lap)
PAUSE_MS=${PAUSE_MS:-1710000}
HEALTH_PAUSE_MS=${HEALTH_PAUSE_MS:-1710000}
AUTHPUMP=${AUTHPUMP:-1710000}
RECOV_BOUND=${RECOV_BOUND:-180}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_dlywrite_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="DLYWRITE-MARK-$LABEL"
NONCE="MXDLYN-$LABEL-$(date -u +%Y%m%dT%H%M%SZ)-$$"
CTRLNONCE="MXDLYC-$LABEL-$(date -u +%Y%m%dT%H%M%SZ)-$$"
echo "=== delayed_write_across_fence label=$LABEL A(prover)=$A B(held)=$B site=$SITE hold=multipath-failed-path $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
bad_lines() { echo $(( $(grep -a 'hutting down filesystem' "$1" 2>/dev/null | grep -avc 'mxfs_dlm_fence_notify') + $(cnt "$1" 'BUG:\|Oops') )); }
waitboot() {
    local n w=0
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}

case $SITE in
    dio)      ORACLE=block; CLASSDESC="O_DIRECT write" ;;
    data)     ORACLE=block; CLASSDESC="buffered write + fsync" ;;
    log)      ORACLE=slice; CLASSDESC="create+fsync" ;;
    *)  echo "ABORT: '$SITE' is not a class this lap can hold in the block layer (dio, data, log)"
        echo "RESULT: ABORT label=$LABEL stage=site evidence=$OUT"; exit 2 ;;
esac

# ---- 0. the build must carry every probe this lap reads
for sym in P163-RECOVERY-COMPLETE P-HB-INJECT-PAUSE P-DBG-RESV-HEALTH-PAUSE P-DBG-AUTH-PUMP-PAUSE P-MPATH-RESOLVE; do
    [ "$(strings -a mxfs.ko | grep -c "$sym")" != 0 ] || {
        echo "ABORT: mxfs.ko carries no $sym, so there is nothing here to measure"
        echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
done
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')

for n in "$A" "$B"; do
    st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
    [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
done
waitboot "$A" "$B"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV
mxfs_dev_resolve "$B"; BDEV=$MXFS_DEV_RESOLVED
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build-check evidence=$OUT"; exit 2; }
case "$BDEV" in /dev/mapper/*|/dev/dm-*)
    echo "ABORT: B's LUN path is already a device-mapper device ($BDEV); stacking a map on a stack is not what this lap measures"
    echo "RESULT: ABORT label=$LABEL stage=bdev evidence=$OUT"; exit 2 ;; esac

# ---- 1. B leaves the cluster cleanly and comes back through the map.  A
#         stacked device with a nonzero data offset would be refused by the
#         module's passthrough resolver, so the map is the whole LUN from
#         sector 0.  The mount is the first thing the record asked to be
#         tested; its failure is an answer, not an infra fault.
rsx 60 "$B" "echo $MARK-DM > /dev/kmsg; timeout 120 umount $MNT; echo UMOUNT rc=\$?" > "$OUT/B_umount0.txt"
capture_require "$OUT/B_umount0.txt" '^UMOUNT rc=' "B's clean unmount before the map"
ck "B unmounted cleanly before the map" "$(field "$OUT/B_umount0.txt" rc)" 0
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=umount0 evidence=$OUT"; exit 2; }
MAPPED=0
ARMED=0
BMM=; DMNODE=; SZ=
dly_cleanup() {
    if [ "$ARMED" = 1 ]; then
        echo "CLEANUP: B's heartbeat is parked and its LUN is under the map — destroying and restarting $B so the next prep finds neither"
        $VIRSH destroy "$B" > /dev/null 2>&1
        $VIRSH start "$B" > /dev/null 2>&1
    elif [ "$MAPPED" = 1 ]; then
        echo "CLEANUP: unmounting $B and removing the map so the next prep finds $BDEV free"
        timeout 200 $SSH "$B" "timeout 120 umount $MNT 2>/dev/null; timeout 10 dmsetup message $DMNAME 0 reinstate_path $BMM 2>/dev/null; timeout 30 dmsetup remove --retry $DMNAME; echo CLEANUP_REMOVE rc=\$?" 2>/dev/null | filt | sed 's/^/  /'
    fi
    return 0
}
trap dly_cleanup EXIT
measure "$B" 90 "$OUT/B_dmcreate.txt" '^DM_END$' "the single-path multipath map over B's LUN" \
    "modprobe dm-multipath; modprobe dm-round-robin; SZ=\$(blockdev --getsz $BDEV); echo SZ=\$SZ; MM=\$(lsblk -nd -o MAJ:MIN $BDEV | tr -d ' '); echo BMM=\$MM; timeout 30 dmsetup create $DMNAME --table \"0 \$SZ multipath 1 queue_if_no_path 0 1 1 round-robin 0 1 1 \$MM 1\"; echo CREATE rc=\$?; timeout 10 dmsetup table $DMNAME; timeout 10 dmsetup status $DMNAME | sed 's/^/STATUS /'; echo DMNODE=\$(basename \$(readlink -f $DMDEV)); echo ADOPTED=\$(multipath -ll 2>/dev/null | grep -c .); echo DM_END"
ck "the multipath map was created over $BDEV" "$(field "$OUT/B_dmcreate.txt" rc)" 0
DMNODE=$(field "$OUT/B_dmcreate.txt" DMNODE)
SZ=$(field "$OUT/B_dmcreate.txt" SZ)
BMM=$(field "$OUT/B_dmcreate.txt" BMM)
[ $fails = 0 ] && [ -n "${DMNODE:-}" ] && [ -n "${SZ:-}" ] && [ -n "${BMM:-}" ] || { echo "RESULT: ABORT label=$LABEL stage=dmcreate evidence=$OUT"; exit 2; }
MAPPED=1
ck "multipathd did not adopt the map (no mpath- uuid, so its checker cannot reinstate the path under the lap)" "$(field "$OUT/B_dmcreate.txt" ADOPTED)" 0
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=dmcreate evidence=$OUT"; exit 2; }
echo "STAGE $DMDEV ($DMNODE) maps $SZ sectors of $BDEV ($BMM) through one multipath path at +$(el)s"
measure "$B" 300 "$OUT/B_mount_dm.txt" '^MOUNT rc=' "B's mount through the multipath map" \
    "T0=\$(date +%s%N); timeout 240 mount -t mxfs $DMDEV $MNT; echo MOUNT rc=\$? wall_ms=\$(( (\$(date +%s%N) - T0) / 1000000 ))"
MRC=$(field "$OUT/B_mount_dm.txt" rc)
if [ "$MRC" != 0 ]; then
    window_into "$OUT/B_mountfail.txt" "$B" 60 "$MARK-DM"
    echo "ABORT: B could not mount MXFS through a whole-LUN single-path multipath map (mount rc=$MRC) — this is the record's own first question answered: the module does not run on a stacked device on this rig, so an initiator-side block-layer hold is not available.  B's kernel lines since the mark:"
    grep -a 'mxfs\|MXFS\|XFS' "$OUT/B_mountfail.txt" | tail -12 | cut -c1-220 | sed 's/^/    /'
    echo "RESULT: ABORT label=$LABEL stage=mount-dm rc=$MRC evidence=$OUT"; exit 2
fi
echo "STAGE B mounted through $DMDEV in $(field "$OUT/B_mount_dm.txt" wall_ms) ms at +$(el)s"
BSLOT=
value_now_into BSLOT "$B" 30 "$OUT/B_slot.txt" '^[0-9]+$' "B's heartbeat slot after the mount through the map" \
    "dmesg | grep -a 'DLM initialized' | tail -1 | grep -oE 'slot=[0-9]+' | cut -d= -f2"
value_now_into resolved "$B" 30 "$OUT/B_resolve.txt" 'P-MPATH-RESOLVE' "the module's resolution of the map to its backing SCSI disk" \
    "dmesg | sed -n '/$MARK-DM/,\$p' | grep -a 'P-MPATH-RESOLVE' | tail -1"
echo "STAGE B holds heartbeat slot $BSLOT (its log slice) through the map; $(echo "$resolved" | grep -ao 'stacked bdev.*' | head -1)"

# ---- 2. the probe target and the control, as in the park lap
EXTENT_B64=$(base64 -w0 <<'PY'
import os, sys, struct, fcntl
p = sys.argv[1]
fd = os.open(p, os.O_RDONLY)
buf = bytearray(32 + 56)
struct.pack_into("<QQIIII", buf, 0, 0, 1 << 20, 0, 0, 1, 0)
fcntl.ioctl(fd, 0xC020660B, buf)          # FS_IOC_FIEMAP
mapped = struct.unpack_from("<I", buf, 20)[0]
os.close(fd)
if mapped < 1:
    print("EXTENT none")
else:
    lo, po, ln, _, fl = struct.unpack_from("<QQQQI", buf, 32)
    print("EXTENT logical=%d physical=%d length=%d flags=0x%x" % (lo, po, ln, fl))
print("EXTENT_END")
PY
)
WRITER_B64=$(base64 -w0 <<'PY'
import os, sys, errno, time, mmap
d, tag = sys.argv[1], sys.argv[2]
site = sys.argv[3] if len(sys.argv) > 3 else "dio"
blk = 4096
print("WRITER_START tag=%s site=%s pid=%d t=%.3f" % (tag, site, os.getpid(), time.time())); sys.stdout.flush()
t = time.monotonic()
rc, err = 0, "-"
try:
    if site == "data":
        fd = os.open(d + "/probe", os.O_WRONLY)
        try:
            os.pwrite(fd, tag.encode().ljust(blk, b"\0"), 0)
            os.fsync(fd)
        finally:
            os.close(fd)
    elif site == "log":
        fd = os.open(os.path.join(d, tag), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            os.write(fd, (tag + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    else:
        buf = mmap.mmap(-1, blk)
        buf.write(tag.encode().ljust(blk, b"\0"))
        fd = os.open(d + "/probe", os.O_WRONLY | os.O_DIRECT)
        try:
            os.pwrite(fd, buf, 0)
        finally:
            os.close(fd)
except OSError as e:
    rc, err = 1, errno.errorcode.get(e.errno, "E%d" % e.errno)
except Exception as e:
    rc, err = 1, "OTHER:" + type(e).__name__
print("WRITER_DONE rc=%d err=%s ms=%d t=%.3f" % (rc, err, (time.monotonic() - t) * 1000, time.time()))
print("WRITER_END"); sys.stdout.flush()
PY
)
PDIR=$MNT/dlywrite_$LABEL
measure "$B" 60 "$OUT/B_target.txt" '^EXTENT_END$' "B's probe target, made durable before anything is armed, and its physical extent" \
    "mkdir -p $PDIR && python3 -c \"
import os
b=bytearray(4096); b[0:9]=b'baseline\n'
fd=os.open('$PDIR/probe', os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o644); os.write(fd,b); os.fsync(fd); os.close(fd)
\" && sync -f $MNT && echo $EXTENT_B64 | base64 -d > /run/dlywrite_extent.py && python3 /run/dlywrite_extent.py $PDIR/probe && echo $WRITER_B64 | base64 -d > /run/dlywrite_writer.py"
PHYS=$(grep -ao 'physical=[0-9]*' "$OUT/B_target.txt" | head -1 | cut -d= -f2)
echo "STAGE probe block physical offset on the LUN: ${PHYS:-none}"
[ -n "${PHYS:-}" ] || { echo "ABORT: the probe block's physical extent could not be read, so a landed write could not be distinguished from an acknowledged one"; echo "RESULT: ABORT label=$LABEL stage=extent evidence=$OUT"; exit 2; }
platter_into() {   # <file> <what>  (always read from A, off the raw LUN)
    measure "$A" 60 "$1" '^PLATTER_END$' "$2" \
        "dd if=$MXFS_DEV bs=4096 skip=$((PHYS / 4096)) count=1 iflag=direct 2>/dev/null | md5sum | sed 's/^/PLATTER md5=/'; dd if=$MXFS_DEV bs=4096 skip=$((PHYS / 4096)) count=1 iflag=direct 2>/dev/null | head -c 48 | od -c | head -3; echo PLATTER_END"
}
platter_md5() { grep -ao 'md5=[0-9a-f]*' "$1" | head -1 | cut -d= -f2; }
slice_find_into() {   # <file> <what> <pattern>
    measure "$A" "$FIND_T" "$1" '^FIND_END$' "$2" \
        "s=\$(date +%s); python3 $SLICETOOL find $MXFS_DEV $BSLOT $3; echo SCAN_WALL s=\$(( \$(date +%s) - s ))"
}
slice_hits() { grep -aoE '^FIND slot=.*hits=[0-9]+' "$1" | grep -oE 'hits=[0-9]+' | head -1 | cut -d= -f2; }
oracle_into() {   # <file> <what> -> ORACLE_VAL
    case $ORACLE in
        block) platter_into "$1" "$2"; ORACLE_VAL=$(platter_md5 "$1") ;;
        slice) slice_find_into "$1" "$2" "$NONCE"; ORACLE_VAL=$(slice_hits "$1")
               echo "    scan wall: $(grep -ao 'SCAN_WALL s=[0-9]*' "$1" | head -1)" ;;
    esac
}
if [ "$ORACLE" = block ]; then
    platter_into "$OUT/P_base.txt" "the probe block on the platter before the control"
    MD_BASE=$(platter_md5 "$OUT/P_base.txt")
    measure "$B" 60 "$OUT/B_control.txt" '^WRITER_END$' "the control write on a healthy B, through the map" \
        "python3 /run/dlywrite_writer.py $PDIR control-write $SITE; sync -f $MNT"
    ck "control: a healthy node's $CLASSDESC returns 0" "$(field "$OUT/B_control.txt" rc)" 0
    platter_into "$OUT/P_control.txt" "the probe block after the control write"
    MD_CONTROL=$(platter_md5 "$OUT/P_control.txt")
    [ -n "$MD_BASE" ] && [ -n "$MD_CONTROL" ] || { echo "ABORT: the probe block could not be read off the raw device, so the platter oracle does not work"; echo "RESULT: ABORT label=$LABEL stage=platter evidence=$OUT"; exit 2; }
    if [ "$MD_BASE" = "$MD_CONTROL" ]; then
        echo "  FAIL control: a healthy node's $CLASSDESC through the map did not change the block on the platter (md5 $MD_BASE unchanged)"
        echo "ABORT: the platter oracle cannot see a write that DID land, so 'the block did not change' would be true of everything"
        echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2
    fi
    echo "  PASS control: a healthy node's $CLASSDESC through the map changed the block on the platter ($MD_BASE -> $MD_CONTROL)"
else
    measure "$B" 60 "$OUT/B_control.txt" '^WRITER_END$' "the control journal write on a healthy B, through the map" \
        "python3 /run/dlywrite_writer.py $PDIR $CTRLNONCE log; sync -f $MNT"
    ck "control: a healthy node's create+fsync returns 0" "$(field "$OUT/B_control.txt" rc)" 0
    slice_find_into "$OUT/S_control.txt" "the control nonce inside B's log slice on the platter" "$CTRLNONCE"
    CH=$(slice_hits "$OUT/S_control.txt")
    [ -n "$CH" ] || { echo "ABORT: B's log slice could not be scanned off the raw device, so the slice oracle does not work"; echo "RESULT: ABORT label=$LABEL stage=slice evidence=$OUT"; exit 2; }
    if [ "$CH" -lt 1 ] 2>/dev/null; then
        echo "  FAIL control: a healthy node's journal write is not visible in its own log slice (hits=$CH)"
        echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2
    fi
    echo "  PASS control: a healthy node's journal write is visible in its own log slice (hits=$CH, scan $(grep -ao 'SCAN_WALL s=[0-9]*' "$OUT/S_control.txt" | head -1))"
    slice_find_into "$OUT/S_base.txt" "this lap's held nonce before anything is armed" "$NONCE"
    ck "baseline: this lap's nonce is not already on the platter" "$(slice_hits "$OUT/S_base.txt")" 0
fi
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2; }

# ---- 3. the marks, then B goes quiet and blind — BEFORE the path is failed,
#         so the heartbeat thread is parked by the knob and not swallowed by
#         the hold with its own confirmation line never landing.
rsx 30 "$B" "echo $MARK > /dev/kmsg; echo MARKED" > "$OUT/B_mark.txt"
capture_require "$OUT/B_mark.txt" '^MARKED$' "the ring mark on $B"
rsx 30 "$A" "echo $MARK > /dev/kmsg; echo MARKED" > "$OUT/A_mark.txt"
capture_require "$OUT/A_mark.txt" '^MARKED$' "the ring mark on $A"
ARMED=1
measure "$B" 40 "$OUT/B_arm_blind.txt" '^ARMED' "B's detectors held off and its heartbeat parked" \
    "echo $AUTHPUMP > $PARM/dbg_auth_pump_pause_ms; echo $HEALTH_PAUSE_MS > $PARM/dbg_resv_health_pause_ms; sleep 1; echo $PAUSE_MS > $PARM/dl_inject_hb_pause_ms; echo ARMED health=\$(cat $PARM/dbg_resv_health_pause_ms) pause=\$(cat $PARM/dl_inject_hb_pause_ms) pump=\$(cat $PARM/dbg_auth_pump_pause_ms)"
wait_for_into paused "$B" 40 "$MARK" 'P-HB-INJECT-PAUSE'
ck "B's heartbeat thread reported that it is parked" "$([ "$paused" = timeout ] && echo no || echo yes)" yes
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }
T_PAUSE=$(date +%s)
value_now_into pl "$B" 20 "$OUT/B_pause_line.txt" 'P-HB-INJECT-PAUSE' "the pause line with its deadline on $B" \
    "dmesg | sed -n '/$MARK/,\$p' | grep -a 'P-HB-INJECT-PAUSE' | head -1"
DEADLINE_MS=$(grep -ao 'deadline_ms=[0-9]*' "$OUT/B_pause_line.txt" | head -1 | cut -d= -f2)
echo "STAGE B is quiet and blind at +$(el)s; its authority deadline is ${DEADLINE_MS:-unprinted} (module ms, 30 s past its last landed beat)"

# ---- 4. the hold goes in: the map's only path is failed, so every request
#         multipath receives is requeued until the path is reinstated.
sda_writes() {   # <file> — completed writes on the LUN device, /sys/block/<dev>/stat field 5
    grep -ao 'LUNSTAT_W=[0-9]*' "$1" | head -1 | cut -d= -f2
}
measure "$B" 60 "$OUT/B_hold.txt" '^HOLD_END$' "the path failed under B's mount" \
    "timeout 10 dmsetup message $DMNAME 0 fail_path $BMM; echo FAILPATH rc=\$?; sleep 1; echo LUNSTAT_W=\$(awk '{print \$5}' /sys/block/$(basename "$BDEV")/stat); timeout 10 dmsetup status $DMNAME | sed 's/^/STATUS /'; echo HOLD_END"
ck "the path was failed" "$(grep -ao 'FAILPATH rc=[0-9]*' "$OUT/B_hold.txt" | cut -d= -f2)" 0
ck "the map reports its path failed and its queue enabled" "$(grep -a '^STATUS ' "$OUT/B_hold.txt" | grep -ac " E .* $BMM F ")" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=hold evidence=$OUT"; exit 2; }
W0=$(sda_writes "$OUT/B_hold.txt")
echo "STAGE every request from B is now held in multipath's requeue at +$(el)s ($(( $(date +%s) - T_PAUSE )) s after the pause); the LUN had completed ${W0:-?} writes"

# ---- 5. ONE write of the class, inside the lease, and proof it is held
if [ "$ORACLE" = block ]; then WTAG=held-old-epoch-write; else WTAG=$NONCE; fi
( timeout 600 $SSH "$B" "python3 /run/dlywrite_writer.py $PDIR $WTAG $SITE" \
      2> "$OUT/B_writer_stderr.txt" | grep --line-buffered -av '^Unauthorized\|^Warning:\|^If you\|^$' > "$OUT/B_writer.txt" ) &
WPID=$!
T_WRITE=$(date +%s)
echo "STAGE the writer was started on $B at +$(el)s (pid $WPID), $(( T_WRITE - T_PAUSE )) s after the pause — inside the 30 s lease"
ck "the write was issued inside the lease (under 25 s after the pause)" "$([ $(( T_WRITE - T_PAUSE )) -lt 25 ] && echo yes || echo no)" yes
sleep 6
WRPID=$(grep -ao 'pid=[0-9]*' "$OUT/B_writer.txt" 2>/dev/null | head -1 | cut -d= -f2)
measure "$B" 30 "$OUT/B_inflight.txt" '^HELD_END$' "the writer's state, the LUN's write count and the dm device's requeue list on $B" \
    "echo LUNSTAT_W=\$(awk '{print \$5}' /sys/block/$(basename "$BDEV")/stat); echo WRITER_STATE=\$(awk '{print \$3}' /proc/${WRPID:-0}/stat 2>/dev/null || echo gone) wchan=\$(cat /proc/${WRPID:-0}/wchan 2>/dev/null || echo gone); echo STACK_BEGIN; cat /proc/${WRPID:-0}/stack 2>/dev/null; echo STACK_END; echo INFLIGHT_DM \$(cat /sys/block/$DMNODE/inflight); echo INFLIGHT_LUN \$(cat /sys/block/$(basename "$BDEV")/inflight); timeout 10 dmsetup status $DMNAME | sed 's/^/STATUS /'; echo REQUEUE_BEGIN; cat /sys/kernel/debug/block/$DMNODE/requeue_list 2>/dev/null | head -8; echo REQUEUE_END; echo HELD_END"
W1=$(sda_writes "$OUT/B_inflight.txt")
stack_of() {   # <file> — the writer's kernel stack between the STACK marks, one line
    sed -n '/^STACK_BEGIN$/,/^STACK_END$/p' "$1" | grep -av 'STACK_' | sed 's/^\[<[0-9a-fx]*>\] //' | tr '\n' ' ' | cut -c1-400
}
echo "    writer state: $(grep -a '^WRITER_STATE=' "$OUT/B_inflight.txt" | head -1); dm inflight: $(grep -a '^INFLIGHT_DM' "$OUT/B_inflight.txt" | head -1); requeue list: $(sed -n '/^REQUEUE_BEGIN$/,/^REQUEUE_END$/p' "$OUT/B_inflight.txt" | grep -avc 'REQUEUE_')"
echo "    writer stack: $(stack_of "$OUT/B_inflight.txt")"
ck "the writer is still inside the kernel 6 s after it was issued (no WRITER_DONE)" "$(grep -ac '^WRITER_DONE' "$OUT/B_writer.txt")" 0
ck "the LUN completed no write while the path was failed" "${W1:-x}" "${W0:-y}"
ck "the path is still failed" "$(grep -a '^STATUS ' "$OUT/B_inflight.txt" | grep -ac " $BMM F ")" 1
if [ $fails != 0 ]; then
    echo "VACUOUS: no write of class '$SITE' is held in the block layer below the module, so nothing crosses the fence"
    echo "RESULT: VACUOUS label=$LABEL stage=inflight evidence=$OUT"; kill "$WPID" 2>/dev/null; exit 3
fi
echo "STAGE B's write is below the module and held in the block layer at +$(el)s — waiting for A's fence and recovery (dead window 62 s, bound ${RECOV_BOUND}s)"

# ---- 6. A declares B dead from silence, fences it, certifies and replays
wait_for_into recovered "$A" "$RECOV_BOUND" "$MARK" 'P163-RECOVERY-COMPLETE'
if [ "$recovered" = timeout ]; then
    window_into "$OUT/A_norecov.txt" "$A" 60 "$MARK"
    echo "VACUOUS: A did not complete a recovery of B's slice inside ${RECOV_BOUND}s, so the held write and the successor's replay never overlapped"
    echo "  A's fence evidence: $(grep -ac 'P-FENCE\|PREEMPT' "$OUT/A_norecov.txt") fence lines, $(cnt "$OUT/A_norecov.txt" 'foreign replay') foreign-replay lines"
    echo "RESULT: VACUOUS label=$LABEL stage=recovery evidence=$OUT"
    kill "$WPID" 2>/dev/null; exit 3
fi
T_RECOV=$(date +%s)
echo "STAGE A completed the recovery of B's slice at +$(el)s (waited ${recovered}s; $(( T_RECOV - T_WRITE )) s after the write was issued)"
oracle_into "$OUT/P_after_replay.txt" "the oracle region immediately after A's recovery completed"
R1=$ORACLE_VAL
echo "STAGE R1 $ORACLE=$R1 at +$(el)s"
if grep -qa '^WRITER_DONE' "$OUT/B_writer.txt" 2>/dev/null; then
    echo "VACUOUS: the writer had already returned before A's recovery completed, so the write was not held across the replay: $(grep -a '^WRITER_DONE' "$OUT/B_writer.txt" | head -1)"
    echo "RESULT: VACUOUS label=$LABEL stage=overlap evidence=$OUT"; exit 3
fi
if [ "$ORACLE" = slice ] && [ "${R1:-0}" -gt 0 ] 2>/dev/null; then
    echo "VACUOUS: this lap's nonce was already inside B's log slice when A's recovery completed (hits=$R1), so the journal write went out before the fence"
    echo "RESULT: VACUOUS label=$LABEL stage=overlap evidence=$OUT"; exit 3
fi

# ---- 7. the release: the path comes back under a mark, the request reaches
#         the target and the writer returns
measure "$B" 60 "$OUT/B_release.txt" '^RELEASE_END$' "the path reinstated under B's mount" \
    "echo $MARK-RELEASE > /dev/kmsg; timeout 10 dmsetup message $DMNAME 0 reinstate_path $BMM; echo REINSTATE rc=\$?; timeout 10 dmsetup status $DMNAME | sed 's/^/STATUS /'; echo RELEASE_END"
ck "the path was reinstated" "$(grep -ao 'REINSTATE rc=[0-9]*' "$OUT/B_release.txt" | cut -d= -f2)" 0
T_RELEASE=$(date +%s)
echo "STAGE the path is back at +$(el)s ($(( T_RELEASE - T_WRITE )) s after the write was issued, $(( T_RELEASE - T_RECOV )) s after A's recovery)"
# The writer's return is budgeted at 30 s after the release (the header);
# it is waited for to twice that, and a writer still inside the kernel then
# is a task on the victim that the release did not free — graded as a FAIL
# with its stack and the victim's ring, never waited for further.  The first
# log arm (s148g) waited out the ssh's own 600 s bound instead, 525 s of it
# after the release, and then destroyed B having captured neither, so it
# could only ABORT.  The rest of the lap still runs: the platter and the
# slice are the record's verdict and a stuck writer does not change what a
# later recovery must decide.
WRET_MAX=60
w=0
until grep -qa '^WRITER_DONE' "$OUT/B_writer.txt" 2>/dev/null || [ $w -ge $WRET_MAX ]; do sleep 1; w=$((w+1)); done
if grep -qa '^WRITER_DONE' "$OUT/B_writer.txt" 2>/dev/null; then
    wait "$WPID" 2>/dev/null
    WRC=$(field "$OUT/B_writer.txt" rc)
    WERR=$(field "$OUT/B_writer.txt" err)
    echo "STAGE the held writer returned at +$(el)s, $w s after the release: $(grep -a '^WRITER_DONE' "$OUT/B_writer.txt" | head -1)"
else
    measure "$B" 30 "$OUT/B_writer_stuck.txt" '^STUCK_END$' "the stuck writer's state and stack on $B" \
        "echo WRITER_STATE=\$(awk '{print \$3}' /proc/${WRPID:-0}/stat 2>/dev/null || echo gone) wchan=\$(cat /proc/${WRPID:-0}/wchan 2>/dev/null || echo gone); echo STACK_BEGIN; cat /proc/${WRPID:-0}/stack 2>/dev/null; echo STACK_END; echo LUNSTAT_W=\$(awk '{print \$5}' /sys/block/$(basename "$BDEV")/stat); timeout 10 dmsetup status $DMNAME | sed 's/^/STATUS /'; echo REQUEUE_BEGIN; cat /sys/kernel/debug/block/$DMNODE/requeue_list 2>/dev/null | head -8; echo REQUEUE_END; echo DSTATE_BEGIN; for p in /proc/[0-9]*; do s=\$(awk '{print \$3}' \$p/stat 2>/dev/null); [ \"\$s\" = D ] && echo \"\$(basename \$p) \$(cat \$p/comm 2>/dev/null) wchan=\$(cat \$p/wchan 2>/dev/null) \$(sed 's/^\[<[0-9a-fx]*>\] //' \$p/stack 2>/dev/null | head -12 | tr '\n' ' ')\"; done; echo DSTATE_END; echo STUCK_END"
    window_into "$OUT/B_win_stuck.txt" "$B" 60 "$MARK"
    ck "the held writer returned within ${WRET_MAX} s of the release (a task the release did not free is a stuck task on the victim)" "$(grep -ac '^WRITER_DONE' "$OUT/B_writer.txt")" 1
    echo "    writer now: $(grep -a '^WRITER_STATE=' "$OUT/B_writer_stuck.txt" | head -1); LUN writes ${W1:-?} -> $(sda_writes "$OUT/B_writer_stuck.txt"); requeue list $(sed -n '/^REQUEUE_BEGIN$/,/^REQUEUE_END$/p' "$OUT/B_writer_stuck.txt" | grep -avc 'REQUEUE_') line(s)"
    echo "    writer stack: $(stack_of "$OUT/B_writer_stuck.txt")"
    echo "    every D-state task on $B:"
    sed -n '/^DSTATE_BEGIN$/,/^DSTATE_END$/p' "$OUT/B_writer_stuck.txt" | grep -av 'DSTATE_' | cut -c1-300 | sed 's/^/      /'
    echo "    $B's ring since the release: $(sed -n "/$MARK-RELEASE/,\$p" "$OUT/B_win_stuck.txt" | grep -ac 'mxfs:\|blocked for more than') mxfs / hung-task lines; the first 12:"
    sed -n "/$MARK-RELEASE/,\$p" "$OUT/B_win_stuck.txt" | grep -a 'mxfs:\|blocked for more than\|RESERVATION\|reservation' | head -12 | cut -c1-240 | sed 's/^/      /'
    WRC=stuck; WERR=stuck
    kill "$WPID" 2>/dev/null
fi
sleep 5
oracle_into "$OUT/P_after_resume.txt" "the oracle region after the held write reached the target"
R2=$ORACLE_VAL
echo "STAGE R2 $ORACLE=$R2 at +$(el)s"
window_into "$OUT/B_win.txt" "$B" 60 "$MARK"
# a withdrawal BEFORE the release mark is the record's vacuity clause; one
# after it is the conflict's own consequence
B_withdraw_pre=$(sed -n "/$MARK\$/,/$MARK-RELEASE/p" "$OUT/B_win.txt" | grep -ac 'P290-AUTH-WITHDRAW')
B_withdraw_post=$(sed -n "/$MARK-RELEASE/,\$p" "$OUT/B_win.txt" | grep -ac 'P290-AUTH-WITHDRAW')
if [ "${B_withdraw_pre:-0}" -ge 1 ]; then
    echo "VACUOUS: B withdrew its own mount before the path was reinstated ($B_withdraw_pre x P290-AUTH-WITHDRAW before $MARK-RELEASE), so the release is a shut-down node's leftover and not an old-epoch arrival — the record's own vacuity clause"
    echo "RESULT: VACUOUS label=$LABEL stage=withdrew evidence=$OUT"; exit 3
fi

# ---- 8. a LATER recovery must decide the same way
measure "$A" 120 "$OUT/A_umount.txt" '^UMOUNT rc=' "A's clean unmount" "umount $MNT; echo UMOUNT rc=\$?"
ck "A unmounted cleanly" "$(field "$OUT/A_umount.txt" rc)" 0
measure "$A" 180 "$OUT/A_remount.txt" '^MOUNT rc=' "A's remount" "mount -t mxfs $MXFS_DEV $MNT; echo MOUNT rc=\$?"
ck "A mounted again" "$(field "$OUT/A_remount.txt" rc)" 0
oracle_into "$OUT/P_after_remount.txt" "the oracle region after A was unmounted and mounted again"
R3=$ORACLE_VAL
echo "STAGE R3 $ORACLE=$R3 at +$(el)s"
NF=
if [ "$ORACLE" = slice ]; then
    value_now_into NF "$A" 60 "$OUT/A_nonce_file.txt" '^NONCEFILE count=[0-9]+$' \
        "whether the old-epoch transaction's file exists in the filesystem A recovered and remounted" \
        "n=\$(ls -1 $PDIR 2>/dev/null | grep -c -- $NONCE); echo NONCEFILE count=\$n"
    NF=${NF#NONCEFILE count=}
fi

# ---- 9. the verdicts
window_into "$OUT/A_win.txt" "$A" 60 "$MARK"
count_file_into A_recov "$OUT/A_win.txt" 'P163-RECOVERY-COMPLETE'
count_file_into A_bad "$OUT/A_win.txt" 'BUG:\|Oops'
count_file_into B_bad "$OUT/B_win.txt" 'BUG:\|Oops'
count_file_into B_conflict "$OUT/B_win.txt" 'RESERVATION CONFLICT\|reservation conflict\|P290-AUTH-PR-CONFLICT\|PR_CONFLICT'
echo "--- verdicts (site=$SITE, oracle=$ORACLE, hold=multipath-failed-path, writer rc=${WRC:-?} err=${WERR:-?}) ---"
ckge "A recovered B's slice while the held write was still in the block layer" "$A_recov" 1
if [ "$ORACLE" = block ]; then
    ck "THE PLATTER: the held old-epoch write did not change the block the successor recovered" "$R2" "$R1"
    ck "THE LATER RECOVERY: a fresh mount of the same filesystem decides the same way" "$R3" "$R1"
else
    ck "THE SLICE: the held old-epoch journal write did not reach the log slice the successor had already recovered" "$R2" 0
    ck "THE LATER RECOVERY: it is still absent from that slice after A unmounted and mounted again" "$R3" 0
    ck "THE RECOVERED FILESYSTEM: the old-epoch transaction left no file behind in the namespace A recovered" "$NF" 0
fi
ck "no host or guest kernel BUG/Oops on A" "$A_bad" 0
ck "no host or guest kernel BUG/Oops on B" "$B_bad" 0
ck "no shutdown of A's filesystem outside the cluster-fence entry" "$(bad_lines "$OUT/A_win.txt")" 0

echo "--- evidence ---"
if [ "$ORACLE" = block ]; then
    echo "  control:   $MD_BASE -> $MD_CONTROL (a healthy write through the map does move this block)"
else
    echo "  control:   the control nonce $CTRLNONCE was found $CH time(s) in slice $BSLOT"
    echo "  nonce:     $NONCE"
fi
echo "  the deadline on the pause line:     ${DEADLINE_MS:-unprinted}"
echo "  write issued:                        $(( T_WRITE - T_PAUSE )) s after the pause; A's recovery complete $(( T_RECOV - T_WRITE )) s after the write; released $(( T_RELEASE - T_WRITE )) s after the write"
echo "  held below the module:               writer $(grep -a '^WRITER_STATE=' "$OUT/B_inflight.txt" | head -1), LUN writes ${W0:-?} -> ${W1:-?}, requeue list $(sed -n '/^REQUEUE_BEGIN$/,/^REQUEUE_END$/p' "$OUT/B_inflight.txt" | grep -avc 'REQUEUE_') line(s)"
echo "  R1 after A's recovery:               $R1"
echo "  R2 after the held write arrived:     $R2"
echo "  R3 after A remounted:                $R3"
[ "$ORACLE" = slice ] && echo "  the nonce-named file after A remounted: ${NF:-?}"
echo "  the writer:                          $(grep -a '^WRITER_DONE' "$OUT/B_writer.txt" | head -1)"
echo "  conflict lines on B:                 $B_conflict; withdrawals before/after the release: ${B_withdraw_pre:-0}/${B_withdraw_post:-0}"
if [ "$fails" = 0 ]; then
    echo "RESULT: PASS label=$LABEL site=$SITE writer_rc=${WRC:-?} writer_err=${WERR:-?} fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL site=$SITE writer_rc=${WRC:-?} writer_err=${WERR:-?} fails=$fails wall=$(el)s evidence=$OUT"; exit 1
