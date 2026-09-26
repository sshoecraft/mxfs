#!/bin/bash
# tests/iomap_stale_loop_control.sh — does tests/iomap_stale_race.py actually
# make a cached mapping go stale?  Answered on NATIVE XFS, on a loop device on
# a spare node, by the kernel's own xfs_iomap_invalid tracepoint — the event
# upstream XFS fires at exactly the refusal MXFS's P312-IOMAP-STALE reports.
# (ledger D-NO-BUFFERED-WRITE-REVALIDATES-ITS-MAPPING-ON-THE-KERNEL-UNDER-TEST)
#
# WHY A CONTROL BEFORE THE RIG LAP.  The rig arm asserts P312-IOMAP-STALE >= 1
# after this schedule.  A zero there has two readings — the hook is installed
# and never refuses on this build, or the schedule never made a mapping stale
# in the first place — and only the second is a harness question.  Native XFS
# on the same kernel, which has had this hook since 6.2, settles it: if its
# tracepoint fires under the schedule, the schedule is sound and a zero under
# MXFS is a finding about MXFS.
#
# BOUND, derived: NFS /src 30 + loop setup + mkfs 20 + the write (MB MiB at
# the ~700 MB/3-4 s figure, fsyncs racing, x2) 20 + remount 20 + verify 20 +
# trace reads 20 = 130 s at MB=256.
#
# Usage: [MB=256] tests/iomap_stale_loop_control.sh <label> <spare-node>
set -u
LABEL=${1:?label}
NODE=${2:?spare node, e.g. test3 — NEVER a node of a running queue}
cd "$(dirname "$0")/.." || exit 2
MB=${MB:-256}
IMG=/var/tmp/iomst_$LABEL.img
DEV=/dev/loop7
MNT=/mnt/iomst
TR=/sys/kernel/tracing
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_iomst_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
case "$NODE" in
    test1|test2) echo "ABORT: $NODE is a queue node; this control runs only on a spare"; exit 2 ;;
esac
echo "=== iomap_stale_loop_control label=$LABEL node=$NODE mb=$MB $(date -u +%FT%TZ) ==="

rsx 60 "$NODE" "mountpoint -q /src || { mkdir -p /src && mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp; }; mountpoint -q /src && echo SRC_OK; uname -r; test -d $TR/events/xfs/xfs_iomap_invalid && echo TP_OK; echo end=1" > "$OUT/node.txt" 2>&1
capture_require "$OUT/node.txt" '^SRC_OK$' "the /src export on $NODE"
capture_require "$OUT/node.txt" '^TP_OK$' "the xfs_iomap_invalid tracepoint on $NODE"
echo "NODE $NODE kernel=$(grep -a '^[0-9]' "$OUT/node.txt" | head -1)"

rsx 40 "$NODE" "umount $MNT 2>/dev/null; losetup -d $DEV 2>/dev/null; rm -f $IMG; mkdir -p $MNT; truncate -s 2G $IMG && losetup $DEV $IMG && mkfs.xfs -f -q $DEV && mount -t xfs $DEV $MNT && grep ' $MNT ' /proc/mounts | awk '{print \$3}'" > "$OUT/setup.txt" 2>&1
capture_require "$OUT/setup.txt" '^xfs$' "the native XFS loop mount on $NODE"
echo "STAGE xfs: $DEV ($IMG) at $MNT at +$(el)s"

# the tracepoint is armed for the write only, and its count is read from the
# per-event hit counter in the trace ring (grep on the ring, not the ring's
# size, so a ring that wraps under other events cannot hide a hit)
rsx 60 "$NODE" "echo > $TR/trace; echo 1 > $TR/events/xfs/xfs_iomap_invalid/enable; python3 /src/mxfs/tests/iomap_stale_race.py write $MNT/stale.dat $MB; echo py_rc=\$?; echo 0 > $TR/events/xfs/xfs_iomap_invalid/enable; echo INVALID=\$(grep -ac xfs_iomap_invalid $TR/trace); grep -a xfs_iomap_invalid $TR/trace | head -3" > "$OUT/write.txt" 2>&1
capture_require "$OUT/write.txt" '^WROTE=[0-9]+ WRITE_CALLS=[0-9]+ FSYNCS=[0-9]+ ELAPSED_MS=[0-9]+ RC=[0-9]+$' "the racing write on $NODE"
capture_require "$OUT/write.txt" '^INVALID=[0-9]+$' "the tracepoint count on $NODE"
SUM=$(grep -a '^WROTE=' "$OUT/write.txt" | head -1)
INV=$(grep -ao '^INVALID=[0-9]*' "$OUT/write.txt" | cut -d= -f2)
FS=$(echo "$SUM" | grep -ao 'FSYNCS=[0-9]*' | cut -d= -f2)
echo "STAGE write: $SUM  xfs_iomap_invalid=$INV at +$(el)s"
grep -a '^ *[a-z0-9_-]*-[0-9]* ' "$OUT/write.txt" | head -3 | cut -c1-200 | sed 's/^/    /'
ck "the write completed" "$(echo "$SUM" | grep -ao 'RC=[0-9]*' | cut -d= -f2)" 0
ckge "fsyncs raced the write (a run with none measured nothing)" "${FS:-0}" 1
ckge "native XFS found its cached mapping stale under this schedule (xfs_iomap_invalid)" "${INV:-0}" 1

rsx 60 "$NODE" "umount $MNT && mount -t xfs $DEV $MNT && echo REMOUNT_OK" > "$OUT/remount.txt" 2>&1
capture_require "$OUT/remount.txt" 'REMOUNT_OK' "the unmount/remount on $NODE"
rsx 60 "$NODE" "python3 /src/mxfs/tests/iomap_stale_race.py verify $MNT/stale.dat $MB" > "$OUT/verify.txt" 2>&1
capture_require "$OUT/verify.txt" '^CHECKED=[0-9]+ BAD=[0-9]+$' "the cold verify on $NODE"
echo "STAGE verify: $(grep -a '^CHECKED=' "$OUT/verify.txt")"
grep -a '^  page=' "$OUT/verify.txt" | head -6 | sed 's/^/    /'
ck "every page reads back with its own stamp after the remount" "$(grep -ao 'BAD=[0-9]*' "$OUT/verify.txt" | head -1 | cut -d= -f2)" 0

rs 40 "$NODE" "umount $MNT; losetup -d $DEV; rm -f $IMG" >/dev/null 2>&1
echo "STAGE done at +$(el)s"
if [ "$fails" = 0 ]; then
    echo "RESULT: PASS label=$LABEL invalid=$INV fsyncs=$FS fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL invalid=$INV fsyncs=$FS fails=$fails wall=$(el)s evidence=$OUT"; exit 1
