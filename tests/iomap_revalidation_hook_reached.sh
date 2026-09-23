#!/bin/bash
# tests/iomap_revalidation_hook_reached.sh — does iomap actually CALL the
# mapping-revalidation hook on this kernel?
# (ledger D-NO-BUFFERED-WRITE-REVALIDATES-ITS-MAPPING-ON-THE-KERNEL-UNDER-TEST)
#
# WHY A WHOLE LAP FOR ONE PROBE.  The defect was that xfs_iomap_valid() existed
# in the source and not in the module: it was installed only in the 6.15+
# iomap_write_ops, and the macro that calls iomap_file_buffered_write() on this
# kernel expands that argument away, so nothing referenced the function and the
# compiler dropped it.  The fix installs it where THIS kernel looks —
# iomap->folio_ops, set beside the validity_cookie in xfs_bmbt_to_iomap.
#
# The compiler already confirms half of that and cannot confirm the other half.
# 'tools/warn_sweep.sh' no longer reports the function as defined-but-not-used,
# which says it is REFERENCED.  A referenced function is not a called one, and
# the claim being made is about a kernel whose fs/iomap/*.c is not on this host
# — only its headers are.  So the contract in include/linux/iomap.h (the hook
# "allows iomap to detect that the iomap needs to be refreshed during a long
# running write operation", called "with the folio over the specified file
# position held locked") is, on this build, a promise nobody has watched being
# kept.  This lap watches it.
#
# A ZERO HERE IS A FINDING, NOT A HARNESS PROBLEM.  If the probe does not fire
# after an ordinary buffered write, then 6.8's iomap reaches this hook by some
# path the header's comment does not describe, or does not reach it at all, and
# the fix does not do what it claims.  That outcome must be reported as a FAIL
# of this record and not explained away.
#
# WHAT THE PROBE IS.  P312-IOMAP-REVALIDATED is pr_info_once: it fires on the
# FIRST call after each module load and never again, which is exactly the
# question ("is this reached") and nothing more.  Because it is one-shot, the
# lap must run against a freshly prepped module — which prep_cluster guarantees
# — and must read the whole dmesg rather than a window, since the one line may
# have been emitted by mount itself before any workload of ours ran.  That is
# not a weaker result: the hook firing during mount is still the hook firing.
#
# P312-IOMAP-STALE is the other arm of the same probe and is rate-limited
# pr_warn.  It fires only when a cached mapping is ACTUALLY found stale, which
# an uncontended single-writer workload does not produce (arm 1 records its
# count and does not assert it).  ARM 2 MAKES IT FIRE ON DEMAND: one write()
# of SMB MiB while a second thread fsyncs the same file continuously
# (tests/iomap_stale_race.py).  Each fsync's writeback converts the delalloc
# blocks dirtied so far, the conversion bumps the inode's extent sequence, and
# the writer's next folio finds its cookie stale — which is the case the hook
# exists for.  The schedule was proven on native 6.8 XFS on a loop device
# first (tests/iomap_stale_loop_control.sh s140x: xfs_iomap_invalid fired 12
# times inside one 0.9 s write of 256 MiB, 22 fsyncs racing), so a zero here
# is not a schedule that never raced: it means MXFS's hook did not refuse a
# mapping native XFS refuses, and that is a FAIL of this record.  The arm then
# unmounts and remounts and reads every page's stamp back cold: a write that
# went on under a stale mapping lands in blocks the mapping no longer names,
# and that shows up as a page whose stamp is not its index.
#
# BOUND, derived: prep_cluster is measured at 53-137 s on this rig and is given
# the 300 s the other laps here give it; arm 1 is a 64 MiB buffered write and
# an fsync, which native XFS on this hardware does in about a second at the
# ~700 MB/3-4 s figure this project measures, budgeted at 20 s (well over 2x);
# arm 2 is a 256 MiB write with fsyncs racing (0.9 s on native XFS, 20 s
# budget), an unmount+remount (60 s, the figure the other single-node laps
# here give it) and a 256 MiB cold read (2 s native, 20 s); the dmesg reads
# are 20 s measurements, four of them.  300 + 20 + 100 + 80 = 500 s.
#
# Usage: tests/iomap_revalidation_hook_reached.sh <label>      (env MB=64 SMB=256)
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
MNT=/mnt/shared
MB=${MB:-64}
SMB=${SMB:-256}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_iomapreval_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }

if [ ! -f mxfs.ko ]; then
    echo "ABORT: no mxfs.ko in the tree (build it first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== iomap_revalidation_hook_reached label=$LABEL node=$A mb=$MB sv=$SV $(date -u +%FT%TZ) ==="

# THE BUILD GATE COMES FIRST AND IS NOT OPTIONAL.  A probe that is not a string
# in mxfs.ko is a guaranteed silence, and a lap that counted it would be reading
# its own emptiness as a measurement of the filesystem.  This is the same class
# of error that made six other harnesses in this directory grade on probes the
# compiler had removed.
if ! strings -a mxfs.ko 2>/dev/null | grep -q 'P312-IOMAP-REVALIDATED'; then
    echo "ABORT: P312-IOMAP-REVALIDATED is not a string in mxfs.ko — the hook is not in the build, so this lap cannot measure whether it is called"
    echo "RESULT: ABORT label=$LABEL stage=build-gate evidence=$OUT"; exit 2
fi
echo "  PASS P312-IOMAP-REVALIDATED is present in the built module"

MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ "$prc" = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }

rsx 20 "$A" "dmesg | grep -ac 'P312-IOMAP-REVALIDATED'; echo end=1" > "$OUT/dmesg_pre.txt" 2>&1
capture_require "$OUT/dmesg_pre.txt" '^end=1$' "the pre-workload probe count on $A"
pre=$(grep -aoE '^[0-9]+$' "$OUT/dmesg_pre.txt" | head -1)
echo "STAGE before the workload: P312-IOMAP-REVALIDATED count=$pre"

# An ordinary buffered write.  NOT O_DIRECT: direct I/O does not go through the
# buffered write iterator and would never reach this hook, so a dio workload
# here would produce a zero that says nothing about the fix.
rsx 60 "$A" "dd if=/dev/zero of=$MNT/iomapreval_$LABEL bs=1M count=$MB status=none conv=fsync; echo dd_rc=\$?" \
    > "$OUT/write.txt" 2>&1
capture_require "$OUT/write.txt" '^dd_rc=[0-9]+$' "the buffered write on $A"
ck "the buffered write completed" "$(grep -ao 'dd_rc=[0-9]*' "$OUT/write.txt" | head -1 | cut -d= -f2)" 0

rsx 20 "$A" "dmesg | grep -ac 'P312-IOMAP-REVALIDATED'; echo end=1" > "$OUT/dmesg_post.txt" 2>&1
capture_require "$OUT/dmesg_post.txt" '^end=1$' "the post-workload probe count on $A"
post=$(grep -aoE '^[0-9]+$' "$OUT/dmesg_post.txt" | head -1)

rsx 20 "$A" "dmesg | grep -a 'P312-IOMAP-STALE' | tail -5; echo end=1" > "$OUT/stale.txt" 2>&1
stale=$(grep -ac 'P312-IOMAP-STALE' "$OUT/stale.txt")

echo "STAGE after the workload: P312-IOMAP-REVALIDATED count=$post (was $pre), P312-IOMAP-STALE lines=$stale"
ckge "iomap CALLED the mapping-revalidation hook on this kernel" "${post:-0}" 1
echo "NOTE P312-IOMAP-STALE fired $stale time(s) under arm 1; that workload does not force a stale mapping, so the number is recorded and not asserted"

# ---- arm 2: force the mapping stale underneath one write, then read the
#             platter back cold (see the header).
rsx 20 "$A" "grep -a ' $MNT mxfs ' /proc/mounts | awk '{print \$1}'; echo end=1" > "$OUT/dev.txt" 2>&1
capture_require "$OUT/dev.txt" '^/dev/' "the device under $MNT on $A"
DEV=$(grep -a '^/dev/' "$OUT/dev.txt" | head -1)
SF=$MNT/iomapstale_$LABEL
rsx 60 "$A" "python3 /src/mxfs/tests/iomap_stale_race.py write $SF $SMB; echo py_rc=\$?" > "$OUT/stale_write.txt" 2>&1
capture_require "$OUT/stale_write.txt" '^WROTE=[0-9]+ WRITE_CALLS=[0-9]+ FSYNCS=[0-9]+ ELAPSED_MS=[0-9]+ RC=[0-9]+$' "the racing write on $A"
SUM=$(grep -a '^WROTE=' "$OUT/stale_write.txt" | head -1)
FS=$(echo "$SUM" | grep -ao 'FSYNCS=[0-9]*' | cut -d= -f2)
rsx 20 "$A" "dmesg | grep -ac 'P312-IOMAP-STALE'; echo end=1" > "$OUT/stale2.txt" 2>&1
capture_require "$OUT/stale2.txt" '^end=1$' "the post-race stale count on $A"
stale2=$(grep -aoE '^[0-9]+$' "$OUT/stale2.txt" | head -1)
echo "STAGE arm 2: $SUM  P312-IOMAP-STALE lines=$stale2 (was $stale)"
ck "arm 2: the racing write completed" "$(echo "$SUM" | grep -ao 'RC=[0-9]*' | cut -d= -f2)" 0
if [ "${FS:-0}" -lt 1 ]; then
    echo "VACUOUS: no fsync completed while the write was in flight, so nothing converted the delalloc blocks underneath it and no mapping could have gone stale — the schedule did not race"
    echo "RESULT: VACUOUS label=$LABEL stage=arm2-race evidence=$OUT"; exit 3
fi
ckge "arm 2: MXFS's hook refused a mapping that had gone stale under the write (P312-IOMAP-STALE)" "$(( ${stale2:-0} - ${stale:-0} ))" 1
rsx 60 "$A" "dmesg | grep -a 'P312-IOMAP-STALE' | tail -3; umount $MNT && mount -t mxfs $DEV $MNT && echo REMOUNT_OK" > "$OUT/remount.txt" 2>&1
capture_require "$OUT/remount.txt" 'REMOUNT_OK' "the unmount/remount on $A"
grep -a 'P312-IOMAP-STALE' "$OUT/remount.txt" | head -3 | sed 's/.*mxfs: /    /' | cut -c1-200
rsx 60 "$A" "python3 /src/mxfs/tests/iomap_stale_race.py verify $SF $SMB" > "$OUT/verify.txt" 2>&1
capture_require "$OUT/verify.txt" '^CHECKED=[0-9]+ BAD=[0-9]+$' "the cold verify on $A"
echo "STAGE arm 2 cold read: $(grep -a '^CHECKED=' "$OUT/verify.txt")"
grep -a '^  page=' "$OUT/verify.txt" | head -6 | sed 's/^/    /'
ck "arm 2: every page reads back with its own stamp after the remount" "$(grep -ao 'BAD=[0-9]*' "$OUT/verify.txt" | head -1 | cut -d= -f2)" 0

rsx 20 "$A" "dmesg | grep -ac 'BUG:\|Oops' ; echo end=1" > "$OUT/bad.txt" 2>&1
capture_require "$OUT/bad.txt" '^end=1$' "the crash scan on $A"
ck "the node logged no BUG or Oops across the workload" "$(grep -aoE '^[0-9]+$' "$OUT/bad.txt" | head -1)" 0

echo "STAGE done at +$(el)s"
if [ "$fails" = 0 ]; then
    echo "RESULT: PASS label=$LABEL fails=0 wall=$(el)s evidence=$OUT"
else
    echo "RESULT: FAIL label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
fi
exit $(( fails > 0 ))
