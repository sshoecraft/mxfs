#!/bin/bash
# blocklayer_selftest.sh — prove clyde's loop / dm / ext4 path is healthy
# BEFORE the fence harness builds a real stack on top of it.
#
# WHY THIS EXISTS (mxfs sess142).  A GPF in an earlier session left
# /dev/loop0 with a permanently parked worker (see loop_flush_probe.sh and
# ccmemory ccloop-c7ee71c6-sess141-fence-stage-ii-blocker-ROOT-CAUSED-leaked-i_dio_count).
# The RULE-5 ruling on how to proceed requires empirical proof, before
# relying on isolation from that quarantined stack, that:
#
#   * new loop devices can read, write, flush and tear down;
#   * unrelated dm table load / suspend / resume / remove complete;
#   * unrelated mounts and unmounts complete;
#   * the loop workqueue still supplies replacement workers.
#
# This script exercises exactly that chain on scratch objects with names
# that CANNOT collide with the quarantined stack, and cleans up after
# itself.  Every step is bounded; a step that exceeds its budget is the
# wedge, and the script says which one.
#
# Usage:  sudo tests/fence_inflight/blocklayer_selftest.sh
# Exit 0 = the chain is healthy, 1 = a step exceeded its budget.
#
# RULE 0 budgets, derived from what each step should cost on NVMe, not
# from "long enough that it probably finishes":
#   losetup attach            1 s
#   4 KiB O_DIRECT write+sync 5 s   (native: single-digit ms)
#   dmsetup create/suspend/reload/resume/remove
#                             5 s each
#   mkfs.ext4 on 64 MiB      15 s
#   mount / umount           10 s
set -u

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 2; }

DMNAME=mxfsblselftest      # deliberately unlike mxfsfence/mxfsfencef
WORK=$(mktemp -d /var/tmp/blselftest.XXXXXX)
IMG=$WORK/img
MNT=$WORK/mnt
LOOP=
rc=0
step_failed=

cleanup() {
	mountpoint -q "$MNT" 2>/dev/null && umount "$MNT" 2>/dev/null
	dmsetup remove "$DMNAME" 2>/dev/null
	[ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null
	rmdir "$MNT" 2>/dev/null
	rm -f "$IMG" 2>/dev/null
	rmdir "$WORK" 2>/dev/null
}
trap cleanup EXIT

run() {   # run <budget_s> <label> <cmd...>
	local budget="$1" label="$2"; shift 2
	local t0 t1 ms
	t0=$(date +%s%N)
	if ! timeout "$budget" "$@" >/dev/null 2>&1; then
		t1=$(date +%s%N); ms=$(( (t1 - t0) / 1000000 ))
		echo "$label FAILED_OR_TIMED_OUT after ${ms}ms (budget ${budget}s)"
		step_failed="$label"
		return 1
	fi
	t1=$(date +%s%N); ms=$(( (t1 - t0) / 1000000 ))
	echo "$label OK ${ms}ms"
	return 0
}

# A dm device with this name must not already exist — if it does, a previous
# run of this script wedged and its objects are the thing to investigate.
if dmsetup ls 2>/dev/null | grep -q "^$DMNAME"; then
	echo "FATAL: dm device $DMNAME already exists — a previous selftest did not clean up"
	exit 2
fi

truncate -s 64M "$IMG" || { echo "FATAL: truncate failed"; exit 2; }

LOOP=$(timeout 1 losetup --find --show --direct-io=on "$IMG") || {
	echo "loop_attach FAILED_OR_TIMED_OUT"; exit 1; }
echo "loop_attach OK $LOOP"

dio=$(cat "/sys/block/$(basename "$LOOP")/loop/dio" 2>/dev/null)
if [ "$dio" != 1 ]; then
	echo "loop_dio FAILED direct-io fell back to '$dio'"
	exit 1
fi
echo "loop_dio OK 1"

run 5  loop_write   dd if=/dev/zero of="$LOOP" bs=4096 count=1 oflag=direct conv=fsync || rc=1
run 5  loop_read    dd if="$LOOP" of=/dev/null bs=4096 count=1 iflag=direct           || rc=1
run 5  loop_flush   blockdev --flushbufs "$LOOP"                                      || rc=1
[ $rc = 0 ] || { echo "RESULT: UNHEALTHY (first failure: $step_failed)"; exit 1; }

SECT=$(( 64 * 1024 * 1024 / 512 ))
run 5 dm_create  dmsetup create "$DMNAME" --table "0 $SECT delay $LOOP 0 0 $LOOP 0 0" || rc=1
[ $rc = 0 ] || { echo "RESULT: UNHEALTHY (first failure: $step_failed)"; exit 1; }

run 5 dm_suspend dmsetup suspend "$DMNAME"                                          || rc=1
run 5 dm_reload  dmsetup reload  "$DMNAME" --table "0 $SECT delay $LOOP 0 50 $LOOP 0 50" || rc=1
run 5 dm_resume  dmsetup resume  "$DMNAME"                                          || rc=1
[ $rc = 0 ] || { echo "RESULT: UNHEALTHY (first failure: $step_failed)"; exit 1; }

# Prove the delay target is actually delaying: a 4 KiB write through a 50 ms
# write delay must take >= ~50 ms.  A dm-delay that silently passes through
# would make the whole fence harness meaningless.
t0=$(date +%s%N)
timeout 5 dd if=/dev/zero of="/dev/mapper/$DMNAME" bs=4096 count=1 oflag=direct conv=fsync >/dev/null 2>&1
t1=$(date +%s%N); dms=$(( (t1 - t0) / 1000000 ))
if [ "$dms" -lt 40 ]; then
	echo "dm_delay_effective FAILED write through a 50ms delay took only ${dms}ms"
	rc=1
else
	echo "dm_delay_effective OK ${dms}ms through a 50ms write delay"
fi

run 5 dm_undelay dmsetup suspend "$DMNAME" || rc=1
run 5 dm_reload0 dmsetup reload "$DMNAME" --table "0 $SECT delay $LOOP 0 0 $LOOP 0 0" || rc=1
run 5 dm_resume0 dmsetup resume "$DMNAME"  || rc=1
[ $rc = 0 ] || { echo "RESULT: UNHEALTHY (first failure: $step_failed)"; exit 1; }

run 15 mkfs      mkfs.ext4 -q -F "/dev/mapper/$DMNAME" || rc=1
[ $rc = 0 ] || { echo "RESULT: UNHEALTHY (first failure: $step_failed)"; exit 1; }

mkdir -p "$MNT"
run 10 mount     mount -o noatime "/dev/mapper/$DMNAME" "$MNT" || rc=1
[ $rc = 0 ] || { echo "RESULT: UNHEALTHY (first failure: $step_failed)"; exit 1; }

# The fileio stack's real workload: a preallocated file, initialized, fsynced.
run 20 file_init dd if=/dev/zero of="$MNT/probe.img" bs=1M count=16 oflag=direct conv=fsync || rc=1
run 10 fs_sync   sync -f "$MNT/probe.img" || rc=1
run 10 umount    umount "$MNT" || rc=1
run 5  dm_remove dmsetup remove "$DMNAME" || rc=1
run 5  loop_det  losetup -d "$LOOP" || rc=1
[ $rc = 0 ] && LOOP=

if [ $rc = 0 ]; then
	echo "RESULT: HEALTHY — loop, dm-delay, ext4 and the mount path all complete"
else
	echo "RESULT: UNHEALTHY (first failure: $step_failed)"
fi
exit $rc
