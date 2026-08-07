#!/bin/bash
# loop_flush_probe.sh — decide whether a loop device's root-cgroup work path
# is alive before the fence harness builds a stack on top of it.
#
# WHY THIS EXISTS (mxfs sess141).  sess136/137 killed the loop_rootcg_workfn
# worker on /dev/loop0 with a GPF (the SCST fileio bvec UAF).  A workqueue
# worker that dies inside its callback stays in the pool's busy_hash forever
# with worker->current_work still pointing at that work_struct.  Every later
# queue_work() of the SAME work_struct finds it via find_worker_executing_work()
# and appends to the DEAD worker's ->scheduled list, where it never runs.
#
# loop_queue_rq() picks the worker from the bio's blkcg css:
#
#	if (rq->bio) cmd->blkcg_css = bio_blkcg_css(rq->bio);
#	...  queue_on_root_worker(css) ? &lo->rootcg_work : &worker->work
#
# A blk-mq FLUSH request has rq->bio == NULL, so it ALWAYS takes rootcg_work.
# That makes "flush hangs, read completes" the exact signature of a poisoned
# lo->rootcg_work, and it is permanent for the life of the struct loop_device
# — detaching with losetup -d does NOT re-INIT_WORK it, and /dev/loop0..7 are
# preallocated, so the poisoned struct is reused on the next attach.
#
# Usage:  sudo tests/fence_inflight/loop_flush_probe.sh [dev ...]
#         (default: probe every existing /dev/loopN that is currently free)
#
# Exit 0 if every probed device flushed within the budget, 1 otherwise.
# Prints one line per device: "<dev> FLUSH_OK <ms>" or "<dev> FLUSH_HUNG".
#
# RULE 0 budget: a flush of a 1 MiB freshly-written file on NVMe is a few ms.
# The budget is 5 s — three orders of magnitude of headroom; anything slower
# is the wedge, not slowness.
set -u

BUDGET=5
WORKDIR=$(mktemp -d /var/tmp/loopprobe.XXXXXX)
trap 'rmdir "$WORKDIR" 2>/dev/null' EXIT

if [ "$(id -u)" != 0 ]; then
	echo "must run as root" >&2
	exit 2
fi

devs=()
if [ $# -gt 0 ]; then
	devs=("$@")
else
	for d in /dev/loop[0-9]*; do
		[ -b "$d" ] || continue
		# skip devices that already have a backing file
		if losetup "$d" >/dev/null 2>&1; then
			echo "$d SKIP in-use"
			continue
		fi
		devs+=("$d")
	done
fi

rc=0
for dev in "${devs[@]}"; do
	img="$WORKDIR/$(basename "$dev").img"
	if ! truncate -s 1M "$img" 2>/dev/null; then
		echo "$dev SKIP cannot-create-image"
		continue
	fi

	if ! losetup "$dev" "$img" 2>/dev/null; then
		echo "$dev SKIP losetup-failed"
		/bin/rm -f "$img"
		continue
	fi

	# Dirty a block so the flush has something to do, then time the flush.
	# blockdev --flushbufs issues BLKFLSBUF -> sync_blockdev + a real
	# REQ_OP_FLUSH down the queue, which is the request under test.
	dd if=/dev/zero of="$dev" bs=4096 count=1 conv=notrunc status=none 2>/dev/null

	t0=$(date +%s%N)
	if timeout "$BUDGET" blockdev --flushbufs "$dev" 2>/dev/null; then
		t1=$(date +%s%N)
		echo "$dev FLUSH_OK $(( (t1 - t0) / 1000000 ))ms"
	else
		echo "$dev FLUSH_HUNG (>${BUDGET}s)"
		rc=1
		# Leave the device attached: the hung flush still owns the queue and
		# detaching would block too.  The caller unwedges with
		# scripts/loop_unwedge (act=1) and then detaches.
		/bin/rm -f "$img" 2>/dev/null
		continue
	fi

	losetup -d "$dev" 2>/dev/null
	/bin/rm -f "$img"
done

exit $rc
