#!/bin/bash
# fix27_wb_shared_exerciser.sh — targeted trigger + negative control for the
# FIX-27 SHARED-class writeback-submission admit.
#
# THE DEADLOCK (ccloop c7ee71c6 sess24, captured live on test27 @32/caw 0.11.201)
# -----------------------------------------------------------------------------
#   kworker/u9:29+mxfs-ino-bast/dm-1   wchan=folio_wait_bit_common
#     folio_wait_bit_common <- __folio_lock <- write_cache_pages
#     <- iomap_writepages <- xfs_vm_writepages <- do_writepages
#     <- filemap_write_and_wait_range <- mxfs_dlm_bast_process
#   kworker/u12:30+flush-252:1         wchan=mxfs_dlm_ilock_begin
#     mxfs_dlm_ilock_begin <- xfs_ilock <- xfs_map_blocks
#     <- iomap_writepage_map <- write_cache_pages <- xfs_vm_writepages
#     <- __writeback_single_inode <- writeback_sb_inodes <- wb_writeback
# The BAST drain holds the inode lock and waits on a folio; the writeback
# submitter holds that folio and waits on the inode lock.  4+ `sync` then pile up
# on wb_wait_for_completion, loadavg hits 20, and the node can never again reach
# a barrier -- while still passing every liveness check (mounted, ls answers, no
# BUG/WARNING, no shutdown).
#
# WHY FIX-26's EXERCISER CANNOT TEST THIS
# ---------------------------------------
# FIX-26 admits the writeback submitter only when it requests EX, and its
# exerciser arms fix26_delay_ms inside xfs_convert_blocks -- the DELALLOC
# CONVERSION path.  But the submitter's FIRST lock here is SHARED:
# xfs_map_blocks() takes xfs_ilock(ip, XFS_ILOCK_SHARED) before any conversion is
# considered, and a folio needing no conversion never reaches xfs_convert_blocks.
#
# So this harness inverts FIX-26's v4 workload lesson.  That session found plain
# `dd` (truncate + rewrite) was REQUIRED for FIX-26 because conv=notrunc
# "REWRITES already-real extents, so after pass 1 there is NO delalloc and
# xfs_convert_blocks never runs".  That is precisely what FIX-27 needs: rewriting
# real extents drives map_blocks' SHARED acquire on every folio with no
# conversion anywhere.  Hence conv=notrunc here, deliberately.
#
# ARMS
#   fix27_shared_admit=1  the fix: expect P25 admits with req=3 src=writepages,
#                         sync completing, no wedge.
#   fix27_shared_admit=0  the negative control: expect the deadlock. THIS WILL
#                         WEDGE THE WRITER NODE. It is recovered automatically at
#                         the end (virsh destroy+start + scripts/rig_recover.sh).
#
# Usage: fix27_wb_shared_exerciser.sh <writer> <reader> [secs] [delay_ms] [arm]
set -u
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
W="${1:?writer host}"; R="${2:?reader host}"
SECS="${3:-45}"; DELAY="${4:-150}"; ARM="${5:-1}"
MNT=/mnt/shared
D="$MNT/.fix27_$(date -u +%H%M%S)"

echo "=== fix27 exerciser: writer=$W reader=$R secs=$SECS delay=${DELAY}ms arm=$ARM ==="

"$SSH" "$W" "mkdir -p '$D'" >/dev/null 2>&1
# Pass 1 creates the files; every later pass rewrites REAL extents (no delalloc),
# which is the whole point -- map_blocks takes SHARED and never converts.
"$SSH" "$W" "for i in 1 2 3 4 5 6 7 8; do dd if=/dev/urandom of='$D/f\$i' bs=4096 count=16 status=none; done; sync" >/dev/null 2>&1

for h in "$W" "$R"; do
    "$SSH" "$h" "echo $ARM > /sys/module/mxfs/parameters/fix27_shared_admit" >/dev/null 2>&1
done
got=$("$SSH" "$W" "cat /sys/module/mxfs/parameters/fix27_shared_admit" 2>/dev/null | tr -d '\r\n ')
[ "$got" = "$ARM" ] || { echo "!! arm did not take (got=[$got]) — measurement invalid"; exit 3; }
echo "--- arm fix27_shared_admit=$ARM verified on writer ---"

# Hot bdi flusher so SUBMISSION comes from the flusher: the exact task type
# captured D-state in the live wedge.  Arm the collision injection on the writer.
"$SSH" "$W" "echo 20 > /proc/sys/vm/dirty_writeback_centisecs
             echo 1  > /proc/sys/vm/dirty_expire_centisecs
             echo $DELAY > /sys/module/mxfs/parameters/fix27_delay_ms" >/dev/null 2>&1

MARK="MXFS_FIX27_$(date -u +%H%M%S)_arm$ARM"
"$SSH" "$W" "echo $MARK > /dev/kmsg" >/dev/null 2>&1

# Writer: rewrite real extents buffered, no explicit sync (let the flusher submit).
( "$SSH" "$W" "n=0; end=\$(( \$(date +%s) + $SECS ))
   while [ \$(date +%s) -lt \$end ]; do
     for i in 1 2 3 4 5 6 7 8; do
       dd if=/dev/urandom of='$D/f\$i' bs=4096 count=16 conv=notrunc status=none 2>/dev/null
     done
     n=\$((n+1))
   done
   echo WRITER_ITERS=\$n" 2>/dev/null | grep -oE 'WRITER_ITERS=[0-9]+' ) &
wpid=$!

# Reader: tight stat + read loop -> DLM PR ping-pong -> BAST storm on the writer.
( "$SSH" "$R" "n=0; end=\$(( \$(date +%s) + $SECS ))
   while [ \$(date +%s) -lt \$end ]; do
     for i in 1 2 3 4 5 6 7 8; do
       stat '$D/f\$i' >/dev/null 2>&1; head -c 4096 '$D/f\$i' >/dev/null 2>&1
     done
     n=\$((n+1))
   done
   echo READER_ITERS=\$n" 2>/dev/null | grep -oE 'READER_ITERS=[0-9]+' ) &
rpid=$!

wait "$wpid" "$rpid" 2>/dev/null

"$SSH" "$W" "echo 0 > /sys/module/mxfs/parameters/fix27_delay_ms
             echo 500 > /proc/sys/vm/dirty_writeback_centisecs
             echo 3000 > /proc/sys/vm/dirty_expire_centisecs" >/dev/null 2>&1

echo "--- verdict (writer=$W, window scoped to $MARK) ---"
"$SSH" "$W" "
  w() { dmesg | awk '/$MARK/{f=1} f'; }
  echo -n '  P27-INJECT (collision windows armed): '; w | grep -c 'P27-INJECT'
  echo -n '  P27-INJECT collided=1                : '; w | grep 'P27-INJECT' | grep -c 'collided=1'
  echo -n '  P25 admits src=writepages req=3 (PR) : '; w | grep 'P25-IOEND-ADMIT' | grep 'src=writepages' | grep -c 'req=3'
  echo -n '  P25 admits src=writepages req=5 (EX) : '; w | grep 'P25-IOEND-ADMIT' | grep 'src=writepages' | grep -c 'req=5'
  echo -n '  P47-FILEBLOCK (blocked, NOT admitted)  : '; w | grep -c 'P47-FILEBLOCK'
  echo -n '  P47 with req=3 (shared class)          : '; w | grep 'P47-FILEBLOCK' | grep -c 'req=3'
  echo -n '  P73-WAITSTALL (parked >3s)             : '; w | grep -c 'P73-WAITSTALL'
  echo '  --- D-state mxfs/writeback/sync tasks NOW ---'
  ps -eo stat,pid,comm --no-headers | awk '\$1 ~ /^D/' | grep -E 'mxfs|flush-|sync' | sed 's/^/    /' | head -6
  echo -n '  bounded sync completes: '; timeout 20 sync && echo YES || echo 'NO -- WEDGED'
  echo -n '  loadavg: '; cut -d' ' -f1-3 /proc/loadavg
" 2>/dev/null | grep -vE "^Warning|^Unauthorized|^If you"

"$SSH" "$W" "rm -rf '$D'" >/dev/null 2>&1
echo "=== done (arm=$ARM) ==="
