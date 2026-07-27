#!/bin/bash
# fix26_wb_bast_exerciser.sh — targeted trigger for the FIX-26 admit path.
#
# The FIX-26 deadlock (ccloop c7ee71c6 sess6, captured live on test8
# 2026-07-25): a writeback-SUBMISSION task (bdi flusher / sync / fsync inside
# xfs_vm_writepages) holds a folio lock across ->map_blocks' delalloc
# conversion, whose xfs_ilock(EX) -> mxfs_dlm_ilock_begin parks in the
# demote-wait because the inode went BAST; the bast drain's
# filemap_write_and_wait then blocks forever in __folio_lock on the folio the
# submitter holds.  FIX-26 admits writepages tasks through the demote-wait
# (nested EX under a still-granted EX/PR mirror), same theorem as FIX-25's
# ioend admit.
#
# This driver makes the precondition COMMON instead of rare:
#   writer node: continuously rewrites a file set buffered (delalloc), with
#     the bdi flusher tuned hot (dirty_writeback_centisecs=20,
#     dirty_expire_centisecs=1) so SUBMISSION comes from the flusher — the
#     exact task type captured D-state in the live wedge.  No explicit syncs:
#     early conversion narrows the collision window.
#   reader node: tight stat+head-read loop over the same files (no
#     drop_caches — the DLM PR ping-pong alone generates the bast storm).
#
# v2 (same session): first cut used writer-side sync every 0.2s + reader
# drop_caches sweeps — 0 admits in 60s (delalloc pre-converted, ~3 basts/s).
# v3 (same session): v2's natural window (folio locked -> BAST lands -> ilock
# entered) is MICROSECONDS wide — 90s of load produced 0 collisions.  v3 arms
# the deterministic injection param fix26_delay_ms (v0.11.89: xfs_convert_blocks
# holds the conversion — folio locked, ilock imminent — until a bast lands or
# N ms elapse, demoter-exempt) on the WRITER, so a peer BAST reliably collides
# with the window.  Small files keep each bast drain cheap (fast ping-pong).
# v4 (same session): v3 still 0 admits at 693 writer iters — conv=notrunc
# REWRITES already-real extents, so after pass 1 there is NO delalloc and
# xfs_convert_blocks never runs.  Plain dd (truncate + rewrite) reallocates
# every pass: every file x iteration converts delalloc, arming the window.
#
# Success criteria:
#   - zero new P73-WAITSTALL on the writer during the window, AND
#   - writer dmesg P25-IOEND-ADMIT src=writepages > 0 (admit fired), AND
#   - both loops progress (iteration counts printed).
#
# Usage: fix26_wb_bast_exerciser.sh <writer-host> <reader-host> [secs] [mnt] [delay_ms]
set -u
W="${1:?writer host}"; R="${2:?reader host}"; SECS="${3:-45}"
MNT="${4:-/mnt/shared}"
DELAY="${5:-150}"
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
NF=32     # files
FKB=256   # KB per file

echo "=== FIX-26 exerciser v3: writer=$W reader=$R ${SECS}s mnt=$MNT files=$NF x ${FKB}KB inject=${DELAY}ms"

W0=$("$SSH" "$W" x "dmesg | grep -c 'src=writepages'" 2>/dev/null | tail -1); W0=${W0:-0}
P73_0=$("$SSH" "$W" x "dmesg | grep -c 'P73-WAITSTALL'" 2>/dev/null | tail -1); P73_0=${P73_0:-0}

# Writer: hot flusher + injection armed + continuous buffered rewrites.
# Sysctls and injection param restored/disarmed after (and again by the
# driver below, in case the ssh leg dies mid-window).
"$SSH" "$W" x "cd $MNT || exit 1
  owc=\$(sysctl -n vm.dirty_writeback_centisecs); oec=\$(sysctl -n vm.dirty_expire_centisecs)
  sysctl -qw vm.dirty_writeback_centisecs=20 vm.dirty_expire_centisecs=1
  echo $DELAY > /sys/module/mxfs/parameters/fix26_delay_ms
  rm -f fix26_f*; n=0; end=\$((\$(date +%s)+$SECS))
  while [ \$(date +%s) -lt \$end ]; do
    for f in \$(seq 1 $NF); do dd if=/dev/zero of=fix26_f\$f bs=64k count=$(( FKB / 64 )) 2>/dev/null; done
    n=\$((n+1))
  done
  echo 0 > /sys/module/mxfs/parameters/fix26_delay_ms
  sysctl -qw vm.dirty_writeback_centisecs=\$owc vm.dirty_expire_centisecs=\$oec
  echo WRITER_ITERS=\$n" 2>/dev/null > /tmp/.fix26_wlog &
WPID=$!

# Reader: fast PR ping-pong — stat + 4KB head read per file, no cache drop.
"$SSH" "$R" x "cd $MNT || exit 1; n=0; end=\$((\$(date +%s)+$SECS))
  while [ \$(date +%s) -lt \$end ]; do
    for f in \$(seq 1 $NF); do stat fix26_f\$f >/dev/null 2>&1; dd if=fix26_f\$f of=/dev/null bs=4k count=1 2>/dev/null; done
    n=\$((n+1))
  done; echo READER_ITERS=\$n" 2>/dev/null > /tmp/.fix26_rlog &
RPID=$!

wait $WPID $RPID
# Belt-and-braces disarm (writer leg may have died before its own disarm).
"$SSH" "$W" x "echo 0 > /sys/module/mxfs/parameters/fix26_delay_ms" 2>/dev/null
grep -h 'ITERS' /tmp/.fix26_wlog /tmp/.fix26_rlog

W1=$("$SSH" "$W" x "dmesg | grep -c 'src=writepages'" 2>/dev/null | tail -1); W1=${W1:-0}
P73_1=$("$SSH" "$W" x "dmesg | grep -c 'P73-WAITSTALL'" 2>/dev/null | tail -1); P73_1=${P73_1:-0}
IOEND=$("$SSH" "$W" x "dmesg | grep -c 'src=ioend'" 2>/dev/null | tail -1)
echo "P25 src=writepages admits during window: $(( W1 - W0 )) (total $W1)"
echo "P25 src=ioend total: ${IOEND:-0}"
echo "new P73-WAITSTALL during window: $(( P73_1 - P73_0 ))"
"$SSH" "$W" x "dmesg | grep 'src=writepages' | tail -3" 2>/dev/null
"$SSH" "$W" x "cd $MNT && rm -f fix26_f*" 2>/dev/null
if [ $(( P73_1 - P73_0 )) -eq 0 ] && [ $(( W1 - W0 )) -gt 0 ]; then
    echo "RESULT: PASS (admit fired $(( W1 - W0 ))x, zero waitstalls)"
elif [ $(( P73_1 - P73_0 )) -eq 0 ]; then
    echo "RESULT: INCONCLUSIVE (zero waitstalls but admit did not fire — precondition not hit)"
else
    echo "RESULT: FAIL (P73-WAITSTALL appeared — writeback task parked during window)"
fi
