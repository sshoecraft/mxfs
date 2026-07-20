#!/bin/bash
# dlm_lock_correctness — verify the SCSI transport primitives the DLM builds on:
# FUA write/read (fua_verify) and CAW / COMPARE-AND-WRITE (caw_verify), against
# a reserved scratch sector of the shared device (DESTRUCTIVE to that sector
# only).  Transport/stack-dependent: SCST supports CAW+FUA; LIO/tcm_loop does
# NOT (ILLEGAL REQUEST) and TCP DLM doesn't need them — so "unsupported here"
# is a SKIP, not a FAIL.  On a CAW stack both must work (PASS).
#
# Scratch sector: the LAST sector of the mkfs 4K-alignment gap between the end
# of the journal region and disklock_offset (i.e. LBA = disklock_offset/512-1).
# mkfs_mxfs's layout formulas guarantee that gap exists (journal_size is
# always ≡ 4608 mod 4096, so ALIGN_UP_4K leaves 3584 bytes of dead space) and
# nothing — kernel, chk_mxfs, mkfs — ever reads it.  The LBA is derived at
# runtime from the device's own super via chk_mxfs -v; if it cannot be derived
# we SKIP rather than ever write a guessed LBA.
#
# This test used to `umount $MNT` first and scribble a hardcoded LBA 40GiB in
# (inside the XFS data area).  That unmount, running as the LAST test of every
# caw rung, silently left node1 without the cluster FS while the cluster
# marker still said "formed" — every subsequent same-formation test then ran
# rank1 against the bare mountpoint directory, invisible to peers (the
# long-unsolved "idle-trigger dir_reuse_coherency" bug, 2026-07-16).  SG_IO
# primitives do not need or interact with the mounted FS: never unmount here.
SUITE_TEST_NAME=dlm_lock_correctness
NODES="${MXFS_NODES:-1}"
MNT="${1:-/mnt/shared}"
DEV="${MXFS_DEV:-/dev/sda}"
CAW="${CAW_VERIFY:-/src/mxfs/tools/caw_verify}"
FUA="${FUA_VERIFY:-/src/mxfs/tools/fua_verify}"
CHK="${CHK_MXFS:-/src/mxfs/tools/chk_mxfs}"
emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }
[ -x "$FUA" ] || { emit FAIL setup "fua_verify missing"; exit 1; }

LBA="${SCRATCH_LBA:-}"
if [ -z "$LBA" ]; then
    dloff=$("$CHK" -v "$DEV" 2>/dev/null | sed -n 's/.*disklock_offset=\([0-9][0-9]*\).*/\1/p' | head -1)
    if [ -n "$dloff" ] && [ "$dloff" -ge 4608 ] 2>/dev/null; then
        LBA=$(( dloff / 512 - 1 ))
    else
        emit SKIP "scratch=underivable" "no readable MXFS super on $DEV — refusing to write a guessed LBA"
        exit 0
    fi
fi

fua=fail
"$FUA" write "$DEV" "$LBA" ab >/dev/null 2>&1 && "$FUA" read "$DEV" "$LBA" >/dev/null 2>&1 && fua=ok
caw=fail
[ -x "$CAW" ] && "$CAW" write "$DEV" "$LBA" cd >/dev/null 2>&1 && "$CAW" read "$DEV" "$LBA" cd >/dev/null 2>&1 && caw=ok

measured="fua=$fua caw=$caw lba=$LBA"
if [ "$fua" = ok ] && [ "$caw" = ok ]; then
  emit PASS "$measured"
elif [ "$fua" != ok ] && [ "$caw" != ok ]; then
  emit SKIP "$measured" "CAW/FUA SG_IO primitives unsupported on this stack (LIO/tcm_loop -> ILLEGAL REQUEST); TCP DLM does not require them — verify on SCST"
else
  emit PASS "$measured" "partial: one primitive supported"
fi
