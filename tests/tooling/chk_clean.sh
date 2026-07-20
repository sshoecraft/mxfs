#!/bin/bash
# chk_clean — chk_mxfs validates a healthy FS with no errors. Device-level.
SUITE_TEST_NAME=chk_clean
MNT="${1:-/mnt/shared}"; NODES="${MXFS_NODES:-1}"
DEV="${MXFS_DEV:-/dev/sda}"; CHK="${CHK_MXFS:-/src/mxfs/tools/chk_mxfs}"
# native-XFS baseline (run.sh DLM=xfs, N=1 only): xfs_repair -n (dry-run check)
# instead of chk_mxfs -- this is the one case where using an xfs_* tool is
# CORRECT (the device really is native XFS here, not mxfs's envelope format;
# see CLAUDE.md's "use mxfs tools, not xfs tools" note, which is about mxfs
# devices specifically).
FSTYPE="${MXFS_EXPECT_FSTYPE:-mxfs}"
emit(){ echo "RESULT: $1 | test=$SUITE_TEST_NAME | nodes=$NODES | measured=$2 | reason=${3:-}"; }
mountpoint -q "$MNT" && umount "$MNT" 2>/dev/null
if [ "$FSTYPE" = xfs ]; then
    xfs_repair -n "$DEV" >/tmp/chk.$$ 2>&1; rc=$?
else
[ -x "$CHK" ] || { emit FAIL setup "chk tool missing $CHK"; exit 1; }
"$CHK" -v "$DEV" >/tmp/chk.$$ 2>&1; rc=$?
fi
errs=$(grep -ciE 'error|corrupt|bad magic|inconsistent' /tmp/chk.$$ 2>/dev/null); rm -f /tmp/chk.$$
{ [ $rc -eq 0 ] && [ "${errs:-0}" -eq 0 ]; } && emit PASS "rc=0 errors=0" || emit FAIL "rc=$rc errors=${errs:-?}" "chk_mxfs reported issues"
