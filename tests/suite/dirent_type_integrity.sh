#!/bin/bash
# dirent_type_integrity — no directory entry may name an inode of a DIFFERENT
# type than the entry's own ftype, and no such mismatch may go unresolved.
#
# WHY THIS EXISTS
#   The behavioural test can pass while the defect is live: cache_coherency
#   checks a bounded pool of names, so an unresolved flip on a name it does not
#   happen to check goes unnoticed.  This criterion asks the direct question
#   instead — did ANY dirent/inode type flip go unresolved in this workload?
#
#   (Do NOT repeat the measurement mistake that produced this file's first
#   draft: an unscoped `dmesg | grep -c` reported "338 hits on a freshly prepped
#   mount".  prep_cluster does not clear the ring and dmesg survives a module
#   reload, so those were leftovers from earlier builds.  Properly scoped, the
#   same condition read total_flips=80, unresolved=0.  Flips are COMMON and
#   normally resolve; the unresolved case is rare.  Always scope to the window.)
#
# THE DEFECT (ccloop c7ee71c6 sess22, D-DIRENT-INODE-TYPE-MISMATCH)
#   A dirent claims XFS_DIR3_FT_REG_FILE while the inode it names is a live
#   DIRECTORY of the SAME incarnation.  Settled from the ring for ino 17315221:
#       disk_mode=040755 (DIR)  disk_gen=4124037817
#       incore_mode=040755      incore_gen=4124037817   <- same incarnation
#   i.e. the inode really is a directory and the DIRENT is the corrupt side.
#   xfs_lookup's P95B resolver treats the dirent as ground truth, spins its full
#   200 rounds trying to make a correct directory inode "become" a regular file,
#   and gives up (resolved=0).  Both of its outcomes are wrong: publish the
#   mismatch (durable silent corruption -- node5.txt became a directory on all
#   32 nodes) or fail the lookup with -ESTALE (visible, but the name stays
#   unusable).
#
# WHAT THIS MEASURES
#   Every unresolved type flip in THIS run's window.  Threshold 0.
#
#   P95B-TYPEFLIP-WAIT ... resolved=0   -- the resolver gave up
#   P201-TYPEFLIP-UNRESOLVED-FAIL       -- and the lookup was failed rather
#                                          than publishing the mismatch
#
#   EXPECTED TO FAIL until the dirent side is rooted.  That is deliberate:
#   RULE 6 forbids carrying an unresolved credible defect as a green cell.  Do
#   NOT silence the probe, widen the threshold, or delete the criterion to make
#   the board green.
#
# Ordering: P8, after the workload criteria that generate rename/create churn.
SUITE_TEST_NAME=dirent_type_integrity
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"

# The -ESTALE arm only exists from v0.11.183.  On an older module the mismatch
# is published silently and this criterion cannot see it -- say so rather than
# pass, because unverifiable is not a pass.
probe_built=1
[ -e /sys/module/mxfs/parameters/typeflip_fail_unresolved ] || probe_built=0

# Scope to this boot's workload.  dirent_durability stamps MXFS_DIRENT_WINDOW;
# reuse it when present so a stale hit from an hour-old run cannot keep the cell
# red forever after the defect is fixed.  With no marker, scan the whole ring --
# for THIS defect that is the conservative direction (it can only over-report,
# and over-reporting a critical namespace defect is the safe error).
# SCOPING IS LOAD-BEARING HERE.  dmesg survives a module reload and
# prep_cluster does NOT clear it, so an unscoped scan re-reports hits from an
# hour-old run forever and the cell can never go green again even after the
# defect is fixed.  Measured: a standalone run on a freshly prepped cluster
# read 32 hits that were all leftovers from a previous build's run (same ino,
# same name, old probe format) while the workload that run produced ZERO.
#
# dirent_durability (P6) stamps MXFS_DIRENT_WINDOW on every node when it starts,
# and this criterion is ordered after it (P8), so in a full sweep the marker is
# always present.  With NO marker there is nothing this criterion can honestly
# judge -- and per the same rule applied everywhere else in this ledger,
# unverifiable is not a pass.
# sess24: scope via the shared helper, which falls back from the (rotatable)
# kmsg marker to the durable window-start timestamp.  Without that fallback this
# criterion reported FAIL on the 5 of 32 nodes whose ring is short, claiming the
# workload had not run when it had just PASSED on that node.  See lib.sh.
DW_FILE=$(mktemp)
dirent_window_scope "$DW_FILE"
WINDOW=$(cat "$DW_FILE"); rm -f "$DW_FILE"
have_window=$DW_HAVE
# Fail closed on an unset global rather than treating "" as "fine": an empty
# have_window is what made the first cut of this fix report a VACUOUS GREEN.
have_window=${have_window:-0}

unresolved=$(printf '%s' "$WINDOW" | grep 'P95B-TYPEFLIP-WAIT' | grep -c 'resolved=0')
failed=$(printf '%s' "$WINDOW" | grep -c 'P201-TYPEFLIP-UNRESOLVED-FAIL')
skips=$(printf '%s' "$WINDOW" | grep -c 'RELOAD-TYPEFLIP-STALE-SKIP')
total=$(printf '%s' "$WINDOW" | grep -c 'P95B-TYPEFLIP-WAIT')

if [ "$unresolved" -gt 0 ] || [ "$failed" -gt 0 ]; then
    echo "DTI-HIT-SAMPLE ($(hostname), first 3):"
    printf '%s' "$WINDOW" | grep -E 'P201-TYPEFLIP-UNRESOLVED-FAIL|P95B-TYPEFLIP-WAIT.*resolved=0' \
        | head -3 | sed 's/^/  DTI-HIT: /'
fi

st=PASS; reason=""
if [ "$have_window" = 0 ]; then
    st=FAIL
    reason="no MXFS_DIRENT_WINDOW marker on this node — the workload has not run in this boot, so the ring cannot be scoped to it and any hit found would be stale evidence from an earlier run. Run this after dirent_durability (P6), which stamps the marker."
elif [ "$probe_built" = 0 ]; then
    st=FAIL
    reason="typeflip_fail_unresolved not present in this build — a dirent/inode type mismatch would be published SILENTLY and cannot be verified here, and unverifiable is not a pass"
elif [ "$unresolved" -gt 0 ] || [ "$failed" -gt 0 ]; then
    st=FAIL
    reason="$unresolved unresolved dirent/inode type flip(s) of $total total; $failed lookup(s) failed -ESTALE rather than publish the mismatch. A dirent naming an inode of a different type is namespace corruption whether or not a behavioural test happens to notice."
fi
# sess24: publish HOW the window was established and whether the ring still
# reaches back to its start.  With src=timestamp trunc=1 the counts are a LOWER
# BOUND (the earliest part of the window has rotated out), so a green cell can be
# read for what it is instead of being mistaken for full coverage.
echo "RESULT: $st | test=dirent_type_integrity | nodes=$T | measured=unresolved=$unresolved failed_estale=$failed total_flips=$total stale_skips=$skips probe=$probe_built window=$have_window win_src=$DW_SOURCE win_trunc=$DW_TRUNC | reason=$reason"
[ "$st" = PASS ]
