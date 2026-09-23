#!/bin/bash
# audit_ilock_nowait_pairs.sh — mechanical check for D-0532's class.
#
# xfs_ilock_nowait() enters a DLM begin (mxfs_dlm_ilock_try) ONLY for IOLOCK
# flags, while xfs_iunlock() ALWAYS runs mxfs_dlm_ilock_end for ILOCK flags.
# An ILOCK taken by xfs_ilock_nowait and released by plain xfs_iunlock is
# therefore an unpaired end: with no other holder it underflows
# (P71-UNDERFLOW), and with one it silently consumes that holder's count, so
# the release pipeline sees holders==0 under a live holder and may give the
# grant away mid-operation.
#
# For every xfs_ilock_nowait call whose flags name XFS_ILOCK_* or are a
# variable, the enclosing function must contain one of:
#   xfs_iunlock_nodlm(  up_write(&ip->i_lock  up_read(&ip->i_lock
#   mxfs_iunlock_rwsems_raw(      (raw release: no end is run)
#   mxfs_dlm_ilock_begin(  mxfs_dlm_ilock_try(   (explicit pairing: the
#                                  lock becomes a counted holder)
#   xfs_iget_recycle(             (handed to the recycle, which releases raw)
# or, for a helper whose variable flags can only ever be IOLOCK modes, the
# annotation comment "nowait-iolock-only" inside the function (IOLOCK nowait
# takes its own DLM try, so plain xfs_iunlock pairs; the helper must also
# WARN on an ILOCK flag), or "nowait-nodlm-mount-only" where the function
# returns before the nowait whenever the mount has a cluster DLM (then
# xfs_iunlock runs no end at all).
# Anything else is a FAIL — including a helper that RETURNS holding the lock
# ("caller-released"), because the audit cannot see its callers' unlocks and
# they are, in practice, plain xfs_iunlock.  That blind spot is exactly how
# xfs_ilock_for_iomap escaped the first version of this check.
#
# The file set is every .c under xfs/ (scrub excluded by the build), pal/,
# mxfs_clayer/ that has a sibling .o, i.e. what the last build compiled.  A
# tree with no build is refused rather than scanned against a guessed list.
# Exit 0 = every site paired; 1 = at least one unpaired site; 2 = no build.
set -u
cd "$(dirname "$0")/.." || exit 2
files=()
while IFS= read -r c; do
  [ -f "${c%.c}.o" ] && files+=("$c")
done < <(ls xfs/*.c xfs/libxfs/*.c pal/linux/*.c mxfs_clayer/*.c 2>/dev/null)
[ "${#files[@]}" -gt 0 ] || { echo "NO BUILD: no compiled .c found (run make modules first)"; exit 2; }
for f in "${files[@]}"; do
  awk -v F="$f" '
    /^[a-zA-Z_][a-zA-Z0-9_]*\(/ { fn=$0; sub(/\(.*/, "", fn); start=NR; body=""; }
    { body = body "\n" $0 }
    /^}/ {
      if (body ~ /xfs_ilock_nowait\(/) {
        n = split(body, lines, "\n")
        for (i = 1; i <= n; i++) if (lines[i] ~ /xfs_ilock_nowait\(/ && lines[i] !~ /^[ \t]*\*/ && lines[i] !~ /^[ \t]*\/\*/ && fn != "xfs_ilock_nowait") {
          call = lines[i] " " lines[i+1]
          if (call !~ /ILOCK_/ && call ~ /(IOLOCK|MMAPLOCK)_/) continue   # literal IOLOCK/MMAPLOCK only
          paired = (body ~ /xfs_iunlock_nodlm\(/ || body ~ /up_write\(&ip->i_lock/ || body ~ /up_read\(&ip->i_lock/ || body ~ /mxfs_iunlock_rwsems_raw\(/ || body ~ /mxfs_dlm_ilock_begin\(/ || body ~ /mxfs_dlm_ilock_try\(/)
          hand = (body ~ /xfs_iget_recycle\(/)
          iolock_only = (call !~ /ILOCK_/ && body ~ /nowait-iolock-only/ && body ~ /WARN_ON_ONCE\(lock_mode & \(XFS_ILOCK_EXCL \| XFS_ILOCK_SHARED\)\)/)
          nodlm_only = (body ~ /nowait-nodlm-mount-only/ && body ~ /m_mxfs_dlm\) \{/)
          if (paired || hand || iolock_only || nodlm_only) printf("OK   %s:%d %s()\n", F, start+i-2, fn)
          else if (body ~ /xfs_iunlock\(/) printf("FAIL %s:%d %s(): ILOCK nowait released by plain xfs_iunlock\n", F, start+i-2, fn)
          else printf("FAIL %s:%d %s(): returns holding a nowait ILOCK with no DLM try/begin; its callers release it with xfs_iunlock\n", F, start+i-2, fn)
        }
      }
      body=""
    }' "$f"
done | tee /dev/stderr | awk -v NF_="${#files[@]}" '/^FAIL/{f++} /^OK|^FAIL/{s++} END{printf("FILES=%d SITES=%d FAILS=%d\n", NF_, s, f+0); exit (f>0)}'
