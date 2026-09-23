---
name: trap-a-mount-in-proc-mounts-is-not-a-working-mount-and-two-shell-counter-bugs
description: TRAP (sess573): my harness checked /proc/mounts, ran its workload against a shut-down fs, and reported VACUOUS instead of PRECOND_FAIL; plus grep -c…
metadata:
  type: feedback
tags: [harness, precondition, vacuous, shell, grep, df, icount]
---

# Harness bugs, one of which faked a clean negative result

sess573, writing `tests/d0949_sole_survivor_chunkfree.sh`.

## 1. A mount in `/proc/mounts` is not a usable mount

My precondition was `grep -c ' /mnt/shared mxfs ' /proc/mounts` = 1. It passed.
Then the first workload step — `mkdir -p $MNT/...` — failed and 0 of 12000
files were created. **A filesystem that has been shut down still appears in
`/proc/mounts` and returns EIO on everything.** (Here it had been self-fenced by
`P305-RESV-SELF-GONE` long before the harness started.)

The run then computed its counters, found zeros, and printed `verdict=VACUOUS`.
That is the dangerous part: a broken *precondition* reported as a completed
*measurement* with a null result — one careless read away from "the defect did
not reproduce".

**Fix:** probe *usability*, not presence, and `exit 2` on failure:

    mkdir -p $MNT/.probe.$$ && rmdir $MNT/.probe.$$ && echo WRITABLE

Corollary: a `touch /mnt/shared/x` used as a manual check **succeeded while
nothing was mounted there** — it wrote to the *root* filesystem at the
mountpoint directory. Checking a mountpoint proves nothing until you have
confirmed something is mounted on it.

## 2. `grep -c` exits 1 on zero matches

    cnt() { grep -ac -- "$1" "$f" 2>/dev/null || echo 0; }   # WRONG

`grep -c` **prints `0` and exits 1** when there are no matches, so `|| echo 0`
fires *in addition* and the function returns `"0\n0"`. Every counter became
garbage and the summary broke across nine lines. Use:

    c=$(grep -ac -- "$1" "$f" 2>/dev/null | head -1); echo "${c:-0}"

## 3. `df -i --output=itotal` is rejected, AND itotal is the wrong number

    df: options -i and --output are mutually exclusive

Drop the `-i`. **But then it still doesn't measure what I wanted** — CORRECTION
to this note's own first version, which recommended it as an unbudgeted way to
count inode chunks. Measured: `df --output=itotal` on a 48G MXFS volume read
**25991808 both before and after 12000 file creates**. XFS's statfs reports
`f_files` as the *dynamic maximum* (`maxicount`), not `sb_icount`, so it does
not move when inode chunks are carved. It is useless for counting chunks.

**What actually reports allocated inodes:** `tools/chk_mxfs -v <dev>`, which
prints `Superblock icount:` and `Total inodes (inobt sum):` (it read `64` on a
freshly prepped volume, and it works on a mounted device — 2 s wall on a 24-AG
48G LUN). That is the counter to use.

## The surviving general lesson

Prefer a counter the kernel maintains over a probe you print — probes have print
budgets (`P133-ICLUSTER-SYNCINIT` prints only its first 20 per module load, so
counting carves from it measures the budget). But **verify the counter means
what you think** before building a verdict on it: I replaced a budgeted probe
with a maximum masquerading as a total.
