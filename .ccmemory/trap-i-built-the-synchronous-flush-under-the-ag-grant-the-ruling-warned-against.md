---
name: trap-i-built-the-synchronous-flush-under-the-ag-grant-the-ruling-warned-against
description: TRAP (sess572): a RULE-5 ruling named "do not hold the cluster AG grant across a synchronous flush" as head-of-line blocking; I implemented its progr…
metadata:
  type: feedback
tags: [d0946, d0947, rule5-ruling, head-of-line, allocator]
---

# Implementing a ruling's fix while violating the ruling's caveat

## The ruling said

The D-0946 RULE-5 ruling gave a progress rule for the transient refusal, and
listed its hazards explicitly:

> 3. release the locks the publication path needs before waiting;
> Do not wait for publication while holding AGI/inobt/buffer locks the publisher
> needs, **and do not hold the cluster AG grant across a synchronous flush — that
> is cluster-wide head-of-line blocking.** Worst-affected workload is exactly
> rapid unlink/create churn in a small inode population, which is this rig's.

## What I built

`mxfs_pubob_drive_publication()`: `xfs_log_force(mp, XFS_LOG_SYNC)` +
`xfs_ail_push_all()` + up to 200 ms of `msleep(2)` polling — called from
`mxfs_dialloc_two_phase` **with the AG EX held**. Then `mxfs_pubob_flush_owed()`
for D-0947 did the same synchronous force on every no-magic candidate, with no
cap at all.

I even wrote a comment justifying it: the AG EX is what *sanctions* the
publication write, so holding it is required. That is true and it is not the
point — the ruling's objection was never that the grant is unnecessary, it was
that other nodes and other local tasks queue behind it for the duration.

I satisfied the half of the instruction that was about correctness (drop the AGI
and the cursors, keep the transaction clean) and read straight past the half
that was about cost.

## What the board then showed

`node_responsive` FAIL — `dstate=1[kworker:mxfs-ino-bast:mxfs_dlm_ilock_begin]`,
the inode-BAST worker blocked acquiring an inode lock — and `soak` FAIL on
`P36-STACK ... (first timeout, dumping wait site)`, i.e. inode acquires timing
out at least once. Both rows had passed on the previous build. Attribution to my
change was not yet proven when this was written, but the construction is one the
ruling had already ruled out, so it goes regardless.

## The shape that satisfies both halves

Kick the publication **asynchronously** (`xfs_log_force(mp, 0)`, `xfs_ail_push_all`),
refuse the candidate transiently, and let the existing 500-1000 ms reservation
cooldown be the retry delay. Progress is still guaranteed — the write has been
started — and nothing waits under the grant. That is what "queue or drive
publication; release the locks the publication path needs before waiting; retry"
actually asks for.

## The habit to change

When a ruling gives a numbered procedure AND a list of hazards, the hazards are
part of the procedure. Re-read them against the diff, line by line, before
building — not after a board row fails.
