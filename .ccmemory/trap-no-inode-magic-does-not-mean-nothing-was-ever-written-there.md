---
name: trap-no-inode-magic-does-not-mean-nothing-was-ever-written-there
description: TRAP (sess572): I reasoned that a home with no dinode magic proves nothing was ever written there and allocated on it; the block held a live XDD3 dir…
metadata:
  type: feedback
tags: [d0947, allocator, inference, rule4]
---

# Absence of ONE magic is not absence of ALL content

## What I concluded, and why it sounded airtight

The inode allocator's candidate validator was failing every create with -EIO
because its platter reader returned the same `0xFFFF` for "the read failed" and
"the read succeeded and there is no inode magic there". I separated the two and
allowed the second, with this argument:

> A dinode keeps its `0x494e` magic once written, including after it is freed
> (the free zeroes `di_mode`, not the magic). So the absence of magic proves no
> inode was ever durably written at that home. And a peer cannot have one in
> flight, because we hold the AG EX and a peer must publish every owed image
> before releasing it. Therefore it is safe to allocate.

Every clause of that is true. The conclusion still does not follow.

## What the rig said

Thirteen rounds passed — 11,700 creates, where the previous build had died at
round 10, so the "un-destaged cluster of ours" case is real and common. Round 14
allocated ino 4321728, whose home read cleanly with no inode magic and contained:

    58 44 44 33 68 ef 9f e4 00 00 00 00 00 41 f1 c0

`XDD3` — a dir3 **data block**, carrying `blkno 0x41f1c0` in its own header, the
same address it was read from. Eight `xfs_inode_buf_verify` failures, then
`P378-TRANS-READ-FAIL ... dirty=1 -> forcing shutdown`.

## The actual error

I proved "no *dinode* was ever written here" and used it as "nothing was ever
written here". Two different causes produce identical bytes:

- our own inode cluster, initialised in memory and not yet destaged;
- a home that belongs to something else.

No read distinguishes them. I had picked the reading that suited the fix.

## The shape of the fix that works

Where inference cannot separate two causes, **act and re-observe**. One
`xfs_log_force(SYNC)` + `xfs_ail_push_all`, then read the home again: ours now
has its magic; not-ours still does not. The second is refused transiently
(cooldown, re-pick, nothing dirtied) rather than allocated or hard-failed —
so neither of the two blanket answers, both of which were terminal.

## The general lesson

When a fix rests on a chain of individually-true statements, the failure will be
in the *step between* them, not in any statement. Ask specifically: what else
could produce exactly this observation? If the answer is "something I have not
enumerated", the fix needs an experiment, not a better argument.
