---
name: trap-a-caller-tag-or-return-address-cannot-discriminate-callers-that-all-funnel-through-one-function
description: TRAP (D-0924, 0.85.7): a funnel exempted why=="iodone", but that tag is stamped by xfs_buf_item_done, which 9 overlay arms call with no I/O — the tag…
metadata:
  type: feedback
tags: [instrumentation, xfs_buf, agmeta, probe-design]
---

# A caller tag names the funnel, not the caller's intent

`xfs_buf_item_relse` decided whether to return the MXFS AG-metadata tracking
token with `strcmp(why, "iodone")` — the reading being that `"iodone"` meant
"the write completion is about to run `bp->b_iodone`, which will consume it".

It did not mean that. `"iodone"` was stamped by **`xfs_buf_item_done`**, and the
MXFS overlay calls `xfs_buf_item_done` directly from **nine** release-drain and
acquire-evict arms that retire a log item with **no I/O at all**. On those the
tag read `"iodone"`, nothing ran `b_iodone`, and nothing reclaimed.

The diagnostic probe next to it had the identical flaw: it printed
`__builtin_return_address(0)`, which inside `xfs_buf_item_relse` is **always**
`xfs_buf_item_done`, whoever called *that*. 145 firings were all recorded as
`caller=xfs_buf_item_done` and dismissed as benign completions. The discriminator
had been thrown away before the data was read.

## The general shape

When N callers reach a decision point through one intermediate function, neither
the return address nor a tag that intermediate stamps can tell them apart. Nor
can state on the object: a sticky provenance field (`b_mxfs_done_site`) can be
stale or absent, and a flag like `XBF_WRITE` is wrong in the other direction
(`xfs_buf_ioend_fail_unsubmitted` submits no write yet still runs the
completion).

**The caller must declare the property, as a parameter.** MXFS now uses
`enum xfs_bli_release_ctx { XFS_BLI_NO_IODONE, XFS_BLI_IODONE_FOLLOWS }`; only
`__xfs_buf_ioend`, which dispatches `b_iodone` on the very next line, passes
`IODONE_FOLLOWS`.

**Change the prototype, don't add an optional argument.** That makes the compiler
enumerate the call sites instead of trusting a grep — and it keeps doing so for
arms added later. Here it confirmed the grep had found all ten.

## And separate hardening from cause

Closing that hole did NOT prove it was the leak's route: all nine overlay arms
are gated on directory-buffer predicates (`xfs_dir3_*_buf_ops`,
`mxfs_dir_buf_is_owned_dir3`, `mxfs_dir_buf_is_undestaged`, `b_mxfs_dir_epoch`)
and `mxfs_buf_is_ag_metadata` matches a **disjoint** `b_ops` set — so an AG-meta
buffer cannot reach them as the tree stands, and the verification lap measured
the new reclaim firing **zero** times. Say "unsound contract, now sound" and keep
the defect open; do not let a plausible mechanism that measured zero become a
closure.
