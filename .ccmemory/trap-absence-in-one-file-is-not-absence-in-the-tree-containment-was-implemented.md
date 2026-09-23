---
name: trap-absence-in-one-file-is-not-absence-in-the-tree-containment-was-implemented
description: TRAP (sess571): I declared a ruling's containment "never implemented" from its absence in xfs_create; it was in xfs_dialloc, the only place it could…
metadata:
  type: feedback
tags: [rule4, d0946, d0351, methodology]
---

# "Not implemented" needs a tree-wide search, not a file-wide one

## What I did

D-0351's sess427 ruling specified containment: *"validate the platter dinode
BEFORE dialloc dirties the transaction."* I read `xfs_create` in
`xfs/xfs_inode.c`, found no platter read between `mxfs_quar_gate_locked` and
`xfs_dialloc`, confirmed the only `mxfs_dbg_disk_di_mode` call in that function
was the post-error P-CR62 probe — and wrote **"the containment half was never
implemented"** into two ledger records with a file:line citation that looked
authoritative.

It was wrong. `mxfs_dialloc_validate_candidate()` at
`xfs/libxfs/xfs_ialloc.c:1657` does exactly what the ruling asked: reads the
platter with the transaction still clean, returns `-EUCLEAN` on a live image,
adds the agino to `pag_disklive_q`, caller re-picks. Its own probe text even
says *"no transaction dirtied"*.

## Why the reasoning was bad, not just unlucky

The ruling says "before dialloc dirties the transaction". I searched *before the
call to* `xfs_dialloc`. But **the candidate inode number does not exist until
dialloc picks it** — so a validator of that number cannot possibly live earlier
than dialloc. The only place it can live is *inside* dialloc, between selection
and logging. The phrase that sent me to `xfs_create` was the phrase that ruled
`xfs_create` out.

A one-line `grep -rn 'disk_di_mode' xfs/` would have found it. I grepped one
file because I had just been reading that file.

## The rule

**A negative claim about the whole tree requires a search of the whole tree.**
"X is not implemented" / "nothing calls Y" / "there is no check for Z" is a
claim about every file, and it is exactly the kind of confident, checkable,
wrong statement that gets written into a ledger and believed for months.

Corollary: when a spec says "before <operation>", ask *where the operand comes
into existence*. If it is produced by that operation, "before" means "inside".

## The finding that replaced it is better

`P-DIALLOC-DISKLIVE` fired **zero** times in all three D-0946 occurrences, so
the validator ran and **allowed** the inode. That relocates the root from "no
gate" to "the gate's allow path is wrong", and there are exactly two zero-returns
to tell apart:

- **(a)** the `mxfs_pubob_lookup` early return (`xfs_ialloc.c:1676`) — allows
  without reading the platter when this node holds an open non-UNLINK obligation
  on the number ("the live image at home is this node's").
- **(b)** `mxfs_dbg_disk_di_mode_coherent()` returned 0 = free — while the raw
  `mxfs_dbg_disk_di_mode()` read the same inode as LIVE a millisecond later.

**These are different readers** (`xfs_mxfs_dlm.c:42254` vs `:42096`). If (b)
holds this is a coherency defect in the reader the containment depends on, not
an allocator defect at all. `P946-VALIDATE-ALLOW via=pubob|coherent-free`
(0.75.116, in tree) names the branch. Do not patch either until it reports.
