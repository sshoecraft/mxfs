---
name: reference-the-obligation-completion-engine-has-its-own-durability-point-before-it-publishes
description: REFERENCE (s133): the goto complete_ladder after mxfs_recov_obl_complete is NOT an ordering hazard — the engine flushes durable itself before the pro…
metadata:
  type: reference
tags: [recovery, durability, obligations, freplay]
---

# The obligation-completion engine is durable before it publishes

s132 left an open question: `xfs/xfs_mxfs_dlm.c:60608` does `goto complete_ladder`
after `mxfs_recov_obl_complete(mp, slot)` returns 0, re-entering
`mxfs_v5_dlm_recovery_complete2` **without** passing the
`mxfs_blkdev_flush_durable` at `xfs/xfs_mxfs_dlm.c:60512`. The worry was the
shape sess59 fixed one milestone earlier — publication destroying the evidence
that would make anyone redo work whose metadata is still in the target's
volatile write cache.

**It is not that shape.** The engine carries its own durability point:

`xfs/xfs_mxfs_recov_obl.c:310-317`, after every extent is completed and before
the proof is written:

    xfs_log_force(mp, XFS_LOG_SYNC);
    rc = mxfs_recov_obl_home_flush(mp);
    if (rc) { ...P-OBL-ENGINE-HOMEFLUSH-FAIL...; goto out_task; }   /* stays OPEN, retries */

and `mxfs_recov_obl_home_flush` (`xfs/xfs_mxfs_dlm.c:59723-59732`) is exactly:

    rc = mxfs_dlm_peer_joined_flush(mp);   /* peer VISIBILITY */
    if (rc) return rc;
    return mxfs_blkdev_flush_durable(mp);  /* platter SURVIVAL */

It is the real durable flush, not `mxfs_blkdev_flush_epoch` — which is the
distinction that made the sess59 bug (epoch flush issues no device flush at all
under the default `mxfs_fua_disable`).

Order actually enforced: extents freed in live transactions → `XFS_LOG_SYNC`
force → peer-joined flush → **durable device flush** → `..._obl_done_write`
(proof) → `..._advance_obl_done` (OBLIGATIONS_DONE) → return 0 → the ladder's
publication. Every failure between them leaves the case OPEN with the freeze
retained and re-arms.

## The general lesson

A second entry into a publication ladder does not need the ladder's own flush
when the engine that jumped there already flushed. Before calling a bypassed
flush an ordering defect, read the bypassing callee to its end — the durability
point may have moved into it deliberately, and here the comment naming it
("the same primitive the replay path uses before it publishes") says so.
