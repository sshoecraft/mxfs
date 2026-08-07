---
name: ccloop-c7ee71c6-sess95-GPT-ruling-step5.3-inode-authority
description: sess95 RULE-5 ruling on step 5.3: BOTH my designs rejected — no iget in the formatter, no buffer stamp. Immutable RCU authority certificate + 5 new s…
metadata:
  type: reference
tags: [sess95, foreign-replay, step5.3, authority-token, RULE-5, D-FOREIGN-REPLAY-UNGATED-IMAGES]
---

# sess95 RULE-5 ruling — step 5.3 (inode authority capture)

I brought two designs. **Both were rejected as written.**

## Design B (stamp the buffer at the modify seam) — UNSOUND, do not ship

A buffer stamp is *historical* state. Unless it holds an authority PIN, at format time it
can claim "prepared under epoch E" while E was already released, a peer held and modified
the inode, and we reacquired at E+N. Stamping the local `i_mxfs_ex_grant_seq` alongside
does not fix it: the seq is only useful if format time can compare it against a
*currently active* authority object, and if format time had that object it would not need
the stamp. B is sound only with (1) a release-blocking pin, (2) a nonblockingly-checkable
active flag, or (3) a **mechanical audit** proving the grant cannot be released between
stamp and CIL format on EVERY path. Do not rely on (3): "the inode is normally still
joined and ILOCKed" is not an invariant across attr, symlink, bmbt, deferred ops,
relogging, cancellation and push-worker paths.

## Design A (`xfs_iget(XFS_IGET_INCORE)` in the formatter) — right semantics, wrong mechanism

`XFS_IGET_INCORE` means "do not instantiate from disk". It does NOT mean wait-free,
reclaim-free, allocation-free, or safe under all XFS transaction lock orders. Reachable:
INEW/reclaim/recycle states, retries on cache-state transitions, per-AG locks, reference
acquisition racing final reclaim, reclaim interactions. `xfs_irele` in the CIL formatter
is not something to introduce because the common path is an atomic decrement.

"The owner is joined and pinned" is NOT a proof: the buffer item and owning inode item
need not be in the same transaction; deferred work logs under different transaction
structure; a buffer can outlive the transaction that established the relationship; a
corrupt/stale owner field can point at an unrelated reclaiming inode.

## THE RULING — immutable per-grant authority certificate, looked up nonblockingly

Publish, on **successful durable EX acquisition only**, an immutable object:
`{ino, grant_epoch, local_grant_seq, backing_resource, backing_kind, active, refs}`.

- publish only AFTER the durable grant is established, with release ordering
- unpublish/mark inactive at the FIRST release-begin boundary, before the release can
  become externally visible
- **never reactivate** — a reacquire mints a NEW certificate
- format-time lookup is RCU/nonblocking, keyed by inode number; copy the immutable tuple
  only if still active, then RECHECK the registry still points at the same certificate
- a release that starts after that linearization point does NOT falsify the token: the
  node did hold authority at emission

Do not publish epoch/kind/routing/active as unrelated fields read with unrelated
READ_ONCEs — the formatter would build a tuple from two different grants. One RCU
pointer to an immutable payload, or a seqcount, or a final generation recheck.

## Owner derivation — central mechanism is right, header is NOT trustable unconditionally

Derive ONCE per logical buffer log item from offset 0 (map 0), cache it, use it for every
segment. Never derive independently per segment. Validate: b_ops family, exact magic +
format version, header fits, CRC-format expected, UUID, owner is a plausible ino, magic
agrees with BLFT and b_ops, and **for bmbt that it is a long-format inode-owned bmap
btree block, not an AG btree admitted through the generic BTREE BLFT**.

Subtle and important: reading the owner from buffer *memory* is not proof that the owner
field is inside the LOGGED regions. If only a dirent range is logged, the trailer may
name an owner the replay target no longer has after block reuse. Inode authority alone
cannot prove an old partial image still targets a block owned by that inode.

## Statuses — v2's set cannot express the populations; add distinct ones

    9  OWNER_UNKNOWN      owner could not be derived/validated
    10 AUTH_NOT_CACHED    owner known, no in-core authority object exists
    11 AUTH_NOT_HELD      authority object exists, EX not active
    12 EPOCH_UNAVAILABLE  EX active, no durable epoch published
    13 AUTH_RACED         authority changed/unpublished during capture

`UNSUPPORTED` must NOT become the generic parser-failure bucket — it means "recognized
format this wire version cannot represent". A malformed supposedly-supported header is
UNPROVEN (or OWNER_UNKNOWN), not INCOMPLETE; INCOMPLETE is a transient capture failure.
All new/unknown statuses fail closed in recovery; old recovery must never read them as
VALID.

`i_dlm_mode == EX && epoch == 0` must never be read as "we probably hold EX" — it is a
publication transition, a release transition, an ordering bug, a missing acquire site, or
a violated invariant.

## Q4 — inode authority ONLY for dir content. CONFIRMED

The inode EX grant authorizes the directory's logical content; the AG grant authorizes
allocation metadata, which is logged separately in AGF/AGFL/btree records that already
classify correctly. Putting the AG token on a dir-content image recreates the exact
semantic error under a new label. A future v3 dual-authority trailer would mean "this
image requires BOTH predicates", never "either is enough".

## RELEASE BLOCKERS named

1. **inode vs iclus epoch NAMESPACE** (the largest unaddressed wire issue). An epoch read
   from an inode-resource CAW slot is not comparable to one from an iclus-resource slot.
   `class=INODE, resource=ino, grant_epoch=<whichever backing was used>` is NOT
   self-describing. Need one of: a single per-inode durable epoch namespace regardless of
   backing lock; deterministic recoverable routing; or the backing KIND + exact resource
   id on the wire. **Do not ship a VALID inode token until this is resolved.**
2. Audit EVERY EX/NL transition for the publication lifecycle: no publish before durable
   acquire success; clear before release is visible; clear on acquire rollback, forced
   shutdown, eviction/reclaim, EX->PR demote, fencing, error unwind, routing change. Kill
   raw mode stores that bypass the helper.
3. Transaction atomicity — the captured live corruption was inode item applied + buffer
   images skipped. A correct per-buffer token does not cure transaction fragmentation.
   5.4 needs an explicit policy for MIXED-AUTHORITY transactions; "evaluate every item
   independently" is not safe for namespace transactions.
4. Segment consistency — all segments of one discontiguous buffer carry identical fields;
   recovery computes ONE decision for the logical buffer item; disagreement fails closed.
5. Any token cached on `struct xfs_buf` needs a generation tied to the exact logged image
   (clear on invalidate/stale/reassign/cancel/relog-under-different-owner). This is why
   authority state belongs on the buffer LOG ITEM, not as an unqualified `bp` field.
6. **No AG fallback**: if owner derivation or inode authority lookup fails, do NOT fall
   back to the containing AG because its epoch happens to be available.
7. Mixed-version rollout: tokenless/unknown-version/unknown-status/malformed/inconsistent
   records must skip, quarantine, refuse or fence — never fall back to `XFS_LSN_CMP`.
8. Recovery must re-validate the owner: resource plausible for the record type, segments
   agree, target block not repurposed, logged header agrees with the token, class agrees
   with buffer type. A producer bug or corrupt trailer must not authorize a wrong owner.
