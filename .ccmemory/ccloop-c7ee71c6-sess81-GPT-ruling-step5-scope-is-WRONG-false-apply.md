---
name: ccloop-c7ee71c6-sess81-GPT-ruling-step5-scope-is-WRONG-false-apply
description: sess81 RULE-5 ruling: the ledger's step-5 scope (AG exact-match gate) would INTRODUCE a false-APPLY regression. v1 tokens are NOT authority evidence.…
metadata:
  type: reference
tags: [rule5, gpt-ruling, foreign-replay, authority-token, step5, sess81, false-apply]
---

# sess81 RULE-5 ruling — D-FOREIGN-REPLAY-UNGATED-IMAGES step 5

**Verdict: the ledger's step-5 scope is WRONG and must not be enabled.**
Enabling an exact `{class,resource,epoch}` AG match on the tokens as they are
produced today would introduce a **false-APPLY regression** — strictly worse
than the false-SKIP it was meant to close.

## The two producer-side facts that break the scope (found sess81, code-verified)

**(A) The AG grant is not the authority for most buffers.** The fill site
(`pal/linux/xfs_buf_item.c:341-404`) classifies purely by
`xfs_daddr_to_agno(blf_blkno)`. A dir data block, da-node, attr block, symlink
block or bmbt block lives *inside* an AG but its authority is the **inode's**
EX grant. They get labelled `class=AG{containing agno, whatever epoch pag holds}`.

**(B) `pag_mxfs_grant_epoch` is written at fresh AG acquire and NEVER cleared
on release.** Single assignment site in the whole tree (`xfs_mxfs_dlm.c:34644`);
no unlock path clears it. So a buffer formatted while we do NOT hold that AG
still gets a class=AG token with a stale epoch.

**The resulting false-APPLY:** V holds AG3 EX@E and never releases it; V also
modifies dir block D (in AG3) under the *dir inode* EX; token on D = AG{3,E};
V hands the dir inode to survivor S, S rewrites D; V dies still holding AG3@E.
The proposed gate asks "did V hold AG3 EX@E at death?" → yes → **applies D and
reverts S's committed write.** The gate proved the wrong resource. Today's
blanket taint has no such hole because it never applies anything.

## GPT's binding points

- **v1 tokens are not trustworthy authority evidence, ever.** Derived from
  physical location, can carry a stale epoch, captured with no positive
  "grant currently held" assertion, and `owner_boot` is memset 0 and never
  filled. Keep report-only; do not accept `version=1,class=AG` as exact-gate
  evidence even after fixing the producer.
- Classification must key on **true authority**, not containing AG.
  `bp->b_ops` beats BLFT as the discriminator (`XFS_BLFT_BTREE_BUF` conflates
  AG btrees with inode bmbt), but only inside a conjunction: allowlisted
  b_ops AND BLFT agreement AND *positively held* EX grant AND the epoch of
  *that* held grant. Anything unmappable ⇒ class NONE ⇒ taint.
- Clearing the stale scalar is **necessary but not sufficient** — needs a
  synchronized `held/releasing/epoch` state; capture must be blocked once
  release begins; in-core authority invalidated **before the disk unlock
  becomes visible** (clearing only after the unlock leaves a capture window);
  epoch published only after the granting CAS succeeds.
- An audited **AG-metadata-only** gate is a legitimate, independently-safe
  incremental step — but it does **not** close the dir-image case that made
  this defect critical. An **INODE authority class is required** for that.
- Wire: new token version with a real **be64 resource** (do not overload
  grant_epoch, do not truncate inode numbers, no 32-bit hash). ~32B shape:
  `be16 version; be16 class; be32 flags; be64 resource; be64 grant_epoch;
  be32 owner_slot; be32 owner_boot`. Bind to the victim incarnation; 32-bit
  boot id is weak, prefer a 64-bit/UUID recovery incarnation if available.
- **Transaction-envelope alternative (my Q4): viable but does NOT remove the
  hard problem.** A generic snapshot of held locks cannot prove completeness —
  recovery cannot tell an omitted required resource from an absent one. Also:
  a CIL checkpoint is not an `xfs_trans`, it can aggregate items from several
  transactions and several epochs; never merge by resource discarding epoch.
  Build per-item provenance first, then optionally aggregate into an envelope
  that is the exact union of item tuples, with a fail-closed completeness bit.
- **Epoch mismatch = atomic skip + loud telemetry, NOT quarantine.** Legit
  sequence: modify under E, release, re-grant at E2, die at E2. Quarantine is
  for trust-breaking conditions: malformed/truncated token, unknown mandatory
  version, owner_slot inconsistent with the fenced victim, manifest integrity
  failure, manifest not frozen / fence certificate invalid, impossible epoch
  ordering, contradictory duplicate records, evidence a frozen grant moved,
  incarnation mismatch.
- **Adopted slices:** age is irrelevant, *stability* is what matters. Require
  descriptor for the specific victim incarnation + valid completed fence
  certificate + stage ≥ FENCED + grants/heartbeat still frozen + no
  GRANTS_RELEASED before IMAGES_REPLAYED is durable + token owner_slot ==
  descriptor victim slot + serialized replay ownership. `slot % node_count`
  mapping is **never** authority. Descriptor absent (pre-descriptor dirty
  slice) ⇒ never exact-apply; keep transaction-atomic skip at minimum.
  `GRANTS_RELEASED` without a durable `IMAGES_REPLAYED` is a hard
  state-machine inconsistency, not a fallback to applying records.

## The landing order (each step independently safe)

- **5.0** preserve containment; mark token v1 explicitly report-only.
- **5.1** grant-state lifecycle: synchronized held/releasing/epoch, capture
  blocked once release begins, in-core authority invalidated before the disk
  unlock, epoch published only after the granting CAS. **No replay change.**
- **5.2** token v2: be64 resource, bound to victim slot + incarnation,
  provenance captured at mutation/join time. Proto-gen bump. Still report-only.
- **5.3** enable audited **AG-metadata-only** apply.
- **5.4** add inode authority (dir/attr/symlink/bmbt), fault-inject authority
  handoff between commit and victim death.
- **5.5** DQUOT/QUOTAOFF/ICREATE/SB — audit or deliberately leave tainted.
  ICREATE *may* be AG-authorized but must be established, not assumed.
- **5.6** optional transaction envelope built from complete per-item provenance.
