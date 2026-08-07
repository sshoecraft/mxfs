---
name: ccloop-c7ee71c6-sess164-step4-AUDIT-descriptor-exists-shadow-eval-design
description: sess164 pt2: step-4 machinery ALREADY BUILT (stages/freeze/ordering in recovery_complete). Real gap = step-5 shadow evaluator; design + threading not…
metadata:
  type: project
tags: [mxfs, sess164, foreign-replay, step4, step5-shadow, recovery-descriptor, victim-manifest]
---

# sess164 part 2 — step-4 audit: the descriptor machinery exists; build the step-5 shadow evaluator next

## Audit result: step 4 is substantially LANDED (fence/descriptor arc sess62-93)

`mxfs_v5_dlm_recovery_complete` (dlm/v5_mount.c ~2897-3180) already implements
the sess48 ruling's ordering, with gates at every irreversible step:

1. Fence certificate written at FENCING→FENCED (immutable in `struct
   mxfs_recov_desc`, dlm/disklock.h ~389: victim identity, recovery_gen,
   owner_term vs fence_term — the recovery-lease-vs-member-claim distinction
   ALREADY EXISTS, as does the split predicate MXFS_RECOV_SLOT_* classify).
2. Durable slice replay → recovery_acquire + replay_authorized gate +
   v5_exclusion_recheck → advance **MXFS_RECOV_STAGE_IMAGES_REPLAYED** (=3,
   the IMAGE_REPLAY_DONE equivalent — CRC'd, in the victim HB sector, durable
   CAS) — all BEFORE the first irreversible act.
3. Only then `mxfs_dlm_caw_purge_node` (victim CAW authority bits cleared) →
   `mxfs_pal_bdev_flush` → advance GRANTS_RELEASED ("asserts a fact about the
   platter") → `mxfs_disklock_purge_node` broadcast (sector zero) — and the
   disklock purge freeze-gate refuses to zero below GRANTS_RELEASED
   (disklock.c ~1919/2017: "frozen by a live recovery descriptor").
4. Mount cohort: `mxfs_v5_dlm_mount_cohort_complete` purges only after EVERY
   cohort slice durably replayed — CAW table preserved as the cross-slice
   authority manifest during replay (comment at v5_mount.c ~3185 says exactly
   this).

**Victim-manifest freeze = the CAW slot table itself, frozen by this
ordering.** The ledger #7 (D-FOREIGN-SLICE-INTENTS-ABANDONED) item-1 text
"Land the versioned GUARD/recovery descriptor + victim-manifest freeze" is
STALE — that landed. Its next-field needs a refresh like sess150 did for #1.

**Tenure-release invariant (sess163 hazard)**: older-epoch AG images are
destaged-by-construction — bast_work_fn Phase 2 (drain_meta_buffers +
drain_alloc_buflist + drain_inode_buffers + blkdev_flush BEFORE ag_unlock,
architectural invariant #1) means any image logged under a RELEASED grant is
already on the platter; only the FINAL (held-at-death) epoch has
replay-required images. Inode-class needs its own audit later.

## The real remaining work = STEP 5, shadow first (ratified early by sess163 (D))

Shadow evaluator at the two existing sites in xfs/xfs_log_recover.c:
`mxfs_blf_parse_authority` (2043) + P227-TOKEN decode (2199-2267) + ATOMIC-SKIP
(2328) already exist (step 3b LANDED). Add, decisions UNCHANGED:
per-token exact-match {agno→resource, grant_epoch} vs the fenced victim's slot
entry → counters {would_apply, would_skip_stale_epoch, would_skip_not_held,
would_skip_classless/malformed} + capability check "valid frozen descriptor
at stage>=FENCED exists for the victim" before any would-enforce verdict.

### Threading gaps found (the next session's first edits)

1. **struct xlog has NO victim-slot field** — only opstate bits
   XLOG_MXFS_FOREIGN_REPLAY(5)/XLOG_MXFS_ADOPTED_SLICE(6) (xfs_log_priv.h
   ~476-519). Add `l_mxfs_victim_slot` (+valid sentinel), set in
   mxfs_xlog_recover_foreign_slice(mp, dead_slot) (xfs_log.c 742 — has the
   slot; shadow xlog created there) and in the adopted-slice mount path
   (victim slot = our own claimed slot; find where ADOPTED_SLICE is set in
   xfs_log_mount).
2. **Consumer-side slot read primitive needed**: given resource(agno) +
   victim slot → {victim_holds_ex, ex_grant_epoch}. sess48's
   mxfs_dlm_caw_read_ex_grant_epoch was DELETED sess110 for PRODUCER misuse
   (out-of-band read unbindable to a held grant — comment at dlm_caw.c ~3228
   says do-not-reintroduce). The replay-gate read has DIFFERENT semantics:
   reads the FENCED victim's frozen manifest (stable because purge is
   post-IMAGES_REPLAYED). New function must be named/documented
   consumer-only (e.g. mxfs_dlm_caw_victim_manifest_read) with an explicit
   contra-sess110 comment, and ideally WARN if the victim slot isn't frozen
   (no live recovery descriptor).
3. Wire from xfs_log_recover.c to the dlm ctx: via mp → mxfs v5 ctx →
   dlm_caw ctx (same route the AG acquire uses; check
   mxfs_v5_dlm_ag_grant_epoch plumbing in v5_mount.c from step 2a for the
   accessor pattern).
4. SB-class tokens: victim slot table has no SB resource epoch? Check how SB
   class was filled (step 3a: xfs_sb_buf_ops → class SB) and what manifest
   entry it matches — may need would_skip_sb_unmatched counter arm only.

## Also this session (part 1, separate memory): 0.11.459 rig-verified clean —
begin=clean=revoke=31520 exact per-node, backstop/phantom/publive all 0,
27/27 board PASS in budget. Ledger #1 next-field refreshed with the evidence.

Cluster left UP: 32/caw mounted+converged on 0.11.459, marker current.
Compaction backlog 194 — still owed (sess163 folded 9; nothing folded this
session; next fold target: lreq/waiter-cancel sess111-125 ~20 notes).
