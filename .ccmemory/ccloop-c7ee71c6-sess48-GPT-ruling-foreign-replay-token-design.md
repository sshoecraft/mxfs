---
name: ccloop-c7ee71c6-sess48-GPT-ruling-foreign-replay-token-design
description: sess48 GPT ruling (implementation spec): foreign-replay fix = per-buffer v2 blf token {class,agno,grant_epoch,slot,boot}; disklock-as-manifest; DONE…
metadata:
  type: project
---

# GPT ruling — D-FOREIGN-REPLAY full-fix implementation shape (sess48)

## 1. Transport: PER-BUFFER tokens (option a) — v2 buffer log format
New blf_flags bit + token bytes after the variable-length bitmap; helper accessors for boundaries. Token:
`{__be16 version; __be16 resource_class /*AG, GLOBAL_SB, ...*/; __be32 resource_id /*agno*/; __be64 grant_epoch; __be32 owner_slot; __be32 owner_boot_epoch}`
Set a log-incompat feature; old kernels reject; foreign replay ABORTS (no DONE) on untagged/malformed replay-relevant images. Transaction-level authority records (b) REJECTED: CIL aggregation coalesces items across transactions/relogs — recovery's transaction hash does not preserve per-buffer authority attribution; multi-AG transactions prove only "some grant existed". Checkpoint summaries (c) same flaw.

## 2. Content + manifest
{agno, grant_epoch} sufficient IFF grant_epoch is a durable, NON-REUSED, per-acquisition epoch: changes on EVERY release/reacquire (same node too), survives crashes, **persisted BEFORE the grantee may modify/log AG metadata**, bound to node instance. One clearly-named 64-bit `grant_epoch`; separate tenure_id redundant. Owner slot/boot-epoch = cheap defense.
Disklock table CAN be the manifest iff victim entries: carry epoch, checksummed/torn-detectable, CAW-atomic transitions, IMMUTABLE after fencing until DONE, survive first-survivor crash, never reused by slot adoption, distinguish slice generation. Still write a small durable **recovery descriptor**: {victim slot, victim boot incarnation, slice generation, death epoch, replay boundary (head/tail), digest of frozen held-set entries, recovery state}. Release ordering must be synchronous (AG not "released" until on-disk record says so) or fencing snapshot ≠ held-at-death.

## 3. Apply rule
Exact match (class, id, grant_epoch [, owner]) vs manifest → apply in normal forward SAME-SLICE order; no cross-slice LSN comparison; ordinary XFS transaction/cancellation/verifier rules stay. Preconditions: exclusive tenure, fence-drained victim, no new owner until DONE, forward order. Same-tenure multiple rewrites = forward replay handles. **SB/global buffers: own resource_class + own grant epoch — NEVER inherit authority from co-transaction AG items; fsync-relevant authority failure = abort recovery, no DONE.**
**Critical release invariant**: exact-held-at-death does NOT recover acked writes of a grant released before death ⇒ release must guarantee acked state durably destaged (MXFS Invariant #1 drain) INCLUDING CIL stability — see §5.

## 4. Ordering (survivor)
fence(PR) → freeze grants + victim records/slice (bind to incarnation+slice gen) → durable manifest/descriptor BEFORE any purge → record replay boundary → pass1/2 with token gate → make replay output durable (flush/FUA) → write DONE durably (OUTSIDE purged slice; keyed to victim incarnation+slice gen+endpoint+manifest digest; checksummed) → purge slice + clear slots + resume grants. 7 before 8, never reversed. Mount-time: matching DONE → suppress replay, finish cleanup; no DONE → recover from preserved state then DONE; mismatched DONE → fail closed; neither → fail mount. Replay pre-DONE restartable/idempotent.

## 5. Simplifications blessed / forbidden
Blessed: grant_epoch==tenure (one counter); disklock-as-manifest + small descriptor; no held-set copy; no authority-item joins. FORBIDDEN simplification: the grant-release/CIL boundary — before releasing an AG grant, force+wait all CIL/log items authorized by that grant to be formatted and stable (or split/snapshot mixed-epoch items, or reject mixed-epoch aggregation). Without this, G1-dirtied buffer relogged under G2 misattributes and NO tagging scheme is sound.

## Implementation order suggestion for relay
1. Durable grant_epoch in disklock records (persist at grant, before first AG modification) + epoch plumbing to the DLM layer.
2. CIL-drain-at-release barrier (audit invariant-1 drain: does it guarantee CIL formatting stability for AG items, not just buffer destage? bast_work_fn Phase 2 currently drains delwri+flush — CIL push+wait may need adding).
3. v2 blf token write path (+log-incompat flag), replay-side parse.
4. Recovery descriptor + DONE marker + ordering rework of the existing foreign-replay flow (P163-RECOVERY-COMPLETE path in dlm).
5. Token gate replacing the P223 untagged-skip; A/B via tests/foreign_replay_ab.sh + fault injection at the 5 sess32 points.
