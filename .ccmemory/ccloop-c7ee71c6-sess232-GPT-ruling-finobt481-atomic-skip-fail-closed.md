---
name: ccloop-c7ee71c6-sess232-GPT-ruling-finobt481-atomic-skip-fail-closed
description: sess232 RULE-5 ruling #21: mechanism endorsed; P0 = atomic-skip of committed foreign txn MUST block recovery_complete/RW (fail closed); (c) rejected;…
metadata:
  type: project
---

# sess232 GPT ruling — D-FINOBT-IBT-FREE-MISMATCH-481 fix shape

## Mechanism verdict
Endorsed as leading explanation, treat as established enough for immediate
fail-closed change. Refinement: atomic-skip is safe only when every durable
effect of the committed txn is proven absent, fully present, or causally
subsumed. All-or-none writeback safe; mixture unsafe. XFS atomicity is
log-commit atomicity; redo restores it; atomic-skip removed the redo path.
Alternatives to exclude in incident record: later stale inobt overwrite
(P150 family), post-withdrawal victim I/O, storage lost-write, pre-existing,
log-format defect, memory corruption — all judged worse fits.

## Implementation order (verbatim)
1. IMMEDIATELY: any committed foreign txn that atomic-skips prevents
   recovery_complete and RW publication. No RW cluster join/mount; mark
   needs-repair; preserve victim log + skip evidence; emit txn id, victim
   incarnation, slice, item types, target blocks, token verdicts.
2. IMMEDIATELY: diagnostic platter classification (exact-post / pre /
   descendant / unknown) — diagnosis only, must NOT gate recovery permissive.
3. NEXT: transaction-wide tokenization/manifest for ALL replayable item
   types (inode, icreate, EFI/EFD, quota): txn identity, node incarnation,
   authority epoch, item count+digests, target identities, lineage, digest.
   Authorize the TRANSACTION as a unit; subset application forbidden.
4. SAME enforcement gate: replace cross-node buffer LSN compare with
   persistent predecessor/post per-object lineage + stale-write enforcement
   (governs normal live writeback too, not just replay). Replay rule:
   disk==post → idempotent skip; disk==predecessor → apply; disk proven
   descendant → skip; else CONFLICT fail recovery. Owner-epoch = authority,
   NOT freshness — must not replace LSN cmp alone.
5. THEN: authoritative idempotent redo; remove atomic-skip from authorized
   foreign recovery.
6. Close #21 only after matrices pass.

## Option (c) repair-at-skip: REJECTED under current evidence
Untagged inode item ⇒ txn not authorized; applying remainder creates a
different partial txn; no valid cross-node ordering. Sound only once txn-wide
authority + full coverage + lineage + exclusion + CAS stale-write prevention
exist — at which point it is just ordinary authoritative redo.

## #21 closure evidence required (distinct from #1)
(1) Deterministic partial-checkpoint fault matrix over xfs_inode_uninit
    (every single-omission and single-only subset of AGI/inobt/finobt/inode
    cluster/unlinked buckets home) — no case may yield published RW recovery
    + fsck mismatch. (2) Recovery-crash idempotence (crash after each replay
    write, repeat, converge). (3) Later-writer tests (descendant never
    overwritten; stale cached write rejected at checkpoint; needed victim
    write never LSN-skipped). (4) Block-reuse/incarnation tests. (5) fsck
    invariants (inobt==finobt==AGI, nlink0 accounted, no orphans).
    (6) Incident-scale 32-node withdrawal storm w/ randomized writeback +
    AG5-style controls. (7) Publication-state assertions.
Interim fail-closed = valid containment for #21+#6 but closes #21 only if
product contract accepts fail-closed as resolution; preferred closure is
authoritative replay completion.
