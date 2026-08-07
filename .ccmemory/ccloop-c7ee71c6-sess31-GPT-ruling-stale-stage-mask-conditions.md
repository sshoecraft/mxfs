---
name: ccloop-c7ee71c6-sess31-GPT-ruling-stale-stage-mask-conditions
description: GPT ruling on D-RELEASE-BARRIER containment: skip case1 AND case2; 3-state SKIPPED_STALE model; per-I/O stage-tuple capture; gate on stage-epoch vali…
metadata:
  type: project
---

# sess31 — GPT final ruling on the stale-stage submission mask (IMPLEMENT NEXT)

Full text in transcript (session 13 / sess31, task k5sbg3p1p). Conditions for
approval — ALL must hold in the implementation:

1. **Skip BOTH cases.** Case 1 (durable==flush, image landed: late rewrite is
   redundant/peer-reverting) AND case 2 (durable<flush, never landed): NEVER
   let a known stale-tenure image reach home. Case-2 "leave it in the write"
   is forbidden — that trades AIL pressure for known cross-node corruption.
   If safe reacquire/reconcile isn't available for case 2: fence/shutdown
   rather than write. (Expected near-zero; count loudly.)
2. **Three-state model, not rollback-only**: keep stage_seq/stage_epoch intact
   and add stage_state ∈ {VALID, IN_FLIGHT, LANDED, SKIPPED_STALE}. Rolling
   flush_seq:=durable_seq for case 2 destroys the needs-restage information.
   MXFS_IF_PUB_SKIPPED can BE the third state if every consumer honors it.
3. **Per-I/O capture**: iodone must promote durable from the tuple captured at
   SUBMIT (submitted_stage_seq), never from the inode's current mutable
   flush_seq (relog between submit and iodone falsely marks newer stage
   durable). Current code does `durable = flush` at iodone — AUDIT/FIX.
4. **Gate on stage-epoch validity, not mode==NL**: an old staged image does not
   become valid on reacquisition (stage_epoch=old, live=new, mode=EX must ALSO
   skip+restage). Rule: submit only if stage epoch is authorized for THIS
   submission or a protocol token proves the old epoch remains exclusively
   writable. Class Z (mid-EX stale-parent submits) falls under this too.
5. **Token/demoter exceptions must not survive actual release**: a local
   relflush boolean cannot authorize an old-tenure write after wire unlock.
   Bind exceptions to {epoch, staged seq, submission} + cluster-visible
   publication block through iodone.
6. **Attached-item/AIL bookkeeping**: skipping a slot while the buffer
   completes for other slots must not discharge the skipped slot's obligation
   (mirror P56-NL-LOGGED-DIR-SKIP's flush_seq rollback + PUB_SKIPPED re-arm,
   upgraded to the 3-state model). Case 1 with pending>durable ALSO needs a
   restage arm (the newer pending needs a future flush; don't let iodone imply
   it landed).
7. **Foreign log recovery must honor authority** — else slice replay of the
   dead node's records reintroduces the exact revert the runtime mask
   prevented. Replay needs: global fence, or per-inode authority acquisition,
   or persistent publication-epoch validation, or replay-into-adopt. AUDIT
   tests/… foreign-replay (sess17 design) for this gate.
8. **Prove masking is physically real** at bio construction (the existing
   partial-write machinery does build sub-runs — verify the skipped slot's
   bytes are genuinely omitted, CRCs stay per-inode-valid, and no whole-buffer
   fallback (the `declined` path GPT flagged in sess29) can reinstate them).
9. **Revalidate under proper synchronization immediately before submission**
   (mode/epoch/token can change between masking pass and bio build).

Implementation order: (1) submission-time mask [immediate containment] →
(2) skipped-state + AIL progress handling → (3) recovery authority gate →
(4) strengthened release quiescence (inodegc must not relog into a closing
tenure between last flush pass and unlock without reopening the drain) →
keep the mask forever as a defensive invariant.
Producer/verify: dirent_durability@32/caw (~13 events/lap), acceptance =
stale_nl writes → 0, board green, plus cluster_authority_merge.sh divergence=0.
