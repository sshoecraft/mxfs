---
name: sess10run-FIX2-grant_gen-change-fastpath-refresh
description: sess10(ccloop) FIX2 REFUTED+REVERTED: fast-path grant_gen-change trigger is INERT (P-FXGGEN=0; cached_gg tracks hgg every serve). Fast-path approach…
metadata:
  type: project
---

## sess10 (ccloop 4cb2d0a2) FIX2 — REFUTED & REVERTED (tree back at baseline DE3A7E21)

### What I tried
Added a fast-path EX dir trigger: refresh (safe reload post_release=false + drain_evict) when `hgg != i_dlm_cached_grant_gen` (acked-TCP grant_gen changed). Build 82ED14E1.

### RESULT: REFUTED — the trigger is INERT
- dir_reuse 4/tcp: FAIL 0/4 (2/2 real runs; runs 3-4 hit mkfs-prep wedge).
- **P-FXGGEN-REFRESH fired 0 times** in production runs. The trigger `hgg != cached_gg` is NEVER true on the fast path because `i_dlm_cached_grant_gen` is updated to `hgg` on EVERY fast-path serve (xfs_mxfs_dlm.c:10611) and to `fresh_gg` on every slow-path reacquire (~11214). So it always equals the current grant gen at serve time.
- The earlier P-FXAUDIT "grant_gen changed 147x, ho=0 in 126" (build 5332071C, dirwr=2) was MISLEADING: it compared `mxfs_v5_dlm_inode_grant_handoff`'s hgg against cached_gg at a probe point, but in steady production flow they converge. The fast-path simply has NO live staleness signal: handoff bool consumed via acted_gen, epoch constant within tenure (epoch_adv=0), grant_gen tracked into cached_gg.

### CONCLUSION: the FAST-PATH approach is a DEAD END for this bug.
All three candidate fast-path signals are unusable. Combined with: writer durability works (P-DSIG flush=1), slow-path acquire already cold-reads+evicts, and the loss is a DURABLE clobber (all nodes lose same entry) → the staleness must be injected where the node DOES re-read: the **slow-path cold-read returns pre-peer-durable content** (GPT-5.5 Rank 1/2: DLM grant handed to the next owner before the prior owner's modified block is actually visible on the shared target, OR a release-side drain coverage hole). This is now the LEADING hypothesis.

### NEXT SESSION — pivot to RELEASE SIDE (do NOT re-try fast-path/gen/epoch gating; all refuted)
1. Instrument the RELEASE→GRANT ordering: timestamp (realns) A's dir-data bwrite-complete + blkdev_flush-complete vs B's grant-received + first-cold-read of the same daddr. If B's read precedes A's flush-complete → release-ordering race (GPT Rank 1): fix = DLM master must not grant next EX until releaser's drain+flush completes (two-phase unlock: send UNLOCK_DONE only after the fence).
2. Audit `mxfs_dir_flush_data_blocks` (xfs_mxfs_dlm.c:1239) release drain for a coverage hole: the "uncached ⇒ assume already-on-disk, skip" (line ~1290) and the extent-map-iteration assumption. Maintain a per-EX-grant TOUCHED-SET of modified daddrs and force-write exactly those at release (GPT Rank 2).
3. Verify whether the releasing node's modified dir block is provably destaged (not in-AIL-undestaged) at the moment the next owner cold-reads.

### Status: criterion NOT met. Tree DE3A7E21 (baseline, all sess10 experiments reverted), cluster reset (test1-4). test1-8 VMs available.
See [[sess10run-DECISIVE-fastpath-dominant-P63-handoff-never-fires]] [[sess10run-GPT-consult-durable-clobber-stale-inAIL-block-survives-release]] [[sess10run-NEXT-real-fix-direction-concurrent-rmw-stale-base]].</body>
