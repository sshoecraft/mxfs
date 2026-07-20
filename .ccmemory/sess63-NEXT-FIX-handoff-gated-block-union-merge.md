---
name: sess63-NEXT-FIX-handoff-gated-block-union-merge
description: sess63: THREE residual fixes refuted (all reverted to 5E78DEE0). STRONGEST LEAD: release-side durable-signal flush gated on handoff_acted_gen made 3/…
metadata:
  type: project
---

## sess63 — dir_reuse 4/tcp residual: 3 fixes tried, all REVERTED to 5E78DEE0 (validated 1/16, 2/17)

### Recurring wall: reliable dir coherence needs a SYNC log force (RULE-0 too slow) OR a force-free disk-read merge (corrupts). Root = node C's OWN un-checkpointed prior-tenure dir buffer is pin-tailed; the next EX owner can't evict it (clearing XBF_DONE on pinned corrupts, sess64) -> RMWs stale -> single-dirent loss. The lossy DIR_MODIFY evict-ring under-fires the existing coherence forces (P-DE-ENTER: gen==loaded always).

### ATTEMPT 1 — acquire-side xfs_log_force in drain_evict on handoff: REFUTED (RULE-0)
SYNC eliminated loss (rounds 1-18 clean) but desynced barriers (rank1 fell 2 rounds behind -> timeout -> EIO cascade). ASYNC too weak (push didn't finish in the 100ms per-block wait -> loss returned). Targeted SYNC (only pin-skipped blocks) still timed out (pins common under storm).

### ATTEMPT 2 — handoff-gated block-union-merge (mxfs_dir_merge_peer_into_tp): REFUTED (corruption)
FUA-reads peer dirents into the create tp (force-FREE, the ideal cost). But running it on handoff -> "Corruption of in-memory data (0x8) at mxfs_dlm_ilock_begin xfs_mxfs_dlm.c:10364" SHUTDOWN at round 1. The default-off merge has a latent bug at 4 nodes. **This is still the only force-FREE mechanism — debugging its corruption is a top next-session lead.**

### ATTEMPT 3 — release-side durable-signal flush gated on handoff_acted_gen: STRONGEST LEAD (reverted)
mxfs_dlm_dir_durable_signal (xfs_mxfs_dlm.c:13287, post-commit per modify) already does `xfs_log_force(SYNC)+mxfs_dir_flush_data_blocks` to checkpoint the node's dir blocks, but gated on the LOSSY `dir_gen>0`. I added `|| i_dlm_handoff_acted_gen!=0` (reliable "contended" signal).
RESULT: **test1/test2/test4 ran ALL 24 rounds CLEAN** (the single-dirent loss is GONE — direction CONFIRMED), but **test3 FROZE its view at 340/400 from round 18** (consistent ~60 missing peer .md5 entries rounds 18-24; NO shutdown, NO timeout, mount up, reached round 24). So it's a COHERENCY freeze, not a RULE-0 stall: test3 stopped picking up peer creates from round 18. Hypothesis: the extra flush (firing when dir_gen==0) advanced some gen/evicted state so test3's drain_evict/reload decided it was current and stopped refreshing. NOTE this freeze is NEW (baseline 5E78DEE0 never showed a 340-stuck view, only 399/400 single losses).

### NEXT SESSION (fresh context — the release-side flush is RIGHT, 3/4 clean)
1. Re-apply the attempt-3 gate AND find why test3 freezes: probe i_dlm_dir_loaded_gen / i_dlm_dir_evicted_gen / i_dlm_stale on test3's dir around round 18; check if the extra flush wrongly advances loaded_gen/evicted_gen so reload self-skips. The flush must NOT make the node think its IN-CORE is current (it only makes DISK current for peers). Likely a one-line guard: don't let mxfs_dir_flush_data_blocks (or its callees) touch i_dlm_dir_loaded_gen/evicted_gen.
2. OR debug attempt-2's merge corruption (force-free path).
KEEP handoff infra. Repo at 5E78DEE0. Re-verify 2/tcp 17/17 after any change. Marker NOT written. See [[sess63-residual-root-crossnode-gen-divergence-reused-dir]] [[sess63-handoff-signal-works-1of24-residual-writeside-block0]].</body>
