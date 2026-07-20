---
name: sess10run-GPT-consult-durable-clobber-stale-inAIL-block-survives-release
description: sess10(ccloop) GPT-5.5 consult + refined root: 4/tcp dir_reuse loss is a DURABLE write clobber (all nodes lose same entry); writer durability+acquire…
metadata:
  type: project
---

## sess10 (ccloop 4cb2d0a2) — GPT-5.5 consult + refined root for 4/tcp dir_reuse durable loss

### New decisive evidence narrowing the root
1. **DURABLE write clobber, not read staleness:** ALL 4 nodes lose the SAME single entry (399/400 everywhere) → the entry is gone from the shared TARGET, not a per-initiator read cache. So some node RMW'd a dir data block from a stale base and wrote it durably.
2. **Writer durability WORKS:** P-DSIG flush=1 fires ~1400-2950/node (fmt=2 EXTENTS) — `mxfs_dlm_dir_durable_signal` (xfs_mxfs_dlm.c:14006) synchronously `xfs_log_force(SYNC)+mxfs_dir_flush_data_blocks` (bwrite+blkdev_flush) every create on a contended dir. So peer A's new entry a1 reaches the coherent SCST cache immediately, before A releases.
3. **Acquire side ALREADY evicts+cold-reads:** the slow-path DLM acquire unconditionally calls `mxfs_dir_drain_evict_data_blocks(ip)` (xfs_mxfs_dlm.c:11189-11196) for EVERY dir on a fresh grant — drains transiently-pinned blocks and clears XBF_DONE so the first read cold-fetches the peer's durable image. NOT gated on the (unsound) gen.
4. Clobber is stale_base=0 (gen says fresh). [[sess10run-DISCRIMINATOR-clobber-stale_base0-invisible-to-gen]]

### Refined root (the only consistent explanation)
The clobbering node B RMWs block X from a STALE cached copy that is **dirty/in-AIL (committed-but-not-checkpointed) and survived B's OWN prior release**. The slow-path drain_evict SKIPS it (dirty/in-AIL guard — clearing XBF_DONE on it risks resurrecting B's own committed-unwritten work). So B does NOT cold-read; it RMWs the stale in-AIL block (B's old image, predating peer a1) and writes it durably → clobbers a1. The trap: that block is B's COMMITTED (released) work, so per Invariant 1 the DISK already has B's work AND a1 (A added it after) = disk is a strict superset; but B keeps its stale in-AIL in-core copy instead of adopting disk. Why is X still in-AIL at B's reacquire when B's release should have checkpointed it? Candidate: the release bwrite writes the buffer but AIL removal (iodone + log tail move) is async, OR a late CIL unpin re-dirties X after the drain but before unlock — i.e. X is not provably CLEAN at unlock.

### GPT-5.5 architectural verdict (RULE-5 consult, full transcript-worthy)
- In-core gen counters are UNSOUND here (stamp stale bytes fresh); do not use them as the safety gate. Freshness must mean "bytes read from the canonical device by an IO issued after this EX grant, or modified locally under this grant" — track read_under_grant_gen / modified_under_grant_gen per buffer, not gen>=inode_gen.
- RELEASE must be a true writeback fence: DLM must not grant the next EX until the releasing node has checkpointed its modified dir blocks HOME (use a per-grant TOUCHED SET of daddrs, NOT an incore-buffer scan; the "uncached⇒assume durable, skip" at mxfs_dir_flush_data_blocks:1290 is unsafe). Verify grant-to-B never precedes A's flush-complete (add tracepoints: A flush-complete ts vs B grant-received ts).
- ACQUIRE/RMW: on first RMW of a block under a remote-acquired EX, force coherent device read ignoring gen; but NEVER re-read a block modified under the CURRENT grant (avoids resurrecting own deletes). For a dirty/in-AIL block left from a PRIOR tenure after a genuine handoff: it must be checkpointed (so disk has our work) THEN replaced by the disk superset — the safe form of "adopt".
- 2-node passes / 4-node ~80% fail ⇒ multi-party handoff race: with ≥1 queued waiter the master grants the next EX in a window where the prior owner's drain/AIL-removal isn't truly complete; 4 nodes almost always have a waiter ready. Also more old owners (C,D) holding stale buffers.

### NEXT (concrete, RULE 4)
1. Instrument the clobber: at the dir-data write that drops an entry, log X's b_log_item dirty/in_ail/pin + whether it was cold-read this tenure + whether AIL-removal completed at last release. Confirm "stale in-AIL from prior release" vs "release-ordering (grant before flush)".
2. Fix per branch: (a) make dir-inode EX release provably checkpoint+clean its modified blocks (per-grant touched-set drain; wait AIL removal; don't unlock until done) so no dirty block survives into the next tenure; AND/OR (b) at reacquire after genuine handoff, for a dirty/in-AIL dir block, log_force+wait to checkpoint our committed work, then evict+cold-read the disk superset.
3. Validate: dir_reuse 4/tcp needs MULTIPLE runs (it's intermittent ~80%); target ~5/5 PASS. Then full 1/2/4/8 (+ watch resurrection canaries unlink_visibility/rename_visibility/dlm_fairness, and RULE-0 timing ~13s/round).

### Status: criterion NOT met. Tree baseline DE3A7E21, cluster clean (test1-4 rmmod'd), test1-8 up. Also blocking criterion: in-suite contamination (fault tests degrade later tests; pass standalone).

See [[sess10run-REFINED-handoff-read-stamps-fresh-over-stale-durability-race]] [[sess10run-DISCRIMINATOR-clobber-stale_base0-invisible-to-gen]] [[sess61-DECISIVE-dirty-bufgen0-divergent-block0-kept-by-dirty-guard]] [[sess58-CRITERION-MET-2tcp-17of17-8consecutive]].</body>
