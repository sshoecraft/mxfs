---
name: sess40-PROVEN-799-is-release-drain-gap-async-writeback-overlap
description: sess40 PROVEN BY ELIMINATION: 799 loss is async-writeback overlap across EX handoff (release-drain gap). NOT flap/double-grant/stalemaster/count-regr…
metadata:
  type: project
---

## sess40 (ccloop 4cb2d0a2) — ROOT of the 8/tcp dir_reuse readdir=799 loss, PROVEN BY ELIMINATION (RULE 4). Keeper `A985424B`; detector build `B17141DA`.

### The complete elimination (all on no-flap failing 8/tcp iters, build B17141DA = A985424B + detectors)
The single/few-dirent durable loss (readdir=799/785, all nodes agree, LOOKUP_ENOENT REREAD_MISS, cascades to DABUF_MAP_HOLE) fires with ALL of these SILENT at the failure:
- **No flap** (`deferring death`/`reconnected`/`timed out (slow peer)` — none). [refutes the sess40 TCP-flap theory]
- **No `MX-DOUBLEGRANT`** (dlm.c:601 single-master audit — master never granted two conflicting EX holders).
- **No `P-STALEMASTER-GRANT`** (no mastership divergence / split-brain grant).
- **No `P-COUNTREGRESS`** (per-buffer dir-data write count never drops below its own high-water → each node's buffer is internally consistent; NOT a per-node stale-RMW).
- **No `P-DATACLOBBER-SKIP`** (no dir-data write had disk as a superset at submit).
- **No `P25-RELVERIFY-MISMATCH`** (in-core==disk at EX release, in the runs where it was enabled).

### CONCLUSION: the DLM lock layer SERIALIZES CORRECTLY (one EX holder at a time), but the WRITEBACK of a dir-data block crosses the EX handoff boundary = async-writeback overlap / release-drain gap.
Mechanism: node A holds dir EX, modifies a dir-data block, commits; A releases EX while that block's write is NOT yet durable on the LUN (or its bio is still in flight / queued in xfsaild). Node B acquires EX, cold-reads the block (missing A's entry) OR A's late write lands after B's — the two writes interleave, each individually consistent with disk-at-its-own-submit (so dataclobber/countregress are blind), net one entry lost. The lock said "A released before B acquired" but the DATA protected by the lock was not made durable/visible before release (Architectural Invariant #1 violated in a way the release fence doesn't catch).

### Why the release fence misses it (prime suspect)
The EX release fence (`mxfs_dir_data_durable`, xfs_mxfs_dlm.c ~1103, gating the break at ~8781) decides a dir-data block is "durable" partly via `mxfs_dir_buf_is_undestaged(dbp)` = `b_mxfs_logged_seq != b_mxfs_written_seq` (xfs_mxfs_dlm.c ~15715). `written_seq` is snapshotted at write SUBMIT, not at I/O COMPLETION — so a block whose bio was SUBMITTED but not yet COMPLETED reads `logged==written` = "destaged" = durable, and the fence releases EX before the bio lands. (Also: the acquire-side evict `mxfs_dir_drain_evict_data_blocks` LOCKED-SKIPs a block with an in-flight write, keeping a stale cached copy.) My mount-wide `dir_wr_barrier` (m_mxfs_dir_wr_inflight) was a NO-OP because it counted bios at SUBMIT and most dir writes ARE synchronous (publish-before-notify) so the counter was 0 at release — but the PROBLEM block is an ASYNC xfsaild write the fence wrongly passes.

### FIX DIRECTION (next session)
Make the EX release fence guarantee ACTUAL durability + quiescence of EVERY one of THIS dir's data-fork blocks before releasing:
1. Per-DIR-INODE in-flight dir-bio counter (not mount-wide) so the release wait has something real to wait on; OR
2. At release, for each cached dir data/leaf/free block: take a BLOCKING buffer lock (waits out any in-flight bio), then if dirty/in_ail/!written-to-completion → synchronous `xfs_bwrite` + wait, UNCONDITIONALLY (do NOT trust the lseq==wseq `mxfs_dir_buf_is_undestaged` heuristic — make written_seq stamp at I/O COMPLETION, or add a separate `b_mxfs_io_inflight` flag set at submit / cleared at ioend and waited on); AND
3. Acquire-side: `mxfs_dir_drain_evict_data_blocks` must not LOCKED-SKIP — wait out the in-flight write then evict+cold-read.
Reference: GPT-5.5 consult #1 (in [[sess40-FIX-dir-writeback-completion-barrier-readdir799]]) prescribed exactly "EX tenure owns the writeback LIFETIME; wait for physical bio completion before unlock" — the right idea, wrong granularity (mount-wide submit-count). Do it PER-INODE with completion-stamped state.

### Caveat
A genuine multi-dirent remove also regresses count, but dir_reuse only ADDS within a round, so any in-round loss is the bug. The mass-fail membership-flap mode is SEPARATE (flap-prevention `A985424B` helps it). Supersedes [[sess40-REFUTED-countregress-799-is-cross-node-concurrent-overwrite]], [[sess40-CORRECTION-799-is-concurrent-add-not-flap-bmbt-extent-fork]].
