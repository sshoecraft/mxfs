---
name: sess42-PROVEN-799-is-stalebase-clobber-not-insert-loss-gpt-tenure-fence-plan
description: sess42(ccloop): dir_reuse 799 loss PROVEN = stale-base RMW clobber (count can rise during clobber→fools sum=801 discriminator); written_seq-at-submit…
metadata:
  type: project
---

## sess42 (ccloop 4cb2d0a2). Build on disk `9B06D682` (was keeper `5E7CC562`). Criterion NOT met (8/tcp dir_reuse still ~33% fail). All new params default such that behavior == keeper except the written_seq fix (default ON, see below).

### THE BIG CORRECTION (RULE 4, hard dland evidence): the loss is a STALE-BASE RMW CLOBBER, not pure insert-loss.
The sess41 "sum of final per-daddr dirent counts == 801 ⇒ insert-loss" discriminator is **AMBIGUOUS and was MISLEADING**. Proven this session with the dland write-COMPLETION ring (mxfs.dirland=1, per-block active-dirent COUNT at each bio completion):
- Victim `node2_f23.md5` placed by node2 (P13-NADD) in data block daddr=16745864. The block's completion-count trajectory: **node2 wrote it up to count 112, then test6 wrote it up to count 132 — and the final on-disk image (132) does NOT contain the victim.** Count went UP (112→132) while the victim was dropped = a count-INCREASING stale-base RMW: test6 RMW'd the block from a base lacking the victim, added 20 new entries, rewrote without it. This fools BOTH the count-regression detector AND the sum=801 discriminator (sum=801=799+`.`+`..` looks like "never inserted" but the ring proves written-then-clobbered).
- So: EX is serialized (no double-grant, audited), node2 adds the entry in-core+log under EX, but it is NOT durable on the LUN when the next EX holder (test6) reads the block → test6 clobbers it. And the creator itself loses it on a reload-adopt (P63-HANDOFF disk-superset-adopt / P62-RELOAD-FORK-SHRINK) that trusts disk over its own un-checkpointed add.

### ROOT FIX KEPT (correct, GPT-endorsed, but INSUFFICIENT alone): written_seq stamped at SUBMIT not COMPLETION.
`b_mxfs_written_seq = b_mxfs_logged_seq` was stamped in `xfs_buf_submit` (pal/linux/xfs_buf.c ~4212) → `mxfs_dir_buf_is_undestaged()` (logged!=written) reported an in-flight (or skip-emulated no-bio) dir write as durable. FIXED: for shared dir-metadata bufs (dir3 data/block/leaf1/leafn/free + da3node), DEFER the stamp to `__xfs_buf_ioend` (gated on `b_mxfs_dir_wr_counted` = real bio, only on !b_error). New param `mxfs.dir_wseq_at_completion` default **1**. Defer-set == counted-set (xfs_buf_submit_bio), and only bmbt early-returns FUA (not dir3), so all deferred bufs reach the counted submit+ioend → no wedge. ⚠️ NOT YET re-verified on 1/2/4 tcp — next session MUST confirm no regression (it's a hot-path correctness change).

### REFUTED this session (each built+deployed+reproduced):
1. write-merge ON (`dir_write_merge=1`): INERT (dko=0 — at the clobbering write the LUN does NOT have the victim → nothing to graft). ⇒ victim is NOT durable on LUN when peer reads = a real durability gap, not recoverable-from-disk.
2. `dir_release_flush_all_done=1` (force-flush every DONE dir DATA block at release, bypass destaged heuristic): still fails ⇒ the releasing path that hands EX to the peer does NOT run the release flush (or block not in map at release).
3. BTREE-vacuous-durable bail (`mxfs_dir_data_durable`/flush return true when fmt=BTREE && need_iread): probe `P42-VACUOUS-DURABLE` fired **0×** at fails ⇒ NOT the gap (dir is mostly fmt=2 EXTENTS).
4. prior-tenure-evict override (P16/P23, xfs_mxfs_dlm.c ~4276): params `dir_evict_prior_tenure`/`dir_tenure_evict` default **0** ⇒ not firing.

### SMOKING-GUN PATH (GPT's #1 suspect, seen in trace): cached-EX re-acquire bypasses release-drain.
Right when the creator loses its entry, trace shows `P-TCPEX-REACQ ino=131 ... (cached EX, mirror !held -> re-acquire)` then `P65-EPOCH-ADOPT`/`P63-HANDOFF post_release=1 forcing disk-superset adopt`/`P62-RELOAD-FORK-SHRINK` (disk grew nx 2→3) then `P-DE-BLK daddr=120 disp=EVICT`. The node thought it still held EX (cached) but a peer had taken it — so NO proper release-drain ran for the just-added block — then it reload-adopts disk (without its entry). GFS2 invariant violated: lock downconvert/handoff happened with tenure dirty metadata not home-written.

### GPT-5.5 PLAN (consulted, RULE-5 justified — full proven diagnosis + 3 refuted distinct fixes). See [[sess42-gpt-tenure-checkpoint-fence-fulltext]] if saved; summary:
- **The lock resource (per-dir EX tenure), NOT the physical daddr, owns the writeback lifetime.** daddr-keyed durability checks are defeated by the heavy block REUSE/ABA in this dir.
- **Primary fix = EX release/downconvert MUST be a real checkpoint**: block new dir writers → wait active dir txns → force log → write+wait ALL tenure-dirty dir metadata home (data+leaf+node+free+dinode+bmbt+freed/converted blocks) → 1 device flush (not per-block FUA) → only THEN downconvert/unlock. Track the dirty set by TENURE via generic hooks (`xfs_trans_log_buf`/`xfs_trans_log_inode`), NOT format-specific drains (the leaf-drain path misses the data block).
- **Cached-EX must be impossible without a valid DLM grant token**; the transition HELD_EX→NOT_HELD must always pass DRAINING→CHECKPOINTED→DOWNCONVERTED. If a path finds `!holds_ex && tenure_has_undestaged_dirty` ⇒ FAIL-CLOSED (fence / EIO), never reload-adopt over it.
- **Reload/adopt guardrail**: never discard undestaged local dirents; if still hold EX → checkpoint first; else fail-closed. (Name-merge is only a defensive recovery, not primary — real dir semantics need op-intent journaling.)
- **Phase 1 (do FIRST, cheap)**: add always-on FAIL-CLOSED detectors at (a) dir EX downconvert/unlock, (b) reload/adopt, (c) cached-EX-reacquire (P-TCPEX-REACQ) — each scans cached dir data blocks for undestaged content and logs/BUG. This NAMES the exact illegal path. Then Phase 2 = coarse correct checkpoint on that path; Phase 5 = conservative reload-adopt.

### TOOLS (build 9B06D682, all default-off except wseq fix):
- `mxfs.dirland=1` → write-COMPLETION ring with per-block dirent COUNT (decisive — distinguishes clobber from insert-loss; sum alone is AMBIGUOUS). `tests/drc_cap8.sh N "dirland=1"` → dland_<host>.txt.
- NEW probes: `P13-LADD` (leaf-format placement: ino/daddr/aoff/name — twin of P13-NADD), `P42-RELDUR` (per-data-block durability verdict at release), `P42-VACUOUS-DURABLE` (BTREE bail — fired 0×, refuted).
- Decisive parse: per-victim, find P13-LADD/NADD daddr, then dland count trajectory for that daddr across all nodes (`grep "P-DLAND d=<D> o=131"`) → look for a count that rose past the victim then a peer's write at higher count WITHOUT it.

### NEXT (RULE 4): implement GPT Phase-1 fail-closed detector on the P-TCPEX-REACQ / P63-HANDOFF / release-to-NL paths → name the path that hands EX to a peer with an undestaged dir data block → make THAT path checkpoint-before-handoff (GPT Phase-2) or fail-closed. Re-verify 1/2/4 tcp after. Cross-ref [[sess40-PROVEN-799-is-release-drain-gap-async-writeback-overlap]] (right family, partial), [[sess41-DEFINITIVE-loss-is-insert-time-not-writeback-ring-proven]] (its sum=801 discriminator is now shown AMBIGUOUS).</body>
