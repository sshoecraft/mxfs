---
name: compiled-agi-unlinked-list-corruption
description: AGI unlinked-list cross-node corruption under inode reuse: tenure_id redesign (FA1D1C0D) that replaced gen/LSN heuristic, plus AGI reentrancy deadloc…
metadata:
  type: project
tags: [compiled, agi, cache-coherency, inode-reuse, tenure-id, ag-dlm, unlinked-list]
---

## AGI unlinked-list cross-node corruption under inode reuse — root, tenure_id fix, reentrancy deadlock

The `cache_coherency` ship criterion (11/12 others passing) was blocked for ~12 sessions (sess19/42/43/102/103/110/117/120/122, culminating sess123) by cross-node corruption of the XFS AGI unlinked list. The `unlink_visibility` / `rename_visibility` / `cross_write_read` subtests forced an FS shutdown via `xfs_iunlink_remove_inode` line 632 `XFS_CORRUPTION_ERROR` (in-core AGI bucket = NULLAGINO while disk head was a valid agino). This article folds the proven root cause, the failed heuristic family, the structural tenure_id redesign that fixed it, and a separate AGI self-deadlock.

### The corrupting mechanism — cross-node AGI staleness under inode reuse
Proven in [[sess15_agi_xnode_corruption]] (build `1853FF8F`, clean 4-node power-cycle, RULE 4). The decisive lifecycle of inode 10485909 (agino 0x95, AG5):
- test4 creates `node4_before_20` = ino 10485909.
- test3 `P82-ADD ino=10485909 agno=5 agino=0x95 bucket=21` — unlinks it, commits, on-disk AGI bucket[21] head becomes 0x95.
- test4 `P103-RELOAD-REUSE-ADOPT` — inode FREED and REUSED by peer (disk_gen 279186378→622545939), test4 re-adopts the same ino#.
- test4 later inactivates 10485909, reads its STALE cached AG5 AGI (bucket[21]=NULLAGINO, never saw test3's add) → `xfs_verify_agino(0xffffffff)` fails → shutdown. `P71-INSTR ... agi_disk_differs=1` confirms in-core (0xffffffff) differs from FUA disk read (0x95).

So one node ADDs to an AG's unlinked list, another REMOVEs the same inode; the remover's cached AGI never reflected the committed add. A contributing violation: `P88-CLOBBER-PRODUCER agno=5 ag_held=0` — test4's xfsaild wrote AG5 metadata while test4 did not hold AG5's DLM (both test3 and test4 did ACQ-FRESH on AG5 and modified it concurrently), violating Invariant #1 (drain before release). `pag_dlm_meta_gen` for AG5 stayed stuck at 1 the whole run, so `mxfs_ag_meta_invalidate_stale` no-op'd and the AGI was never re-invalidated. Corruption sites: `xfs_iunlink_remove_inode` (xfs/libxfs/xfs_inode_util.c:612/632), reached via `xfs_inactive_ifree`.

Note a Gemini consult in [[sess15_agi_xnode_corruption]] gave a WRONG-premise answer (Hypothesis A: single-node stale-FUA revert, fix = extend `mxfs_buf_is_undestaged` to AGI/AGF). Static analysis refuted single-node revert (`_XBF_FUA_FRESH` cleared only by `xfs_buf_stale`, AG5 AGI staled once and never re-read). The real cause is cross-node + AG-DLM exclusion failure.

### Why every gen/LSN heuristic patch failed structurally
Diagnosed in [[sess123-tenure-id-agi-coherency-design]] (ccloop run 14d31183, build `70826FA0`). The sess122 resume plan (disable read-side P110 interlock, pal/linux/xfs_buf.c:2785) was built as `70826FA0` (P110 LOG-ONLY) and STILL FAILED — P110 was a backstop masking the bug, not the cause. Proven mechanism on `70826FA0`: `P82-ADD` insert commits (AGI bucket in-core = valid), then ~3ms later `P117-INAIL-STALE-ARTIFACT ... buf_gen=0 pag_gen=1 — discarded prev-epoch in-AIL artifact` — the node discarded ITS OWN committed-but-not-yet-durable AGI insert mid-tenure, re-read the stale on-disk AGI (NULLAGINO), lost the insert → `P71-INSTR` corruption → shutdown.

Structural failure of `b_mxfs_ag_gen`: it is stamped to `pag_dlm_meta_gen` in only 2 sites — the SCSI-FUA read success path (xfs_buf.c:1772) and the discard-rebranch (xfs_mxfs_dlm.c:5370). Default config `fua_disable=1` (SCST coherent cache) means AG-meta reads go via PLAIN BIO → gen never stamped → `buf_gen=0` forever. Once a peer bumps `pag_gen` to 1, every this-node-ahead AGI buffer looks gen-lagging and the in_ail discard branch (xfs_mxfs_dlm.c:5371-5465) fires; the `mxfs_buf_is_undestaged()` LSN guard mis-decides and lets the discard through.

Deeper reason all patches failed: `in_ail`, `b_log_item`, dirty/pin, and LSN CONFLATE two physically-identical-looking cases — (a) a genuinely-stale prev-epoch log-tail artifact (drained durable, peer wrote newer → MUST discard + cold-read, the sess117 bnobt fix) vs (b) a current-tenure committed AGI insert (must PRESERVE). Only "which DLM lock tenure produced this content" distinguishes them, a dimension the heuristics never captured.

### The fix — DLM tenure_id cache lifecycle (build FA1D1C0D, KEEP, VERIFIED)
Gemini RULE-5 architectural design in [[sess123-tenure-id-agi-coherency-design]], implemented and PROVEN in [[sess123-tenure-id-FIXED-agi-corruption-now-starvation]] as build `FA1D1C0D3FA6E5BD4A34C52` (KEEP). Replaces per-buffer `b_mxfs_ag_gen` + `pag_dlm_meta_gen` + `mxfs_buf_is_undestaged` LSN heuristic with a tenure-keyed lifecycle. Five edits, all KEEP:
1. `xfs/xfs_buf.h`: add `u64 b_tenure_id` to struct xfs_buf.
2. `xfs/libxfs/xfs_ag.h`: add `u64 ag_dlm_tenure_id` to struct xfs_perag.
3. `xfs/xfs_mxfs_dlm.c` ~7036 (genuine fresh-CAW-acquire, P102-ACQ site): `pag->ag_dlm_tenure_id++`. NOT at the reclaim paths (6786/6845/6868) — those keep the same tenure since the slot was never yielded (Invariant #1 not run).
4. Top of `mxfs_ag_meta_invalidate_stale` (after dirty/in_ail computed, before gen branches): **tenure guard** — `if (pag->ag_dlm_tenure_id && cbp->b_tenure_id == pag->ag_dlm_tenure_id) { xfs_buf_relse(cbp); return; }`. A current-tenure buffer is this-node-authoritative (hold AG EX → no peer advanced disk) → NEVER discarded mid-tenure. Only PRIOR-tenure buffers fall through to gen-based cold-read, preserving the sess117 bnobt fix (prev-epoch drained artifacts carry old tenure id → still discarded).
5. Stamp `b_tenure_id = pag->ag_dlm_tenure_id` after each successful AG-meta read: `xfs_read_agi` (xfs_ialloc.c), `xfs_alloc_read_agf` (xfs_alloc.c), `xfs_btree_read_buf` (xfs_btree.c, AG-type only).

Invariant: within a tenure the buffer is authoritative and gets zero heuristic checks (preserves the AGI insert from `P82-ADD` through the matching remove); a buffer with `b_log_item != NULL` is never discarded while tenure matches (holding AG EX means no peer can have advanced disk). WARN_ON if a prior-tenure buffer is found dirty/has b_log_item (means release-drain failed).

Release-side drain must avoid the sess111 synchronous-AIL-push wedge: use a decoupled async worker (`mxfs_drain_wq`, holds zero XFS locks) — quiesce AG (`MXFS_AG_RELEASING`), `xfs_inodegc_flush`, `xfs_log_force(XFS_LOG_SYNC)` to unpin, `xfs_buf_delwri_queue` dirty/log-item bufs to a local list, `xfs_buf_delwri_submit` (direct block-layer, bypasses `xfs_ail_push` deadlock), then `mxfs_ag_dlm_release_caw` + set NL.

PROVEN result (RULE 4, clean power-cycle + reset4, `fua_disable=1 instr=0`): the `P82-ADD → P117-discard → P71 NULLAGINO` corruption + force-shutdown is GONE on all 4 nodes (grep P71-INSTR / Metadata I/O Error / Corruption / EFSBADCRC = 0 on test1/test2/test4; test3's 2 hits were the DIFFERENT starvation failure below). P110 is left LOG-ONLY (harmless now).

### After the fix — remaining blockers become visible
The slowness was always lurking behind the corruption; the fix exposed it.
- **Parent-dir inode-EX starvation** [[sess123-tenure-id-FIXED-agi-corruption-now-starvation]]: `unlink_visibility` still FAILs, now on SLOWNESS. `unlink_30_files avg=36284ms max=123174ms`. test3 shut down with `DLM inode lock unrecoverable: ino=135 mode=5 rc=-110` (ETIMEDOUT, 120s CAW timeout) at `mxfs_dlm_ilock_begin` (xfs_mxfs_dlm.c:4356). ino=135 = the shared parent dir; `EVICT-RING-DIRMOD ino=135` storm with gen climbing 67→76 in ms = 4 nodes ping-ponging the parent-dir EX lock (each unlink needs EX to remove a dirent). Same family as [[sess50_lessons]] (CAW writer starvation, defer_for_waiter) and [[sess49_lessons]] (slow barrier visibility); per [[feedback_timing_is_first_class]] this slowness IS a ship failure. Next (RULE 4): investigate whether defer_for_waiter engages for inode locks and whether the per-handoff dir drain can be batched; consider RULE-5 Gemini consult on EX-handoff fairness.

### Separate defect — AGI reentrancy self-deadlock (build E25DD67F, KEEP)
Distinct from the coherency bug. [[sess41-ccloop-agi-reentrancy-deadlock-fixed]] (ccloop run 14d31183): `test_concurrent_touch`@16 hung forever, single D-state thread = self-deadlock. Stack: `xfs_create → xfs_iunlink → xfs_iunlink_reload_next → xfs_irele → iput → xfs_inactive → xfs_ifree → xfs_difree → xfs_read_agi → xfs_buf_lock`. `xfs_iunlink` HOLDS the AGI buffer; nested inactivation re-locks the same AGI. Root: MXFS runs `xfs_inactive()` synchronously in `xfs_inode_mark_reclaimable` (xfs/xfs_icache.c ~2960) for multi-node P25 recycle protection, whereas upstream queues async inodegc (no reentrancy). FIX (`E25DD67F4CE7D18750E1A66`, KEEP): gate sync-inactive on `current->journal_info == NULL` (XFS active-trans marker); nested-in-trans iput defers to async inodegc, top-level unlink stays sync. VERIFIED no more wedge.

By sess41 (build `5D2D50C8`) `cache_coherency` PASSES 4/4 — the ~50-session blocker resolved. Ship gate then 18 PASS / 1 FAIL, the lone FAIL being `posix_semantics_multi16` (`elapsed>600s`) from an INTERMITTENT 120s barrier dir-visibility timeout at 16 nodes (shortform-dir `EVICT-RING-DIRMOD` push not converging under load — reader `xfs_dir2_sf_getdents` holds only IOLOCK_SHARED, no inode DLM reacquire/FUA reload). Same family as sess50 / sess79-92 / sess131; a separate hard problem, not the AGI corruption.

### Iteration protocol (BINDING, consistent across sessions)
- Power-cycle ALL nodes: `sudo virsh -c qemu:///system destroy+start` (module wedges "in use" after interrupted repros → power-cycle, not rmmod).
- `INSMOD_OPTS="fua_disable=1 instr=0" bash tests/reset4.sh <N>`; verify srcversion on every node via `/sys/module/mxfs/srcversion`; `dmesg -C`.
- Subtest: `MXFS_NODE_OFFSET=0 MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh --nodes 4 --phase cluster --test test_unlink_visibility --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`. Must set MXFS_TESTS_DIR (nodes have /src via NFS, not /mnt/mxfs-src).
- Regression gates: keep `P71-INSTR` / `P82-ADD` / `P117` / `P88-CLOBBER-PRODUCER` probes; grep `P71-INSTR` (agi_disk_differs), `P82-ADD` (which node unlinked), `P103-RELOAD-REUSE-ADOPT`.
- 16-node slate: `scripts/cluster_reset_n.sh 16` then `tests/reset4.sh 16`. Kill orphans: `pkill -9 -f run_tests.sh` AND mxfs_test.sh AND the sshpass timing pattern.
