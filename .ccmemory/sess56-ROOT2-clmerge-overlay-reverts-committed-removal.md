---
name: sess56-ROOT2-clmerge-overlay-reverts-committed-removal
description: sess56 ROOT of RESIDUAL 2/tcp leak (after the 2 KEEP fixes): mxfs_iflush_cluster_merge_dirs (xfs_inode.c:5508) overlays stale disk onto a dir slot BE…
metadata:
  type: project
---

## sess56 ROOT-2 — the RESIDUAL durable dirent resurrection (after [[sess56-FIX-coresident-dir-slot-skip-plus-release-drain-wait]]). Build base 5EA07421 = ~67% suite reliability (s5✓ s6✗ s7✓). This is the remaining failure.

### PROVEN (RULE-4, fast repro + name-dump probe)
`mxfs_iflush_cluster_merge_dirs` (xfs/xfs_inode.c **~5508**) does `memcpy(dbuf, ddisk, inodesize)` — OVERLAYS the on-disk dinode image onto the cluster-buffer slot for a co-resident dir we're not flushing. The guard at **5487-5506** only SKIPS the overlay when `bsf->count > dsf->count` (buffer strictly AHEAD of disk = our committed ADD, sess85). It does NOT skip when buffer is BEHIND disk (`buf_cnt < disk_cnt`) — but "behind" is AMBIGUOUS: it's EITHER (a) our committed REMOVAL not yet durable [keep buffer] OR (b) a peer's add we're stale on [adopt disk]. The overlay blindly adopts disk → REVERTS our committed removal → the removed dirent (e.g. mv source `n2_i2_r1`) is RESURRECTED on the platter (durable, both nodes agree).

### Captured timeline (rrd2 node2, dir ino=8929665, ~754.6s):
1. `P-CONVBLK-DENY held_mode=PR req_mode=EX → EDEADLK` (PR→EX conversion denied to avoid the sess13 deadlock) → `DLM inode lock failed rc=-35` → self-demote PR→NL.
2. `P51-REL held_mode=5(EX) drain_ms=0` — EX released, drain did nothing (the mv change committed in the release window / wasn't flushed).
3. `P119-NONEX-FLUSH-SKIP i_dlm_mode=0 in_ail=1 comm=mv` — node2's mv REMOVAL is committed (in_ail) but stranded at NL; P119 correctly does NOT discard it.
4. `P-CLMERGE restored ino=8929665 slot=1` — the merge OVERLAYS stale disk (still has the removed dirent) onto the buffer → resurrection.

### FIX TO IMPLEMENT (next session): in mxfs_iflush_cluster_merge_dirs, BEFORE the memcpy overlay (5508), for a dir slot whose in-core inode is **in_ail** (committed-not-durable change pending) OR pinned, SKIP the overlay (the buffer/in-core image is authoritative — same principle as the reload-merge clean-gate at xfs_mxfs_dlm.c ~7854 and the partial-write dir-skip). Need the in-core ip for slot i: `radix_tree_lookup(&bp->b_pag->pag_ici_root, first_agino + i)` then check `ip->i_itemp && test_bit(XFS_LI_IN_AIL,...)` / `i_pincount`. Only overlay a dir slot that is CLEAN (no local delta) — then disk is authoritative. Mirrors the count-guard but uses in_ail (the count-guard's "ahead" test misses removals; in_ail catches both directions).

### TOOLS THIS SESSION
- **FAST REPRO** (9x faster than full suite, reproduces standalone iter 1-7): `bash tests/tcp/repro_rename_drain.sh 150 N` (N=8-15). To load a new build first: reboot test1/test2, `./run.sh 2 tcp precond_readiness` (preps+mounts), then the repro. mv does NOT error (no MVFAIL) — the dirent silently resurrects.
- Probes in tree (build 5544DC4A): P56-RELOAD-MERGE (now dumps `disk=[names]`), P56-CORESIDENT-DIR-SKIP, P56-DIRWRITE (write-side dir names, UNDER pag_ici_lock — move out or remove), `mxfs_sf_disk_names()` helper (now non-static, declared extern in xfs_buf.c). Reverted: dead dirty==0 FUA-refresh (P56-DIRTY0 fired 0x; FUA-into-buffer-mid-submit caused a CORRUPT_INCORE shutdown — NEVER do that).

### SEPARATE BLOCKER (heavy-churn only, full suite does NOT hit it): the sess13 AG-DLM deadlock → `xfs_trans_cancel`/`Corruption of in-memory data (0x8)` shutdown in xfs_remove, fires at repro iter ~3-7. CONVBLK-DENY (PR→EX conversion deny) is part of this. Address AFTER the resurrection if it shows up in the suite.
