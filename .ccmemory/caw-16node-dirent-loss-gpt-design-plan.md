---
name: caw-16node-dirent-loss-gpt-design-plan
description: GPT-5.5 RULE-5 design for the 16-node durable dir-block dirent-removal loss (dangling dirent). Top roots: (1) final dir buf not drained before CAW un…
metadata:
  type: project
---

## GPT-5.5 consult (RULE 5, 2026-07-06) — 16-node durable dirent-removal loss

**Bug (instrumented, [[caw-multipath-16node-instability-diagnosis-sess1]])**: 16 nodes each create 30 files + unlink all in ONE shared dir (ino 2097305). ~1 dirent/480 survives as DANGLING dirent (dirent present on disk, its inode freed → lookup finds name → iget ENOENT err=-2, `P26-IGET-FAIL`). Always the LAST-ish file in a node's batch (_file19, _file30). Inode-cluster free DOES persist (P-IRESURRECT/P119/P17B guards work); the DIR DATA/LEAF block RMW loses the removal. Solid at 8 nodes, ~30-50%/test fail at 16. MHT-increase REFUTED.

### GPT root-cause ranking
1. **Release/drain does NOT synchronously write the final touched dir DATA/LEAF buffer before CAW unlock.** Committing the unlink to the LOG ≠ dir block durable at home location. Last-file bias = earlier unlinks get accidentally flushed by later ops; the final unlink relies entirely on the MHT-expiry/BAST idle-release drain — if that path misses the last dir-block delta (covers inode cluster but not DATA/LEAF), it leaks. CHECK: does the release drain force log through the tenure's max LSN, wait for touched dir bufs to UNPIN, synchronously write the EXACT dir DATA/LEAF/FREE/NODE bufs, wait IO completion, blkdev_flush, THEN release?
2. **`_XBF_FUA_FRESH` is a timeless boolean, not tied to DLM/CAW generation → peer reuses stale cached xfs_buf across an EX handoff.** Pattern: A reads dir (sets FUA_FRESH), releases EX; B acquires EX + removes a dirent + drains + releases; A RE-acquires EX, still has old xfs_buf XBF_DONE+FUA_FRESH → "FUA read" submits NO bio → A RMWs stale base (still has B's removed dirent) → writes it back → resurrect. A "FUA read" wrapper around an already-XBF_DONE buffer is NOT a FUA read. FRESH must mean "fresh for THIS parent-dir lock generation only", invalidated on any EX handoff.
3. Drain enumeration misses some dir buffer CLASSES (data vs leaf vs free vs node) or misses pinned/late-logged bufs (drain snapshots dirty set before final tx commit).
4. BAST-demotion vs MHT-expiry-demotion drain paths NON-equivalent (verify both call the identical durable-drain with same buffer set + waiting).
5. Write/flush ordering (submit→WAIT completion→flush→WAIT→release; not submit→flush→release→wait).
6. Actual SCSI FUA not honored (lower — inode cluster is coherent).

### DECISIVE PROBE (do this first, RULE 4)
After drain + blkdev_flush but BEFORE releasing the CAW/DLM slot: **raw scratch READ(16) FUA** (bypass xfs_buf entirely, NOT via _XBF_FUA_FRESH) of every dir DATA/LEAF block modified this EX tenure; parse dirents; assert the just-removed name/inum is ABSENT.
- **Case A: victim STILL PRESENT before unlock** → drain broken (roots 1,3,4,5).
- **Case B: absent before unlock, present later** → peer stale-base RMW clobber (root 2). Then find first later physical write to that block where victim reappears; log writer node, CAW gen, EX grant seq, whether a real FUA bio was submitted, buffer FUA_FRESH/XBF_DONE/pinned state, foreground-RMW vs drain. If writer's "FUA read" submitted no bio (buf already valid) → confirms root 2.
- Optional acquire-side check: on EX acquire, raw-FUA scratch-read + compare to the xfs_buf image about to be RMW'd; mismatch (scratch says absent, buf says present) = stale cached buffer despite "freshness" = root 2 proven.
- dirent-COUNT is insufficient (two images, same count, different surviving name) — log victim_name_present / name-hash+inum.

### Robust fix pattern (GFS2/OCFS2)
Cache validity tied to the LOCK RESOURCE generation, not a per-buffer timeless boolean. On EX acquire (unless proven uninterrupted same-node tenure): invalidate cached dir DATA/LEAF/FREE/NODE bufs + real FUA read + stamp bp->fresh_ex_seq=grant_seq. On any xfs_trans_log_buf of a dir buf: add to the tenure's dirty_buffer_set + record LSN. On demote (BAST or MHT-expiry, SAME path): force log thru max LSN, wait unpin, sync-write exact dirty set, wait, flush, invalidate/clear FUA_FRESH, release. GFS2 = go_sync (flush before demote) + go_inval (invalidate on demote).

### NEXT (implement)
Start with the CODE CHECK for root 2: grep `_XBF_FUA_FRESH` set/clear sites; confirm whether dir-EX acquire (mxfs_dlm_ilock_begin / dir reload) CLEARS FUA_FRESH / invalidates dir bufs, or lets a stale buf survive the handoff. If not cleared on handoff → root 2, fixable. Then add the decisive raw-FUA-before-unlock probe to confirm Case A vs B. Escalate to ask_gpt again (2nd call same issue) only if implemented design doesn't converge.
