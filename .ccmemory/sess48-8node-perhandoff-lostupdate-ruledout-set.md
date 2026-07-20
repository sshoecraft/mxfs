---
name: sess48-8node-perhandoff-lostupdate-ruledout-set
description: sess48(ccloop): 8/tcp dir_reuse residual = PER-HANDOFF data-block lost-update (loss∝handoff count: mht=0→8/10 rounds fail, batching helps). 1/2/4 tcp…
metadata:
  type: project
---

## sess48 (ccloop 4cb2d0a2) — 8/tcp residual lost-update: comprehensive findings

### STATUS (build 237F937D = config #1 defaults baked)
- **1/2/4 tcp dir_reuse_coherency: PASS clean** (24 rounds, 0 loss, 0 shutdown). Confirmed.
- **8/tcp: FAILS** with residual readdir=796-799/800 (1-4 dirents lost) ~1-2 per 24 rounds.
  Plus heavy but NON-FATAL XFS_DABUF_MAP_HOLE_OK (xfs_da_btree.c:2876, ~3800×) — self-heals
  (datascan_lookup fallback), no actual FS shutdown (has-been-shut-down=0). The real FAIL is
  the readdir DATA-block lost-update.

### THE RESIDUAL = PER-HANDOFF data-block lost-update (KEY new finding)
Loss probability scales with EX-handoff COUNT:
- inode_mht_ms=300 (batch, fewer handoffs): ~1-2/24 rounds lose.
- inode_mht_ms=0 (per-create handoff, ~800/round): **8/10 rounds lose** (MUCH worse).
So MHT batching HELPS (refuted as cause); each EX handoff has a small chance of dropping a
dirent. A peer RMWs a dir DATA block with a base LACKING entry X (X was added+committed by
its writer in the prior tenure). All nodes agree X is gone (LOOKUP_ENOENT REREAD_MISS).

### RULED OUT this session (RULE 4, instrumented)
1. Split-brain/double-grant: P-DOUBLEGRANT(dg_shadow) is a FALSE POSITIVE — MX-DOUBLEGRANT
   (chain-based, dlm.c:601)=0 always; P48-DG-CHAIN shows single GRANTED holder; loss occurs
   with P-DOUBLEGRANT=0.
2. Acquire owner-evict skipping a DIRTY stale base: P48-OWNEREVICT-DIRTYSKIP dirty=1 count=0
   on all nodes (all skips are !DONE = benign). The acquirer cold-reads from platter.
3. owner_scan causing DABUF_HOLE: refuted — DABUF_HOLE just as high (3800) with owner_scan=0.
4. MHT batching causing loss: refuted — disabling it is far worse.
5. Release write-durability gap (di_size): release path DOES blkdev_issue_flush via
   mxfs_dlm_dir_inode_durable on EX release; P68-GROWREL-VERIFY/P-SFREL-VERIFY STALE-DISK=0.

### REGRESSIONS (reverted, default 0)
dir_release_flush_all_done (DATA-only) and dir_release_flush_leaf (DATA+leaf) → P21H-LEAFHOLE
tear → DABUF_HOLE storm. Force-writing dir blocks at release desyncs leaf-vs-data. Avoid.

### Config #1 levers BAKED default=1 (KEEP — remove P13-COLLIDE multi-loss, keep 1/2/4 clean):
dir_owner_scan, dir_grant_evict, dir_modify_target_flush. RULE-0: owner_scan per-AG rhashtable
walk per handoff ⇒ ~16s/round (slow; optimize later). owner_scan is ~neutral on the residual
but removes P13 multi-loss.

### NEXT (RULE 4): the per-handoff race. Decisive probe to build: for a lost entry X, capture
(a) WRITER at release — block containing X: was X present + was the block FUA-pushed to platter?
(b) READER at its RMW — was X in the reader's cold-read base? Pinpoints writer-release vs
reader-acquire gap. Suspect: reader's post-evict cold-read served from a stale LOCAL initiator
READ-cache (SCST may drop READ FUA; target_flush only flushes WRITES, not reader read-cache) —
test reader-side cache INVALIDATE vs FUA-read. Repro: tests/drc_dirtyskip.sh "<modargs>" <rounds> <N>.
See [[sess48-config-combo-and-leaf-tear-and-relabort-lead]].
</body>
