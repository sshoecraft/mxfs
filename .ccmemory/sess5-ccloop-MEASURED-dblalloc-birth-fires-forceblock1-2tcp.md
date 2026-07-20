---
name: sess5-ccloop-MEASURED-dblalloc-birth-fires-forceblock1-2tcp
description: sess5(run6614) MEASURED on build C7C10753 @ fb1 2/tcp cache_coherency (deterministic FAIL): P-DBLALLOC-BIRTH foreign=1 FIRES (refutes sess4 '0 foreig…
metadata:
  type: project
---

## sess5 (run 6614) — deterministic fb1 2/tcp cache_coherency repro, FULL probe timeline captured

Build C7C10753 (current tree, probes-only). `MXFS_EXTRA_MODARGS='instr=1 dirwr=1' ./run.sh 2 tcp cache_coherency` @ default force_block=1 → FAIL 0/2, deterministic ~T+290s. Both nodes shut down on `xfs_dir3_block_verify` EFSCORRUPTED.

### TWO faces, SAME root (cross-node bnobt free-space double-alloc):
**test2 (decisive):** dir ino=2097281 mkdir sf→block allocates block0 @ daddr=2093344. `P-DBLALLOC-BIRTH ino=2097281 daddr=2093344 disk_owner=2097280 foreign=1` **FIRES** (disk holds a FOREIGN LIVE XDB3 block owned by 2097280, 4 dirents "."..). Then `P-BLKRV-STRUCT daddr=2093344 owner=2097280` → shutdown. **REFUTES sess4 handoff claim "P-DBLALLOC-BIRTH=0 foreign".** The bnobt double-alloc IS real and caught at birth.
**test1:** dir ino=132 block0 @ daddr=112 (a LOW metadata-region block, ~fsb 14) reads back GARBAGE (magic 0x424d4133, owner 0x91..) → P-BLKRV-CRC → shutdown. Allocator handed out a metadata block.

### Lineage of the victim block (test2):
- 2097280 = ".cache_coherency" barrier dir, created by test1 (winner; test2 got P127-EEXIST-LOSER). block0 @ daddr 2093344 durably written.
- test2 NEVER freed 2097280 (P128-INACT/INACT-SKIP-STALE gen-mismatch skipped it; P-IRESURRECT ino=2097280 = still LIVE). Yet test2's bnobt handed daddr 2093344 to 2097281.
- ⇒ test2's in-core bnobt is STALE: never saw test1's allocation of 2093344 to 2097280. coldread_discard failed to prevent it. So 2093344 is double-allocated between TWO LIVE dirs (2097280 test1, 2097281 test2).

### Read-time symptom mechanism (xfs_da_btree.c:3435-3461 keep-guard):
2097281's freshly get_buf-init'd block0 has b_mxfs_dir_gen=0 while i_dlm_dir_gen=1 → gen-mismatch triggers invalidate. Buffer is UNDESTAGED (never written, P-EVICT-SKIP undest=1) but left the AIL (in_ail 1→0, BLI removed w/o writeback). Keep-guard bypass `!in_ail || !undestaged` — the `!in_ail` term lets invalidation clear XBF_DONE → re-read disk → gets 2097280's foreign content → shutdown. BUT this is only the read symptom; the ROOT is the double-alloc.

### force_block tie-in: fb1 forces .cache_coherency→block (gives it data block 2093344 = the victim). fb0 keeps barrier dirs shortform (no data block) ⇒ cache_coherency PASSES @ fb0 (2/tcp=17/17). dir_reuse @ fb0 hits SAME bnobt double-alloc via heavy sf→block churn.

### NEXT: decisive read-vs-write on test2's stale bnobt. At P-DBLALLOC-BIRTH foreign=1, compare in-core pag->pagf_freeblks vs disk agf_freeblks (FUA). differ⇒in-core AG-meta stale (coldread miss, read-coherence); same⇒on-disk bnobt itself says free (test1's alloc never durably persisted bnobt, write/durability). Then fix at proven side.
See [[sess4-ccloop-ROOT-forceblock-tension-is-bnobt-dirblock-double-alloc]] [[sess4-ccloop-UNIFIED-bug-corrupt-dir-extent-map-both-tests-same-root]]
