---
name: sess11run-ROOTCAUSE-PROVEN-cross-node-dirblock-freeslot-double-allocation
description: sess11(ccloop) ROOT CAUSE PROVEN of 4/tcp dir_reuse durable loss: cross-node INTRA-BLOCK freespace DOUBLE-ALLOCATION — two nodes write different dire…
metadata:
  type: project
---

## sess11 (ccloop) ROOT CAUSE PROVEN — 4/tcp dir_reuse_coherency durable single-dirent loss = cross-node dir-data-block FREE-SLOT DOUBLE-ALLOCATION

### THE PROOF (P11-DATALOG probe with byte offset, build C0290572, dirwr=1)
Lost entry node2_f1.md5. Two DIFFERENT nodes logged two DIFFERENT dirents to the SAME physical byte slot of the shared dir data block:
- `123.404675 test4: P11-DATALOG ino=131 daddr=2093296 off=2768 name=[node4_f4] comm=dd`
- `124.609292 test2: P11-DATALOG ino=131 daddr=2093296 off=2768 name=[node2_f1.md5] comm=bash`
Same daddr=2093296, same off=2768, different names, 1.2s apart, different nodes. => INTRA-BLOCK FREESPACE DOUBLE-ALLOCATION across nodes. The later writer overwrites the earlier at that offset; one dirent is durably lost (readdir 399/400, lookup ENOENT clusterwide).

### MECHANISM
A dir data block's internal free space (xfs_dir2_data_hdr bestfree[] + unused entries) tells addname where to place a new dirent. When node B acquires dir-EX and RMWs the block, its bestfree must reflect ALL peers' committed allocations. Here test2 RMW'd block 2093296 from a STALE base that did NOT include test4's node4_f4 (already at off=2768) -> test2's bestfree saw off=2768 as free -> placed node2_f1.md5 there -> double-use of the slot -> durable loss. This is the DIRECTORY analog of AG free-space double-allocation (sess24/42/43 family), at the dir-data-block bestfree level.

### Reconciles all prior sess11 observations
- "committed dirent vanishes from in-core before durable_signal, no evict/reload, ILOCK held": the slot it occupies is double-allocated; the bestfree/compaction or a peer's overwrite at the same offset displaces it. The entry's BYTES were logged (P11-DATALOG) but the slot is contested.
- Always during 2->3 block growth / heavy concurrency: more free-slot churn = more divergent bestfree.
- No cross-node DADDR divergence (all agree block layout) but INTRA-block OFFSET collision.
- Connects to GPT Rank 1 (publish-before-handoff): test2 cold-read block 2093296 before test4's node4_f4 was durable/visible -> stale bestfree.

### THE FIX (clear direction)
Ensure a node's dir-data-block RMW uses a COHERENT base that includes every peer's committed dirent (so bestfree never double-allocates a slot). Options:
1. PUBLISH-BEFORE-HANDOFF must be a true fence: a node's committed dir-block additions (the actual data block w/ the new entry at its offset) must be durable+visible on the LUN BEFORE the DLM grants dir-EX to a peer. Then the peer's evict+cold-read gets the real bestfree. (The release drain mxfs_dir_flush_data_blocks must reliably destage the EXACT modified block — sess11 showed committed entries that never reach any flush.)
2. The acquiring node's cold-read must be COHERENT (FUA/latest), not a stale cache/target image, so its bestfree is correct.
3. NOT a union-merge of dir blocks (GPT: corrupts bestfree/tail/crc). EX serialization + coherent base is the foundation.
KEY: the proof that the FAILURE is a same-offset double-allocation means the fix MUST make the pre-RMW read coherent w.r.t. peer free-space, OR serialize so no peer reads a block mid-another-node's-uncommitted-add.

### NEXT (RULE 4): 
- Confirm directionality: for the SAME (daddr,off) collision, check via realns which node's write was durable first and which read stale (cross-ref P-DIRRD crc at dirwr=2 for daddr=2093296 on test2 BEFORE its add vs test4's P-RELFLUSH/P29-DATAWRITE realns). Then target the read-coherency or release-durability gap at that block.
- Probe the bestfree the addname used: log the data block's bestfree[].length/offset for the storm dir right before placement, to see test2 believing off=2768 free while disk has node4_f4 there.

### Tree: C0290572 = clean baseline + inert FIX3 + SAFE dirwr-gated probes (P11-DATALOG w/ off=, PRELOGF, P11-FLUSH-UNCACHED/CLEANSKIP, mxfs_dir_dump_block_names). Cluster grub log_buf_len=16M. Repro: /tmp/...scratchpad/drc4_d1.sh (dirwr=1, ~70-220s). Criterion NOT met. See [[sess11run-SMOKINGGUN-datalog-entry-bytes-logged-then-vanish-no-evict-no-reload]] [[sess11run-ROOT-committed-dirent-reverted-by-evict-before-publish-GPT-fix]] [[sess42-SYNTHESIS-block0-split-is-double-sf-conversion-lineage]] [[sess24_lessons]].
