---
name: sess32-reused-dir-dualEX-gap-sync-publish-fix
description: sess32 FINAL reframe: dir_reuse 2/tcp loss = AG free-space DOUBLE-ALLOC on cross-node dir grow (allocator hands out a daddr already holding live dire…
metadata:
  type: project
---

## sess32 (ccloop 8ddb16a2) — dir_reuse_coherency 2/tcp: FINAL reframe (supersedes ALL earlier sess32 notes)

### Criterion: `./run.sh 2 tcp` 100%. Only FAIL = `dir_reuse_coherency` (16/17). Marker NOT written.

### PROVEN ROOT (RULE 4, instrumented — names detector in P31E)
The dir-data loss is an **AG free-space DOUBLE-ALLOCATION on a cross-node dir grow**, NOT dual-EX, NOT reload-stale:
- At the clobber, the growing node's fork is `incore_size=8192 (nx=2)` — it is LEGITIMATELY adding lblk 1 — and the daddr the allocator returns for the "new" lblk 1 (e.g. 25118768, 2093304) **ALREADY HOLDS a live committed dirent** (`first_name="node2_f50.md5"`, and once `"node1_f50.md5"` = the PEER's). So the block allocator handed out a daddr already in use by the SAME dir → `xfs_dir3_data_init` zeroes it → those dirents vanish from the DATA block but remain in the LEAF index → readdir lists them, lookup ENOENTs (**P26-DSCAN-MISS=93 on test2, ndb=1 scanned~120**: the dir lost its 2nd data block's ~80 entries → leaf-hash holes → the test's lookup_fail check fails). RDMISS (readdir count) was empty this run; the failing check is lookup_fail (leaf-hash holes).
- **Single-node is CLEAN** (`tests/drc_single_node.sh test1` = 0/12 short on a good build) ⇒ the free-space staleness is CROSS-NODE (the AG bnobt/cntbt coherency across nodes), exercised only when both nodes alloc/free in shared AGs under reuse churn. (AG affinity: preferred_ag = node_slot % agcount.)

### Ruled out / corrected this session
- **P31E-DATAINIT-ABA is AMBIGUOUS**: it ALSO fires benignly (test1 `first_name="."` = sf→block reuse of a prior incarnation's `.`/`..` at the reused daddr; readdir stays 100). Only the cases with REAL dirent names (node{1,2}_f*) are true clobbers.
- **NOT reload-stale**: P34D-RELOAD-FRESHSRC fired 8× with `buf nx=1 / fresh nx=1` — the coherent fresh-read reload is correct (disk truly had nx=1 then). P133-DINO-READSTALE=0 on test2.
- **NOT (just) dual-EX / unpublished**: the publish-at-create fix (`mxfs_dlm_publish_inode(du.ip)` in xfs_create) was REVERTED — it SHUT DOWN the FS (xfs_trans_cancel "Corruption of in-memory data" in xfs_create at ~round 6 of single-node churn). Reverted build BE10EB0B = single-node CLEAN.

### State / tools
- Build with NAME detector (P31E first_name) ≈ 7408B4DF (KEEP detectors; log-only). FS healthy (no shutdown on clean build).
- `tests/drc_single_node.sh` (fast single-writer repro; CLEAN on good build — use to guard against single-node regressions).
- Prior AG-free-space double-alloc fixes: sess42 (`C6970FF9`, b_mxfs_ag_gen advance only when fresh), sess43 (`BB54A138`, in-AIL AG-meta not discarded), sess47 (stale cached inode inactivation). This dir-block-grow double-alloc may be an uncovered case of the same family on TCP.

### NEXT
1. Confirm double-alloc: at the P31E clobber, the daddr holds live data yet was allocated as new ⇒ the AGF/bnobt считал it free. Investigate the AG free-space DLM acquire/reload coherency (bast_work_fn drain + AG buffer invalidation on acquire; pag_mxfs_alloc_buflist; b_mxfs_ag_gen) for the gap that lets node B's cached bnobt allocate a block node A (or its own prior op) holds.
2. Build a faster 2-node repro than the 24-round suite test.
3. Fix the AG free-space cross-node coherency so a grow never allocates an in-use block; re-run dir_reuse + full `./run.sh 2 tcp` x3 (watch cache_coherency/zsl/crash_consistency/rsync timing).
[[sess28-ROOTFIX-inode-revert-fresh-gen-on-create-reuse]] [[sess42_lessons]] [[sess47_lessons]] [[sess18-merge-v2-single-tenure-REFUTED-dlm-timeout]]
