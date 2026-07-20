---
name: sess6-ccloop-8node-dirreuse-undercount-refuted-levers
description: sess6(run6614): 8-node dir_reuse residual = scattered-dirent readdir undercount (~4 lost, e.g. round1 796/800: node5_f5,node8_f44/46/47.md5 durable).…
metadata:
  type: project
---

## sess6 (run 6614) — 8-node dir_reuse residual, precise

### THE 8-node failure (build 9AA569A0 = gg_refresh=1 + leaf_flush=1 defaults):
- Reliability ~1/3 at 8 nodes (4-node = 12/12). Failure = **readdir undercount, a few SCATTERED dirents durably lost** (lookup_fail=0, all nodes agree, REREAD_MISS). Examples: round1 readdir=796/800 missing=[node5_f5, node8_f44.md5, node8_f46.md5, node8_f47.md5]; other runs 793/800, and a transient readdir=0/800 (test4 round17). Losses skew to LATE creates by HIGH-numbered nodes (node8's .md5 second wave) and are spread across rounds (not only round 1). NO shutdown in the default build (the undercount itself fails the test).
- Also seen: `DLM inode reload imap_to_bp failed rc=-5` for consecutive file inodes (14682045/46/47) — inode-cluster read/verify EIO on a reused cluster; appears regardless of levers. May be a separate symptom or contributor.

### REFUTED 8-node levers (do NOT retry — both REGRESS with shutdowns):
- `dir_release_flush_all_done=1`: **Corruption of in-memory data at xfs_trans_cancel (xfs_trans.c:1061) Shutting down** on test4/test8 (the release-time bwrite interferes with an in-flight transaction). Harmful even with leaf_flush on.
- `dir_tenure_evict=1`: DABUF_MAP_HOLE leaf-flood shutdown (run2 FAIL) — as prior sessions.

### ANALYSIS: gg_refresh (evict on grant_gen change) + leaf_flush cover both fast+slow acquire paths (both reload+drain_evict on handoff), yet ~4 dirents leak at 8-way concurrency. Suspected window: drain_evict SKIPS a block flagged undestaged (our uncommitted work) that is a FALSE POSITIVE (actually durable+stale vs a peer), OR the round-1 shortform→block→leaf FORMAT CONVERSION under 8-way concurrency races the base. The undestaged-tracking (b_mxfs written_seq/logged_seq) reliability is the prime suspect for the residual.

### NEXT: (a) GPT-5.5 consult (RULE 5 bar met: proven diagnosis + multiple refuted self-fixes + architectural). (b) OR instrument the exact clobber: at the addname RMW that drops a peer's committed dirent, log whether drain_evict skipped that block as undestaged (false-positive undestaged) — the P-DE-BLK LOCKED-SKIP / undestaged-skip counters. (c) The imap_to_bp EIO inode-reuse path (mxfs_dlm_reload_inode:11791) gives up on EIO — could re-derive imap from inobt.
KEEP: build 9AA569A0 (gg_refresh+leaf_flush) is the best default; 4-node 12/12, 8-node ~1/3, 1/2/4 tcp=100%.
See [[sess6-ccloop-8node-dirreuse-inode-reuse-cascade-faces]] [[sess6-ccloop-FIX-COMPLETE-gg-refresh-plus-leaf-flush-12of12]]</body>
