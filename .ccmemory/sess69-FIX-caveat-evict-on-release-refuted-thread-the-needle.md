---
name: sess69-FIX-caveat-evict-on-release-refuted-thread-the-needle
description: sess69 FIX CAVEAT: the true-root fix (invalidate dir buffers on loss-of-writer-exclusion) must NOT naively evict-on-release — sess96 force-evict-on-r…
metadata:
  type: project
---

## sess69 — caveat for implementing the TRUE-ROOT fix (read before coding)

The proven root ([[sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base]]): a node serves a STALE local XBF_DONE dir-buffer on a non-FUA read (cache hit) because a peer advanced the block and the LOSSY eviction-ring failed to invalidate. Fix direction = reliable invalidation.

### CAVEAT 1 — naive evict-on-release was already REFUTED
xfs_mxfs_dlm.c release path (~6059) comment: "the sess96 force-evict-on-release was REFUTED" — evicting dir buffers when releasing the grant caused durable RESURRECTION (clearing DONE on a buffer with un-checkpointed work → re-read loses our work / re-adds removed entries). That is why the release path does a FLUSH (in-core→platter), NOT an evict. So DO NOT simply call mxfs_dir_evict_data_blocks at release.
- To thread the needle: invalidation must run AFTER the durability flush (mxfs_dlm_dir_inode_durable / mxfs_dir_flush_data_blocks make blocks platter-durable) and ONLY on CLEAN/destaged buffers (mxfs_dir_evict_data_blocks already skips dirty/pinned/in-AIL-undestaged — but the REFUTED attempt presumably still regressed, so test 2/tcp unlink_visibility/rename_visibility for resurrection on ANY such change).

### CAVEAT 2 — the harder half: NL reads re-populate the cache stale
Even with invalidate-on-release, a node at NL (no grant) that READS the dir (md5sum/ls/lookup) re-populates the buffer XBF_DONE from disk; if a peer THEN advances the block, the node's next non-FUA read cache-HITS the now-stale buffer. The proven stale reads were comm=bash (md5sum/ls) at fua=0. So the read path for a non-grant-holder must either:
  (a) re-validate via a RELIABLE cross-node signal (not the lossy eviction-ring) — e.g. consult a DLM-grant-carried dir_change_seq before trusting a cached dir block, or
  (b) hold at least PR while reading (PR excludes peer EX, so the cached block stays valid), or
  (c) force FUA/uncached re-read of multinode dir blocks when the holder is below PR.
The mxfs_dlm_dir_consumer_refresh path is meant to do (a) but is gated on the lossy i_dlm_dir_gen → misses peer modifies → stale hit. Making consumer_refresh fire on a reliable signal is the core of the fix.

### Recommended approach (GPT-5.5 + this evidence)
Tie dir-buffer cache validity to LOCAL writer-exclusion state, reliably:
1. On dropping below writer-exclusion (EX/PR→NL), AFTER the flush, mark the dir's cached DATA/leaf buffers as needing-revalidation (a per-buffer or per-inode "validated-under-grant epoch" — NOT clearing DONE if that resurrects; instead a flag the read path checks).
2. On any read while NOT continuously holding ≥PR since the buffer was loaded, force a coherent re-fetch (clear DONE / FUA) before trusting it.
3. Keep continuous-PR / continuous-EX holders on the fast path (no re-fetch) so timing (RULE 0) is preserved.
VALIDATE with the dirwr=2 RD/WR trace: ZERO stale cross-node reads on the dir block daddr after the fix.

Marker NOT written — criterion NOT met. Build DE3A7E21 (baseline + dirwr-gated probes, inert at production). Cluster left clean (all nodes rmmod'd). See [[sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base]].</body>
