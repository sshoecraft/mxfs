---
name: sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush
description: FIX DESIGN (GPT-5.5): dir_reuse 2/tcp root = xfsaild flushes node2's STALE in-core dir INODE FORK (block0→112) over canonical dinode (block0→120). Fe…
metadata:
  type: project
---

## dir_reuse_coherency 2/tcp — FIX DESIGN (GPT-5.5 consult, RULE 5). Build 2045BCE9, marker NOT written.

### THE NOVEL INSIGHT (38 sessions missed this): the corrupting object is the INODE FORK, not the dir DATA block.
All prior fixes invalidated/evicted/staled dir DATA BLOCK buffers. But the loss is the dir INODE's data-fork EXTENT MAP. xfsaild/xfs_iflush serializes node2's STALE in-core fork (logical block0 → daddr 112, a freed prior-incarnation daddr) into the home dinode, OVERWRITING node1's canonical fork (block0 → daddr 120). Then both nodes reload the now-stale canonical dinode → both getdents read block0 @ 112 (short, missing node1_f1..f12) while lookup uses the leaf @ 120 (lookup_fail=0). Self-sustaining 112↔120 oscillation. (See [[sess-tcp-ROOT-stale-incore-extent-map-getdents-blk0-daddr]] for the forensics: node1 ALWAYS allocs block0@120 (fsb=15), node2 NEVER allocs block0; disk@120 is correct cnt=100.)

### ROOT (GPT): DLM protects mutual exclusion but NOT writeback authority over the inode fork. The in-core dir inode fork acts like a dirty cache line not owned/fenced by the DLM. A node can checkpoint an OLD data-fork extent map (via ANY inode-dirtying: timestamp/size/nlink/dirent/AIL push/undrained release) and clobber the real dinode — it need not allocate block0, only flush an inode whose cached fork still says block0→112.

### THE INVARIANT NEEDED: a shared dir inode fork may only be flushed if it was VALIDATED under the currently-held DLM lock epoch. "No stale in-core fork may ever reach the on-disk dinode." (GFS2/OCFS2: DLM = cache-coherency lock, not just a mutex — demote writes back+invalidates, promote validates/reloads, stale metadata may NOT be written back.)

### IMPLEMENTATION PLAN (priority order; do Step 4 first — it directly breaks the loop):
1. **Reload must NOT bail silently** (mxfs_dlm_reload_inode ~xfs_mxfs_dlm.c:6717 down_write_trylock): on contention, block or return -EAGAIN/restart — never proceed with a possibly-stale fork. (It already retries 1000×; verify it actually succeeds.)
2. **Validate/reload from DLM (not the heartbeat ring)** on dir-lock acquire: stamp the fork with an epoch on reload; if local_epoch != current epoch (peer modified), blocking-reload. Remove correctness dependence on the evict-ring (it's asymmetric — node1 gets 0 DIR_MODIFY; node2 338 — and lossy/latent; keep only as optimization).
3. **Release/demote flushes the inode FORK HOME**, not just dir data blocks: extend publish-before-notify (xfs_mxfs_dlm.c ~4858 mxfs_dlm_dir_inode_durable) to synchronously iflush+bwrite the dir DINODE/bmbt to its home block (log_force alone is NOT publication for FUA-cold-reading peers) BEFORE bumping gen/unlock.
4. **FENCE inode flush (the key fix)**: in the inode-flush path (xfs_iflush / xfs_inode_to_disk / xfs_iflush_cluster — find the mxfs hook point), for a SHARED (multi-node) DIRECTORY inode, REFUSE to serialize the fork to the dinode unless this node holds the current valid DLM epoch (e.g. i_dlm_mode==EX AND the fork was reloaded under the current i_dlm_dir_gen/loaded_gen). Else skip/requeue (-EAGAIN, AIL-safe) + mark need-reload. Start HARSH+diagnostic (pr_warn/ASSERT) to confirm the stale-iflush fires, then enforce. THIS is what stops node2 re-asserting block0→112.
5. **Bump a map_epoch ONLY on bmap/incarnation change** (dir block alloc/free, sf↔block convert, extent ins/del, bmbt split, inode reuse) — NOT per-dirent-insert — so reload only fires on real extent-map changes (avoids the always-reload perf wall / 24s→500s flush storms that killed prior attempts).

### WHY IT BREAKS THE LOOP: node2's stale fork (112) can no longer be flushed (fence) when its epoch is stale; on acquire node2 blocking-reloads to the canonical 120; only 120 is flushable → block0 single-valued → 120 stops oscillating.

### CAVEAT TO VERIFY (RULE 4): node2 holds EX during its own release-flush, so a naive "holds EX" fence won't block the release path — the fence MUST also require the fork was VALIDATED under the current epoch (reloaded since the peer's last write), not merely "holds EX". The epoch-stamp (Step 2) is what makes Step 4 correct.

Reproduce: `MXFS_EXTRA_MODARGS='inode_mht_ms=300 dirwr=1' bash tests/drc_cap2.sh` (~50% FAIL; inode_mht_ms=300 still not code default). P-GROW0 instrument live in xfs_dir2_grow_inode (gated dirwr/instr). [[sess-tcp-ROOT-stale-incore-extent-map-getdents-blk0-daddr]] [[sess-tcp-HANDOFF-phantom-ex-fixed-residual-incarn-aba]]
