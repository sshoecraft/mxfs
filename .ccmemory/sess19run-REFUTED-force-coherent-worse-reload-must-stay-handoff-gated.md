---
name: sess19run-REFUTED-force-coherent-worse-reload-must-stay-handoff-gated
description: sess19(ccloop) REFUTED: force_coherent=1 @ mht=50 made dir_reuse WORSE (24/24 vs 18/24 failrounds). Aggressive unconditional dir reload clobbers comm…
metadata:
  type: project
---

## sess19 (ccloop) — narrowing the dir-reload-at-low-mht loss (RULE 4 refutations)

### REFUTED this session (do NOT repeat):
1. **P34-TRYLOCK-STALE is NOT the main cause** — fires only 5-32× in a failing mht=50 run while the loss is ~130 entries. A bounded-retry of that trylock would not fix it.
2. **`force_coherent=1` @ mht=50 made it WORSE** — 24/24 failrounds (vs 18/24 without). force_coherent (xfs_da_btree.c:3340) invalidates dir blocks on EVERY read, not just on handoff → it discards the node's own COMMITTED-BUT-NOT-YET-DRAINED in-core dir work MID-TENURE (the release-drain only lands work at RELEASE, not continuously) → self-clobber. So the reload MUST stay handoff-gated (invalidate only on cross-node re-acquire), NOT continuous.

### CONFIRMED robust (not the bug):
- The dir-EX RELEASE drain (xfs_mxfs_dlm.c:6592, runs UNCONDITIONALLY for dir inodes, loops until `!in_ail && !pinned && mxfs_dir_data_durable(ip)` with the sess97 xfs_bwrite checkpoint fence) lands all dir DATA blocks durable before handoff. NOT fast-path-skipped.

### REFINED diagnosis: the loss is the ACQUIRE-side handoff-gated reload being <100% reliable.
- After a node releases the dir-EX, its work is DRAINED durable (disk has everything). So on re-acquire, FUA-reading disk is SAFE (no own-undrained work to clobber). The bug = on re-acquire the node sometimes serves its STALE warm prior-tenure cache (missing the peer's new entry) instead of FUA-re-reading → addname RMWs the stale base → durable dirent clobber. At mht=50 the handoff rate is ~10× mht=275 so the per-handoff miss accumulates (round8: 130/800 lost).
- The gen-invalidation (xfs_da_btree.c:3176, handoff-gated via i_dlm_dir_gen bump on P63/P64 handoff) is the RIGHT mechanism but misses occasionally. Candidate gaps (next session, instrument each): (a) the i_dlm_dir_gen bump doesn't fire on every real cross-node handoff (P63-FASTEX-HANDOFF / P-FASTEX-EPOCH counts were 0 in one capture — the FASTEX fast-path handoff-detect may under-fire; check mxfs_v5_dlm_inode_grant_handoff + dir_epoch_adopt); (b) addname for a LEAF-format 800-entry dir uses the leaf `bests[]` free-space array / freeindex — verify THAT block is invalidated+FUA-reloaded on handoff, not just the data blocks; (c) the per-block invalidation stamps b_mxfs_dir_gen but the block addname actually selects (via bestfree) may be a different one than was invalidated.

### Build `15447D0C` KEEP (inode-skip fix, mht default 300). See [[sess19run-NEXT-check-dir-data-durable-invoked-at-lowmht-release]] (release side now CLEARED), [[sess19run-FULL-8tcp-suite-13of17-mht-tradeoff-is-core-blocker]].
</body>
