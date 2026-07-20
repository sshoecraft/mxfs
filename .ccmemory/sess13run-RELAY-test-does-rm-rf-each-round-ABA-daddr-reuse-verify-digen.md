---
name: sess13run-RELAY-test-does-rm-rf-each-round-ABA-daddr-reuse-verify-digen
description: sess13(ccloop) RELAY-boundary note: dir_reuse test rm -rf's the whole dir EACH round (line 145) → full inode+leaf/data daddr free+realloc; ino 131 re…
metadata:
  type: project
---

## sess13 (ccloop) RELAY note — the dir is rm -rf'd every round (ABA daddr reuse)

### Test structure (tests/suite/dir_reuse_coherency.sh:142-147)
Each round, AFTER verify, rank1 does `rm -rf "$D"; sync` — frees the WHOLE dir (inode + leaf + data daddrs). Next round rank1 `mkdir -p "$D"` recreates it. The DIRID probe shows dirino=131 EVERY round → inode 131 is freed and REUSED each round; its leaf/data block daddrs are returned to the AG and realloc'd. So this test is fundamentally an ABA daddr-reuse + inode-reuse stressor (hence the name dir_reuse).

### Why this matters for the residual
mxfs's defense against ABA daddr reuse is `b_mxfs_dir_incarn` (= dir inode i_generation, stamped at read time; checked in xfs_da_btree.c ~3246: stale if b_mxfs_dir_incarn != current i_generation → invalidate+reread). This ONLY works if di_gen (i_generation) CHANGES when ino 131 is rm'd and re-mkdir'd. VERIFY NEXT (decisive): does ino 131's i_generation differ between consecutive rounds? Add/grep a probe logging VFS_I(dp)->i_generation per round for the storm dir. If di_gen is the SAME across the rm/recreate (XFS inode reuse without gen bump, or the inode stays cached IRECLAIMABLE and is recycled with same gen), then a peer's CACHED data/leaf buffer from the PRIOR incarnation (same daddr, same di_gen) passes the incarn check and is served STALE → the node uses a stale near-empty block (P13-STALEREAD bf0len~3984) / stale leaf bestsp[] → places at low offset → clobbers = the dir_reuse loss. This unifies: P13-STALEREAD (reused block read near-empty), the leaf bestsp convergence, and sess11run "vanishes from own block".

### Session state at relay: winning config fua_disable=0 fua_always=1 dir_epoch_adopt=1 dir_epoch_convert_gate=1 → dir_reuse 4/tcp 399/400, corruption ELIMINATED. 7 builds (final B2FAE263, probes + off-by-default levers, default==40AC2A0C). 2 GPT consults. Loss 1-26/round, contention-scaled (2/tcp passes, 4/tcp fails). 8/tcp unrun. Criterion NOT met.
### TOP NEXT STEPS: (1) verify di_gen changes on rm/recreate of ino 131; if not, fix the incarn check to also key on the daddr's free/realloc generation (AG-level) so a reused daddr from a prior incarnation is never served from a stale cached buffer even at the same di_gen. (2) If di_gen DOES change, the incarn check should already catch it → then the stale serve is a different path (cached buffer whose incarn was re-stamped current pre-content — sess97 restamp race). 
See [[sess13run-LEAD-nodes-converge-same-use_block-stale-leaf-freespace-bestsp]] [[sess13run-WINNING-CONFIG-fua-plus-epoch-adopt-399of400]] [[sess13run-P13-STALEREAD-mostly-normal-need-correlate-specific-lost-name-with-probes]].</body>
</invoke>
