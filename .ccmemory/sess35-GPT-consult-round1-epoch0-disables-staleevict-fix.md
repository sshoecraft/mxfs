---
name: sess35-GPT-consult-round1-epoch0-disables-staleevict-fix
description: sess35 GPT-5.5 consult + fix: round-1 dir_reuse loss = epoch starts 0 → disables stale-base evict during fresh-dir growth → stale freeindex/bestfree…
metadata:
  type: project
---

## sess35 — ROOT (GPT-5.5 consult, matches instrumented evidence) + FIX for round-1 dir_reuse loss.

### PROVEN diagnosis (build 6FE8A391, EVDECIDE+epoch fields, focused round-1 repro)
- Failing round-1 window (dir ino 131, all 8 nodes): 60691 evict-decisions, **ZERO staleprt=1** (read-side KEPT-stale-prior-tenure REFUTED for the cur_mep!=0 cases). BUT **57093/60691 (94%) ran cur_mep=0 AND valid_epoch=0** — epoch UNTRACKED. 37892 of those were undurable=1 (KEPT). P64-MASTER-HANDOFF only 5-7/round.
- cur_mep / valid_epoch BOTH derive from dg_shadow[].epoch (dlm/dlm.c:2521 dg_grant_ex), which starts at 0 (line 2631) and bumps ONLY on owner-change. When 0, the per-block prior-tenure evict (needs cur_mep!=0) AND P16/P23 overrides (need valid_epoch!=0) are ALL DISABLED.

### GPT-5.5 root (RULE 5 consult, converges with evidence)
Round-1 loss = during fresh-dir shortform→block→leaf→node growth, epoch=0 disables stale-base eviction → stale data/leaf/**freeindex** buffers (or lingering clean in-AIL BLIs) survive a handoff → a later creator's xfs_dir2_node_addname allocates from **stale bestfree/freeindex** → **overwrites a LIVE dirent slot** → small, durable, globally-coherent loss (readdir=790..799/800, scattered names, lookup_fail=0). NOT FUA failure (SCST honors FUA + all-nodes-coherent), NOT double-grant, NOT wholesale sf_to_block clobber (count is slot-level).

### FIX applied (build 734EAB23, TESTING)
1. **Epoch never 0** (dlm/dlm.c dg_grant_ex: fresh-resource epoch 0→1, epoch_out 0→1). Makes the validated per-block evict+BLI-retire active from the first tenure so a peer's grown blocks/freeindex are refreshed across the first handoff. (`dir_newtenure_evict` stays default-1.)
2. Confirmation probe: P37-STALEBMAP-MODIFY UN-GATED (was instr-only, now always-on cap 600) — fires if the incoming EX holder modifies on an in-core dir bmap BEHIND durable disk (peer grew dir, fork not reloaded → evict walks too-few blocks). Watch for it at the loss.

### GPT's fuller recommendation if epoch-never-0 insufficient (NEXT)
- Rename epoch→publish_gen; advance on EVERY EX release that published dir metadata (not just owner-change); on EX acquire where gen changed, force-evict+FUA-refresh+retire ALL cached dir data/leaf/freeindex/dabtree buffers (independent of epoch) before xfs_dir_createname; reload inode fork so evict doesn't walk stale extents.
- Release-side ordered publish: data blocks → blkdev_flush → leaf/freeindex → flush → bmap/dinode → flush → advance gen.
- Confirm with a "DIR LIVE-SLOT OVERWRITE" probe in xfs_dir2_data_use_free (target offset already holds a live dirent before the new write → log victim name).
See [[sess35-dir_reuse-two-residual-faces-round1-and-799]].
</body>
