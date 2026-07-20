---
name: sess49b-FINAL-corruption-fixed-remaining-node6-write-durability
description: sess49b FINAL: build EA485CE6 (reload-gate + full-evict-on-handoff) ELIMINATES ALL 8/tcp corruption. Remaining = node6's creates never durable/visibl…
metadata:
  type: project
---

## sess49b FINAL — 8/tcp: ALL corruption fixed; remaining = node6 write-durability/visibility

### Build EA485CE6 (KEEP — best foundation reached in 130+ sessions)
= torn-disk reload gate + P68-PREEVICT owner-evict extended to fire on `genuine_handoff` (FULL evict, data+leaf — leaf-only was MEASURED to re-admit DISK-TORN/HOLE). Plus `leaf_only` param on mxfs_dir_evict_owned_dir_blocks (currently passed false on handoff; kept as a lever). All callers updated (xfs_mxfs_dlm.c ×2, xfs_icache.c ×1).

### What's FIXED (huge): ALL corruption eliminated
With full-evict-on-handoff: **HOLE=0, DISK-TORN=0, kernel-oops=0, no FS shutdown, no node declared-dead**. The DABUF_MAP_HOLE cascade, the leaf-addname oops, the disk-torn dir map — all gone. 2/tcp + 4/tcp still PASS.

### What REMAINS: node6 (rank6) creates never become durable/visible
8/tcp still FAIL 0/8, but now cleanly: **test6 readdir=0 (its OWN entries), all 7 peers readdir=719/800 (missing exactly node6's ~81-100)**. RULED OUT this session: corruption (HOLE/DISK-TORN=0), node isolation/death (no "declaring dead"), evict scope (test6=0 with full-evict AND leaf-only AND reload-gate-only), inode divergence (all nodes drc-DIRID=131), losing fresh blocks on evict (evict skips dirty/pinned). test6 COMPLETES its creates (DRCph create-done) + sync, yet they never appear on disk for anyone. => a rank-6-specific WRITE-DURABILITY gap: node6 releases the dir EX (or its inode-cluster destages) WITHOUT landing its just-created dir DATA blocks on the platter.

### NEXT (RULE 4) — THE converged target: dir-DATA-block release durability for node6's creates
1. Instrument node6's dir EX RELEASE for ino 131: does `mxfs_dir_data_durable` (xfs_mxfs_dlm.c:1418) iterate + bwrite+WAIT every DATA block, and is it CALLED on node6's release path before unlock? Watch P68-DIRINODE-DURABLE-FAIL. Add a release-time FUA-verify: after the drain, FUA-read each of node6's dir data blocks and assert the just-added dirents are on disk BEFORE unlock; if absent → the destage marked the block clean/done without landing it (the LIO FUA-drop / _XBF_FUA_FRESH interaction, or release log_forces but doesn't bwrite the data home).
2. Why rank6 deterministically: 8 nodes, node_slot%agcount affinity — node6 may share an AG/master with a node it always loses the EX-handoff race to at the create→verify boundary. Check the DLM master assignment + EX-handoff order for ino 131 around round 7.
3. Cross-check: does node6's create wave actually COMMIT (not just create-done in the script)? grep node6 for create errors / AG-lock -110 / trans_cancel during round 7 (earlier a DIFFERENT node hit AG-lock -110 → trans_cancel; if node6's creates silently fail/rollback, that's the gap, not durability).

### Verify protocol: once node6 visibility closed, drc_reliab_iter.sh 8 >=5x ALL PASS, then run.sh {2,4} tcp (no regression). Pass rate of EA485CE6 itself: re-measure (>=3 iters) — it may pass when node6 doesn't hit the durability race.
See [[sess49b-evict-on-handoff-kills-corruption-exposes-visibility-gap]] [[sess49b-NEXT-leaf-vs-map-destage-atomicity]] [[sess49b-BREAKTHROUGH-torn-disk-reload-gate-partial-8tcp]].
</body>
