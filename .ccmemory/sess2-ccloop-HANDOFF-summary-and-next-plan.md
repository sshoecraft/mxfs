---
name: sess2-ccloop-HANDOFF-summary-and-next-plan
description: sess2(ccloop) HANDOFF: biggest 8/tcp advance in project history — mht=1500 takes dir_reuse 0%→~80%, ELIMINATES all corruption; residual = clean round…
metadata:
  type: project
---

## sess2 (ccloop relay 6614aa96) — HANDOFF. Criterion NOT met; marker NOT written. Build EA485CE6 unchanged (no core edits; mht via modarg only).

### THE ADVANCE (biggest in 130+ sessions on 8/tcp dir_reuse):
`MXFS_EXTRA_MODARGS='inode_mht_ms=1500'` (vs default 300) → 8/tcp dir_reuse_coherency goes from **0/8 (deterministic corruption+shutdown) → ~80% PASS (4/5, +1/2)**, and **ALL corruption is ELIMINATED** (DABUF_MAP_HOLE=0, FS-shutdown=0, node-flap/declared-dead=0). Confirms GPT-5.5's thesis: the loss is per-HANDOFF; larger EX-tenure batch window → far fewer handoffs → far fewer lost-update overlap windows. [[sess2-ccloop-BREAKTHROUGH-inode-mht-1500-8tcp-dirreuse-PASS]]

### THE RESIDUAL (now precisely isolated, much narrower):
At mht=1500 the ~20% failures are a **CLEAN single-dirent loss (799/800), ROUND-1 ONLY, all nodes agree, NO corruption/shutdown/flap** — the pure cross-node intra-block dir-data freespace DOUBLE-ALLOCATION / write-side lost-update (sess44/36 signature). Round-1 = first concurrent create wave into a freshly-FORMED cluster on a freshly-CREATED dir (shortform→block→leaf grow under 8-way concurrency). [[sess2-ccloop-mht1500-residual-is-clean-round1-single-dirent-loss-no-corruption]]

### REFUTED this session: dir_write_merge=1 (removes DABUF but corrupts use_free + leaf-hash holes); dir_zombie_retire=1 @ mht=1500 (1/2, no help — sess33 right: zombie not in_ail at acquire-evict). Param-tuning does NOT reach 100%.

### TWO BLOCKERS to criterion:
1. **Correctness**: the round-1 single-dirent lost-update (~20% flaky). Needs the STRUCTURAL handoff fix.
2. **RULE 0 timing**: mht=1500 wall≈540s/iter (~3-5× native) — too slow to ship. mht is a DIAGNOSTIC, not the fix. The structural fix must make each handoff CORRECT so a SMALL mht (low latency) reaches 100%.

### NEXT-SESSION PLAN (prioritized, RULE-4):
1. **INSTRUMENT the round-1 loss** (low-perturbation — dirwr=1 HIDES the race, so use always-on capped probes only). Strong hypothesis to test FIRST: in round 1 the per-dir master/valid epoch starts at 0/low, so the addname epoch-staleness gates (b_epoch < valid_epoch, mxfs_dir_addname_epoch_refresh) DON'T FIRE on the first cross-node handoffs → stale-base free-slot RMW → double-alloc. Log valid_epoch + master dir-epoch + b_mxfs_dir_epoch at the round-1 losing addname (xfs_dir2_node_addname / xfs_dir2_data_log_entry). Run at mht=1500 (rare repro ~20%, but corruption-free so the cluster stays up for live capture — use tests/tcp/drc_mht_capfail.sh).
2. If epoch-init gap confirmed → make round-1/epoch-unestablished handoffs force a coherent cold base (FUA re-read the addname target block when master-epoch indicates a cross-node handoff happened but local epoch is 0/uninitialized). 
3. Else → implement GPT's whole-inode coherent handoff [[sess2-ccloop-GPT55-design-whole-inode-EX-handoff-ack-based]]: on genuine EX handoff, release=checkpoint WHOLE dir (data+leaf+node+free+fork) + invalidate; acquire=invalidate WHOLE inode + reread; gate dir-modify on explicit EX epoch token (not lagging mirror/i_dlm_mode). The selective per-block epoch/evict machinery is the gap (violates whole-inode coherency unit).
4. VALIDATE at LOW mht (target default 300) for RULE-0; need ≥10 clean PASS (bug is ~20% flaky) before trusting. Then flip default + run PLAIN ./run.sh {1,2,4,8} tcp full suite (criterion likely = full suite, not just dir_reuse; 2/tcp was 17/17 per sess58).

### Test infra added (RULE 3): tests/tcp/drc_mht_reliab.sh (N MHT batch+timing), drc_mht_capfail.sh (1 iter + live failure-signature dump), drc_modarg_reliab.sh (N arbitrary-modargs batch+timing).
See [[sess2-ccloop-EA485CE6-still-fails-rank1-rm-leaf-vs-data-and-p13collide-garbage]] [[sess44-PROVEN-offset-collision-double-alloc-aoff1600-four-dirents]] [[sess52-ROOT-node-addname-stale-epoch-datablock-readgate-miss]] [[sess35-ROOT-round1-format-transition-block-vs-data-divergence]]
