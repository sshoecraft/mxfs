---
name: sess25-FIX-ail-defer-reduces-dir_reuse-loss-residual-remains
description: sess25: AIL-defer (write-side, defer EX-held contended dir-block destages to release-drain) REDUCES dir_reuse 8/tcp loss 3 rounds->1 BUT REGRESSES 4/…
metadata:
  type: project
---

## sess25 — AIL-defer write-side fix: PARTIAL, set DEFAULT OFF (build C2F02FF6)

Builds on [[sess25-PROVEN-clobber-is-background-aild-destage-of-stale-incore-dirblock]]. GPT-5.5 confirmed the GFS2 invariant (contended dir block changes only via the EX holder's release-drain).

### IMPLEMENTATION (all KEPT in tree, gated OFF by default):
- `mxfs_dir_ail_push_defer(bp)` (xfs_mxfs_dlm.c, decl in .h): defer iff multi-node + dir namespace buf + owner in-core + `i_dlm_mode==EX` + (`i_dlm_dir_gen!=0 || i_dlm_dir_contended`).
- `xfs_buf_item_push` (pal/linux/xfs_buf_item.c): `if (mxfs_dir_ail_push_defer(bp)) { xfs_buf_unlock(bp); return XFS_ITEM_LOCKED; }` — keep BLI in AIL, no I/O.
- Sticky `i_dlm_dir_contended` (xfs_inode.h): set on ANY dir BAST (bast_notify), reset at inode init. Covers create-phase cold window (create path never bumps dir_gen).
- Module param `dir_ail_defer` (DEFAULT 0 now).

### RESULTS (clean reboot each):
- 8/tcp dir_reuse: keeper loses 3 rounds; defer+sticky reduced to 1 round (round 13 node1_f39.md5; round 5 node5_f1/node7_f1 at cold window before sticky fix). dataclobber=1 + defer "PASSED" but that's the latency-masks-race ARTIFACT (detect-only), NOT real.
- 8/tcp defer+inode_mht_ms=50: NO shutdown but still 1 loss (round1 node7_f48.md5). Lower MHT -> fewer defers (P25=10 vs 76) -> less coverage.
- 8/tcp defer+MHT=300 (default): intermittent — once completed 24 rounds (1 loss), once STARVATION-SHUTDOWN at round1 (DLM acquire ino=131 rc=-110 184s -> SHUTDOWN_CORRUPT_INCORE @ xfs_mxfs_dlm.c:12392).
- **4/tcp FULL suite defer-ON: 12 PASS then dir_reuse FAIL 0/4 — round14 lost node2's ENTIRE 49-file md5 batch (readdir=351/400, NO shutdown). REGRESSION (keeper passes 4/tcp dir_reuse).**

### WHY DEFER REGRESSES (two failure modes):
1. **Whole-batch loss**: deferring (XFS_ITEM_LOCKED) WITHHOLDS background writes that the release-drain does NOT reliably make up -> deferred blocks never land -> lost. The "land only at release-drain" premise is FALSE as-is (release-drain has a coverage/timing gap for deferred blocks).
2. **Starvation-shutdown**: deferred blocks pin the AIL/log tail -> EX holder can't progress/release promptly -> peer DLM acquire times out 184s -> shutdown (the same wall sess24 hit with re-read).

### REFUTED this session (modarg, no build): tenure_evict=1+evict_prior_tenure=1; force_evict=0. Both still lose. ex_write_guard (default on) only catches non-EX clobbers.

### DECISION: dir_ail_defer DEFAULT 0 -> build C2F02FF6 is FUNCTIONALLY == keeper 8A437A71 (defer early-returns; i_dlm_dir_contended set-on-BAST is harmless/inert when defer off). 1/2/4 tcp preserved; 8/tcp dir_reuse fails like keeper (data loss). NO REGRESSION vs keeper.

### NEXT SESSION — to make defer viable (the path is RIGHT, the impl is incomplete):
1. Make the release-drain PROVABLY flush EVERY deferred dir block (add assertion: no dir DATA/LEAF AIL item survives EX release; if it does, the fence is false). The whole-batch loss = release-drain missing deferred blocks.
2. Add the liveness valve (GPT): on contention/BAST, run the quiesced checkpoint+release PROMPTLY (cancel MHT); on AIL/log pressure, schedule the release worker — NEVER allow the deferred block to be written async behind the release path's back.
3. Only then re-enable dir_ail_defer and re-test 4 AND 8 tcp.
Alternative if defer stays unviable: the bio-chokepoint backstop needs a real SUBSET check (our entries ⊆ disk) to safely suppress — fingerprint (count+sum+xor) can't prove subset. [[sess25-PROVEN-clobber-is-background-aild-destage-of-stale-incore-dirblock]] [[sess24-gpt5.5-dlm-fairness-and-demand-reread-design]]
