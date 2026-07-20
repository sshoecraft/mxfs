---
name: sess10run-DECISIVE-fastpath-dominant-P63-handoff-never-fires
description: sess10(ccloop) DECISIVE trace counts: 4/tcp dir_reuse modify is fast-path-EX-dominant (P-DIRFASTEX 140-267/node) but the reliable fast-path handoff s…
metadata:
  type: project
---

## sess10 (ccloop 4cb2d0a2) — DECISIVE trace counts (build DE3A7E21, dirwr=2, 4/tcp dir_reuse FAIL)

### Counts per node (whole 20-round run)
- **P-DIRFASTEX = 140-267** (fast-path cached-EX block/leaf-dir MODIFY) — this is the DOMINANT dir-modify path.
- mxfs_dir_drain_evict_data_blocks (slow-path acquire evict): only **~14-19 total** (EVICT 4-16 + SKIP 0-4). So slow-path reacquire (which cold-reads a coherent base) is RARE; most modifies fast-path on the in-core cached block.
- **P63-FASTEX-HANDOFF = 0 on ALL 4 nodes.** The reliable per-grant handoff signal (mxfs_v5_dlm_inode_grant_handoff at xfs_mxfs_dlm.c:10599) NEVER fires on the fast path → the fast-path EX RMW does NO staleness re-validation (the only other fast-path trigger, dir_ex_stale_refresh via lossy i_dlm_dir_gen, is also dead since stale_base=0).
- P106-STALE-EX = 0, P108-REACQUIRE ≈ 0 → NOT a stale-cached/lost-grant.
- P-DE-BLK disp=SKIP lines all show `done=0 ... undestaged=-1` = already-invalidated (benign) blocks, NOT a kept-stale-DONE base. So the acquire-evict is NOT the leak.

### Interpretation
The clobber is a FAST-PATH cached-EX RMW with ZERO staleness re-validation (P63=0, stale_base=0, drain_evict didn't run for it). Two possibilities the next session must separate:
(1) There genuinely ARE no fast-path handoffs (the node holds EX continuously across the modify), so the stale base was injected at the RARE slow-path cold-read returning pre-peer-durable content (release-durability/visibility race — GPT Rank 1/2), and the fast path merely propagates it; OR
(2) mxfs_v5_dlm_inode_grant_handoff is BROKEN/under-firing on TCP (it's a one-shot edge consumed via i_dlm_handoff_acted_gen; sess64 said it's "lost ~80% of the time to fast-path serves / multi-consumer races") so real handoffs are missed → fast path serves a stale base after a peer modified.

Given P-DSIG flush=1 confirms the writer DOES flush its new dirent to the coherent SCST cache before releasing, and the slow-path acquire DOES cold-read+evict, possibility (2) [missed fast-path handoff] is now the leading suspect: a peer took EX and modified between our fast-path serves, but grant_handoff didn't report it, so we RMW'd a stale in-core block.

### NEXT (concrete)
1. Instrument the fast-path EX modify (xfs_mxfs_dlm.c ~10583-10613): for EVERY fast-path EX dir serve, log the LIVE grant_gen vs i_dlm_cached_grant_gen AND the reliable epoch vs i_dlm_dir_valid_epoch AND whether mxfs_v5_dlm_inode_grant_handoff returned true. If grant_gen CHANGED but handoff returned false → the handoff detector is broken (fix it). If grant_gen UNCHANGED across a known peer-modify → the node held EX continuously and the staleness is from the slow-path cold-read (release-durability race).
2. Most robust fix candidate (GPT-endorsed): on the fast-path EX dir modify, use the RELIABLE level-triggered epoch (mxfs_v5_dlm_inode_dir_epoch vs i_dlm_dir_valid_epoch) — NOT the one-shot handoff — to trigger drain_evict+cold-read of the target block before the RMW. (Note: epoch read off LOCAL grant is constant within a tenure; if the loss is within a single continuous EX tenure this won't help and the root is the slow-path cold-read durability race instead.)
3. If (1) shows continuous-tenure staleness: fix the slow-path cold-read to verify the read content reflects the grant epoch (retry/barrier if the peer's write isn't visible yet), or strengthen release so the next acquirer's cold-read is guaranteed to see it.

### Status: criterion NOT met. Tree baseline DE3A7E21, cluster clean, test1-8 up. Fresh dirwr=2 trace data on nodes at /root/drc_stream_rank*.log (rounds lost: 2=node2_f16.md5, 8=node4_f10.md5, 9=node1_f9).

See [[sess10run-GPT-consult-durable-clobber-stale-inAIL-block-survives-release]] [[sess10run-DISCRIMINATOR-clobber-stale_base0-invisible-to-gen]] [[sess61-THE-FIX-implement-sess10-grant-gen-faststale-check]].</body>
