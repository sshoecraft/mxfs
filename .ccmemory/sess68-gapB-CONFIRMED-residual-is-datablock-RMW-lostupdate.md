---
name: sess68-gapB-CONFIRMED-residual-is-datablock-RMW-lostupdate
description: sess68 UPDATE: gap-B CONFIRMED effective (P68-GROWREL-VERIFY DURABLE 48/48, STALE=0). Residual 4/tcp loss = DATA-BLOCK RMW lost-update, NOT extent ma…
metadata:
  type: project
---

## sess68 UPDATE — gap-B CONFIRMED; residual is a DATA-BLOCK RMW lost-update (extent map now durable)

Refines [[sess68-gapB-proven-ownevict-moot-drop_caches-gpt-arch]].

### gap-B IS EFFECTIVE (decisive measurement, RULE 4)
Added always-on probe **P68-GROWREL-VERIFY** (xfs/xfs_mxfs_dlm.c, in the EX-release path right after `mxfs_dlm_dir_inode_durable(ip)` ~line 6034): for a non-LOCAL dir EX release, FUA-read the on-disk dinode and compare di_size to in-core. RESULT: **DURABLE on ALL 48 releases across test1-4, STALE-DISK=0.** So the grown dir's extent map (di_size) IS durable on the platter at every EX handoff. gap-B works. The P33-FROMDISK-DIRSHRINK events are therefore LEGITIMATE adoptions of a freshly rm-rf+recreated (genuinely 1-block) incarnation, NOT a gap-B durability failure.

### THEREFORE the residual durable loss is NOT the extent map. It is a DATA-BLOCK RMW lost-update.
Chain (all now confirmed): extent map durable at release (gap-B, P68-GROWREL-VERIFY) + data/leaf blocks dropped every round by the test's `echo 3 > drop_caches` (so no stale cached block survives to verify) + verify reads COLD from LUN and an entry is genuinely GONE → the on-disk DATA BLOCK was durably written missing the entry = a last-writer-wins lost-update at the dir-DATA-block level.

### MOST LIKELY MECHANISM (next hypothesis to test, RULE 4):
`mxfs_dir_evict_data_blocks` / force_evict (the pre-RMW evict) SKIPS blocks that are dirty/pinned/in-AIL/!DONE, treating them as this-node's own un-checkpointed work. But across an MHT-batched EX yield+reacquire mid-create-wave, a node's in-AIL block0 can be STALE-vs-peer (a peer grabbed EX and added entries in between). Keeping it and RMWing → drops the peer's entry. The sess41 EVICT-SIDE refresh (plain-read disk, drop if disk has MORE live dirents) is supposed to catch the in-AIL-kept case but is gated (`mxfs_dirrefresh`) and uses a live-dirent count that may not catch a same-count-different-content divergence. GPT-5.5's bug #1: needs a DLM-EPOCH-keyed mandatory re-read before RMW; di_gen/local-gen can't catch it, and the existing modify-prelock epoch gate is inert (valid_epoch==grant_epoch by modify time).

### CONCRETE NEXT STEPS:
1. Add a WRITE-SIDE probe: in the dir DATA-block write/verifier path (xfs_dir2_data write, or buffer write completion) for a multinode dir, log daddr + dirent count when a block is written. Correlate a block going from N→N-1 entries = the lost-update in the act. OR instrument `mxfs_dir_evict_data_blocks` to log when it KEEPS an in-AIL block0 (P41 EVICT-SIDE refresh KEEP path) during the create wave.
2. Test forcing the sess41 EVICT-SIDE refresh ON unconditionally for the in-AIL-kept case (drop the in-AIL block if a FUA disk read shows it differs), OR a stronger rule: on a cross-node EX re-acquire (grant handoff), evict in-AIL dir data blocks too (they were drained at our PRIOR release per Invariant 1, so re-reading is safe and catches the peer's superseding write).
3. If data-block RMW coherency can't be fixed surgically, implement GPT's epoch-keyed buffer stamp `(ino, di_gen, dlm_epoch, dir_cache_seq)` validated in xfs_da_read_buf / xfs_dir3_data_read.

### BUILD: srcversion `D3EA5B8D` (gap-B KEEP + owner-evict [moot, collected=0 due to drop_caches] + P68 probes). Shipped-proven baseline still `91962D4A`. gap-B does NOT regress 1/2 tcp (gated dirty + non-LOCAL; 1/2 are mostly shortform/single-block). Re-verify 1/2 tcp before shipping gap-B.

REPRO: clean rmmod test1-4 (umount -l + rmmod test1 first or mkfs prep fails), `./run.sh 4 tcp dir_reuse_coherency` (~5min). epoch_adopt=1 fixes the COUNT loss but the data-block lost-update + reset-incarnation handling still net FAIL.</body>
