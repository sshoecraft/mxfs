---
name: sess10run-REFINED-handoff-read-stamps-fresh-over-stale-durability-race
description: sess10(ccloop) refined root: post-handoff first read of a dir block returns pre-peer-durable content yet stamps b_mxfs_dir_gen=fresh -> postread_rere…
metadata:
  type: project
---

## sess10 (ccloop 4cb2d0a2) — REFINED root for 4/tcp dir_reuse durable loss

### Chain (all confirmed this session, build DE3A7E21)
1. Clobber RMW reports **stale_base=0** (i_dlm_dir_gen <= loaded_gen) at ALL losses — gen says FRESH. [[sess10run-DISCRIMINATOR-clobber-stale_base0-invisible-to-gen]]
2. The clean-stale backstop `dir_postread_reread` (default ON, xfs_da_btree.c:3651) only FUA-re-reads when `b_mxfs_dir_gen < i_dlm_dir_gen`. Since gen says fresh, **it never fires** at the clobber.
3. So the dir DATA block was stamped `b_mxfs_dir_gen = i_dlm_dir_gen` (FRESH) at the stamp sites (xfs_da_btree.c:3619/3690, 3171/3293; xfs_mxfs_dlm.c:12675) while its CONTENT was STALE (missing a peer's committed entry).

### Therefore the root is a DURABILITY/VISIBILITY race at the EX handoff (NOT a gen-detection gap)
The standard serialization argument SHOULD hold: node A adds a1 to block X under dir-inode EX, releases (Invariant-1 drain makes X durable), node B reacquires EX (slow path bumps i_dlm_dir_gen at xfs_mxfs_dlm.c:11134), B's first read of X sees b_mxfs_dir_gen<dir_gen → re-reads fresh (gets a1). For a loss, B's post-handoff first read of X must return PRE-a1 content yet still stamp b_mxfs_dir_gen=dir_gen(fresh), so the subsequent RMW (and every later read incl. postread_reread) treats it as current → adds b1 onto a stale base → drops a1.

Two candidate causes of the stale post-handoff read:
- (i) A's Invariant-1 release drain did NOT actually make block X durable+visible to B before the grant handoff (drain gap; suspect the Phase-3 `meta_pending timeout — forcing release` at xfs_mxfs_dlm.c:16630, and/or mxfs_dir_flush_data_blocks skipping an uncached/leaf block — see its P34-LEAF-DRAIN CACHED=0 branch at ~1282). 
- (ii) B did NOT go through the slow-path bump (held a stale-cached grant), so b_mxfs_dir_gen was never < dir_gen → no re-read. (sess58 said P106/P108 stale-cached fires ZERO — but re-verify for THIS test.)

### NEXT (RULE 4): instrument the post-handoff FIRST read of a to-be-clobbered block
For a round from `mxfs-drc-RDMISS`, find the daddr of the lost name, then on the clobbering node capture, for that daddr's FIRST read after the handoff: was it a disk read or cache hit? slow-path (dir_gen bumped) or fast-path? did the read CONTENT include the peer's entry (crc via P-DIRRD)? was b_mxfs_dir_gen < dir_gen (would trigger postread_reread)? This pins (i) vs (ii).
- If (i): make the dir-DATA release drain GUARANTEE platter durability + visibility before handoff; do NOT force-release dir inodes on the 2s meta_pending timeout; ensure leaf/uncached blocks are drained.
- If (ii): ensure every post-handoff reacquire goes slow-path (bumps dir_gen) so postread_reread fires; or FUA-re-read all contended-dir blocks on reacquire regardless of b_mxfs_dir_gen.

### Status: criterion NOT met. Tree at baseline DE3A7E21 (epoch_adopt reverted to 0), cluster clean (test1-4 rmmod'd), test1-8 VMs up. 2/tcp baseline good (all tests pass standalone; 3 fault tests flaky in-suite = contamination). 4/tcp = only dir_reuse fails (~80%+), all other coherency tests pass.

See [[sess10run-DISCRIMINATOR-clobber-stale_base0-invisible-to-gen]] [[sess10run-NEXT-real-fix-direction-concurrent-rmw-stale-base]] [[sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base]].</body>
