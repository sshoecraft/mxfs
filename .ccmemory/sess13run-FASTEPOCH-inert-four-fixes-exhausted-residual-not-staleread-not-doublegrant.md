---
name: sess13run-FASTEPOCH-inert-four-fixes-exhausted-residual-not-staleread-not-doublegrant
description: sess13(ccloop) fast-path level-epoch check (build 21A59021) INERT (P-FASTEX-EPOCH fired 1x, still 399/400). 4 distinct fixes exhausted. Residual is N…
metadata:
  type: project
---

## sess13 (ccloop) — fast-path epoch check INERT; 4 fixes exhausted; residual deeply narrowed

### Fast-path level-triggered epoch (build 21A59021, the convergent sess61/64 fix applied to the cached-EX serve)
Added to mxfs_dlm_ilock_begin dir-EX fast path (xfs_mxfs_dlm.c ~11100): query mxfs_v5_dlm_inode_dir_epoch; if > i_dlm_dir_valid_epoch, set dir_ex_stale_refresh + bump dir_gen (data-block re-read, NOT in-place fork adopt). Gated dir_epoch_adopt. RESULT: STILL 399/400, no shutdown. **P-FASTEX-EPOCH fired only 1x total** → on the fast path the epoch almost ALWAYS matches valid_epoch (coherent base). So the loser's addname does NOT serve a stale fast-path base.

### FOUR distinct code fixes this session, ALL inert/insufficient (all 399/400, no shutdown):
1. release-invalidate (post-fence clean-block XBF_DONE clear) — fired ~0-4x.
2. xfs_buf_stale publish-and-discard after dir-block bwrite (proven sess99 bnobt primitive) — no change.
3. fast-path level-triggered epoch check — fired 1x.
(plus params: fua_always, epoch_adopt, coherent_modify, force_evict, mht 0/300/2000.)

### What the residual is NOT (all REFUTED this session with evidence):
- NOT read-cache staleness (FUA fixes corruption; readdir loss persists).
- NOT extent-map divergence (sess68 MAPDIVERGE=0).
- NOT gen-stale read (sess67).
- NOT a surviving stale buffer across handoff (xfs_buf_stale publish-discard inert).
- NOT a fast-path stale-base serve (P-FASTEX-EPOCH fired 1x).
- NOT a master double-grant (P-DOUBLEGRANT=0, P-STALEMASTER-GRANT=0).
- NOT MHT-window-sensitive (invariant 300/2000; worse at 0).

### What remains (for next session): the durable double-PLACEMENT happens with BOTH writers having COHERENT bases at addname time, yet ~1.2s apart (sequential handoff, sess11run P11-DATALOG) they pick the SAME (daddr,off). The only mechanisms left:
1. WRITE-DURABILITY ORDERING / multi-hop staleness: the earlier writer's add is durable-on-LIO-cache but the later writer (possibly via a 3rd-node handoff chain) read a platter image lacking it — despite the sess97 fence + H26 blkdev_issue_flush. NEXT: PROVE platter durability of the loser's specific (daddr) at the moment of the later writer's read — instrument a coherent plain-bdev read of that block right before addname placement and compare its live-entry set to what addname's bestfree believes (a focused, low-volume probe that fires only when the chosen offset is occupied on the coherent platter image). If the platter HAS the peer's entry but addname's in-core block does NOT → the in-core block bypassed all refresh paths (find which read populated it). If the platter LACKS it → write-durability gap (the earlier add never reached platter).
2. xfs_dir2 free-slot SELECTION itself: two nodes' bestfree[] independently choosing the same offset even from equal-content blocks (e.g. a freespace-header bookkeeping divergence) — compare the two blocks byte-for-byte at the collision.

### Build 21A59021 = all sess13 changes, DEFAULT behavior == original 40AC2A0C (every new lever gated off/epoch-default-0; verified no shutdown). Winning config still 399/400. Criterion NOT met. See [[sess13run-REFUTED-master-double-grant-P-DOUBLEGRANT-zero-narrows-to-xfs-stale-ex]] [[sess13run-CONCLUSION-readside-buffer-fixes-exhausted-residual-is-write-placement]].</body>
</invoke>
