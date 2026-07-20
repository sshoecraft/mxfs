---
name: sess30-LEAD-bgen0-clobber-block-origin-is-next-target
description: sess30(ccloop) LEAD for dir_reuse single-dirent loss: per sess28 the clobbering xfsaild write is in_ail=1 dirty=0 bgen=0 (b_mxfs_dir_gen=0=never-stam…
metadata:
  type: project
---

## sess30 LEAD — the dir_reuse single-dirent loss clobber block has bgen=0

### Synthesis of sess28 smoking-gun + sess30 analysis
The durable single-dirent loss (P21H-LEAFHOLE, 399/400, node1_f10.md5) is, per sess28, an EX-holder destaging a STALE in-AIL dir-DATA block: signature `held_mode=5(EX) in_ail=1 dirty=0 **bgen=0** MERGE-NEEDED(disk_extra>=1, incore_extra=1)`. sess28 also PROVED the modify-time read was coherent (diff1=0) — staleness develops in the AIL between commit and destage.

### The KEY unexplained detail: **bgen=0** on the clobbering block
`bgen` = `b_mxfs_dir_gen`. A dir-DATA block cold-read through the gen-stamping read hook (`xfs_da_read_buf`/`mxfs_buf_read_fua`) gets `b_mxfs_dir_gen` stamped to the current `i_dlm_dir_gen` (nonzero after handoffs). **bgen=0 means this block was obtained WITHOUT the gen-stamping read path** — e.g. `xfs_buf_get` (uncached, no read) or a path that never stamps bgen. This is the SAME class as the sess30 soak `b_ops==NULL` buffer (also from a non-standard get path). So the holder is RMW'ing/destaging a block it got via a get-without-read (stale base, missing the peer's add B), and the read-side gen-invalidation (`bgen<dir_gen→clear DONE`) can't help because it's a WRITE.

### NEXT SESSION (clean dev-host needed — contamination after ~15 cycles): 
Instrument the ORIGIN of bgen=0 dir-DATA buffers for the storm dir: where is a dir data block `xfs_buf_get`'d (or otherwise obtained) WITHOUT going through the gen-stamping read, then modified+logged? Candidates: xfs_dir2 grow/addname allocating a new/under-populated block; a reload/FUA path filling b_addr without stamping bgen. Fix direction: ensure EVERY dir-DATA buffer that reaches a modify has bgen stamped from a coherent cold-read (so a stale prior-tenure base is detected), OR a transactional 3-way re-apply of the holder's delta onto the current disk base at re-acquire (sess28's untried recommendation — must update leaf/freeindex too, so it CANNOT be the refuted bio-chokepoint byte-merge).

REFUTED (do not retry): all write-side drop-suppression (dataclobber, dir_ex_write_guard, dir_stale_incarn_skip, dir_subset_guard, dir_ail_defer), bio-chokepoint byte-merge (dir_write_merge → cross-block dup), force-flush-all-DONE (dir_release_flush_all_done → loss persists + rc=-110 timeout). See [[sess28-SMOKINGGUN-EXholder-destages-stale-inAIL-base-bgen0-mergeneeded]] [[sess30-TRUE-HEAD-handoff-final-corrected]].
