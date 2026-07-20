---
name: sess22-REFUTED-exheld-stale-write-suppression-harmful
description: sess22(ccloop) REFUTED: suppressing an EX-holder's dc_stale+same_incarn content-divergent dir write (dir_stale_incarn_skip=1) is HARMFUL — readdir 47…
metadata:
  type: project
---

## sess22 (ccloop) — EX-held stale-write suppression REFUTED (do NOT re-try write-side)

### What I tried (build B16314B5, GPT Layer-2 idea): extend the bio-chokepoint clobber guard (pal/linux/xfs_buf.c) to ALSO fire for an EX-HOLDER when the block is dc_stale (bgen<dir_gen = prior-tenure base) AND same-incarnation (b_mxfs_dir_incarn==i_generation, to dodge the rm-rf ghost) AND the disk-proven content fingerprint shows divergence → suppress the write (P12-DIR-EXGUARD-SKIP). New param dir_stale_incarn_skip.

### RESULT: CATASTROPHIC — readdir 474/800 (was 799), leaf-hash lookup_fail=124, **4 of 8 nodes shut down**. The skip fired only ~1× but the damage was massive. So dc_stale && same_incarn && content-divergent is NOT a sufficient discriminator for "stale clobber vs legit write": it suppresses LEGITIMATE dir DATA/LEAF writes (e.g. this node's own current leaf/conversion/compaction work whose bgen stamping lags, or a legit destage), corrupting the dir. This is the sess23 "write-side suppression WAS the corruptor" trap, re-confirmed. REVERTED to default 0 (inert lever).

### DECISIVE CONCLUSION for readdir=799 (combine with siblings):
- The loss is a real durable content-divergent clobber (proven), NOT an addname free-slot double-alloc (P22-FREESLOT-STALE 0×), NOT catchable by count guards, and NOT safely fixable by WRITE-SIDE suppression (this refutation — you cannot distinguish a stale clobber from a legit write at write time, even with dc_stale+incarnation+content fingerprint).
- THEREFORE the only viable direction is GPT's **Layer 1 (READ-SIDE)**: ensure the EX holder NEVER RMWs a stale base. The stale base exists because the modify/acquire evict KEEPS a dir DATA block that is in-AIL-undestaged ("our uncommitted work") — but across an EX loss that "uncommitted work" was already drained (Inv 1), so the kept block is actually a superseded prior-tenure base. FIX: on EX (re)acquire / modify, do NOT keep ANY dir-fork block (data+leaf+**freeindex**) whose b_mxfs_dir_gen < i_dlm_dir_gen (prior tenure) — force-evict + FUA-re-read it (gated same-incarnation). Refreshing the base before the RMW is always correct (incl. legit removes), unlike a write-side skip. The sess41 evict-refresh (mxfs_dirrefresh, default off) is the right place but was COUNT-based ("disk strictly MORE") and "fired 0x" — make it fire on any dc_stale prior-tenure dir block (clear XBF_DONE → re-read), NOT gated on a count/content compare. Watch: must not clear XBF_DONE on a genuinely dirty/pinned block (corruption); only on a clean DONE block whose bgen<dir_gen.

### KEEPER: D589FA5FxxxxxxxxF4CEC66 = EFBB9861 (reorder + datascan heal) + Layer-3 freeslot guard (8948C889, harmless 0x) + inert refuted dir_stale_incarn_skip param. Functionally == 8948C889. See [[sess22-freeslot-guard-0x-loss-is-postadd-stale-destage]] [[sess22-GPT-fix-design-freeslot-doublealloc-readdir799]].
