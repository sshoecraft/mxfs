---
name: sess25-DECISIVE-exheld-stale-cached-dirblock-subset-of-disk
description: sess25: P25-RELVERIFY probe shows dir EX release mismatches (incore<disk) are ALL done=0 (benign lazy-evict, refetch on access) — release does NOT ha…
metadata:
  type: project
---

## sess25 — RELVERIFY probe: release is COHERENT; loss is MODIFY-time

Method: P25-RELVERIFY probe (xfs_mxfs_dlm.c mxfs_dir_data_release_verify, param dir_relverify default OFF). At dir EX release fence, plain-read each dir DATA block from disk, compare active-dirent fingerprint to in-core, log done/in_ail/undest/counts. Build 5954F53F.

### RESULT (8/tcp dir_reuse, dir_relverify=1):
- RELVERIFY-MISMATCH fires (incore_cnt < disk_cnt, e.g. 55 vs 134) BUT **ALL mismatches are done=0** (XBF_DONE clear = the block was evict-invalidated, b_addr holds pre-evict content, will REFETCH coherent disk on next access). in_ail=0, undest=0.
- ZERO done=1 mismatches → the release NEVER hands off a harmful XBF_DONE-stale block. So the in-core/disk divergence at release is the BENIGN lazy-evict state, not a served-stale base.
- Yet RDMISS=1-2 (loss persists). So Inv-1 RELEASE holds (disk correct after release; blocks either match or are evicted-pending-refetch). 

### CONCLUSION: the readdir=799 loss is NOT a release-fence content gap (REFUTED) and NOT an EX-held-served-stale-DONE-block at release (REFUTED, all done=0). It is a MODIFY-TIME stale-base RMW: an addname reads a (refetched-but-still-stale, or evict-skipped) dir DATA/freeindex block and allocates a slot occupied on disk → background destage of that block clobbers a peer's dirent (the dataclobber=1 detect run PROVED the clobbering WRITE is a background destage of a stale in-core block, EX-held, eq+different fingerprint).

### So the open question is narrow: WHY does an addname RMW get a stale base when (a) the release that produced disk was coherent, (b) the acquire-evict invalidates clean blocks, (c) storage is coherent? Candidates for NEXT SESSION (instrument the addname RMW directly — xfs_dir2_node.c xfs_dir3_data_read before xfs_dir2_data_use_free at xfs_dir2_data.c:1740):
1. The FREEINDEX/leaf block is stale (drives slot choice) even when the DATA block refetches fresh — evict/refetch the freeindex+leaf too, before slot allocation. (freeindex staleness → same-slot double-alloc → eq+diff.)
2. The evict clears XBF_DONE but the REFETCH reads stale disk because a CONCURRENT background destage (by another node that briefly didn't hold EX, or a TRYLOCK-skipped evict) wrote a stale block to disk between the coherent release and this read.
3. xfs_buf for the data block is refetched but via a non-FUA path hitting a per-initiator stale cache (sess24 said storage coherent under cache=none, but re-verify for the specific addname read path).
DECISIVE NEXT PROBE: at addname, after xfs_dir3_data_read of the target block, plain-read disk and compare; AND log the freeindex block's incore-vs-disk. If the data block matches disk but the chosen free offset is occupied on disk → freeindex staleness (#1). If the data block itself differs from disk → refetch race (#2/#3).

### TREE STATE: build 5954F53F = keeper 8A437A71 + gated-OFF dir_ail_defer (REGRESSES if on, [[sess25-FIX-ail-defer-reduces-dir_reuse-loss-residual-remains]]) + gated-OFF dir_relverify probe + harmless sticky i_dlm_dir_contended (set on dir BAST, only read by off-defer). Functionally == keeper. 1/2/4 tcp PASS, 8/tcp 16/17 (dir_reuse loses ~1-2/run). NO regression. [[sess25-PROVEN-clobber-is-background-aild-destage-of-stale-incore-dirblock]]
