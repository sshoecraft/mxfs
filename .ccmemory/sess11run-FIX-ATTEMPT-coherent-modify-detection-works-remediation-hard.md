---
name: sess11run-FIX-ATTEMPT-coherent-modify-detection-works-remediation-hard
description: sess11(ccloop) coherent-modify fix (mxfs_dir_refresh_stale_data_blocks, param dir_coherent_modify default OFF): divergence DETECTION works (P11-COHMO…
metadata:
  type: project
---

## sess11 (ccloop) — coherent-modify fix ATTEMPT: detection works, remediation is the hard part

### What was built (build F0D7B279, param OFF by default = baseline-safe)
`mxfs_dir_refresh_stale_data_blocks(dp)` in xfs/xfs_mxfs_dlm.c (just before mxfs_dir_flush_data_blocks), called at the TOP of mxfs_dlm_dir_modify_refresh (before the lossy gen-skip), gated behind module param `mxfs_dir_coherent_modify` (default 0). For each dir DATA block of a contended dir (gen>0): coherent plain-read the on-disk block (mxfs_pal_bdev_read_plain_bdev), fingerprint in-core vs disk (mxfs_dir3_data_fingerprint — now EXPORTED from pal/linux/xfs_buf.c), and if disk has STRICTLY MORE live dirents (peer added entries we lack) invalidate the cached buffer (clear XBF_DONE|_XBF_FUA_FRESH). Skips cluster-undestaged/dirty/delwri blocks (never reverts own work).

### RESULTS (dirwr=1 dir_coherent_modify=1)
1. DETECTION WORKS: P11-COHMOD fired (4x/node) — CONFIRMS the stale-cached-dir-block root (a node's modify-path cached block is behind disk).
2. memcpy-OVERWRITE version (build 890C3B13) REGRESSED to readdir=345/400 (lost 55). ROOT: "disk has more dirents than in-core" does NOT imply disk is a SUPERSET — overwriting the in-core block with the disk image DROPS this node's own legit entries that disk lacks. UNSOUND. Reverted.
3. INVALIDATE version (clear XBF_DONE, F0D7B279): the proven-losing block (e.g. daddr=2093296) is NOT CACHED at modify_refresh time (xfs_buf_incore miss), so the invalidate never reaches it; AND even when it re-reads, the addname's dir-DATA-block COLD-READ itself returns a STALE image (the real gap). Still fails.

### DECISIVE DEEPER FINDING: the dir DATA-block READ is not FUA-coherent on the modify path
The losing block is faulted in by the addname's xfs_da_read_buf COLD-READ and returns STALE (missing the peer's durable entry) even though that entry was durable >1s earlier. So the fix is NOT at the cache-invalidation layer — it's that dir DATA-block reads do not pierce to the coherent image (FUA). cf [[sess26-FINAL-root-aba-buffer-stale-bli-fua-skip-and-exact-fix]] (clean ABA dir buf keeps stale BLI -> FUA-read SKIPPED). The dir DATA read path's _XBF_FUA_FRESH gating is not forcing a coherent read for these blocks on the modify path.

### NEXT (RULE 4): make the modify-path dir DATA-block read FUA-COHERENT
1. Audit xfs_da_read_buf / mxfs_buf_read_fua: WHY is the cold-read of daddr=2093296 not FUA-coherent (returns stale despite peer's durable entry)? Probe the read path (P-DIRRD at dirwr=2 shows fua=0/1 per read) for the losing daddr on the losing node — confirm fua=0 (non-coherent) on its pre-add read.
2. If dir DATA reads are non-FUA on the modify path, force them FUA when owned_ex && contended (gen>0). This is the real fix: a coherent READ so bestfree sees the peer's slot occupation -> no free-slot double-alloc.
3. SOUND remediation only (no memcpy-superset assumption; no write-suppression): force-coherent-READ, let xfs_dir2 addname recompute bestfree from the true image.

### Tree: F0D7B279 = clean baseline + inert FIX3 + SAFE dirwr-gated probes (P11-DATALOG w/off, PRELOGF, P11-FLUSH-*) + mxfs_dir_refresh_stale_data_blocks (param dir_coherent_modify DEFAULT 0 = OFF; safe-invalidate form). mxfs_dir3_data_fingerprint EXPORTED. Cluster grub log_buf_len=16M. Repro: /tmp/...scratchpad/drc4_d1.sh (dirwr=1) + drc4_chm.sh (adds dir_coherent_modify=1). Criterion NOT met. Full chain: [[sess11run-ROOTCAUSE-PROVEN-cross-node-dirblock-freeslot-double-allocation]] [[sess11run-DIRECTIONALITY-later-writer-stale-bestfree-loses-fix-coherent-refresh]] [[sess11run-REFUTED-dataclobber2-and-readside-gap-is-the-fix-target]].
