---
name: sess40-ABA-fix-REFUTED-clobber-is-current-incarn-stale-tenure
description: sess40 DECISIVE: the dir-block ABA-incarnation writeback skip (build B9F9326E) is REFUTED — on daddr=120 writes bincarn==cincarn in ALL 272 cases (ab…
metadata:
  type: project
---

## sess40 (ccloop 8ddb16a2) — the dir-block ABA writeback skip is REFUTED. Build B9F9326E. Marker NOT written.

### DECISIVE REFUTATION (RULE 4, build B9F9326E P16 with same-moment bincarn+cincarn):
On block-0 (daddr=120) writes, P16-DIRBLK-SUBMIT shows **bincarn == cincarn in ALL 272 cases (aba=0)** and **P40-INCARN-ABA-DIRSKIP fired 0×**. So the clobbering buffer's incarnation ALWAYS equals the dir's LIVE i_generation — it is NOT a dead prior-incarnation ABA leftover. My sess40 incarn discriminator (b_mxfs_dir_incarn != i_generation) is the WRONG token. This re-confirms [[sess16-stale-tenure-keepguard-fix]]: "i_generation discriminator fires 0× — di_gen doesn't differ on reuse; buf_gen-vs-i_dlm_dir_gen is the right token." (sess36's "ABA prior-incarnation" framing was wrong; sess16's tenure framing is right.)

### THE REAL Bug A token: TENURE, not incarnation.
P16 daddr=120: **16 writes had bgen < dgen (b_mxfs_dir_gen < owner i_dlm_dir_gen = STALE TENURE)** vs 256 current-tenure. The clobber is a CURRENT-incarnation buffer logged in a PRIOR EX tenure (we yielded EX, peer advanced block-0 on disk, we re-acquired and xfsaild flushed our stale-tenure cached image). P29-DATAWRITE CLOBBER daddr=120: buf_cnt decreasing (99,98,97... disk_cnt=buf_cnt+1), bufgen=4 — progressive stale-tenure reverts.

### dir_reuse 2/tcp fails in THREE distinct modes (all must be fixed for 100%):
1. **Bug A — content clobber (readdir short / lookup_fail):** xfsaild flushes a STALE-TENURE block-0 (bgen<dgen) over the peer's newer durable image. Token = b_mxfs_dir_gen<i_dlm_dir_gen (NOT incarn).
2. **Bug B — EFSCORRUPTED shutdown:** AG free-space DOUBLE-ALLOC, random file data over inode cluster @0xb40, P117-AGMETA-STALE-CLEAN bnobt. INDEPENDENT, allocator-side. (Hit in C22056240 iter3, corrupt=39.)
3. **Bug C — TIMEOUT (slowness):** B9F9326E batch iter1 FAIL = the test ran all 24 rounds but run_coord's TEST_TIMEOUT=300 killed it (saved /tmp/run_*/{test1,test2} empty, no RESULT line). The test is ~284s at mht=300 (sess36) = BORDERLINE; dirwr=1's heavy detectors + variance tip it over 300s. RULE 0: a timeout IS a failure. ~284s for ~5000 file ops is also ~50x native = RULE-0 violation even when it "passes." Slowness root candidate: MXFS_LOCK_ACQUIRE_WAIT_MS=6000 6s handoff ([[sess34-6s-dir-handoff-is-LOCK_ACQUIRE_WAIT_MS-deferred-bast]]).

### CRITICAL test-methodology note: dirwr=1 (and instr=1) PERTURB timing — they cause the timeout AND may create/mask races. The CRITERION is production config (dirwr=0). Validate at dirwr=0 using ALWAYS-ON detectors (P40, P20-LEAFCLOBBER-SKIP, P-CLMERGE); reserve dirwr=1 for short targeted diagnosis only.

### NEXT FIX (Bug A): extend the always-on leaf-clobber WRITE-GUARD `mxfs_buf_leaf_clobber_skip` (sess20, xfs/xfs_mxfs_dlm.c, currently xfs_dir3_leaf1/leafn ONLY) to DATA/BLOCK buffers (xfs_dir3_data_buf_ops/block_buf_ops). Same discriminator: a dir DATA write with `bp->b_mxfs_dir_gen < owner i_dlm_dir_gen` AND the coherent on-disk block is a VALID same-owner dir block with MORE live dirents (disk_cnt>buf_cnt) → skip (emulate clean ioend). FAST-PATH bgen>=dgen returns immediately (no disk read) so legit current-tenure adds/removes are never skipped. Mirrors the proven leaf guard exactly; the DATA-block analogue was never added. Build B9F9326E carries the REFUTED-but-INERT ABA skip (ABA=0, harmless) + mht=300 default + incarn stamping; the incarn skip can be removed or left.

### Current: production-config (dirwr=0) batch running to get the REAL criterion PASS rate before more fixes. Related: [[sess40-FIX-dirblock-ABA-writeback-skip-build-B9F9326E]] [[sess40-fence-REFUTED-real-root-dirdata-clobber-plus-AG-doublealloc]] [[sess20-PROVEN-bgen0-leaf-clobber-discriminator]]
