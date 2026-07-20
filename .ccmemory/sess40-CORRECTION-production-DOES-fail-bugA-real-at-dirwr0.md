---
name: sess40-CORRECTION-production-DOES-fail-bugA-real-at-dirwr0
description: sess40 CORRECTION to handoff: production config (dirwr=0, mht=300 default, build B9F9326E) DOES fail dir_reuse — iter2 FAIL drc-RDMISS round=12 readd…
metadata:
  type: project
---

## sess40 CORRECTION — production config DOES fail Bug A (supersedes the "production healthy" claim in [[sess40-HANDOFF-production-healthy-three-bugs-next-steps]]).

### PROVEN at PRODUCTION config (dirwr=0, mht=300 default, build B9F9326E, RULE 4):
Batch `bash tests/drc_loop.sh 5` (NO MXFS_EXTRA_MODARGS): **iter1 PASS, iter2 FAIL** (iters 3-5 were still running at context-out; read tests/_cap/loop_summary.txt + fail_N logs).
- iter2 FAIL = **Bug A content clobber**, NOT timeout, NOT EFSCORRUPTED (corrupt=0): `mxfs-drc-RDMISS round=12 rank=2 readdir=186 missing_from_readdir=[node1_f1..node1_f14] ; mxfs-drc-FAIL round=12 readdir=186 exp=200 lookup_fail=0`. BOTH rank1 AND rank2 readdir=186 (durable, both agree). Test reached round 24 (completed — not a timeout).
- **P40-INCARN-ABA-DIRSKIP, P-CLMERGE-DEADINCARN, P20-LEAFCLOBBER all fired 0×** → none of the existing/attempted guards catch this clobber.

### CONCLUSION: Bug A (stale-tenure block-0 clobber) is REAL at production config — NOT a dirwr=1 timing artifact. node1's FIRST data files (node1_f1..f14, no .md5) are durably dropped from block-0 (daddr 120). lookup_fail=0 (leaf intact). This is the canonical signature ([[sess28-dir-data-block-RDMISS-first-block-clobber]], [[sess36-correctness-aba-dirblock-clobber-fix-plan]]) and matches the sess40 finding that the clobber buffer is CURRENT-incarnation but PRIOR-EX-TENURE (b_mxfs_dir_gen < i_dlm_dir_gen), NOT ABA ([[sess40-ABA-fix-REFUTED-clobber-is-current-incarn-stale-tenure]]).

### THE NEXT FIX (do this first next session): tenure-based DATA-block writeback clobber guard.
In mxfs_buf_xfsaild_skip_dir_write (xfs/xfs_mxfs_dlm.c) or the pal chokepoint (pal/linux/xfs_buf.c right after the existing skip_dir_write call ~line 2004), for a dir DATA/block buffer (xfs_dir3_data_buf_ops / xfs_dir3_block_buf_ops):
- FAST PATH: `bp->b_mxfs_dir_gen >= owner_ip->i_dlm_dir_gen` → return (no skip, no disk read). The owner ip + its i_dlm_dir_gen are already resolved in mxfs_buf_xfsaild_skip_dir_write (info->dir_gen).
- SLOW PATH (bgen < dgen, the stale-tenure case — was 16/272 daddr=120 writes at dirwr=1): plain-bdev-read the daddr (mxfs_pal_bdev_read_plain_bdev — pattern at pal/linux/xfs_buf.c:2052-2063, coherent under fua_disable=1), count live dirents in buffer vs disk (mxfs_dir3_data_fingerprint, used by P29 at xfs_buf.c:2177), and SKIP (emulate clean ioend: b_flags|=XBF_DONE; xfs_buf_ioend; return) IFF disk is a VALID same-owner dir3 data/block header with MORE live dirents (disk_cnt > buf_cnt). Else fall through (avoid the sess16/sess23 fresh-block false-positive: a freshly-created block has bgen stale-looking but disk is NOT a valid richer block).
- Add always-on ratelimited P-DATACLOBBER-SKIP log. VALIDATE at dirwr=0 with tests/drc_loop.sh 8 — expect readdir-short gone + the skip firing on the stale-tenure rounds.

### NOTE: b_mxfs_dir_gen stamping — verify a fresh/current-tenure DATA block reliably carries bgen==i_dlm_dir_gen (else false-positive). sess16 Edit-1 stamped b_mxfs_dir_gen in xfs_dir3_data_init but check it's still present (the file changed). The mxfs_dir_data_track modify hook stamps b_tenure_id (NOT b_mxfs_dir_gen) — b_mxfs_dir_gen is set on read (xfs_da_read_buf) + init.

### Bug B (AG double-alloc EFSCORRUPTED) + Bug C (borderline ~284s timeout) remain separate; not seen in iter1-2 production (Bug B was C22056240 iter3). Keep mht=300 default. test VMs healthy (no wedge).
