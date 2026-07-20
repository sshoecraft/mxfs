---
name: sess54-RESIDUAL-six-hypotheses-ruled-out-next-is-reload-revert
description: sess54(ccloop) 8/tcp dir_reuse residual: SIX hypotheses RULED OUT by instrumentation (read-RMW, double-alloc, extent-divergence, keepguard, mepzero,…
metadata:
  type: project
---

## sess54 — 8/tcp dir_reuse residual: exhaustive RULE-4 elimination

### KEEPER (net-positive, A/B 2/4 vs 1/4): build has `dir_addname_epoch_refresh=1` +
fail-closed-on-epoch-regression (eliminated P54-MEPZERO). Build 1A78AEBD (= 8705E114 +
the P54-NOTEX-MODIFY probe). All my probes are capped/cheap diagnostics; the only
behavior change vs baseline is refresh1+fail-closed.

### The residual loss SIGNATURE (stable across many runs):
- ALWAYS a SECOND-WAVE `.md5` sidecar (node6_f47.md5, node3_f13.md5, node8_f36.md5,
  node3_f1.md5, ...), SINGLE dirent (readdir=799/800), DURABLE + CONSISTENT on all 8
  nodes (LOOKUP_ENOENT REREAD_MISS). Round varies (1,2,6,11,13). Round-1/early can be a
  MASS variant (83 lost spread across nodes ~= 2 data blocks). ~50% of clean-reboot runs fail.
- The `.md5` wave is created AFTER a `sync` of the f-files (dir_reuse_coherency.sh:77),
  so the dir is already large (node format, many data+leaf+free blocks) when the lost
  entry is added.

### SIX hypotheses RULED OUT with instrumentation (drc_phantom_diag captures all):
1. Read-side stale-base RMW — P28E (dir_addname_coherent=1 FUA ground-truth compare) diff=0
   EVERY time (in-core==platter at addname). NOT a stale read.
2. Extent-map divergence — P28E pcur=0 (in-core daddr always holds a valid dir block for ino).
3. In-core dir-block double-alloc — P54-DOUBLEMAP=0 (xfs_dir2_data.c:889 I/O-free iext scan).
4. Keep-guard-blocked stale refresh — P54-KEEPGUARD=0.
5. Epoch-regression/unavailable — P54-MEPZERO=0 (after the fail-closed fix).
6. Write-side stale reflush — `dir_tenure_reflush_skip=1` (sess37 destaged-zombie in-AIL dir
   DATA reflush skip) tested via modarg: 3/3 FAIL, does NOT help (confirms sess50 relepoch
   refutation).
7. Modify-without-EX serialization hole — P54-NOTEX-MODIFY=0 (probe at xfs_dir2_data_use_free:
   EVERY dirent placement holds dir DLM EX). Modification IS serialized.
Also: P42-STALEEX-SERVE=0, MX-DOUBLEGRANT=0, P-STALEMASTER-GRANT=0 (DLM master serialization
intact). P62-RELOAD-FORK-SHRINK shrink=1 → 0. P78-FMT-TORN-FIX (working writer fix) ~100/round.

### THEREFORE the remaining mechanism is a RELOAD-REVERT or COMMIT/LOG-ORDERING issue at the
data-block level that NO addname-time probe sees: dirent f47.md5 is placed under EX into block
B (durable), then block B is later REVERTED to a pre-f47.md5 image — either (a) an EX-acquire
RELOAD of the dir reverts block B's in-core image (and re-destages it), or (b) a transaction
commit / log checkpoint ordering writes an older block-B image over the newer one. Both are
INVISIBLE to the addname coherent-compare (which only runs when the block is first read clean
per tenure) and to use_free (which sees the correct in-core at placement).

### NEXT SESSION decisive instrument (the RELOAD + AIL-flush path, NOT addname):
- Probe the EX-acquire dir RELOAD (mxfs_dlm_reload_inode / xfs_da_btree.c read path): for a
  dir DATA block of ino<=256, when the reload replaces/invalidates an in-core block, FUA-read
  the platter and log whether the post-reload in-core content LOST a dirent vs the platter
  (reload-revert caught in the act).
- Probe the dir DATA buffer WRITE submission (xfs_buf_submit / mxfs_buf_xfsaild_skip_dir_write
  call site, xfs_mxfs_dlm.c:22087): FUA-read the platter daddr right BEFORE writing the in-core
  buffer; if the platter has a dirent the in-core buffer lacks, this write is the durable
  clobber — log b_mxfs_dir_epoch, dir_gen, in_ail, dlm_mode, comm.  This DIRECTLY catches the
  durable revert write that all addname-side probes miss.
- Correlate the caught write/reload with the specific lost `.md5` name via daddr.

Marker NOT written (8/tcp dir_reuse ~50%). 1/2/4 tcp believed passing (sess48/58). See
[[sess54-RESIDUAL-is-writeside-AIL-stale-flush-not-readside]]
[[sess54-FIX-addname-epoch-refresh-default-on-reduces-dirreuse-loss]].</body>
