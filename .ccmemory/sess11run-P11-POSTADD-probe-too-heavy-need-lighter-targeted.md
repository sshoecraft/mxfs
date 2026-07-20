---
name: sess11run-P11-POSTADD-probe-too-heavy-need-lighter-targeted
description: sess11(ccloop): P11-POSTADD probe (dump ALL dir block names after each addname) is O(n^2)/perturbing — drc4 verify reads '?' (spurious). dirwr-gated/…
metadata:
  type: project
---

## sess11 (ccloop) — P11-POSTADD probe added but TOO HEAVY; lighter design for next session

### Tree state: build 06F46F9E = clean baseline 1D3115A5 + the P11-POSTADD probe (DEFAULT-INERT, dirwr/instr-gated). Buildable. (one harmless -Wmissing-prototypes warning on mxfs_dir_dump_block_names.)

### P11-POSTADD probe (added this session, KEEP-or-replace)
- Helper `mxfs_dir_dump_block_names(struct xfs_inode*, const char *tag)` in xfs/xfs_mxfs_dlm.c (~1247, EXPORT_SYMBOL): iterates dp->i_df DATA blocks, xfs_buf_incore (no I/O), dumps each cached block's live dirent names via mxfs_dir_block_names. Prints `P11-POSTADD <tag> ino daddr done names=[...]` or `CACHED=0`.
- Called from xfs/libxfs/xfs_dir2.c right after xfs_dir_createname() success (after P-CRNAME-DONE), gated dirwr||instr + ino<=256 + name starts 'node'.
- GOAL: prove whether a just-committed dirent is present in-core RIGHT AFTER addname (before commit/durable_signal) — to bisect the durable-loss revert window (revert confirmed to be in the addname→durable_signal window, UNDER ILOCK_EXCL, on a CACHED buffer).

### PROBLEM: it fires on EVERY storm-dir create and dumps ALL blocks' names = O(dir_size) per create = O(n^2). Under dirwr=2 the log volume + CPU PERTURBED the cluster so drc4_repro's cold-readdir verify returned `?` (spurious fail, not a clean dirent-loss repro). So it did NOT yield clean data this run. Heisenbug class (cf sess42: per-op I/O / instr=1 flips pass/fail).

### NEXT SESSION: replace with an O(1) targeted probe
After xfs_dir_createname() success, do ONE xfs_dir_lookup of args->name (fresh xfs_da_args) to resolve the just-added entry's data-block (args->blkno / dataptr), then log ONLY that one block's daddr + whether mxfs_dir_block_names of THAT block contains the name. O(1) per create, low perturbation. Then a dirwr capture shows, for the lost entry: present-in-core-after-addname? (yes => revert is later, in commit/durable_signal) vs absent (=> addname/split itself didn't land it in a flushable cached block). Combined with the existing durable_signal P-RELFLUSH/P11-CLEANSKIP (which already proved the entry is absent at flush), this isolates the EXACT reverting step. Prime suspects: dir leaf/data SPLIT during a concurrent create relocating the entry to a block whose extent isn't covered by the flush; or buffer xfs_buf_stale+realloc.

### See [[sess11run-HANDOFF-evict-fix-insufficient-revert-under-ilock-next-probe]] [[sess11run-ROOT-committed-dirent-reverted-by-evict-before-publish-GPT-fix]]. Criterion NOT met (4/tcp dir_reuse_coherency durable single-dirent loss; 2/tcp passes).
