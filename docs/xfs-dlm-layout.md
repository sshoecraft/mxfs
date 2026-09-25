# The XFS-side DLM layer: file layout

The XFS side of MXFS cluster coordination (the per-inode lock cache, AG
locks, inode-cluster locks, the release pipeline, recovery and publication)
is 32 files, `xfs/xfs_mxfs_*.c`, that share one private header,
`xfs/xfs_mxfs_dlm_priv.h`.  The interface the rest of MXFS calls is
`xfs/xfs_mxfs_dlm.h`; nothing outside the 32 files includes the private
header.

Until 0.89.89 all of it was one file, `xfs/xfs_mxfs_dlm.c`, of 65,664
lines.  Past line 65,535 the kernel's bug table, which stores a `WARN`/`BUG`
site's line in 16 bits, reported the wrong line; a file that size also
cannot be reviewed, bisected or navigated.

## Files

| file | id | holds |
|---|---|---|
| `xfs_mxfs_dlm.c` | 1 | core: per-AG lock mutex helpers, BAST queueing, demoter claims, the transition trace ring, statistics, inode DLM init, statfs baselines, `mxfs_dlm_cache_init` |
| `xfs_mxfs_authority.c` | 5 | inode authority tenures and inactive-release certificates |
| `xfs_mxfs_iget.c` | 6 | coherent inode reloads at iget |
| `xfs_mxfs_durable.c` | 7 | block-device flush epochs, destage kick, AIL drains, inode-cluster and directory-inode durability |
| `xfs_mxfs_dir_bmbt.c` | 8 | directory and file bmbt tracking and eviction, recovery-image eviction |
| `xfs_mxfs_sb.c` | 9 | superblock summary counters under the cluster summary lock |
| `xfs_mxfs_debug.c` | 10 | test injectors, dump triggers, debugfs surfaces |
| `xfs_mxfs_dir_data.c` | 11 | directory data blocks: platter audits, durability, flush, removed-set |
| `xfs_mxfs_dir_evict.c` | 12 | directory block ownership, eviction, consumer refresh |
| `xfs_mxfs_dir_modify.c` | 13 | directory modification: reloads, shortform rebase, peer merges, epochs |
| `xfs_mxfs_fallible.c` | 14 | per-task context: directory drains, recovery tasks, fallible acquires |
| `xfs_mxfs_obligation.c` | 15 | the F4 obligation registry, inode-cluster writes, the obligation freeze |
| `xfs_mxfs_relbar.c` | 16 | release barrier, release certificates, release-gate faults |
| `xfs_mxfs_bast.c` | 17 | inode BAST processing (`mxfs_dlm_bast_process`) and notification |
| `xfs_mxfs_noino.c` | 18 | BASTs for inodes not in core |
| `xfs_mxfs_reload.c` | 19 | inode reload from the platter (`mxfs_dlm_reload_inode_under`), incarnation poisoning |
| `xfs_mxfs_dir_sf.c` | 20 | shortform directory ownership and three-way merge |
| `xfs_mxfs_ilock.c` | 21 | inode lock admission: `mxfs_dlm_ilock_begin`, end, try, demote |
| `xfs_mxfs_publish.c` | 22 | publishing unpublished inodes and directories |
| `xfs_mxfs_evict.c` | 23 | inode eviction, deferred reaping, the LRU sweep |
| `xfs_mxfs_pubob.c` | 24 | unlinked-inode store and publication obligations |
| `xfs_mxfs_ag_meta.c` | 25 | AG metadata handoff, publication writes, stale-buffer invalidation |
| `xfs_mxfs_disk.c` | 26 | coherent reads of on-disk inodes |
| `xfs_mxfs_coherency.c` | 27 | read coherency: getattr, peer flush, directory durability signals |
| `xfs_mxfs_ag_lock.c` | 28 | AG lock acquisition and buffer drains |
| `xfs_mxfs_open.c` | 29 | open protection, close release, the PR sweep |
| `xfs_mxfs_ag_unlock.c` | 30 | AG unlock, transaction AG handoff, AG BAST work |
| `xfs_mxfs_buf.c` | 31 | buffer tracking, xfsaild write gates, cached-view invalidation |
| `xfs_mxfs_join.c` | 32 | peer join, orphan and unlinked-bucket sweeps |
| `xfs_mxfs_recovery.c` | 33 | fencing, quarantine, foreign replay, replay gates |
| `xfs_mxfs_mount.c` | 34 | the mount recovery barrier |
| `xfs_mxfs_iclus.c` | 35 | inode-cluster locks |

The id is the file's `MXFS_TU_ID` (below).  Ids 2-4 belong to
`xfs/xfs_icache.c`, `pal/linux/xfs_iops.c` and `xfs/xfs_filestream.c`.

## How the files share state

- **One private header.**  `xfs_mxfs_dlm_priv.h` carries the includes,
  every macro and type the files use, and one declaration of every function
  or variable that one file defines and another uses.  A function used only
  in its own file stays `static`.
- **Module parameters live with their users.**  A `module_param*`, its
  `MODULE_PARM_DESC`, and an `EXPORT_SYMBOL` sit in the file that defines
  the variable or function they name.  The parameter namespace is the
  module's, so `/sys/module/mxfs/parameters` did not change (639 parameters
  before and after the split).
- **Call sites carry their file.**  Every file defines `MXFS_TU_ID` before
  including the header.  `igrab`/`iput` pass it to the reference tracker
  (`site=fileN:lineM`), and the forensic fields that record where something
  happened (`i_dlm_demoter_line`, `i_mxfs_auth_line`, `i_dlm_epoch_src`,
  `b_mxfs_done_site`, the transition and demoter rings, the AG mutex sites)
  store `MXFS_SITE`: the id in the high 16 bits, the line in the low 16.
  Probes print them as `file:line` through `MXFS_SITE_FMT` /
  `MXFS_SITE_ARGS`, declared in `xfs_mxfs_dlm.h` for printers elsewhere in
  the tree.

## Adding code

- Put a function in the file whose subject it is; if nothing fits, the
  subject probably deserves a file.
- A new cross-file function gets its prototype in `xfs_mxfs_dlm_priv.h`
  (or `xfs_mxfs_dlm.h` if code outside these files calls it), never a local
  `extern` at the call site: the compiler checks callers only against the
  declaration in scope, and a local `extern` with the wrong parameter list
  compiles cleanly (`scripts/extern_decl_audit.py` finds any that remain).
- A new file gets the next unused `MXFS_TU_ID` and a row above.

## What the split did not change

The split moved whole top-level definitions and changed no function body
except to record `MXFS_SITE` where `__LINE__` was recorded.  It was made by
`scripts/split_c_file.py` from a map built by `scripts/c_toplevel_map.py`,
and checked by symbol comparison: every function and every global of the
old object exists in the new ones, and the module parameters are identical.

## Phase helpers of the three long functions

`mxfs_dlm_bast_process`, `mxfs_dlm_reload_inode_under` and
`mxfs_dlm_ilock_begin` were each a sequence of guarded phases grown by
accretion, 3,600 to 5,200 lines long.  Their large phases are now static
helpers defined just above them in the same file (`mxfs_bast_*`,
`mxfs_reload_*`, `mxfs_ilock_*`), each carrying the comment that described
the phase.  The three are now about 1,500, 1,800 and 700 lines.

The helpers were cut by `scripts/extract_block.py`, which works from clang's
AST of the kernel build and refuses any block it cannot move without
changing meaning.  How a helper's parameters read follows from that:

- a local the phase only reads is passed by value under its own name;
- one it writes is passed as `<name>_io` and copied in at entry and out at
  every exit, so the phase's text is unchanged;
- one whose address is taken anywhere in the parent, or a function-local
  static, is passed as `<name>_ref` and written `(*<name>_ref)`, so the
  phase works on the parent's own object;
- a `return` in the phase stores the value and leaves with
  `MXFS_BLOCK_RETURN`, and a `goto` out of it leaves with
  `MXFS_BLOCK_GOTO + k` (`xfs_mxfs_dlm_priv.h`); the call site returns or
  jumps.

`tests/extract_block_selftest.sh` holds the tool to that: each construct is
moved, compiled at -O0 and -O2 and run against the untouched program, and
the cases it must refuse are refused.
