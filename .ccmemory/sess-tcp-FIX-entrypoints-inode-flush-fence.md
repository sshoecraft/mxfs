---
name: sess-tcp-FIX-entrypoints-inode-flush-fence
description: CODE ENTRY POINTS for the dir-inode-fork-flush fence fix (GPT design): xfs_iflush (xfs_inode.c:4298, fence before xfs_inode_to_disk @4860); note exis…
metadata:
  type: project
---

## Implementation entry points for [[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]]

### Step 4 (inode-flush fence — the key fix) insertion point:
- **xfs_iflush()** at `xfs/xfs_inode.c:4298`. It serializes the in-core inode to the cluster buffer via **`xfs_inode_to_disk(ip, dip, ...)` at xfs/xfs_inode.c:4860**. Insert the fence JUST BEFORE 4860: if `S_ISDIR(VFS_I(ip)->i_mode)` AND multi-node (`mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(...)`) AND the fork is NOT validated under the current DLM epoch (stale), DO NOT call xfs_inode_to_disk for the data fork (skip/abort the flush of this inode, requeue). Determine "stale fork" via: not holding EX (i_dlm_mode != EX) OR i_dlm_dir_gen > i_dlm_dir_loaded_gen (fork loaded before peer's last mod). Start as a pr_warn DETECTOR ("P-STALE-IFLUSH-FENCE") to PROVE node2 flushes block0→stale-daddr while in NL or gen-stale, THEN enforce (skip).
- Existing nearby mxfs hooks in xfs_iflush: `mxfs_iflush_force_bmbt_durable(ip)` @4821 (forces bmbt durable — Step 3 lives near here), and **`mxfs_iflush_cluster_merge_dirs(bp)` @ xfs_inode.c:5024 (called @5471)** — ALREADY a dir-merge-during-iflush mechanism; review whether it can be extended to reconcile the fork instead of flushing stale, OR whether it is itself flushing the stale fork.
- Existing detector `P33-TODISK-DIRSHRINK` @ `xfs/libxfs/xfs_inode_buf.c:515` (inside xfs_inode_to_disk @471) already flags a dir data-fork SIZE shrink at flush — extend/reuse for the daddr-divergence (block0 fsb/daddr changed) case.

### Step 2 (epoch stamp): i_dlm_dir_gen / i_dlm_dir_loaded_gen already exist (xfs_inode.h). loaded_gen is set on reload (mxfs_dlm_reload_inode / acquire). The fence (Step 4) and the flush-fence must compare these. The fork is "valid for current epoch" iff loaded_gen == dir_gen AND (ideally) reloaded since the peer's last write.

### Step 1 (reload no-bail): mxfs_dlm_reload_inode bounded down_write_trylock @ xfs_mxfs_dlm.c:6717 (1000 retries + cond_resched, then BAIL leaving i_dlm_stale set). Verify it actually succeeds for the dir reload; if it bails under create contention, the stale fork persists.

### Step 3 (release flush dinode home): mxfs_dlm_dir_inode_durable @ xfs_mxfs_dlm.c:4858 (called in bast release path). Ensure it iflush+bwrite the dinode/bmbt HOME (not just log_force) before unlock.

Build at handoff: 2045BCE9 (= 6E20D7F9 + P-GROW0 instrument @ xfs_dir2_grow_inode, gated dirwr/instr). Clean compile. Marker NOT written.
