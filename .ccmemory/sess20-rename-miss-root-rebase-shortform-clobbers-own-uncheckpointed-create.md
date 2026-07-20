---
name: sess20-rename-miss-root-rebase-shortform-clobbers-own-uncheckpointed-create
description: sess20(ccloop) ROOT of tcp_dlm_scaling rename-revalidate-miss at sf_mht=100: mxfs_dlm_dir_modify_refresh->mxfs_dir_rebase_shortform reloads the short…
metadata:
  type: project
---

## sess20 (ccloop) — rename-revalidate-miss root cause traced

### Chain: tcp_dlm_scaling test2 `echo>n2_r1; mv n2_r1 n2_r1.done` → the rename's pre-RMW guard (xfs_inode.c:4320 `xfs_dir_lookup_locked` for src) gets ENOENT for n2_r1 → clean-abort → mv fails → 0 rounds.

### Why the lookup misses test2's OWN private file: before the guard, `mxfs_dlm_dir_modify_refresh(src_dp)` (xfs_mxfs_dlm.c) calls `mxfs_dir_rebase_shortform(dp)` when `dp->i_dlm_dir_gen != dp->i_dlm_dir_evicted_gen` (a PEER advanced the shared-dir gen between test2's create and rename). rebase_shortform RELOADS the shortform dir's inline data FROM DISK. If test2's n2_r1 create is committed-in-journal but NOT yet checkpointed to the on-disk dinode (or the reload FUA-reads the platter before the create's iflush lands), the reload OVERWRITES test2's in-core dir (which HAD n2_r1) with the disk image (WITHOUT n2_r1) → lookup miss.

### So the rename-miss = shortform reload CLOBBERING the node's own un-checkpointed create. At `inode_mht_ms=300` (high), handoffs/gen-advances are RARE so a rebase rarely lands between a node's create and its immediate rename → tcp_dlm_scaling passes. At `dir_sf_mht_ms=100` (the format-gate), handoffs are frequent → rebase fires mid-workflow → flaky clobber. Same family as the dir_reuse low-mht coherency bug ([[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]]) and the sess84/sess49 shortform-dir lost-update / 3-way-merge work.

### FIX DIRECTIONS (next session): (a) make mxfs_dir_rebase_shortform a MERGE that KEEPS the node's own committed/un-destaged dirents (never clobber own in-flight work — like the dir_release_invalidate undestaged-keep-guard) rather than a blind disk-reload; (b) ensure the sf_mht release path fully CHECKPOINTS (iflush durable) the create before the gen can advance / before any reload reads disk; (c) pragmatic: raise sf_mht toward 130 (fewer handoffs → fewer rebases; keep 8-node tcp_dlm_scaling <60s, ~49s est at 130) — reduces but may not eliminate the flake. See [[sess20-4tcp-16of17-tcp_dlm_scaling-rename-revalidate-miss-at-low-sfmht]].
</body>
</invoke>
