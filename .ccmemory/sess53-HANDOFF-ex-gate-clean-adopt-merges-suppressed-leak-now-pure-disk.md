---
name: sess53-HANDOFF-ex-gate-clean-adopt-merges-suppressed-leak-now-pure-disk
description: sess53 HANDOFF: build 86DDB26D. iunlink face FIXED (idempotent). GPT EX-gate+clean-adopt SUPPRESSED dir merges but dirent leak PERSISTS as pure on-di…
metadata:
  type: project
---

## sess53 HANDOFF — criterion NOT met (tcp_dlm_scaling dirent leak persists). Build 86DDB26D.

### THE CONFIG (overturned sess52): PLAIN `./run.sh 2 tcp` (pure defaults, dir_pr_release_fast=1, sf_merge=1) + P52 guards is the criterion baseline = 4/5. Option B (=2) was WRONG. Do NOT pass MXFS_EXTRA_MODARGS. See [[sess53-BREAKTHROUGH-plain-defaults-plus-P52-guards-17of17]].

### Two tcp_dlm_scaling faces (the 16 other tests are RELIABLE every run):
- **FACE 2 iunlink corruption shutdown — FIXED (KEEP, idempotent-iunlink, VALIDATED firing h1/h2 with shutdown=0).** xfs/xfs_iunlink_item.c xfs_iunlink_log_dinode: when `old_ptr==next_agino && i_next_unlinked==next_agino` (free/reuse race left only the item's captured old_agino stale; chain already correct) → idempotent no-op instead of force-shutdown. P53 diag also there.
- **FACE 1 durable dirent RESURRECTION — STILL OPEN (~1/5).** node2's rename SOURCE dirent (n2_rN, sometimes a burst) survives durably (both nodes, drop_caches). THE blocker.

### GPT-5.5 consult (RULE 5, full design in this session's transcript) ROOT for FACE 1, CONFIRMED + 2 fixes landed:
ROOT: "Disk is authoritative ONLY at EX-acquire boundaries; in-core is authoritative WHILE owning EX." A reload+3-way-SF-merge firing while a node owns the dir EX (or re-applying a stale prior-tenure delta at acquire) re-adds removed dirents. TWO fixes (KEEP, in 86DDB26D):
  1. **EX-tenure reload suppression** (xfs_mxfs_dlm.c mxfs_dlm_dir_modify_reload_prelock ~2646): `if (dp->i_dlm_mode==MXFS_LOCK_EX) return;` — no mid-tenure disk→in-core reload while owning EX.
  2. **clean-adopt at acquire** (xfs_mxfs_dlm.c reload merge ~7746): only run mxfs_dir_sf_merge_into when `!xfs_inode_clean(ip)` (have a real uncommitted delta); a CLEAN inode at acquire ADOPTS disk (no union of stale prior-tenure image).
RESULT (m1): **dir SF merges are now SUPPRESSED (sfmerge=0 both nodes)** — the merge vector is CLOSED. But the leak STILL happens.

### THE REMAINING VECTOR (m1 forensics, ino 8961304, leftover n2_r123): PURE ON-DISK resurrection.
With merges off, node1 cleanly ADOPTS disk; P62-RELOAD-FORK-SHRINK shows `incore_size==disk_size` every time → disk ITSELF has n2_r123. So node2's rename source-removal is NOT becoming durable, OR node1 stale-FLUSHES it back. P51-REL held_mode=5(EX) clean_skip=0 **drain_ms=0** (release drain did ~nothing). This is the write/flush side = GPT Step-4 flush-fence territory ([[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]]).

### NEXT (decisive): determine publish-gap vs stale-flush.
1. Run PLAIN suite with `MXFS_EXTRA_MODARGS="dirwr=1"` (enables P-SFREL-VERIFY: compares in-core vs disk AFTER the shortform release flush). If it logs `STALE-DISK` for the leak ino → node2's release publish (mxfs_dlm_dir_inode_durable→mxfs_inode_cluster_durable, drain_ms=0) is BROKEN for shortform removal. If `DURABLE` → node1 stale-FLUSHES over it (xfsaild/cluster false-share) → need the flush fence in mxfs_iflush_cluster_merge_dirs (xfs/xfs_inode.c) for a NON-EX dir slot (overlay disk), and check why the existing foreign-slot overlay / DIRAHEAD-overlay (sess53, added under fua_disable ~5349, DORMANT/unproven — consider revert) doesn't catch it.
2. REFUTED this session (do NOT repeat): sf_merge=0 (leaks+regresses fence_during_write); DIRGEN-BUMP bump-gen-on-release (reverted); DIRAHEAD-overlay alone (never fired on leak).
3. Repro: PLAIN `PLAIN=1 bash tests/tcp/fg_one_run.sh <lbl>` (~9min, ~1/5 leak). Helper reboots+runs foreground (RUN_TIMEOUT 565). warm-FS repeat driver INVALID (node2 trans_cancel cascade). Marker NOT written.
Related: [[sess53-dirent-resurrection-multinode-stale-flush-plus-merge-union]] [[sess53-residual-durable-dirent-resurrection-stale-dir-flush]]
