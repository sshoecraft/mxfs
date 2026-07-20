---
name: reference-clustered-fs-sources
description: Local source paths for reference clustered filesystems (GFS2, OCFS2, kernel DLM) + their coherency models, for MXFS design comparison.
metadata:
  type: reference
---

# Reference clustered-filesystem sources (local)

Paths to study when designing/fixing MXFS coherency + lock handoff. All read locally.

## GFS2 — symmetric shared-disk, kernel DLM glocks
`~/src/linux/fs/gfs2/` — `glock.c`, `glock.h`, `glops.c`, `lock_dlm.c`.
Demote protocol in `do_xmote()` (glock.c): `go_sync()` (log_flush + filemap_fdatawait + ail_empty, SYNCHRONOUS) → `go_inval()` (truncate_inode_pages) → THEN `dlm_lock()` unlock. Acquire: `GLF_INSTANTIATE_NEEDED` → `gfs2_inode_refresh()` re-reads disk. Anti-starvation = min hold-time (gl_hold_time HZ/5) + relies on DLM queue fairness.

## OCFS2 — symmetric shared-disk, LVB-based
`~/src/linux/fs/ocfs2/` — `dlmglue.c`, `dlmglue.h`.
Downconvert thread (`ocfs2_unblock_lock`): checkpoint check → `ocfs2_data_convert_worker` (fdatawrite + truncate_inode_pages) → set LVB → `ocfs2_downconvert_lock`. **LVB** (`struct ocfs2_meta_lvb`) passes i_size/times/**generation** with the lock grant; `ocfs2_meta_lvb_is_trustable` = generation match → skip disk read. Anti-starvation = `OCFS2_LOCK_BLOCKED` flag set on BAST blocks new local shared acquirers (`ocfs2_may_continue_on_blocked_lock`).

## Kernel DLM — the fairness reference
`~/src/linux/fs/dlm/` — `lock.c` (`can_be_granted`, `queue_conflict`, `grant_pending_locks`), `dlm_internal.h` (3 queues: grant/convert/wait per `dlm_rsb`), `ast.c`.
**Core anti-starvation rule:** a new request is NOT granted immediately if convert queue OR wait queue is non-empty (`_can_be_granted` now=1 check) → a queued EX blocks new PR grants. Convert queue always checked before wait queue.

## Prior MXFS attempts + userspace
`~/src/mxfs.{1,2,3,wtf,x}` — older MXFS versions w/ their own bug journals (see [[reference_prior_mxfs_versions]]).
`~/src/ocfs2-tools`, `~/src/xfsprogs-dev`, `~/src/scst` (the SCST iSCSI target MXFS runs on).
