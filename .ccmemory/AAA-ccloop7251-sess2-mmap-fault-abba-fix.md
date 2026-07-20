---
name: AAA-ccloop7251-sess2-mmap-fault-abba-fix
description: sess2 ROOT FIXED (0.11.8 B4AF5F8): mmap-fault ABBA — fault holds locked folios then takes cluster ilock; bast drain invalidate needs those folios. Fa…
metadata:
  type: project
tags: [mxfs, deadlock, mmap, dlm, bast]
---

# mmap-fault vs bast-drain ABBA (32/cawd mmap_coherency killer) — FIXED 0.11.8

## Symptom
mmap_coherency 32/cawd: 31 nodes FAIL at "mc barrier verify", 1 node
NO_TERMINAL_RECORD, 600s ceiling. Passed on 0.11.6 by luck — probabilistic
window, not a regression.

## Live capture (test20, 2026-07-18 15:44Z)
- python3 (mmap reader of node2.bin, ino 52955592): D-state,
  wchan=mxfs_dlm_ilock_begin, stack filemap_fault → do_sync_mmap_readahead →
  read_pages → iomap_readahead → xfs_read_iomap_begin → xfs_ilock →
  mxfs_dlm_ilock_begin. P73-WAITSTALL req=3(PR) mode=3 state=3(DEMOTING)
  ex=0 pr=0 bast_pend=0 **work_busy=2(RUNNING)** every 30s, 20+ min.
- kworker/u9:0+mxfs-ino-bast: D-state, mxfs_dlm_bast_process →
  invalidate_inode_pages2 → __folio_lock → folio_wait_bit_common.
- test2 (writer) had RELEASED cleanly at 15:25:49 (P141-UNLK-EXCLR EXIT=full)
  — wedge 100% local to test20.
- Cascade: wedged ino → AG AIL push can't finish → kworker mxfs-ag-bast in
  xfs_ail_push_ag_sync_bounded msleep loop (peers spam P12-AGBAST-RX
  page_ms→483s) → next chunk's fio D-state in __mxfs_ag_dlm_lock →
  cancel_work_sync. One local ABBA poisons the whole board.

## Mechanism
readahead/read_folio get folios ALREADY LOCKED (page_cache_ra_unbounded /
filemap_create_folio), THEN iomap_begin takes ILOCK→cluster DLM. If a bast
drain (demote) is running for that inode, ilock_begin waits for it; the
drain's invalidate_inode_pages2 waits for the task's locked folio. Buffered
read syscalls are immune: xfs_file_buffered_read counts a DLM hold via
IOLOCK_SHARED before any folio lock (in mxfs, IOLOCK/ILOCK both map to the
ONE per-inode DLM lock; MMAPLOCK maps only to the local invalidate_lock).
mmap faults were the ONLY reader path with no outer hold.
Trigger volume: relatime + fresh-written files → every node's FIRST read
does an atime update transaction = cluster EX ⇒ 32×32 cross-read = EX BAST
storm during the read phase.

## Fix (pal/linux/xfs_file.c, 0.11.8 srcversion B4AF5F8AEBDE6028740AB90)
- xfs_filemap_fault (non-DAX): mxfs_dlm_ilock_begin(ip, MXFS_LOCK_PR) around
  filemap_fault; end after.
- __xfs_write_fault (non-DAX): begin/end EX around mxfs_iomap_page_mkwrite
  (same inversion: iomap locks folio then takes ILOCK_EXCL).
- DLM hold ONLY — never i_rwsem in fault context (write() takes rwsem then
  faults → rwsem-vs-mmap_lock inversion).

## Why safe (all verified in source)
- bast_notify with holders>0 DEFERS: sets ISTATE_BAST, queues NO work
  (xfs_mxfs_dlm.c ~15902-15933). Drain can only be running if it started
  before our fault-entry begin — which waits it out BEFORE any folio lock.
- Nested inner acquires admitted: FIX-1 pre-loop arm (state==BAST +
  holders>0 + mirror grant ≥ req, ~21417) and RELFLUSH arm; last ilock_end
  1→0 refires the deferred release.
- Folio locks held at hold-drop resolve at read-bio completion (I/O-bound,
  DLM-independent) — drain's invalidate waits bounded time only.
- ilock_begin/end pairing tolerates unpaired ends (P71 guards, underflow
  checks) — same unconditional call pattern as xfs_ilock/xfs_iunlock.

## Watch codes
- P47-FILEBLOCK in fault comm (python3/etc) = something still blocking.
- P73-WAITSTALL recurrence with work_busy=2 = fix insufficient.
- P79-NESTADMIT with comm of a faulting task = fix engaging as designed.

## Debug technique that found it (reusable)
1. criteria.json record names the barrier + NO_TERMINAL_RECORD node count.
2. Fleet sweep: pgrep leftover test process + dmesg hung-task count per node.
3. /proc/PID/wchan + /proc/PID/stack of the survivor.
4. /proc/PID/maps → ino; dmesg grep ino on waiter AND presumed holder.
5. Stack sweep of all kworkers matching subsystem → both deadlock sides.
