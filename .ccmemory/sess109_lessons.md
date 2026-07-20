---
name: sess109_lessons
description: sess109 — AG-AIL push wedge FIXED (C7393A5A KEEP): targeted ip-only inode drain replaces whole-AG sledgehammer in bast_process. Unmasks sf_lookup NUL…
metadata:
  type: project
---

# sess109 (2026-06-06) — AG-AIL push wedge FIXED, next bug = sf_lookup NULL deref

## PROVEN FIX (KEEP) — build `C7393A5A01DEBFD00AC9DE4`
The cache_coherency `test_rename_visibility` 900s wedge (sess108 P0 blocker) is FIXED.

### Root cause (proven via instrumentation + blocked-task stacks, RULE 4)
`mxfs_dlm_bast_process` honored invariant #1 with a **whole-AG drain**
`xfs_ail_push_ag_sync(AG(ip))`. Under the NEWARCH chokepoint, EVERY -EDEADLK
upgrade routes through bast_process. Deadlock (lock inversion):
1. `rm`→`xfs_remove`→`xfs_lock_two_inodes(ip0,ip1)` locks the LOWER inode ip0
   fully (DLM + `down_write(ip0->i_lock)`), then `xfs_ilock(ip1)`→
   `mxfs_dlm_ilock_begin(ip1)`→ on-disk CAW returns **-EDEADLK**.
2. Chokepoint schedules `bast_process(ip1)`, recursively waits (uninterruptible)
   for ip1's drain. **rm still holds ip0->i_lock EXCL.**
3. `bast_process(ip1)` drains AG(ip1). ip0 is in the SAME AG, dirty in AIL.
4. `xfs_iflush_cluster` (xfs_inode.c:3931) does `xfs_ilock_nowait(ip0,SHARED)`
   → FAILS (rm holds EXCL) → `continue` SKIPS ip0 → ip0's AIL item never
   drains → whole-AG wait spins forever → rm waits forever.
Instr: `P67-INSTR AG-AIL-STALL ... stuck_ino=ip0 buf_locked=0 pin=0 ili_fields=0x4001 in_ail=1`.
Second signature: `buf_locked=1` = ip's cluster buf locked on `pag_mxfs_alloc_buflist`
(`_XBF_DELWRI_Q`), only drained by AG-bast Phase2, not the inode path.

### The fix (xfs/xfs_mxfs_dlm.c) — Gemini-validated (RULE 5)
New `mxfs_ail_drain_inode_sync(ip)`: waits ONLY for ip's OWN inode log item to
leave the AIL (poll `XFS_LI_IN_AIL` under `ailp->ail_lock`), looping
`xfs_ail_push_all`. Invariant #1 only needs IP durable; siblings carry their own
DLM locks. IP's ILOCK is FREE in chokepoint path → xfsaild flushes ip while
skipping ILOCK-held siblings. Cluster-buffer write safe (Gemini: in-core buf
holds last-flushed sibling content, no torn write). NO bounded abort (caller
waits uninterruptibly, bound by inv#1).
bast_process both whole-AG drain blocks REPLACED with: log_force(SYNC) +
`mxfs_dlm_ag_drain_alloc_buflist(mp,pag)` (unlock alloc-queued cluster bufs) +
dir `mxfs_dir_flush_data_blocks` if S_ISDIR + **sess29 settle (msleep20+log_force
MUST precede the wait** else premature !in_ail → Mode A) + `mxfs_ail_drain_inode_sync`.

### Verified
AG-AIL-STALL = **0** on all 4 nodes (was spinning forever at 75K+ iters).
cross_visibility PASS. No wedge.

## NEXT BUG (loop) — pre-existing, was MASKED by the wedge
test1 NULL-ptr Oops: `xfs_dir2_sf_lookup+0x4b` ← xfs_dir_lookup ← xfs_lookup ←
statx. `ip->i_df.if_data == NULL` (reads NULL+1 = sfp->i8count). This is the
**reload-clobber race** state.md/phase0_results.md noted: a dir inode RELOAD
frees/swaps `i_df.if_data` (shortform fork) while a concurrent lookup reads it.
Only test1 crashed (others 0). The wedge used to hit first; now the test
progresses to the lookup and crashes. Form new hypothesis: who reloads
shortform if_data without excluding ILOCK_SHARED readers.

## Infra
- Build/deploy: `make modules`; hard-reboot all 4 (`sudo virsh -c qemu:///system
  destroy/start`) because wedged kworker holds module ref → rmmod busy; then
  unload DKMS auto-load; `bash tests/reset4.sh 4`; verify `cat /sys/module/mxfs/srcversion`.
- Repro: `tests/repro_rvwedge.sh` OR run_tests.sh `--test test_rename_visibility`
  with `MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests`. Watch dmesg for
  `AG-AIL-STALL` (wedge) / oops.
- Instrumentation added to `xfs/xfs_trans_ail.c` AG-AIL-STALL print: pin,
  libuf_null, buf_pinned, ili_fields, in_ail, buf_flags (KEEP, diagnostic).
</body>
