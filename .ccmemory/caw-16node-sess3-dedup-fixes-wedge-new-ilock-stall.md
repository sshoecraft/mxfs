---
name: caw-16node-sess3-dedup-fixes-wedge-new-ilock-stall
description: 16/caw sess3 BREAKTHROUGH: noino_bast_dedup+bast_wq_max_active (build D8BEF5A5) ELIMINATE the dir_reuse@16 WEDGE (0 exhaustion/EIO). New narrower blo…
metadata:
  type: project
---

## 16/caw dir_reuse WEDGE — SOLVED; new narrower blocker exposed (ccloop 26c41354 sess3, 2026-07-06)

Supersedes the unlock-CAS theory in [[caw-16node-sess3-fua-saturation-hypothesis-and-lever-map]]. Build **D8BEF5A5** (from 28A80F8C←3DC2B488←DC39A8DC). All fixes GATED, default 0.

### THE dir_reuse@16 wedge ROOT (fully RULE-4 proven this session, 4 runs)
Chain: hot shared-dir inode (ino=131), 16 nodes create/unlink → in-core inode reclaimed → peers BAST the reclaiming node → `mxfs_dlm_noino_bast_work_fn` queues ONE work item PER BAST on `m_mxfs_inode_bast_wq` (WQ_UNBOUND, max_active=0 ≈512). Two compounding failures:
1. **block-tag exhaustion**: hundreds of concurrent kworkers each do a synchronous FUA `read_slot` in the on-disk unlock → all block in `blk_mq_get_tag` (D-state). PROVEN: 767 D-state on test5, load 733, md5sum hung.
2. **CAS livelock**: hundreds of work items for the SAME ino all retry the unlock CAS on the SAME slot → self-compete → slot mutates faster than any single unlock can RMW it → unlock exhausts even a 5s wall-clock deadline (PROVEN: retry~156, ino=131, `unlock exhausted`→ -EIO → app `Input/output error` + readdir=0).

### THREE gated fixes built (build D8BEF5A5)
- **`bast_wq_max_active`** (xfs_super.c passes it to alloc_workqueue; declared xfs_mxfs_dlm.c): cap mxfs-ino-bast concurrency. FIXES tag-exhaustion. VERIFIED: load 733→58, Dstate recovers. Needed for the MANY-distinct-freed-inode case (rank1 rm-rf frees ~800/round). Default 0=unbounded; ship needs positive (e.g. 16).
- **`caw_unlock_backoff`** (dlm_caw.c, MXFS_CAW_UNLOCK_DEADLINE_MS=5000): wall-clock unlock retry instead of 100-count -EIO. Alone/with-bounding INSUFFICIENT (livelock exhausts even 5s). Probably NOT needed once dedup lands.
- **`noino_bast_dedup`** (xfs_mxfs_dlm.c, global hlist set keyed (mp,ino)): collapse concurrent same-inode no-inode BASTs to ONE in-flight release (dropped dup is safe — peer re-BASTs while our bit set). **THE key fix — kills the CAS livelock.**

### RESULT: `bast_wq_max_active=16 noino_bast_dedup=1` (no deadline) on dir_reuse@16/mpatha
**WEDGE GONE.** Through the ENTIRE +800-1100s critical window (where ALL prior runs spiked to load 58-733 + unlock_exhausted 285→755): load stayed uniform ~1-2, **unlock_exhausted=0, Dstate~0, 0 EIO, 0 shutdown.** Ran clean to ~round-final.

### BUT still FAIL — NEW, NARROWER blocker (single-node straggler, NOT a cluster wedge)
15 nodes finished + idle; **test14 straggled** on ONE stuck op → barrier/2240s timeout FAIL. Root (stacks captured):
- test14 `md5sum` blocked in `open_last_lookups` (file OPEN on shared dir) behind the dir i_rwsem.
- test14 `ls` (statx on the dir) in `mxfs_drain_ilock_read` → `msleep` poll loop: `down_read_trylock(&ip->i_lock)` keeps FAILING because a WRITER holds the dir XFS ILOCK.
- **P132-ILOCK-STUCK ino=131**: `wr_last=xfs_create+0x50b [mxfs] pid=1529 comm=bash` holds the dir ILOCK in WRITE mode for 120s+ → everything queues behind it.
So: a dir_reuse **`xfs_create` on the hot shared dir holds the parent-dir XFS ILOCK across a STUCK DLM acquire** (the documented CLAUDE.md "ILOCK held across CAW poll" design tension; v0.3.148 dropped dp ILOCK across xfs_dialloc — this path is NOT covered or the stuck acquire is elsewhere). All 15 peers idle → likely a LEAKED/stuck lock the create waits on (verify: did any node have unlock_exhausted>0 this run? I only checked test14=0).

### NEXT (RULE 4)
1. Reproduce; capture pid-1529 `xfs_create` FULL stack (it exited before I could — run again, grab it fast) to see EXACTLY what DLM acquire hangs (inode-alloc AG DLM? dir-block DLM for the dirent add? new-inode ilock_begin?). Decode `xfs_create+0x50b` (gdb/objdump on mxfs.ko).
2. Check ALL 16 nodes for a leaked/stuck lock during the stall (who holds the AG/dir lock test14 waits for; is a peer stuck?).
3. Fix pattern: DROP the parent-dir ILOCK across the DLM-polling call in xfs_create (extend the v0.3.148 pattern), so a slow acquire can't block the whole node's dir access.
4. Then re-run dir_reuse@16; if clean, make the 3 fixes default-on (positive bast_wq cap + dedup) and run FULL suite@16 (settle for mode1) + dlm_scaling (mode3) + then 32.

### Infra
Foreground wait-slice pattern works well: `Bash timeout=560000` with internal `while ls -d /proc/$PID; sleep 20; cap 540s`. Monitor high-load nodes for unlock_exhausted (only sampled test1/5/8/12 — wedge victim ROTATES, sample more). Never `find /mnt/shared` under storm (hangs 2min). caw_preflight.sh 16 before every run.
