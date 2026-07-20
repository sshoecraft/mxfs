---
name: compiled-cc-drain-ail-push-wedge
description: Compiled: release/acquire-side drain-pipeline + AG-AIL-push wedges (leaked cluster-buf locks, torn forks) hanging cache_coherency at shutdown.
metadata:
  type: project
tags: [compiled, cache_coherency, drain-pipeline, ail-push, bast, cluster-buf-lock, mode-a]
---

# Drain-pipeline / AG-AIL-push wedges hanging cache_coherency at the shutdown boundary

Central topic: the `cache_coherency` ship criterion (the last of 12 gates) repeatedly
wedges or shuts a node down at the DLM lock-release boundary. Every failure in this
cluster traces to the release-side (or acquire-side) drain pipeline in
`xfs/xfs_mxfs_dlm.c` — specifically how `mxfs_dlm_bast_process` drains dirty state
before `mxfs_v5_dlm_ag_unlock`, and how the inode/dir cluster buffer interacts with the
`_XBF_DELWRI_Q` collision (a documented CLAUDE.md Design Tension). Root always involves
the **root-dir inode ino=128 (sb_rootino)** cluster buffer getting stranded. Marker was
NOT written in any of these sessions — the criterion still FAILS at the head of this
cluster.

## The invariant being served (why the drain exists)
Architectural Invariant #1: **no on-disk DLM unlock without a completed drain pipeline.**
`bast_work_fn`/`bast_process` Phase 2 must drain meta + alloc-buflist + inode buffers +
`blkdev_flush` BEFORE unlock, or the peer reads stale (Mode A regression family). The
GFS2 reference contract ([[GFS2 cache-coherency contract — reference pattern for Mode A and AIL deadlock]])
is the model: `inode_go_sync` (dio_wait → log_flush → fdatawrite+wait → metasync →
`gfs2_ail_empty_gl` = PER-GLOCK AIL drain) before demote, then `inode_go_inval`
(truncate_inode_pages + `GLF_INSTANTIATE_NEEDED` force-reload + dir-hash-inval) on demote.
Two MXFS gaps that reference exposes and that this whole cluster keeps re-hitting:
1. **AIL granularity** — MXFS historically drained with a whole-AIL/whole-AG sledgehammer
   (`xfs_ail_push_all_sync` / `xfs_ail_push_ag_sync`); GFS2 drains per-glock. The whole-AG
   primitive deadlocks under stress because items from OTHER inodes/glocks block the drain.
   Fix direction is per-inode drain, NOT bounded-timeout (bounded-timeout breaks
   correctness — Invariant #1). This is exactly the sess109 fix below.
2. **Cache invalidation on demote** — throw-and-reload (GFS2 `GLF_INSTANTIATE_NEEDED`) is
   safer than MXFS's `i_dlm_mode`/`pag_dlm_cached` validity tracking, which has bugs.

## Chronology / build progression

### sess79 (build `DA1CF4D8`, KEEP) — reg-file BAST-release durability
Established cache_coherency (not rsync_paired) as the real blocker; trust
`.criteria_results.json` + fresh run over the resume narrative. Landed deterministic
reg-file durability on BAST release in `mxfs_dlm_bast_process` (S_ISREG &&
`mxfs_reg_release_durable`): replaced non-deterministic 50×/100ms
(log_force + `xfs_ail_push_ag_sync`, which xfsaild trylock-skips under load → releases
with disk di_size=0 → peer reads empty) with: **early-out if `!in_ail && !pinned`** →
else loop ≤8: `xfs_log_force(SYNC)` → `xfs_imap_to_bp` → `xfs_iflush_cluster(bp)` →
`xfs_bwrite(bp)` → `blkdev_issue_flush`. `P-REG-DURABLE-FAIL` = 0 all nodes;
cross_write_read PASS in isolation. **The `!in_ail && !pinned` early-out is load-bearing**
— v1 (`A8A048F5`) did an unconditional `log_force(SYNC)` first and regressed rsync_paired
105%→137%; v2 with the early-out kept 103% and durability. Never remove it. Open at the
time: unlink bnobt double-free SHUTDOWN + dir-block reader staleness (separate blockers).
See [[sess79_lessons]].

### sess101 (build `286311EE`, KEEP) — unlink_visibility PASS, acquire-side drain
Acquire-side `mxfs_dir_drain_evict_data_blocks` (~L766) gated its clear-XBF_DONE evict on
`DONE && !dirty && !in_ail && !pinned && !delwri`. The **`!in_ail` guard was the
lost-update source**: a node acquiring dir EX during a concurrent create/delete storm kept
its OWN in-AIL cached dir block (committed but log-tail-pending) and RMW'd that STALE base,
durably dropping a peer's just-committed dirents. Signature: a node's own `rm` returning
ENOENT on a CONTIGUOUS RANGE of files it created, no I/O error. **Fix: gate becomes
`(DONE && !pinned)`** — in-AIL/dirty/delwri now evicted too; only PINNED stays a hard skip
(clearing DONE on pinned corrupts, sess64). Safe now because publish-before-notify (sess97)
fences every committed dir change to the LUN before any peer is told, so a cold-read sees
the durable image (contradicts sess99's "aggressive cold-read stale" which predated
publish-before-notify). Use `xfs_buf` DONE-clear, NOT `xfs_buf_stale` (drops rhashtable
entry while AIL refs it → ghost/duplicate buf corruption). Decisive instrument: **P-DIRWR
write-trace** (pal/linux/xfs_buf.c:2003) merged across all 4 nodes by realns — first
`date -u -s` all nodes to a common second (they drift ~1.5s/node). Note: the read-path
twin `mxfs_dir_evict_data_blocks` (L379) STILL has the old `!in_ail` skip — apply the same
in-AIL-safe evict there if a visibility residual shows. See [[sess101_lessons]].

### sess109 (build `C7393A5A`, KEEP) — AG-AIL push wedge FIXED (the core fix)
The `test_rename_visibility` 900s wedge fixed. Root (proven via instrumentation +
blocked-task stacks, RULE 4): `mxfs_dlm_bast_process` honored Invariant #1 with a
**whole-AG drain** `xfs_ail_push_ag_sync(AG(ip))`. Lock inversion under the NEWARCH
-EDEADLK chokepoint: `rm`→`xfs_remove`→`xfs_lock_two_inodes` locks lower inode ip0 fully
(DLM + `down_write(ip0->i_lock)`), then `xfs_ilock(ip1)` → CAW returns **-EDEADLK** →
chokepoint schedules `bast_process(ip1)` and waits uninterruptibly while rm still holds
ip0->i_lock EXCL. `bast_process(ip1)` drains AG(ip1); ip0 is in the SAME AG, dirty in AIL;
`xfs_iflush_cluster` does `xfs_ilock_nowait(ip0,SHARED)` → FAILS → `continue` skips ip0 →
ip0's AIL item never drains → whole-AG wait spins forever. Instr:
`P67-INSTR AG-AIL-STALL ... stuck_ino=ip0 buf_locked=0 pin=0 ili_fields=0x4001 in_ail=1`.
Second signature `buf_locked=1` = ip's cluster buf locked on `pag_mxfs_alloc_buflist`
(`_XBF_DELWRI_Q`), only drained by AG-bast Phase2, not the inode path.
**Fix:** new `mxfs_ail_drain_inode_sync(ip)` waits ONLY for ip's OWN inode log item to
leave the AIL (poll `XFS_LI_IN_AIL` under `ailp->ail_lock`, loop `xfs_ail_push_all`).
Invariant #1 only needs IP durable; siblings carry their own DLM locks; IP's ILOCK is FREE
in the chokepoint path so xfsaild flushes ip while skipping ILOCK-held siblings.
`bast_process` both whole-AG drain blocks REPLACED with: `log_force(SYNC)` +
`mxfs_dlm_ag_drain_alloc_buflist(mp,pag)` + dir `mxfs_dir_flush_data_blocks` if S_ISDIR +
**sess29 settle (msleep20 + log_force MUST precede the wait** else premature `!in_ail` →
Mode A) + `mxfs_ail_drain_inode_sync`. Verified: AG-AIL-STALL = 0 all 4 nodes;
cross_visibility PASS. **Unmasked next bug**: test1 NULL-deref `xfs_dir2_sf_lookup+0x4b` ←
xfs_lookup ← statx, `ip->i_df.if_data == NULL` — the shortform reload-clobber race
(a dir inode reload frees/swaps `i_df.if_data` while a concurrent ILOCK_SHARED lookup
reads it). See [[sess109_lessons]].

### sess111 (build `413C9D5D`, KEEP if proven) — release-drain wedge on ino=128
On clean build-87726318 run, cache_coherency shut test2 down at t≈100s:
`DLM inode lock unrecoverable: ino=128 mode=3 rc=-110` (xfs_mxfs_dlm.c:3973, -ETIMEDOUT
after 3× caw_lock). NOT bnobt double-free. Holder test1 showed
`SESS50-STARVE ino=128 our_mode=5 waiter_mode=3 waiters=8 h_ex=1` + `P109-INODE-DRAIN
ino=128 ... still in_ail pin=0 ili_fields=0x0` — test1's `bast_process` release WEDGED in
`mxfs_ail_drain_inode_sync`: the item is in_ail, iflushed (ili_fields=0), unpinned, but
`xfs_ail_push_all` can never make it leave the AIL. **Mechanism = the `_XBF_DELWRI_Q`
collision**: ino=128 (root dir, SHORTFORM fmt=1) has dirents inline in the dinode, so
durability is the INODE-CLUSTER buffer. The iflush that pushes ino=128 into its cluster
buffer happens at bast step4-5, AFTER step2's `drain_alloc_buflist` already ran; the
cluster buffer then carries `_XBF_DELWRI_Q` but sits on `pag_mxfs_alloc_buflist`
(mxfs-managed) → xfsaild's `xfs_buf_delwri_queue` returns false → never submitted → item
stuck `XFS_ITEM_FLUSHING` forever. The sess109 fix only covered the pushable case.
**Fix:** when stuck (`iter≥8 && pin==0 && still in_ail`), re-run
`mxfs_dlm_ag_drain_alloc_buflist(mp,pag)` ONCE for ip's AG — it splices
`pag_mxfs_alloc_buflist` and `xfs_buf_delwri_submit`s the parked cluster buffer → IO
completion → `xfs_iflush_done` pulls the item from AIL → release completes, no -ETIMEDOUT.
Provably safe (empty-list no-op). Enhanced `P109-INODE-DRAIN` probe to dump `cbuf_rc`
(-EAGAIN=locked by other holder, -ENOENT=not cached, 0=got it), `cbuf_flags` (0x400000=
`_XBF_DELWRI_Q`, 0x100000=`_XBF_MXFS_ALLOC_QUEUED`, 0x20=XBF_DONE), `cbuf_pin`, `redrained`.
If a P109 line shows `cbuf_rc=-EAGAIN` → re-drain won't fix → find the buffer-lock holder
(this is what sess112/113 chase). See [[sess111_drain_wedge_fix]].
Handoff [[sess111_handoff_status]]: `413C9D5D` deployed all 4, cc_run4 IN PROGRESS and
HEALTHY past the ~100s shutdown point (P109-INODE-DRAIN=0, rc=-110=0, all mnt UP) at ~155s
elapsed — strong sign the fix holds, full run unfinished. Methodology: cache_coherency
buffers stdout until done (log stays 0 bytes; judge via node dmesg but peek sparingly);
`P109-INODE-DRAIN` only prints at `iter&255` (~2.5s stuck) while the fix engages at iter≥8
(~80ms), so P109 can legitimately stay 0 even when redrain fired — decisive signal is
rc=-110/unrecoverable staying 0 + all nodes mounted through the whole run.

### sess112 (build `6403DE59`, deployed pending) — ROOT pinned to leaked b_sema, force-unlock FAILED
Blocker on this path = release-side drain wedge in `mxfs_ail_drain_inode_sync` for ino=128.
Enhanced probe (build `A39E1130`, `lb_*` fields) + full task-stack dump nailed buffer
state: `lb_flags=0x20` (**XBF_DONE ONLY** — NOT XBF_WRITE, NOT `_XBF_DELWRI_Q`, NOT
XBF_STALE), `lb_onlist=0` (off ALL lists), `lb_pin=0`, `lb_locked=1` (b_sema.count==0),
`lb_hold=4`; inode `in_ail=1 pin=0 ili_fields=0x0`. **This is exactly the state right after
`xfs_iflush_cluster()` returns 0 and BEFORE `xfs_bwrite()` — an abandoned flush.** Full
`/proc/*/stack`: NO thread holds the buffer (only the drain kworker in msleep), no SCSI/blk
errors → **b_sema is genuinely LEAKED**. Trigger: NEWARCH chokepoint `P109-EDEADLK ino=128
req=5` (PR→EX upgrade hits -EDEADLK, self-queues bast_work → drain), preceded by
`SESS50-STARVE ino=128`. Second face still present: 8× `P93-REVERT-CLOBBER` from xfsaild
(stale bnobt nr=2 over disk_nr=3, all 4 AGs) at mount, one-time burst. Ruled out as leak
site by code-read: `xfs_inode_item_push` (always relse), `xfs_iflush_cluster`+`merge_dirs`,
both durable paths — all pair `iflush_cluster==0` → bwrite+relse ⇒ leaker is a **RACE on
the SHARED cluster buffer** (ino=128 shares its cluster with siblings). **FAILED FIX
(reverted, build `5B40B6AA` `P112-DRAIN-RECOVER`)**: force `xfs_buf_unlock`(leaked sema) →
re-lock → `xfs_bwrite` → relse HARD-HUNG test1 (ping alive, all shells dead) the moment it
fired. Force-`up()` on a sema with any real holder corrupts. Both AIs (Gemini+Grok): do NOT
bolt recovery onto the drain-in-BAST locus — re-architect where the drain runs (GFS2 glock
workqueue). Build `6403DE59` removed force-unlock, added safe leaker-capture
`P112-IFLUSH-CALLER ino=128 caller=%pS` in `xfs_iflush_cluster` right after
`__xfs_iflags_set(ip,XFS_IFLUSHING)` (rate-limited, root-dir only, no lock manipulation) —
the LAST caller before the P109 wedge = the path that abandons the flush. See
[[sess112_lessons]].

### sess113 (build `5E2660AC`, BUILT not deployed) — ROOT NAMED: merge_dirs forced-FUA
**Method win (KEEP)**: added `void *b_lock_ip` to `struct xfs_buf` (xfs/xfs_buf.h), set to
`__builtin_return_address(0)` in `xfs_buf_lock()`+`xfs_buf_trylock()` (pal/linux/xfs_buf.c),
cleared in `xfs_buf_unlock()`. Drain probe `P113-DRAIN-WEDGE` prints `holder=%pS`. Named the
leaker in ONE repro where 90 sessions of code-reading failed. **PROVEN (build `1F8B4DD1`)**:
the wedge = ino=128 inode-cluster buffer LEAKED-LOCKED,
`lb_flags=0x20 lb_hold=4 lb_onlist=0 lb_locked=1 holder=xfs_inode_item_push+0x92`, stable
across iter 256..4352. `+0x92` disassembles to the instruction right after
`call xfs_buf_trylock` (line 771 of `xfs_inode_item_push`) → xfsaild's push trylocked the
buffer and it was never unlocked; NO thread in D-state holds it. State = post-iflush_cluster,
pre-delwri_queue window; the only blocking op there is
**`mxfs_iflush_cluster_merge_dirs(bp)`** at the END of `xfs_iflush_cluster` (xfs/xfs_inode.c
~4013), which does a SYNCHRONOUS forced SCSI FUA read (`mxfs_pal_scsi_read_fua_bdev`) while
holding the cluster buf lock. `merge_dirs` is `void` (can't error-return), so Gemini's
error-bubble theory is out — the mechanism is the FUA read stalling/erroring on the SCST
target (`fua_disable=1` default since sess94 exists precisely because forced-FUA reads
misbehave here; merge_dirs bypassed that gate). **Fix (build `5E2660AC`)**:
`mxfs_iflush_cluster_merge_dirs` returns early `if (mxfs_fua_disable)` — when FUA disabled,
reads are coherent via shared cache so the FUA overlay is unnecessary AND is what wedges the
flush. Added `extern int mxfs_fua_disable;` to xfs_mxfs_dlm.h; drain reverted to PASSIVE +
b_lock_ip probe. See [[sess113_lessons]].

## Recurring failure modes (deduplicated)
- **`_XBF_DELWRI_Q` collision** — cluster buffer parked on `pag_mxfs_alloc_buflist`
  (mxfs-managed, `_XBF_MXFS_ALLOC_QUEUED`) is invisible to xfsaild's `xfs_buf_delwri_queue`
  (returns false) → item stuck `XFS_ITEM_FLUSHING`. Root of the sess111 timeout.
- **Whole-AG / whole-AIL drain sledgehammer** — deadlocks under lock inversion when a
  sibling inode in the same AG is ILOCK-held by another thread (rm holding ip0). Replaced by
  per-inode `mxfs_ail_drain_inode_sync` (sess109). Matches GFS2 per-glock granularity gap.
- **Leaked cluster-buf b_sema** — buffer left `XBF_DONE`-only, off all lists, locked, no
  holder, post-iflush_cluster/pre-bwrite (sess112). Named as `xfs_inode_item_push+0x92`
  trylock never released, wedged in `merge_dirs` forced-FUA (sess113).
- **-EDEADLK chokepoint** — NEWARCH PR→EX upgrade returns -EDEADLK, self-queues bast_work →
  drain; recursively waits uninterruptibly while holding ip0->i_lock EXCL.
- **`SESS50-STARVE`** — EX holder never releases while ≥8 waiters queue on ino=128; peer EX
  eventually -ETIMEDOUT (rc=-110) shuts the node down.
- **acquire-side stale-base RMW** — `!in_ail` skip in dir evict keeps a stale in-AIL base,
  durably drops a peer's committed dirents (sess101 rm-ENOENT-on-range).
- **Shortform reload-clobber** — `xfs_dir2_sf_lookup+0x4b` NULL-deref when a dir reload
  swaps `i_df.if_data` under a concurrent ILOCK_SHARED reader (unmasked by sess109 fix).
- **bnobt double-free / `P93-REVERT-CLOBBER`** — separate AG-coherency blocker, surfaces
  ~1/2 runs; not the drain wedge.

## Hard rules learned (do NOT repeat)
- **Never force-`up()`/force-unlock a leaked b_sema and re-drive it** — hard-hangs the node
  (sess112 `5B40B6AA`; sess113 active own-the-flush drain both = hard hang, no ping/ssh/sysrq).
- **Never `xfs_bwrite`/force-unlock from the BAST kworker** — `xfs_bwrite` on a buffer still
  carrying `_XBF_DELWRI_Q` corrupts XFS buf-list invariants (fatal); calling
  `drain_alloc_buflist`=`xfs_buf_delwri_submit` in a loop compounds it (sess113). Passive
  drain only soft-wedges (debuggable); active recovery hard-hangs.
- **Use DONE-clear evict, never `xfs_buf_stale`** on an in-AIL clean buffer (sess101).
- **Keep the `!in_ail && !pinned` early-out** in reg-file release durability — removing it
  regresses rsync_paired (sess79).
- **Never bounded-timeout the drain** to escape a wedge — breaks Invariant #1 correctness
  (sess27/GFS2 reference); fix granularity instead.
- Both external AIs converge on the same architectural rec: **move the drain OUT of the BAST
  locus into a GFS2-style demote workqueue** rather than patching recovery onto it.

## Repro / infra
- Clean reboot ALL 4 (`virsh -c qemu:///system destroy+start`, ~70-90s for NFS) before
  every trusted run — a wedged kworker holds the module ref → rmmod-busy → RESET_FAIL;
  then `bash tests/reset4.sh 4`; then `dmesg -C` all 4. Run with `fua_disable=1`, `instr=0`.
- Repro: `tests/repro_rvwedge.sh` OR `run_tests.sh --test test_rename_visibility` with
  `MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests`; watch dmesg for `AG-AIL-STALL`/oops.
- `tests/criteria/cache_coherency.sh --nodes 4` is the criterion; `verify_ship.sh` runs all
  12 in one pass. reset4 (~480-540s) + a criterion exceeds the 600s foreground cap → run as
  separate background tasks and wait for completion (stdout is buffered when backgrounded).
- Full design writeup: `/src/mxfs/CACHE_COHERENCY_ISSUE.md`.

## State at head of this cluster (sess113)
`merge_dirs` forced-FUA identified as the leaker (build `5E2660AC` fix BUILT, NOT deployed).
Next: clean reboot 4, `reset4.sh 4`, confirm `5E2660AC`, `dmesg -C`, run cache_coherency —
success = no `P113-DRAIN-WEDGE` and more subtests pass, then `verify_ship.sh`. If the wedge
persists, `P113-DRAIN-WEDGE holder=` still names the leaker; consider Gemini Option A (move
merge BEFORE the IFLUSHING loop, return -EAGAIN on failure) or the GFS2-style demote-workqueue
re-arch. Marker NOT written — criterion still FAILS.
