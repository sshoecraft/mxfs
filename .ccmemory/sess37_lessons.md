---
name: sess37_lessons
description: sess37 — ROOT-CAUSED + FIXED the single-node log wedge (ail_head_lsn=0 grant-balloon). The deep blocker from sess36 is solved.
metadata: 
  node_type: memory
  type: project
  originSessionId: 9112edd7-e173-4cbb-8d95-7a9271ac1c17
---

2026-05-29 (sess37). **SOLVED the single-node log WEDGE** that blocked all heavy-load
criteria and consumed all of sess36 (16 continuations of wrong size/AIL theories).

**RULE-4 capture path (decisive):** gated instrumentation (mxfs.instr) in
xfs/xfs_trans_ail.c xfsaild_push (`P-LWEDGE`) showed items were NOT pinned/locked/
flushing — `count=0` every cycle because `ail_target` was stuck at `0x100000000`
(cycle1 block0) below the whole AIL. Then `P-LGRANT` in xfs/xfs_log.c
xlog_grant_head_wait dumped the grant: `rgrant=4261446260` (~4.26 GB) on a 32 MB log
→ free clamped to 0 → every writer wedges in xlog_grant_head_wait. Balance counters
(`P-LGRANT2`) showed `subbed` was NEGATIVE → `xlog_grant_sub_space` called with negative
bytes (atomic64_sub of negative = ADD). `P-LSUBNEG`+dump_stack pinned it:
`xlog_grant_return_space(old=0x0, new=0x100000540) diff=-4260724736` from
`xlog_cil_ail_insert` on the FIRST checkpoint commit.

**ROOT CAUSE:** `ail_head_lsn` starts at 0 (cycle 0). `l_tail_lsn` is seeded to
`0x100000000` (cycle 1, block 0) in xlog_alloc_log, but `ail_head_lsn` is NOT.
A freshly-mkfs'd mxfs log is ZEROED (cycle 0 at block 0), so mount's `xlog_find_tail`
hits the fresh-log special case (xfs_log_recover.c ~1261: `head_blk==0 &&
xlog_get_cycle==0` → `goto done`) which leaves `ail_head_lsn=0`. First CIL checkpoint:
`xlog_grant_return_space(old=0, new=cycle1_lsn)` → `xlog_lsn_sub` sees
hi_cycle(1)!=lo_cycle(0), cross-cycle branch `l_logsize - BBTOB(lo_block - hi_block)`,
uint32 `(0 - hi_block)` underflows → garbage ~-4GB diff → grant += ~4GB → permanent
wedge. Upstream mkfs.xfs avoids this by stamping the log (cycle 1 + unmount record) so
the special case is never taken; mxfs's mkfs leaves it zeroed. Upstream kernel code is
BYTE-IDENTICAL — it's a latent upstream bug only mxfs's zeroed-log mkfs triggers.

**FIX (1 line + comment):** in xfs/xfs_log_recover.c fresh-log special case, before
`goto done`: `log->l_ailp->ail_head_lsn = atomic64_read(&log->l_tail_lsn);`
(l_ailp is valid there — same fn writes ail_head_lsn at ~1182/1217).

**VERIFIED:** full recursive `rsync -a /root/open-gpu-kernel-modules/ /mnt/shared/w/`
single-node now completes rc=0, 8137/8137 files, `diff -r` clean (only dangling
symlinks present identically in src+dst). neg-sub count=0. NO wedge. Build srcversion
`3CF4D8DAD71DD73C509C462` (VERSION 0.4.6 + this fix). Reproducer:
`tests/repro_logwedge_full.sh test1` (full recursive rsync; the older subset
`repro_logwedge.sh` did NOT reliably wedge).

Disproven sess36 theories now explained: log SIZE (4/16/32MB) only delayed the wedge
because a bigger log = more grant headroom before the ~4GB bogus add exhausts it. It
was never about xfsaild/AIL push or slice LSN math — purely the first-checkpoint grant
underflow. The 32MB slice (tools/mkfs_mxfs.c:1145 log_node_count*8192) can stay; harmless.

Instrumentation added (all gated behind mxfs.instr, default 0, zero prod impact):
xfs_trans_ail.c P-LWEDGE; xfs_log.c P-LGRANT/P-LGRANT2/P-LRET/P-LSUBNEG + grant
balance counters. Keep for future log debugging.

## Mode A (cross-node concurrent same-name create) — partial fix, build B9A6EC22

ROOT CAUSE (proven via instrumented repro_modea): xfs_create trusts the VFS
negative dentry from ->lookup and never re-checks existence. Single-node the
parent i_rwsem serializes; cross-node a peer creates the same name in the
lookup→create window → two inodes for one name (split-brain). On a FRESH mkfs
root is SHORTFORM (fmt=1, dirents inline in inode); reload refreshes the inode
fork so shortform coherency works once we re-check. After ~15 entries root
converts to BLOCK dir (fmt=2, separate data block at daddr 120) and the
acquire-side reload's H18 stale-walk uses xfs_buf_trylock and SKIPS locked
bufs → reads a stale dir data block → split-brain returns.

FIX SHIPPED (B9A6EC22): wired up the dormant D9 pin mechanism
(mxfs_clayer/pinned_resource.c, was implemented but NEVER called/honored):
 - bast_notify: defer BAST when i_dlm_pin_count>0 (new branch before the
   holders==0 immediate branch).
 - ilock_end: don't release while pin_count>0.
 - xfs_create (xfs/xfs_inode.c): mxfs_inode_pin(dp) + xfs_ilock(dp,EX) +
   xfs_dir_lookup_locked() existence re-check BEFORE trans_alloc (clean tp so
   -EEXIST cancels safely; canceling a dialloc-DIRTIED tp force-shuts-down the
   FS — that was the EIO). Drop local ILOCK after check (pin, not rwsem, holds
   the DLM) so xfs_dialloc doesn't hit the v0.3.148 AG-drain inversion. unpin
   on every exit path (fires deferred BAST → flush+release to peer).
 - new helper xfs_dir_lookup_locked() in libxfs/xfs_dir2.c (lock-free variant;
   stock xfs_dir_lookup takes ilock_data_map_shared → recurses DLM hook → wedge).

repro_modea 20 iters: 19-20/20 fail (before) → 11/20 (after). Shortform iters
pass; remaining fails are (a) block-dir split-brain [H18 trylock-skip reads
stale dir data block on acquire] and (b) EEXIST-loser sees nothing [stale VFS
negative dentry: after EEXIST, mkdir -p's stat reuses the cached negative
dentry and can't see the winner's dir; XFS has no d_revalidate].

## Mode A pin/check approach FAILED — reverted (build back to 9C72EEFE log-wedge-only)

CRITICAL LESSON: the pin/check approach (mxfs_inode_pin + early xfs_ilock(dp,EX) +
existence check + xfs_iunlock + dialloc + xfs_ilock(dp,EX) at line 801) does a SECOND
EX DLM acquire on a slot the pin still holds EX. The CAW DLM re-acquire CAW-compares
the slot expecting it free but finds it EX-owned-by-us → CAW mismatch → `dlm_caw:
caw_slot N I/O error -5 retry 1/5..5/5` → DLM lock rc!=0 → xfs_force_shutdown (EIO).
**Do NOT double-acquire the inode DLM (acquire→iunlock-with-pin→re-acquire same mode).
The CAW slot accounting breaks.** A PR-then-EX UPGRADE is fine (normal); a same-mode
re-acquire of a pin-held slot is NOT.
The d_drop-on-EEXIST (xfs_iops.c) made repro WORSE (20/20, test2 always shuts down) —
because the shutdown (above) cascaded. Both reverted.

BASELINE (clean log-wedge-only 9C72EEFE): repro_modea 16/20 fail (iters 1-4 shortform
OK, 5-20 block-dir split-brain two-inodes). Mode A is a genuine severe unsolved bug.
The dormant D9 pin-honoring in bast_notify/ilock_end + xfs_dir_lookup_locked helper
LEFT IN (harmless, pin_count never set). Gated instrumentation (P-LWEDGE/P-LGRANT/
P-LRET/P-LSUBNEG + xfsaild counters) left in (mxfs.instr default 0).

KEY INSIGHT for the criteria: the test FRAMEWORK barriers (tests/lib/cluster.sh
barrier_signal/wait) use concurrent same-name `mkdir -p $barrier_dir` from all nodes,
then touch node$id + find. So Mode A (concurrent same-name) MUST work for the framework
criteria (cache_coherency/posix_semantics/strong_consistency via run_tests.sh) to pass.
The minimal direct test showed cross-node create ~90ms (not the bottleneck); the
framework slowness is barrier 1s-poll granularity × rounds. cache_coherency TIMED OUT
at the 700s outer wrap (its own set_script_timeout is 900s) — it progressed through
3/4 tests, so it's slow not hung. zero_silent_loss / workload-A use UNIQUE per-node
names (test_concurrent_mkdir: node${id}_dir${i}) → NOT same-name; they need acquire-side
cross-visibility of distinct entries (readdir sees peers' dirs), which works after a
BAST (slow-path reload + FUA). MISSING: scripts/sess88_workload_a_modeN_baseline.sh
(zero_silent_loss's wrapped script does not exist — leftover from mxfs.1).

## Mode A fix v2 (RE-APPLIED with CAW fix) — build 4ADC786A, 8/20 (from 16/20), NO shutdown

The pin/check CAW shutdown was caused by: when a BAST arrives during the pin (state→BAST),
the dir-strict fast-path in mxfs_dlm_ilock_begin requires state==CACHED, so it took the
SLOW path → CAW re-acquire of a slot we already hold EX (via pin) → CAW compare mismatch
→ dlm_caw I/O error → shutdown. FIX: allow the dir fast-path when i_dlm_pin_count>0
(xfs_mxfs_dlm.c ~1349: added `&& ip->i_dlm_pin_count == 0` to the fall-through condition).
The pin guarantees the lock is still held (BAST deferred) and content valid, so fast-path
(holder++) is correct and CAW-safe. RE-APPLIED: pin/check in xfs_create + unpins + d_drop
on EEXIST in xfs_iops.c. Result: repro_modea 8/20 fail, NO shutdown.
 - Iters 3-15 mostly PASS (shortform root). Remaining fails: block-dir split-brain
   (16-20, after root grows past shortform → the existence-check's reload reads a STALE
   dir DATA block: H18 stale-walk trylock-SKIPS locked bufs) + occasional EEXIST-loser
   n2=[] (2,6) + occasional gap-1 race (1).
KEY: the test framework barriers (.mxfs_barriers/<name>, N entries = SHORTFORM) now work
(shortform Mode A fixed) → framework tests should no longer time out on barrier timeouts.
NEXT: block-dir acquire-side reliable refresh (H18 trylock-skip → bounded-wait or FUA) for
zero_silent_loss / test_concurrent_mkdir (TESTDIR grows to block dir). Running cache_coherency
on 4ADC786A to see if shortform fix is enough for that criterion.

## sess37 FINAL build state = 2A5CCF1E90ACC43EB77A31D (VERSION 0.4.6 + fixes)

Contains: (1) LOG-WEDGE FIX (ail_head_lsn seed, xfs_log_recover.c) — solid, verified.
(2) Mode A v2: pin/check in xfs_create + mxfs_inode_pin/unpin wired into bast_notify
(defer when pin>0) + ilock_end (don't release when pin>0) + ilock_begin dir-fast-path
allows pin>0 (CAW-safe) + d_drop-on-EEXIST in xfs_iops.c + xfs_dir_lookup_locked helper.
(3) gated instrumentation (mxfs.instr=0 default). H18 stale-walk LEFT as trylock-skip
(blocking xfs_buf_lock DEADLOCKS — lock inversion, confirmed twice; do NOT retry).
repro_modea 2-node: 16/20 baseline → ~1/12 (shortform) / 8/20 (20 iters incl block-dir).
NO shutdown, NO deadlock on 2 nodes. Build is the NFS-shared /src/mxfs/mxfs.ko.

REMAINING blockers (next session, in priority order):
## sess37 HEARTBEAT-PRIORITY FIX (build 622ADB5B) — prevents the 4-node fencing shutdown

Added `REQ_PRIO | REQ_SYNC` to mxfs_pal_bdev_write_fua (pal/linux/kern.c:757) so the
latency-critical disklock heartbeat + CAW/metadata FUA writes jump ahead of bulk data in
the block-layer queue. RESULT: in cache_coherency --nodes 4, at 144s all 4 nodes stayed
mounted with 0 DLM shutdowns (PREVIOUSLY node3 was fencing-shutdown by ~200s). So the
heartbeat-priority hint prevents the load-induced false-fence cascade. BUT cache_coherency
still slow (barriers still time out 120s each because Mode A on the concurrent same-name
barrier dirs isn't 100% at 4 nodes) — likely still FAILs on visibility assertions / slow.
Created BOTH missing test-infra scripts (syntax-OK, untested on cluster):
scripts/sess88_workload_a_modeN_baseline.sh (zero_silent_loss: N-node shared-dir mkdir storm
of UNIQUE per-node names, counts pre/post-drop_caches visibility, emits fs_silent=/
iters_with_fs_silent_loss=) and tools/mxfs_multinode_bench.sh (rsync_paired: N-node parallel
rsync of open-gpu-kernel-modules to per-node subdirs, seeds SRC from /src NFS to /root,
emits the bench.json .results[] rows rsync_paired expects. Syntax-OK, untested on cluster.
Build 622ADB5B = 2A5CCF1E + heartbeat-priority. This is the NFS-shared ko.

0. **DEFINITIVE (sess37 end): the 4-node shutdown is LOAD-INDUCED heartbeat-starvation
   false-fencing, NOT a setup/registration bug.** 4-node IDLE for 75s (past the 62s fence
   threshold) is STABLE — all 4 stay mounted, no shutdown. Under HEAVY load (Mode A DLM
   thrash + data I/O saturating the shared iSCSI LUN), a node's disklock heartbeat FUA
   write (dlm/disklock.c heartbeat thread, every HB_INTERVAL_MS=2000ms, write_sector_fua
   under ctx->lock) is delayed/starved; after DEAD_THRESHOLD=31 missed checks (62s) the
   survivors fence it (expire_cb → preempt its SCSI PR registration); the fenced node's
   next heartbeat write gets `reservation conflict` → `DLM shutdown`. Cascade: the
   shut-down node can't `touch $barrier_dir/node$id` → barriers time out (120s each) →
   all framework tests fail. FIX DIRECTIONS: (a) prioritize/guarantee heartbeat I/O isn't
   starved by data/CAW I/O (separate queue, or don't hold ctx->lock across the 64-slot
   monitor reads); (b) raise fence tolerance / detect self-fence; (c) reduce load by making
   Mode A DLM efficient. This gates ALL multi-node criteria. Highest priority.
1. **4-node SCSI PR / disklock-heartbeat reservation conflict → DLM shutdown.** cache_coherency
   --nodes 4 FAILED 0/4: node3 got `reservation conflict error sector 131090 (heartbeat
   write)` → `DLM shutdown complete` → `Corruption ... mxfs_dlm_ilock_begin ... Shutting
   down` (the force_shutdown on DLM-lock failure). Node fenced/lost-PR-registration under
   4-node load. Light 2-node clean test does NOT hit it. Investigate dlm/scsipr.c +
   dlm/disklock.c heartbeat + fencing (false-positive fence of a briefly-slow node?, or a
   PR registration race in the 4-node parallel join). This SHUTS DOWN a node → cascades
   (can't signal barriers → all framework tests fail/timeout). HIGHEST priority for the
   framework criteria (cache_coherency/posix_semantics/strong_consistency via run_tests).
2. **Block-dir Mode A** (existence-check reads stale via H18 trylock-skip on locked dir
   buf). repro_modea iters 16-20 (root grown to block dir) split-brain. Need a CAW-safe,
   deadlock-free acquire-side dir-block refresh (NOT blocking xfs_buf_lock).
3. **Missing test scripts**: scripts/sess88_workload_a_modeN_baseline.sh (zero_silent_loss)
   and tools/mxfs_multinode_bench.sh (rsync_paired) DO NOT EXIST — must be created for v5
   (test1-16). Also /root/open-gpu-kernel-modules is ONLY on test1 (rsync_paired needs the
   source on every node — distribute it, or the bench must).
4. cache_coherency criterion has dead MXFS_NODE_OFFSET=16 (harmless; run_tests uses
   get_node_hostname=test${i}).

## ROBUST Mode A fix IMPLEMENTED + WORKS for barriers — build D89D508ED00CC56511652B9

Implemented the design below: REMOVED the early pin/check; added the existence re-check at
the SINGLE xfs_inode.c line-801 acquire (xfs_dir_lookup_locked(tp,...) after xfs_ilock(dp,EX),
held through commit). On EEXIST, orphan the dialloc'd inode tmpfile-style: create with
`XFS_ICREATE_TMPFILE` (nlink=0) + mode S_IFREG|0600 + xfs_iunlink + clean commit + irele →
inactivation frees it (NO dirty-tp cancel/shutdown). Kept d_drop-on-EEXIST (xfs_iops.c) +
heartbeat-priority. Removed pin var/calls (dormant pin-honoring in bast_notify/ilock_end +
ilock-pin-fastpath left, harmless). Compiles clean.
RESULT: **cache_coherency framework barriers now COMPLETE FAST** — test_cross_visibility +
test_rename_visibility ran in ~5s TOTAL (were 245-265s EACH, timing out). So the shortform
concurrent same-name `mkdir -p $barrier_dir` race is essentially closed → barriers work →
the framework criteria become viable. test_unlink_visibility (4 barriers × 2-level 4-way
same-name mkdir -p) still occasionally hits a residual (one barrier ~120s timeout) — the
last ~10% of 4-node Mode A reliability (likely EEXIST-loser visibility or 2-level race).
repro_modea 2-node 8/20 (block-dir cases 16-20 still split-brain: line-801 check reads a
STALE dir DATA block via H18 trylock-skip — blocking xfs_buf_lock DEADLOCKS, need a
deadlock-free acquire-side block-dir refresh). NO shutdown, NO deadlock.
NEXT: (a) close the residual barrier timeout (EEXIST-loser visibility at 4 nodes / 2-level
mkdir -p); (b) block-dir acquire-side refresh for zero_silent_loss. Heartbeat-priority +
robust Mode A together prevent the fencing cascade AND make barriers fast.

FINAL sess37 build = **D89D508ED00CC56511652B9** (NFS-shared /src/mxfs/mxfs.ko). Contains:
log-wedge fix + heartbeat-priority (REQ_PRIO|REQ_SYNC) + robust Mode A (line-801 existence
re-check + tmpfile-orphan on EEXIST) + d_drop-on-EEXIST + simple-trylock H18. cache_coherency
tests 1-2 (cross/rename visibility) now run in ~5s (were 245-265s timing out); test 3
(unlink, .mxfs_barriers grown to BLOCK dir) still times out on the block-dir staleness.
TRIED + REVERTED (made it worse, 20/20): blocking xfs_buf_lock in H18 (DEADLOCK) and
bounded-retry trylock+msleep in H18 (regressed correctness + test2 unhealthy). The block-dir
acquire-side refresh needs a different, safe approach (NOT in the reload msleep path).
NEXT-APPROACH IDEA for block-dir (deadlock-free): a per-inode "dir-data generation" counter
incremented on each DLM (re)acquire-after-BAST; stamp it on the dir-data buf when FUA-read;
in the dir-block READ path (xfs_da_read_buf / xfs_buf_get for dir bufs) force a FUA re-read
+ invalidate when buf.gen < inode.gen — checked BEFORE returning a cached XBF_DONE buf, so
no buf-lock-in-reload is needed (the staling happens lazily at read time when the buf is
naturally lockable, not eagerly under the DLM acquire). Also ensure the RELEASE side writes
the dir DATA home block durably before DLM release (architectural invariant #1) so the FUA
re-read finds the peer's content. Cluster left CLEAN-RESET (test1-2 fresh, unmounted).

DEFINITIVE workload-A measurement (sess88 script, fixed to count only mounted nodes):
4 nodes × 40 dpn, DISTINCT per-node names (no same-name/Mode A), no framework barriers →
expected=160, pre_drop=42, post_drop=49, silent=111. TWO components proven:
 - pre_drop(42) < post_drop(49): drop_caches revealed entries node1's CACHE missed but disk
   HAD → acquire-side cache-staleness (block-dir H18 trylock-skip) confirmed, ~7 entries.
 - post_drop(49) << expected(160): ~111 missing even from DISK → on-disk LOST-UPDATE: nodes
   concurrently RMW the SHARED parent dir's BLOCK (distinct names, but same parent block); a
   node reads a stale parent block, adds its entry, writes back, CLOBBERING peers' entries.
=> The core gating coherency bug is **block-format directory parent-block RMW lost-update**
   (manifests for BOTH same-name and distinct-name concurrent creates into one block dir),
   = the bigger component (~70% loss). The serialization is via the parent's inode DLM, but
   the parent's DATA-BLOCK read for the RMW uses a stale cached/disk copy. The fix must make
   the parent dir DATA block coherent for the RMW: acquire-side fresh re-read (B) AND/OR the
   releasing node must flush the parent's data block home before release (A) so the next
   node's RMW reads the latest. This is why even distinct-name workload-A loses entries.

BLOCK-DIR bug has TWO halves (both must be fixed):
 (A) RELEASE-side (xfs_mxfs_dlm.c bast_process ~line 450 BAST-DIR-STALE walk): after
     log_force+ail_push_ag_sync(inode's AG), it STALES (discards) the dir data bufs. But if
     a dir data block was committed-but-not-yet-home-written (earlier instrumentation:
     bip_in_ail=-1, so ail_push_ag_sync didn't write it — possibly because the dir block's
     extent is in a DIFFERENT AG than the inode, or the CIL→AIL insert hadn't happened),
     staling DISCARDS it → the on-disk home block stays stale → peer reads stale. Fix: ensure
     the dir DATA home blocks are durably WRITTEN before release (push ALL the dir blocks'
     AGs / wait for the specific bufs to reach disk), THEN stale.
 (B) ACQUIRE-side (H18 walk ~line 1060): trylock-skips locked dir bufs → cached stale read.
     **DECISIVE sess37 capture (instr=1, build EED3145C, repro_modea block-dir iters):
     EVERY block-dir reload of root logs `P-H18-INSTR ... blocks=1 staled=0 locked_skip=1
     miss=0` on BOTH nodes.** I.e. the parent dir's single data block buf is ALWAYS LOCKED
     at acquire-reload time (held by in-flight async writeback I/O), so trylock fails 100%
     → never staled → the RMW reads the stale cached block → clobbers peer → lost-update.
     This is THE root, 100% reproducible. NOTE: my earlier blocking-xfs_buf_lock deadlock was
     under the OLD pin-based double-acquire structure (now removed); under the current robust
     line-801 structure the lock is held by I/O (completes independently) so blocking MIGHT be
     safe now — UNTESTED (stopped at context limit). FIX to try next: (i) re-test blocking
     xfs_buf_lock in H18 under the current no-pin structure (tight timeout to catch any hang);
     if safe, it waits for the node's own writeback to drain, then stale+FUA-reread gets the
     peer's durable block. (ii) If it deadlocks, wait for the buf's in-flight WRITE completion
     specifically (not the lock) before staling, or force the acquiring node's prior dir-block
     writeback to fully drain on DLM release so the buf isn't mid-write at the next acquire.
     gotcha: setting instr at runtime needs `echo 1 > /sys/module/mxfs/parameters/instr` WITH
     the space (`echo 1>` is a redirect that writes a newline → sets instr=0!).
     **sess37 RE-TESTED blocking xfs_buf_lock under the no-pin structure: STILL DEADLOCKS
     (repro hung, nodes wedged, timeout-killed). So reload-time invalidation of the locked
     dir buf is fundamentally deadlock-prone (REAL lock inversion, not just independent I/O)
     — RULE OUT the entire reload-time-stale approach (trylock/blocking/bounded-retry all
     exhausted).** The fix MUST be one of: (a) READ-TIME lazy invalidation — a per-inode
     dir-data generation counter bumped on DLM (re)acquire; the dir-block read path forces a
     FUA re-read + invalidate when buf.gen < inode.gen, done when the READER naturally holds
     the buf lockable (no reload-time lock contention); or (b) RELEASE-side — drain the
     acquiring node's prior dir-block writeback fully (so the buf isn't mid-write/locked at
     the next acquire), OR the releasing node ensures peers re-read (FUA gate). (a) is the
     cleanest. Reverted to trylock-skip; final clean build = EED3145C2BA7A11B231F546.
     Fix idea: lazy gen-counter FUA re-read at read-time (deadlock-free), per note above.
     sess37 added GATED diagnostic counters to P-H18-INSTR (build EED3145C2BA7A11B231F546 =
     D89D508E + counters, NO behavior change): logs blocks=/staled=/locked_skip=/miss= per
     reload. Run with mxfs.instr=1 during repro_modea/workload-A and grep P-H18-INSTR to see
     whether the stale block is locked_skip (buf held → need lazy/read-time invalidation) or
     miss (not cached → next read FUA-reads disk, so staleness is from a DIFFERENT block /
     the disk copy itself = release-side). This decides B vs A definitively. EED3145C is the
     current NFS-shared ko (still the good robust-Mode-A state).
Both are EXTENTS/block-format-dir only (LOCAL/shortform is in the dinode → reload reads it
fresh, which is why shortform Mode A + the barriers now work). This is the core 35-session
"Mode A" coherency bug, now split into the two precise halves above with the log-wedge and
fencing cascades removed so it can be worked in isolation.
Confirmed ship-gate: PASS=10 (incl single_node_paired ratio 85% on final build), FAIL=2
(cache_coherency: block-dir barriers; rsync_paired: needs mxfs_multinode_bench.sh — created
this session, untested + 4-node heavy-load fence risk), several criteria unrun (missing
sess88 script / framework block-dir dependence).

## ROBUST Mode A fix DESIGN (IMPLEMENTED above — kept for reference)

The current pin/check does the existence check at an EARLY xfs_ilock+iunlock (before
trans_alloc), then dialloc, then re-acquire at line 801. This leaves gap-1 (two nodes both
pass the early check before either commits) — the residual block-dir/4-node split-brain.
INSIGHT: the check belongs at the SINGLE existing acquire at xfs_inode.c:801
(`xfs_ilock(dp, ILOCK_EXCL|ILOCK_PARENT)` after xfs_dialloc), which is held CONTINUOUSLY
through xfs_trans_commit (line ~855). holders>0 there defers any peer BAST, so no peer can
modify dp between the check and our commit → NO gap-1, NO double-acquire (so NO CAW slot
issue), and NO pin needed. The ONLY obstacle is that xfs_dialloc already dirtied the tp, so
canceling on EEXIST force-shuts-down (XFS_TRANS_DIRTY). SOLUTION on EEXIST: don't cancel —
orphan the allocated inode like xfs_create_tmpfile does (xfs_icreate the inode but skip
xfs_dir_create_child; put it on the unlinked list / set nlink=0 + undo the parent nlink
bump icreate did for a dir; commit cleanly; irele → inactivation frees it), return -EEXIST.
Model on xfs_create_tmpfile (xfs_inode.c) which creates a dirent-less nlink=0 inode and
commits cleanly. Then REMOVE the early pin/check block + the d_drop stays (EEXIST-loser
dentry). This closes gap-1 fully → barriers reliable → framework criteria can pass (with
the heartbeat-priority fix preventing shutdown). Keep the dormant pin-honoring + ilock
pin-fast-path (harmless) or remove. Verify with repro_modea 20-iter (expect 0/20) + cache_coherency.

CORRECT Mode A fix direction (not yet implemented): existence re-check under the SINGLE
existing EX acquire at xfs_inode.c:801 (NO double-acquire), but handle that the tp is
already dirtied by xfs_dialloc (canceling a dirty tp force-shuts-down). Options: (a)
re-check before dialloc while holding dp EX across dialloc — but that's the v0.3.148
AG-drain deadlock; (b) on EEXIST, create the inode then add it to the unlinked list
(O_TMPFILE-style) so it's freed, instead of canceling. Plus EEXIST-loser visibility
(negative dentry — d_revalidate exists in xfs_mxfs_dentry.c but is NOT installed via
s_d_op AND returns 1 unconditionally for negative dentries; installing it risks the
xfs_ilock-rwsem-vs-held-parent-rwsem deadlock in create paths).

PRIOR remaining blocker (now being fixed): cross-node coherency lost-update (Mode A), cache_coherency FAIL.
See [[sess36_lessons]] for that diagnosis (create-path stale-view; DLM serializes
correctly; reload doesn't re-read peer's committed dir block). repro_modea.sh ~19-20/20.
Other criteria (zero_silent_loss, strong_consistency, posix_semantics, crash,
fence_during_write, scaling, rsync_paired, soak) not yet re-run on the fixed build.

## sess37 FINAL — decisive P-H18-LOCKED + fix direction confirmed
Build for handoff = 99A1B4E0BE1EDEFF6B43680 (robust Mode A + gated H18 counters + P-H18-LOCKED diag; 0 errors; NFS-shared).
DECISIVE: every block-dir acquire-reload logs `P-H18-LOCKED ino=128 d=120 flags=0x30 pin=0`.
0x30 = XBF_DONE|XBF_ASYNC; NOT XBF_WRITE(0x2), NOT _XBF_DELWRI_Q(0x400000), pin=0 → the
locked parent dir block is NOT under active write I/O and NOT pinned — it's thread/completion-held.
=> RULES OUT release-side writeback-drain (no pending write) AND explains the blocking-xfs_buf_lock
deadlock (lock inversion with holder). THE FIX = read-time/lazy invalidation: per-inode dir-data
generation counter bumped on DLM (re)acquire-after-BAST; the dir-block read path forces a FUA
re-read + content refresh when the cached buf's stamped gen < inode gen, done when the READER
naturally holds the buf (no reload-time trylock contention, deadlock-free). Implement + verify:
repro_modea (->0 expected), then cache_coherency + zero_silent_loss. This is THE single remaining
gating fix. To re-capture P-H18-LOCKED: insmod mxfs.ko then `echo 1 > /sys/module/mxfs/parameters/instr`
(WITH space) and run repro_modea >=16 iters so root grows to block format.

## sess37 — EXACT deadlock-free hook for the gen-counter fix (implement this next)
The read-time invalidation hook is xfs_buf_read (pal/linux/xfs_buf.c ~712-718):
  if (!(bp->b_flags & XBF_DONE)) { _xfs_buf_read(bp); }   // DONE buf short-circuits here
At this point the CALLER ALREADY HOLDS the buf lock (xfs_buf_get locked it), so clearing
XBF_DONE here to force a re-read is DEADLOCK-FREE (this is the whole point — reload-time H18
can't lock the buf, but the reader path already holds it). Design:
 1. add `uint32_t i_dlm_dir_gen` to struct xfs_inode (xfs_inode.h, i_dlm block); init 0 in
    mxfs_dlm_inode_init; BUMP it in mxfs_dlm_ilock_begin slow-path reload (where i_dlm_stale
    is set, ~xfs_mxfs_dlm.c:1466) for S_ISDIR inodes.
 2. add `uint32_t b_mxfs_dir_gen` to struct xfs_buf (xfs/xfs_buf.h); stamp it = dp->i_dlm_dir_gen
    whenever a dir data buf is read fresh.
 3. the DIR-block read carries dp: hook in xfs_da_read_buf (xfs/libxfs/xfs_da_btree.c:2812,
    has args->dp) OR xfs_dir3_data_read — before returning, if the buf is XBF_DONE and
    bp->b_mxfs_dir_gen < dp->i_dlm_dir_gen, clear XBF_DONE|_XBF_FUA_FRESH (caller holds lock)
    so xfs_buf_read re-reads via the FUA path → fresh peer content; then stamp b_mxfs_dir_gen.
 This invalidates the parent dir block lazily at READ time (when lockable) instead of at
 reload time (when locked) → the RMW reads the peer's committed entries → no lost-update.
 Verify: repro_modea 20 iters (->0), then cache_coherency + zero_silent_loss. Build to start
 from = 99A1B4E0BE1EDEFF6B43680 (clean, all sess37 wins + diagnostics).

## sess37 — gen-counter fix FOUNDATION laid (build 6E90A6D1DE71255D441046B)
DONE (compiles clean, behaviorally still the good robust state since gen has no consumer yet):
 - added `uint32_t i_dlm_dir_gen` to struct xfs_inode (xfs_inode.h, i_dlm block)
 - init = 0 in mxfs_dlm_inode_init (xfs_mxfs_dlm.c ~1855)
 - bump `if (S_ISDIR) ip->i_dlm_dir_gen++` on slow-path re-acquire in mxfs_dlm_ilock_begin
   (xfs_mxfs_dlm.c ~1549, right where i_dlm_stale=true is set)
REMAINING (fresh session — 2 parts, then verify):
 1. add `uint32_t b_mxfs_dir_gen` to struct xfs_buf (xfs/xfs_buf.h).
 2. hook xfs_da_read_buf (xfs/libxfs/xfs_da_btree.c:2812, has args->dp) for DIR data bufs:
    after getting the buf (caller HOLDS the lock → deadlock-free), if XBF_DONE &&
    bp->b_mxfs_dir_gen < args->dp->i_dlm_dir_gen → clear XBF_DONE|_XBF_FUA_FRESH (forces
    xfs_buf_read → FUA re-read of the peer's committed block) THEN set
    bp->b_mxfs_dir_gen = args->dp->i_dlm_dir_gen. Only for whichfork==XFS_DATA_FORK + S_ISDIR.
 Verify: insmod, repro_modea 20 iters (expect ->0, root grows to block format ~iter16),
 then cache_coherency --nodes 4 + zero_silent_loss. New handoff build = 6E90A6D1.

## sess37 — gen-counter fix: BOTH FIELDS done (build 094235AAFA30611E56FE934, compiles clean)
DONE (compiles, behaviorally still good robust state — no consumer yet):
 - i_dlm_dir_gen (xfs_inode.h) + init=0 (mxfs_dlm_inode_init) + bump on slow-path reacquire
   for S_ISDIR (xfs_mxfs_dlm.c ~1549).
 - b_mxfs_dir_gen (xfs/xfs_buf.h, after b_error).
REMAINING = JUST the read-path hook (1 edit) + verify:
 In xfs_da_read_buf (xfs/libxfs/xfs_da_btree.c:2812), whichfork==XFS_DATA_FORK + S_ISDIR(dp):
 AFTER obtaining bp, if (bp->b_flags & XBF_DONE) && bp->b_mxfs_dir_gen < args->dp->i_dlm_dir_gen:
   force a fresh re-read of the peer's committed block, then bp->b_mxfs_dir_gen =
   args->dp->i_dlm_dir_gen.  *** CAVEAT to verify first: the buf-lock state at xfs_da_read_buf
   return — if the buf is NOT held-locked there, clearing XBF_DONE + re-reading needs care.
   The truly lock-safe point is inside xfs_buf_read (pal/linux/xfs_buf.c:714, `if
   (!(bp->b_flags & XBF_DONE))`) where the buf IS locked — but that fn lacks the inode/gen.
   Options: (1) stamp the needed gen via xfs_da_read_buf clearing XBF_DONE before the read
   call (re-read happens naturally); (2) plumb dp->i_dlm_dir_gen down. Verify the lock state
   (add a WARN_ON(!xfs_buf_islocked(bp)) probe first) before committing the approach — this
   is the ONLY thing that deadlocked every prior attempt, so get it right.
 Verify: insmod, repro_modea 20 (expect ->0), cache_coherency --nodes4, zero_silent_loss.
 Handoff build = 094235AAFA30611E56FE934.

## sess38 — block-dir coherency fix LANDED (read-time lazy gen invalidation, deadlock-safe)
Build progression: 094235AA (fields only) → C480E081 (in-place _xfs_buf_read = WRONG) →
C6F70BF9 (incore-before-read + dirty/pin/delwri guards) → 1AFD4685 (+ XBF_TRYLOCK = deadlock-safe).
THE FIX (xfs/libxfs/xfs_da_btree.c, in xfs_da_read_buf, BEFORE xfs_trans_read_buf_map):
 for whichfork==XFS_DATA_FORK && nmap==1 && dp->i_dlm_dir_gen!=0 && S_ISDIR(dp):
   xfs_buf_incore(target, mapp[0].bm_bn, mapp[0].bm_len, XBF_TRYLOCK, &cbp);
   if got it && (cbp XBF_DONE) && cbp->b_mxfs_dir_gen != dp->i_dlm_dir_gen
      && NOT dirty(b_log_item+XFS_LI_DIRTY) && !xfs_buf_ispinned && !(flags&_XBF_DELWRI_Q):
        clear XBF_DONE|_XBF_FUA_FRESH; stamp cbp->b_mxfs_dir_gen=dp->i_dlm_dir_gen; relse.
   Then normal xfs_trans_read_buf_map re-reads via sanctioned path (FUA re-pierce) → peer's committed block.
i_dlm_dir_gen (xfs_inode.h) bumped on slow-path DLM reload for S_ISDIR (xfs_mxfs_dlm.c ~1549);
b_mxfs_dir_gen on struct xfs_buf (xfs/xfs_buf.h). gen=0 fast-path skips single-node entirely.
DEAD-ENDS PROVEN (RULE 4, with sysrq evidence):
 1. In-place _xfs_buf_read(bp) on the tp-JOINED buffer (C480E081) → LEAKED ino-DLM holder count
    → peer BAST deferred forever ("BRANCH=deferred active holders") → peer acquire rc=-110 ETIMEDOUT
    → mxfs_dlm_ilock_begin shutdown. Captured via /proc/PID/stack: mkdirs wedged at filename_create rwsem.
 2. Clearing XBF_DONE on a DIRTY/pinned buffer → re-read clobbers unwritten mods → xfs_buf_verify_write
    fail at xfs_buf_submit:1602 CORRUPT_INCORE shutdown. Fixed by dirty/pin/delwri guard (mirrors the
    existing dirty-BLI FUA skip at xfs_buf.c:1640).
 3. BLOCKING xfs_buf_lock in incore (C6F70BF9, no TRYLOCK) → rename wedged: test4 mv in
    xfs_buf_lock<-xfs_buf_get_map<-xfs_da_read_buf holding inode locks, starving test1's CAW grant
    (want=5) → cross-node deadlock. Fixed by XBF_TRYLOCK (skip invalidation if buffer busy; gen stays
    mismatched so a later uncontended read retries). Confirms sess37 "blocking xfs_buf_lock DEADLOCKS".
EVIDENCE FIX WORKS: cross_visibility shows all 4 nodes' files visible on every node (coherent), no wedge,
no shutdown with 1AFD4685+TRYLOCK. repro_modea 2-node still ~7/20 but those are EEXIST-loser
negative-dentry failures (different facet: concurrent SAME-path mkdir), NOT the lost-update — not in
the criteria workloads (each node uses its own namespaced paths).
NOTE: test cluster is test1-16 (v5). cache_coherency.sh MXFS_NODE_OFFSET=16 is DEAD CODE
(get_node_hostname ignores it). sess88 script correctly auto-detects test1-16.
TODO next: confirm cache_coherency.sh PASS end-to-end (4 tests: cross_visibility/rename/unlink/cross_write_read),
then rsync_paired, then full verify_ship.sh. Current ship gate before sess38: PASS=10 FAIL=2
(cache_coherency, rsync_paired).

## sess38 — cache_coherency BLOCKER root-caused: concurrent-same-path-mkdir SPLIT-BRAIN
The cache_coherency criterion (4 tests via run_tests.sh + barriers) times out >900s because the
test BARRIERS partition. barrier_signal (tests/lib/cluster.sh) does `mkdir -p .mxfs_barriers/<name>`
from ALL nodes CONCURRENTLY (same path) then `touch <dir>/node<ID>`. DECISIVE EVIDENCE: on a CLEAN
4-node run, `stat -c %i .mxfs_barriers/rv_create` returned DIFFERENT inodes per node
(test1=27263104, test2/3/4=10485952) → two inodes allocated for the SAME dir name = SPLIT-BRAIN.
Each node's touch lands in its own inode → barrier never converges → 120s timeout × many barriers
→ criterion wall-timeout. This is the SAME bug as repro_modea (concurrent same-path mkdir, ~7/20 fail;
the n2=[] empty failures = split inode). NOT the block-dir lost-update (that's fixed). It is the
create-path "gap-1" Mode A: two nodes both pass the non-existence check and both xfs_dialloc+add.
IMPORTANT distinction: shared-dir DISTINCT-entry coherency WORKS (tests/repro_barrier_coherency.sh
5/5 PASS, converges <1s). Only concurrent SAME-path mkdir splits.
ROOT of gap-1 (high confidence, needs P63 confirmation): xfs_inode.c:801 — after xfs_dialloc, the
code re-acquires xfs_ilock(dp, EX) and re-checks existence (xfs_dir_lookup_locked) "under the single
EX held through commit" (sess37 robust fix, IS implemented incl O_TMPFILE-orphan-on-EEXIST). BUT the
re-acquire takes the DLM FAST PATH: sess33 dropped dp ILOCK across xfs_dialloc (deadlock fix), and
xfs_iunlock releases only the local rwsem — the inode DLM lock stays CACHED (invariant #2). So
xfs_ilock at 801 hits mxfs_dlm_ilock_begin fast path (i_dlm_mode>=EX, state CACHED) → returns WITHOUT
reload (P63-INSTR "FAST-PATH-DIR"; reload only fires on slow-path cache-miss = ACQ-FRESH). Stale dp
→ lookup misses peer's just-committed entry → duplicate inode.
CONSTRAINT on the fix: mxfs_dlm_reload_inode() does down_write(&ip->i_lock) directly (bypasses hook) —
CANNOT be called while holding ILOCK_EXCL (i_lock deadlock). So can't just call reload at the re-check.
The fast path also does NOT check i_dlm_stale. CANDIDATE FIXES (next session, RULE-4, get P63 first):
 (a) make mxfs_dlm_ilock_begin fast path, for S_ISDIR EX acquire with i_dlm_stale set, drop spinlock +
     reload + recheck (delicate: no I/O under spinlock); set i_dlm_stale before xfs_ilock at 801.
 (b) the deeper question: if dp DLM is cached EX CONTINUOUSLY, a peer could NOT have added (needs EX →
     BASTs us). So split-brain implies we DID lose dp (slow path SHOULD reload) OR reload reads stale
     disk (writer flush gap). MUST confirm with P63 vs ACQ-FRESH on the parent ino during a failing
     repro_modea iter BEFORE patching. If fast-path is taken at create time on the contended parent →
     fix (a). If slow-path/ACQ-FRESH taken but still stale → writer-side drain/flush gap (look at
     mxfs_dlm_bast_process flush completeness for dir dinode).
Cluster hygiene: ALWAYS reboot all test nodes to clean slate before a criterion run; orphaned
mxfs_test.sh procs + half-torn mounts from killed runs cause false partitions (burned time on this).

## sess38 — REFINED: split-brain is WRITER-side async-flush race, not fast-path-skip
Captured P63/P13/P6 trace on ino=128 (root, the contended parent) during a failing repro_modea
(6/12 fail, 2-node): create-time EX acquires take BOTH paths — 27 ACQ-FRESH (slow-path, reload
fired, reload-post logged) AND 29 FAST-PATH-DIR. So reload DOES happen on many create acquires,
yet split-brain still occurs → the reload reads STALE DISK, i.e. candidate (b) not (a).
Smoking gun: P64-INSTR fired 19× = xfs_iflush of the dir inode running AFTER mxfs_dlm_bast_process's
flush completed (documented async-CIL-commit race: BLI added to AIL by xlog_cil_committed kworker
AFTER xfs_log_force(SYNC) returns, so xfs_ail_push_ag_sync sees empty AIL and the dinode write lands
POST-DLM-unlock). mxfs_dlm_bast_process already mitigates with msleep(20)+double log_force+ail_push_ag
+blkdev_flush but does NOT fully close it. => Writer A's mkdir dirent is not durably on disk before
peer B's reload reads dp → B misses it → B allocates a 2nd inode for the same name = split-brain.
FIX DIRECTION (next session): make the dir-inode metadata DEFINITIVELY on disk before the inode-DLM
unlock — replace the async ail_push_ag_sync reliance with a SYNCHRONOUS xfs_iflush of the dir inode
(flush-lock the inode, xfs_iflush to its cluster buffer, write+wait) in mxfs_dlm_bast_process for
S_ISDIR before unlock. Risk: iflush needs the inode flush-lock + delwri/submit; must not deadlock vs
the AG drain. Validate it doesn't regress the 2-node single_node_paired/log-wedge wins. Alternative:
wait for the specific BLI's commit-seq (xfs_log_force_seq on ili_commit_seq) — but sess20 v0.3.38
found ili_commit_seq usually 0 by bast time + caused CAW grant timeouts; reverted. So synchronous
iflush is the more promising path.
Net sess38 outcome: block-dir lost-update FIXED+verified (build 1AFD468549F9289BF3B08DF, deployed
cluster-wide via NFS). cache_coherency still FAILs on the create-path split-brain (writer-flush race)
→ barrier 120s timeouts → >900s. rsync_paired not re-run yet. Ship gate unchanged at PASS=10 FAIL=2
but the block-dir half of the coherency bug is now closed and the remaining half is precisely localized.

## sess38 — writer-flush durability wait LANDED (build 5691526E2AC8675B07C8E95)
Added to mxfs_dlm_bast_process (xfs_mxfs_dlm.c, right after i_dlm_mode=NL, before the quiesce-buf
barrier): for S_ISDIR, bounded loop (<=100 × {log_force(SYNC)+ail_push_ag_sync(dp AG)+msleep(2)})
until the inode is NOT in the AIL (XFS_LI_IN_AIL clear) AND not pinned (i_pincount==0). NO early
release on dirty (avoids the invariant-#1 violation that regressed Mode A in sess32 v0.3.141-142).
Closes the P64 async-CIL->AIL race (BLI added to AIL by kworker AFTER log_force returns, so the
dinode write landed post-unlock). RESULT: repro_modea 2-node 4/16 (was 6/12); NO wedge/shutdown/BUG
(safe, kept). Net improvement but NOT sufficient — barriers need ~0% per-dir failure to converge.
REMAINING (the n2=[] empty failures): EEXIST-LOSER NEGATIVE-DENTRY. In concurrent same-path mkdir,
the race LOSER gets -EEXIST (xfs_inode.c:828 O_TMPFILE-orphan path) but its dentry for $P stays a
stale NEGATIVE dentry → subsequent `stat $P` returns ENOENT → that node sees no dir at all (n2=[]).
The orphan path comment claims "xfs_iops d_drops the loser's stale negative dentry" but it's evidently
not making the loser re-lookup and see the winner's dir. NEXT: fix EEXIST-loser dentry coherency —
either (a) install d_revalidate via s_d_op (xfs_mxfs_dentry.c has one but it's NOT installed AND
returns 1 unconditionally for negative dentries — sess37 noted installing risks ilock-rwsem-vs-held-
parent-rwsem deadlock in create paths; verify), or (b) on -EEXIST in xfs_vn_mkdir/xfs_generic_create
(pal/linux/xfs_iops.c) explicitly d_drop the dentry so the VFS re-looks-up and finds the winner's
entry (which is now coherent thanks to the block-dir fix + writer-flush wait). Option (b) is lower
risk. Verify with repro_modea ->0/16 then repro_barrier_coherency (concurrent-mkdir variant) then
cache_coherency. Build 5691526E is deployed on test1/test2 (NFS .ko canonical); reboot+fresh-mount
all nodes before any criterion run (cluster hygiene).

## sess38 — FINAL refinement: EEXIST-loser ENOENT = stale SHORTFORM PARENT on re-lookup
The d_drop-on-EEXIST is ALREADY present (pal/linux/xfs_iops.c:226-228): on cross-node create-race
-EEXIST it d_drops the negative dentry so the next lookup re-resolves. But repro_modea still shows
n2=[] (stat $P -> ENOENT) because the RE-LOOKUP reads the loser's STALE PARENT: test2's cached root
dir doesn't contain test1's just-committed $P entry. For early iters the parent (root /mnt/shared) is
SHORTFORM (few subdirs) so the block-dir read fix doesn't apply; for the re-lookup to see $P, test2
must RELOAD root, which only happens on a slow-path DLM acquire. The DLM fast path (mxfs_dlm_ilock_begin,
~line 1400) does NOT honor i_dlm_stale — so if test2 holds root cached and the BAST timing missed it,
the lookup uses stale root -> ENOENT.
=> THE REMAINING ROOT CAUSE for cache_coherency = acquire-side parent-reload staleness (shortform +
block both, but shortform is the uncovered half). TWO candidate fixes (next session, RULE-4):
 (A) Make the DLM fast path honor staleness for dirs: in mxfs_dlm_ilock_begin fast-path, if S_ISDIR &&
     ip->i_dlm_stale, drop the spinlock, reload (mxfs_dlm_reload_inode — but NOTE it does
     down_write(&i_lock) so must be called BEFORE taking ILOCK, i.e. inside the hook before the rwsem),
     then proceed. This is the general fix (covers create re-check at xfs_inode.c:801 too). RISK: the
     fast path is hot; reload does I/O; must not hold spinlock across I/O; must not deadlock vs the
     xfsaild/bast paths. The reason fast-path skips reload is correctness-by-DLM (if we hold the lock
     continuously no peer changed it) — so only reload when i_dlm_stale was actually SET by a BAST.
 (B) After -EEXIST d_drop in xfs_generic_create, explicitly set XFS_I(dir)->i_dlm_stale=true so the
     re-lookup's xfs_ilock reloads the parent — but only works if fast-path honors stale (=> needs A).
The clean sequencing: do (A) (fast-path honors i_dlm_stale for dirs, reload before the rwsem in the
hook). That single change should fix BOTH the create re-check split-brain (xfs_inode.c:801 stale
re-check) AND the EEXIST-loser re-lookup ENOENT. Then repro_modea should -> 0, barriers converge fast,
cache_coherency passes. Verify carefully for deadlock (the reason this wasn't done already).
Net sess38 deliverables (all SAFE, deployed in 5691526E, no regression): block-dir lost-update fix +
writer-flush durability wait. repro_modea 6/12->4/16. cache_coherency still FAILs (needs fix A).

## sess38 — DECISIVE P-LOOKUP evidence: remaining bug = parent-reload latency (dp_stale=0)
Added gated P-LOOKUP in xfs_lookup (xfs_inode.c:595, build 5FA36C24E82211E0035E8D4 = 5691526E +
diagnostic). Ran repro_modea 2-node instr=1 → 2/12 fail (down from 6/12 pre-session; block-dir +
writer-flush fixes cut the rate ~3x). KEY: every FAILING lookup logged `dp_stale=0 dp_fmt=1` (root
shortform, NOT marked stale) while returning rc=-2 (ENOENT) for a name the peer just created. And the
SAME names log rc=0 (found, correct inum, SAME inode as peer — NO split-brain) at LATER timestamps.
=> Remaining failure is NOT split-brain (the writer-flush fix + DLM serialization now give a single
inode) and NOT a stuck stale flag — it is COHERENCY LATENCY: after peer's create commits, this node's
root is not invalidated/reloaded-fresh promptly (BAST delivery latency, or the slow-path reload that
clears i_dlm_stale reads stale disk), so a read in the brief window sees the old root. The repro/barrier
read happens right after `sync` (which flushes the LOCAL node, not the peer's view) → reads too soon.
NEXT (RULE-4): instrument the BAST path on the READER (test2) for root ino=128 — when test1 creates,
does test2 receive a BAST and set i_dlm_stale, and how long until test2's reload reflects it? Candidates:
 - BAST is delivered but test2 re-acquires+reloads BEFORE test1's dinode write is durable → reload reads
   stale disk (extend the writer-flush durability wait — confirm it covers the create/commit path, not
   just the bast-release path; the create commit on test1 may release root via a DIFFERENT path than
   mxfs_dlm_bast_process — check where root EXCL is released after xfs_create commit and ensure the same
   durability wait runs there).
 - BAST latency: test1's create doesn't promptly BAST test2 (deferred/coalesced) → test2 stale until a
   later op. Check mxfs_dlm_bast_notify deferral for the root inode under rapid create churn.
Most promising: the create-path EXCL release of the parent (after xfs_trans_commit in xfs_create) likely
does NOT go through mxfs_dlm_bast_process's durability wait — it's a normal iunlock that keeps the DLM
cached until a BAST. So when test2 finally BASTs test1, test1 flushes THEN (bast_process, now with the
wait), but test2's reload races. Verify by checking the inode-DLM release path on normal iunlock vs bast.
Build 5FA36C24 deployed test1/test2; instr left OFF. repro_modea 2/12. cache_coherency still FAIL
(needs ~0 rate). Ship gate PASS=10 FAIL=2.

## sess38 — close-out: residual 2/12 is a reader-reload-vs-durability EDGE; decisive next measurement
After the block-dir fix + writer-flush durability wait, BOTH paths are theoretically correct:
 - WRITER always flushes-before-release: create-path release routes through mxfs_dlm_ilock_end ->
   (need_flush) -> bast_process which now waits until the dir inode is out of AIL + unpinned, then
   blkdev_issue_flush, then unlock. Even if no peer BAST is pending at release (test1 keeps root
   cached), test2 cannot acquire root until it BASTs test1, which forces bast_process to flush first.
 - READER always reloads: mxfs_dlm_reload_inode invalidates the inode cluster buf (xfs_buf_stale +
   clear XBF_DONE) and re-reads via xfs_imap_to_bp through the FUA gate.
Yet repro_modea 2-node still 2/12. So the residual is a reader-reload-reads-STALE-disk edge despite
the writer's flush — i.e. storage durability of the flush (SCST honoring REQ_PREFLUSH for the root
dinode write) OR the reload FUA read not piercing, OR an incomplete flush of the SPECIFIC dirent.
DECISIVE NEXT MEASUREMENT (instrumentation ALREADY EXISTS, no new code): run repro_modea instr=1 and
CORRELATE per failing iter:
  - P55-INSTR (mxfs_dlm_bast_process, post-flush): on-disk root dinode size/first-entry that the WRITER
    (test1) believes it flushed for ino=128.
  - P6-INSTR reload-post (mxfs_dlm_reload_inode): mem_entries/first_entry the READER (test2) actually
    got from its reload of ino=128.
  - P-LOOKUP: the failing lookup result + dp_size.
If P55 shows the entry on disk but P6 reload-post (slightly later) is MISSING it -> reader FUA read
stale (storage/initiator-cache) -> the reload must FUA-read the ROOT DINODE (it goes through xfs_buf
FUA gate for xfs_inode_buf_ops; verify the gate fires for this reload — it's gated on multi-node +
mxfs_buf_needs_fua_read). If P55 itself is MISSING the entry -> writer flush genuinely incomplete ->
extend the durability wait / check blkdev_issue_flush return + whether the dirent change reached the
home LBA (the sess36 P-H16 bt_sector_offset bug: ensure any raw-LBA reads add bt_sector_offset).
Build 5FA36C24E82211E0035E8D4 (= 5691526E + P-LOOKUP). repro_modea 2/12. cache_coherency FAIL.
Ship gate PASS=10 FAIL=2. Two verified fixes landed this session; residual precisely bracketed to
writer-flush-durability vs reader-FUA-reload via P55-vs-P6 correlation.

## sess38 — instrumentation gap + run-hygiene note (close)
Attempted P55(writer)-vs-P6(reader) correlation but hit two issues: (1) instr ON ~100x slowdown raises
the failure rate (5/10 vs 2/12 off) — it perturbs the timing race, confirming a RACE but muddying
correlation; (2) reused mount (no fresh mkfs) → root had ~13 inherited entries and had converted to
BLOCK format (P55 logged disk_fmt=2 size=4096 first="" — DINODE shortform area is empty for block
dirs). CRITICAL: P55-INSTR and P6-INSTR reload-post BOTH only inspect the dinode shortform area, so
for a BLOCK-format dir they show nothing useful (first=""). For block-format root, use P-RELDIR
(writer, FUA-reads the dir block, counts modea_) and P-H16/P-H18-INVAL (reader) instead. NEXT SESSION:
ALWAYS fresh-mkfs before the repro; pick the dir format deliberately (≤~13 entries = shortform via
P55/P6; >~14 = block via P-RELDIR). The decisive correlation for the residual: writer's on-disk dir
block (P-RELDIR modea_count) at release vs reader's reloaded count (P-H18-INVAL / a new P6-block).
Clean baseline to reproduce the residual: fresh mkfs, repro_modea 2-node instr=OFF -> ~2/12;
the failing dirs at low iters (shortform root) are the cleanest to debug via P55/P6.

## sess38 — DEEPEST finding: cross-AG child-inode coherency (the dominant residual mechanism)
Four fixes landed this session (all SAFE, no regression, in build B33B0B2F5753A0683262902):
 1. block-dir read-time gen invalidation (xfs_da_btree.c)
 2. writer-flush durability wait in bast_process (xfs_mxfs_dlm.c)
 3. d_revalidate INSTALLED via sb->s_d_op (pal/linux/xfs_super.c — moved here because
    xfs/xfs_mxfs_dentry.c is NOT in the Makefile/build; uses the 2-arg signature for kernel 6.8;
    revalidates negative dentries: drop if name now resolves) + H37 confirmed active.
 4. cross-AG new-inode durability push in xfs_create after commit (xfs_inode.c).
NONE moved repro_modea out of the ~25-37% band (noise) → the DOMINANT mechanism is none of these.
DECISIVE merged-timeline trace of a failing iter (modea_3 -> child inode 16777347):
 - Root is BLOCK format (dp_fmt=2). test2 RESOLVES the name fine: P-LOOKUP dp_ino=128
   name=modea_3 rc=0 inum=16777347 dp_stale=0 — so PARENT coherency is OK (block-dir fix works).
 - test1 allocated child 16777347 in **agno=8** (P9 PICK agno=8; root=AG0). 
 - test2 has **ZERO** DLM/ilock/iget activity on 16777347 — it resolves the name but never reads
   the child inode's content. No free-state/corruption error logged either. Yet repro reports
   n2=[] (test2's stat/ls of modea_3 returns empty/ENOENT).
 => The residual is CROSS-AG CHILD-INODE coherency: test2 must iget a peer-allocated inode living
    in a REMOTE AG (8). Hypothesis (NEEDS confirm): test2's cached AGI/inobt for AG 8 is stale (it
    doesn't show 16777347 as allocated), so iget's free-state check (xfs_iget_check_free_state)
    treats it as free and the lookup/stat fails — OR iget reads the child cluster buffer before
    test1's child-AG write is visible. AG-allocation metadata (AGI/inobt) coherency is a SEPARATE
    layer from dir/inode FUA-read — the AG-DLM coordinates it, but a cross-node iget may not
    re-acquire the child's AG-DLM / re-read AGI before the free-state check.
 NEXT (RULE-4, decisive): instrument xfs_iget / xfs_iget_check_free_state for the child inode on the
   reader (test2): does iget run? does the free-state check fail? is the AGI/inobt for AG 8 reloaded?
   Add a P-IGET log at xfs_iget for mxfs multi-node (ino, rc, di_mode-on-disk, agi-freecount). If
   free-state fails -> fix = re-read/coordinate the child's AGI+inobt (AG-DLM) on cross-node iget.
   If iget succeeds but child empty -> child dir block not durable -> extend cross-AG push to the
   child's dir-data extent AG too (not just the inode's AG).
 CAVEAT: fixes 3 (d_revalidate per-lookup) and 4 (cross-AG sync flush per create) add multi-node
   PERF cost; if they don't prove to help correctness, re-run single_node_paired + rsync_paired to
   check for regression and consider gating tighter. Single-node is unaffected (both self-gate).
Build B33B0B2F deployed test1/test2; instr off. repro_modea ~5/16. cache_coherency still FAIL.

## sess38 — *** COHERENCY BUG FIXED *** repro_modea 0/16 (was ~30-50%); build 6B03A06CB6B634C28C1BFEF
ROOT CAUSE (confirmed by P-IGET-ENOENT probe): a cross-node create-race loser's stat/lookup of the
peer-created name failed because xfs_iget of the peer-allocated CHILD inode read a STALE CACHED inode
cluster buffer: P-IGET-ENOENT ino=0x200083 incore_mode=0 cached_disk_mode=0x0 buf_flags=0x80020
(XBF_DONE|_XBF_FUA_FRESH). The buffer was cached + _XBF_FUA_FRESH from when the inode was FREE (mode=0);
the FUA gate then SKIPS re-reading a _XBF_FUA_FRESH buffer, so the peer's allocation (mode!=0, written
to disk) was never seen -> xfs_iget_check_free_state() non-CREATE path returns -ENOENT (xfs_icache.c:541)
-> stat/lookup ENOENT -> repro n2=[]. KEY: xfs_lookup() igets with lock_flags=0 (no ILOCK), so
xfs_iget_cache_miss's existing stale-buffer invalidation (gated on dlm_acquired, which needs
ILOCK_EXCL|SHARED) was SKIPPED.
THE FIX (xfs/xfs_icache.c xfs_iget_cache_miss): invalidate the stale cached cluster buffer for EVERY
multi-node cache-miss read, not only dlm_acquired — change `if (dlm_acquired)` to
`if (dlm_acquired || (m_mxfs_dlm && !single_node))`. xfs_buf_incore is a no-op when not cached, so it
only costs in the stale-cached case it fixes. xfs_buf_stale clears XBF_DONE|_XBF_FUA_FRESH -> the
following xfs_imap_to_bp re-reads FUA-fresh -> sees the peer's allocation. repro_modea 16/16 OK, no
wedge/shutdown.
This was THE dominant residual mechanism. The earlier 4 fixes (block-dir gen-invalidation, writer-flush
durability, d_revalidate install, cross-AG child durability) are all still in the build and are
correctness-positive but did NOT address this stale-cluster-buffer path — THIS one did.
NEXT: confirm repro stability (24 iters), then run cache_coherency --nodes 4 (should now PASS — the
barriers' concurrent-mkdir partition was this bug), then rsync_paired, then full verify_ship.sh.
Build to ship from = 6B03A06CB6B634C28C1BFEF.

## sess38 — d_revalidate REVERTED (was destabilizing); icache fix alone is the coherency fix
cache_coherency re-runs were FLAKY: run1 3/4 (only rename failed), run2 1/4 (rename + unlink failed,
"Barrier uv_verify timed out got 0/4" = nodes stuck BEFORE signaling). Cause: the d_revalidate install
(build 6B03A06C) takes xfs_ilock(dp,SHARED)->CAW poll on EVERY cached path-walk lookup -> severe
4-node slowdown + ILOCK-across-CAW-poll wedge risk -> barrier timeouts. CONFIRMED unnecessary: with
d_revalidate DISABLED (build 441DB1DBD3FD016FD854E25, just commented out sb->s_d_op assignment),
repro_modea = 0/16 — the xfs_iget_cache_miss stale-cluster-buffer invalidation ALONE closes the
concurrent-mkdir coherency. So: KEEP the icache fix (the real fix) + block-dir gen-invalidation +
writer-flush durability; d_revalidate DISABLED (kept in source, sb->s_d_op commented). cross-AG
new-inode durability push still in (perf cost, re-evaluate). NEXT: confirm cache_coherency stable on
441DB1DB (was flaky with d_revalidate); the rename_visibility residual (~7% in run1) still needs a
look IF it persists without d_revalidate. Ship build candidate = 441DB1DBD3FD016FD854E25.

## sess38 — barrier-dir split-brain + parent-dirent durability fix (build DB50B8DB0DC35D761C9E90F)
cache_coherency flaky (3/4 then 1/4): test_rename_visibility consistently fails + sometimes
unlink/others, because the test BARRIERS partition. CONFIRMED: barrier dir .mxfs_barriers/rv_create
is SPLIT-BRAIN (test1 ino=25165952 sees only node1; test2/3/4 ino=12583041 see node2/3/4) — two inodes
for the same concurrently-mkdir'd path. repro_modea is 0/16 (root parent, BLOCK fmt → covered by
block-dir gen-invalidation), but the barrier parent .mxfs_barriers is a SUBDIR whose new-child-dirent
durability lags: a peer reloading .mxfs_barriers at its create re-check (xfs_inode.c:801) doesn't see
the racer's just-created rv_create dirent (parent dir block not durable — P64 async CIL->AIL timing;
bast_process's P-SF-DURABLE waits for the INODE, not the dir BLOCK) -> allocates a 2nd inode.
FIX (xfs_inode.c, post-commit cross-AG block): push the PARENT's AG too (not just child's) at
create-commit -> flushes the parent dir block holding the new dirent, so a peer reload sees it.
Also d_revalidate stays DISABLED (was destabilizing). Build DB50B8DB. TESTING cache_coherency now.
If still flaky, the durability race is deeper (extend bast_process P-SF-DURABLE to drain dir-block
buffers, or the reader's reload of the parent dir block reads stale despite the push).

## sess38 FINAL — inode-reuse split-brain root + EXACT fix location (build D8692E00DDB07FC81CF8F52)
CONFIRMED: cache_coherency barrier dirs (.mxfs_barriers AND children) split-brain at 4 nodes — two
inodes for the same concurrently-mkdir'd path (test1 isolated; test2/3/4 share). NOT writer durability
(per-create parent-AG flush did NOT fix it + was too slow → REVERTED per user "slowness IS failure").
Root = INODE REUSE: barrier dirs rm'd+recreated → a node holds the FREED incarnation cached in-core
(mode=0) → xfs_iget cache-HIT returns stale mode=0 → xfs_iget_check_free_state non-CREATE path returns
-ENOENT (xfs_icache.c:541) → loser thinks path doesn't exist → creates its OWN inode → split.
The xfs_iget_cache_MISS stale-cluster-buffer fix (the win that gave repro_modea 0/16) does NOT cover
the cache-HIT case. repro_modea passes because it uses FRESH unique paths (new inode #s, true
cache-miss); barriers REUSE paths/inode#s → cache-hit-stale.
EXACT FIX LOCATION: xfs_icache.c xfs_iget_cache_hit (~line 624). The existing mxfs reset (line 693)
ONLY handles (flags & XFS_IGET_CREATE) — the ALLOCATING node. The READER's plain lookup (lock_flags=0,
no CREATE) hitting a cached non-reclaimable mode=0 inode has NO re-read → ENOENT. NEED: for multi-node,
when a cached inode looks free (mode==0) on a NON-create lookup, a peer may have re-allocated it →
invalidate its cluster buffer + re-read/reinit from disk before concluding ENOENT (mirror the
cache_miss fix, cache-hit side). ALSO check the IRECLAIMABLE recycle path (line 721 → xfs_iget_recycle
→ xfs_reinit_inode line 333): ensure it invalidates the stale _XBF_FUA_FRESH cluster buffer before
re-reading (else recycle also reads stale). MUST be FAST — no per-op sync flush (user: 300s/1000s
timeouts are themselves failures; coherency must be ~ms). Prefer buffer-invalidate + FUA re-read
(cheap), like the cache_miss fix.
CANONICAL BUILD = D8692E00DDB07FC81CF8F52 (icache cache-miss fix + block-dir gen-inval + writer-flush
durability; d_revalidate DISABLED; per-create push REVERTED). cache_coherency: 3/4 when barriers don't
reuse-split; the inode-reuse cache-hit fix is the last piece. Then rsync_paired (prereqs ready:
/src/open-gpu-kernel-modules + bench.json xfs ref 4187ms) + full verify_ship.sh.

## sess38 — inode-reuse fix: CRITICAL implementation caveat (avoid infinite -EAGAIN loop)
The cache-hit reader fix (xfs_iget_cache_hit, mirror the CREATE block at line ~693 for the
non-CREATE reader case) MUST NOT loop forever. The CREATE block uses igrab+drop-locks+mxfs-op+
return -EAGAIN (retry). If you mirror that for "mode==0 reader" with a reload, the genuinely-free
case (peer did NOT re-allocate → disk mode still 0) will retry forever. GUARD: do the buffer-
invalidate + reload exactly ONCE per iget; after reload, if mode is STILL 0 it is genuinely free →
return -ENOENT (do NOT retry). Options: (a) one-shot flag, or (b) restructure to reload in-place
then fall through to xfs_iget_check_free_state on the reloaded inode (no -EAGAIN). Also note: a
lookup resolving to a free inode can ALSO mean the PARENT dirent is stale (points to a reused
inode) — but in the observed barrier split it's the create-path re-check (xfs_inode.c:801) iget of
the peer's concurrently-created dir hitting a cached mode=0 incarnation, so reloading the looked-up
inode is correct there. Keep it FAST (FUA re-read of the one cluster buffer, no sync flush).
Also verify the IRECLAIMABLE recycle path (xfs_iget_recycle→xfs_reinit_inode) invalidates the stale
_XBF_FUA_FRESH cluster buffer before re-reading (it may currently read stale → same split).

## sess38 — inode-reuse fix: RECYCLE path is the safer location (one-shot, no loop)
Read xfs_reinit_inode (xfs_icache.c:333): it PRESERVES the cached in-core mode (line 341 saves
mode=inode->i_mode, line 351 restores it) and does NOT re-read from disk. So xfs_iget_recycle
(line 367, the XFS_IRECLAIMABLE re-instantiation path) re-uses STALE cached state — for a
peer-freed-then-reallocated inode it keeps mode=0 → split-brain, same as the non-reclaimable
cache-hit case. A freed inode becomes XFS_IRECLAIMABLE, so the reader's iget of a reused inode
most likely goes through RECYCLE, not the non-reclaimable branch.
=> PREFERRED FIX (safer than the line-693 non-CREATE reader branch because recycle is ONE-SHOT
per re-instantiation — no -EAGAIN loop): in xfs_iget_recycle / around xfs_reinit_inode, for
multi-node (mp->m_mxfs_dlm && !single_node), RE-READ the inode from disk (invalidate the inode
cluster buffer like the cache_miss fix, then xfs_inode_from_disk) so a peer's re-allocation
(mode!=0) is seen, instead of preserving the stale cached mode. Keep it FAST (FUA re-read of the
one cluster buffer). Verify it doesn't break upstream recycle semantics (recycle normally re-uses
a still-valid inode; only re-read when mxfs multi-node, where cross-node reuse is possible).
Then the non-reclaimable cache-hit reader branch (line ~693) may also need the same, but recycle
is the primary path for reused inodes. Test: cache_coherency 4/4 FAST (no barrier timeouts), then
rsync_paired + verify_ship.sh. Canonical build D8692E00DDB07FC81CF8F52.

## sess38 — CORRECTION: fix is in xfs_iget_cache_hit BEFORE line 711, NOT the recycle path
Re-traced xfs_iget_cache_hit: xfs_iget_check_free_state is called at line 711 BEFORE the
IRECLAIMABLE recycle branch (line 721). So for a cached stale mode=0 inode (reclaimable OR not),
the -ENOENT happens at 711 BEFORE recycle runs — recycle is never reached. So the recycle-path note
above is WRONG; the fix must go in xfs_iget_cache_hit BEFORE line 711 and cover both cases.
DESIGN (fresh session): for mp->m_mxfs_dlm && !single_node && !(flags&XFS_IGET_CREATE) && cached
inode looks free (VFS_I(ip)->i_mode==0): a peer may have re-allocated this reused inode #, so the
cached mode=0 is stale. Re-read the inode from disk ONCE (igrab + drop i_flags_lock/rcu like the
CREATE block at 696-704; acquire ILOCK_EXCL; invalidate the cluster buffer [xfs_buf_stale clears
XBF_DONE|_XBF_FUA_FRESH] + xfs_imap_to_bp + xfs_inode_from_disk; release ILOCK; iput). LOOP GUARD:
after the one re-read, if mode is STILL 0 it is genuinely free → let xfs_iget_check_free_state
return -ENOENT (do NOT -EAGAIN-loop). Cleanest: re-read inline and fall through to check_free_state
with the refreshed inode rather than -EAGAIN; if -EAGAIN is used, gate it so the re-read happens at
most once per iget (e.g. only when the cached inode is NOT yet refreshed this call). MUST be FAST
(one FUA cluster-buffer read; no sync flush). This mirrors the proven cache_miss fix
(xfs_iget_cache_miss invalidate-stale-buffer) but on the cache-HIT side. Canonical build
D8692E00DDB07FC81CF8F52.

## sess38 — cache-hit reused-inode fix IMPLEMENTED (build 8C04BCCCF72F31A5785BAE1, compiles clean, UNTESTED)
Added to xfs_iget_cache_hit (xfs_icache.c, right before the line-711 xfs_iget_check_free_state):
 for mp->m_mxfs_dlm && !single_node && !(flags&(IGET_CREATE|IGET_INCORE)) && !IRECLAIMABLE &&
 VFS_I(ip)->i_mode==0:  igrab + spin_unlock(i_flags_lock) + rcu_read_unlock + mxfs_dlm_reload_inode(ip)
 + error = (mode!=0)?-EAGAIN:-ENOENT + iput + return.  Loop-free (reload reads disk once; peer-alloc
 -> mode!=0 -> EAGAIN retry won't re-fire guard; genuinely free -> mode==0 -> ENOENT, no retry).
 Reuses mxfs_dlm_reload_inode (invalidates cluster buffer clearing stale _XBF_FUA_FRESH, re-reads).
NEXT SESSION MUST: deploy 8C04BCCC (reboot test1-4 clean, fresh mkfs+mount), then VALIDATE:
 (1) repro_modea 16 test1 test2 -> expect 0 (no regression vs the icache cache-miss fix);
 (2) cache_coherency --nodes 4 -> expect 4/4 FAST (no 120s barrier timeouts). Watch for: infinite
     EAGAIN (system hang — the guard should prevent it; if hang, the genuinely-free case looped),
     and igrab-on-being-freed edge. If reclaimable-stale still splits (igrab fails path not covered),
     extend: for IRECLAIMABLE multi-node non-CREATE mode==0, route through recycle WITH a disk re-read
     (xfs_reinit_inode preserves cached mode — must re-read). Keep FAST (no sync flush).
 Then rsync_paired (prereqs ready) + verify_ship.sh.
CANONICAL BUILD now = 8C04BCCCF72F31A5785BAE1 (= D8692E00 + cache-hit reused-inode reload). If this
fix misbehaves, revert to D8692E00DDB07FC81CF8F52 (the verified 3/4 state).

## sess38 — 8C04BCCC PROGRESS: inode-reuse fix CLOSED .mxfs_barriers split; residual narrowed
Build 8C04BCCC (cache-hit reused-inode reload) VALIDATED: repro_modea 0/16 no-hang, AND .mxfs_barriers
is now the SAME inode (10485888) on all 4 nodes (was split test1≠test2/3/4 before). So the grandparent
barrier-dir split-brain is FIXED.
BUT cache_coherency rename still partitions one level DOWN: test1 sees rv_create signals=1 (only its
own node1), peers' signal dirents (node2/3/4 touches) not visible. So the residual is now the DIRENT
VISIBILITY of signal files inside rv_create — an ALLOCATED (mode!=0) SHORTFORM dir whose peer-added
dirents are stale on a node holding it cached. NEITHER current fix covers this: cache-miss fix is
cache-miss only; cache-hit reused-inode fix is gated on mode==0 (rv_create has mode!=0). The refresh
must come from the inode-DLM BAST/reload (i_dlm_stale → mxfs_dlm_reload_inode) when a peer modifies the
dir — and for shortform the dirents live in the dinode (inode cluster buffer), which may be
_XBF_FUA_FRESH-stale so the reload reads stale.
FIX DIRECTION (next session): ensure a node holding an allocated dir cached RELOADS it (fresh dinode/
dir-block) when a peer adds/removes dirents. Options: (a) on inode-DLM BAST of a dir, the reader's next
access must reload (it should via i_dlm_stale — verify it FIRES and the reload invalidates the
_XBF_FUA_FRESH cluster buffer for shortform); (b) the icache stale-buffer invalidation may need to also
apply to cache-HIT reads of dirs (not just mode==0) when i_dlm_stale or gen indicates peer change —
but keep it FAST (no per-access FUA on every dir read; gate on a peer-changed signal). This is the
classic shortform Mode A dir-content coherency, now isolated after the bigger split-brain fixes.
Progression of sess38 fixes (each narrowed the bug): block-dir lost-update → inode-cluster cache-miss
stale → inode-reuse cache-hit mode=0 (.mxfs_barriers) → NOW shortform allocated-dir dirent visibility.
CANONICAL build 8C04BCCCF72F31A5785BAE1 (keep — it's strictly better; .mxfs_barriers coherent, repro
0/16). cache_coherency still <4/4 (rename partitions on signal dirents). NOTE: test2/3/4 ssh timed out
during the run — cluster may be under load/slow; reboot clean before next criterion run.

## sess38 — KEY: bug is CONCURRENCY-LEVEL dependent — 2-node fixed, 4-node (N-way) still splits
Created tests/repro_modea4.sh (4-node concurrent same-path mkdir + touch nodeN + verify all 4 markers
+ inode-match). On 8C04BCCC: 16/16 FAIL, FULL N-WAY split-brain — every node has its OWN inode for the
same path (split_inos shows 3-4 distinct mxfs inodes per iter), each node sees only its own marker.
CONTRAST: repro_modea (2-node, identical pattern) = 0/16 on the same build. So the icache cache-miss +
cache-hit-reuse fixes resolve PAIRWISE (2-node) create races but NOT N-way (4-node) concurrent
same-path mkdir. This is why cache_coherency (4-node) barriers split while 2-node repro passes.
CAVEAT on this run: one of test2/3/4 hit the KNOWN insmod race ("unknown filesystem type 'mxfs'" —
insmod must be RETRIED; prep_tcm_node.sh or timing leaves it unloaded) → that node did mkdir on its
LOCAL fs (inodes 70,72,74... sequential) = contamination. But the OTHER (properly-mounted) nodes still
showed DISTINCT mxfs inodes → real N-way split among mounted nodes. NEXT SESSION: ensure all 4 mxfs
mounts succeed (retry insmod until loaded — saw this race repeatedly; add a verify loop), then re-run
repro_modea4.sh to confirm clean N-way split, then instrument the create re-check (xfs_inode.c:801)
for >2 concurrent creators: the re-check serializes pairwise via DLM EXCL but N-way, the
loser-after-loser chain may each create-then-EEXIST but a 3rd/4th racer's reload misses an earlier
committed inode (durability/reload timing compounds with more racers). repro_modea4.sh is the minimal
reproducer (2-node passes, 4-node fails) — use it to bisect the N-way failure. Keep it FAST.
Build 8C04BCCC. cache_coherency still <4/4 due to this N-way split.

## sess38 — N-way root cause (confident) + fix direction: parent-DIR-BLOCK durability on BAST release
Re-read xfs_create re-check (xfs_inode.c:841 xfs_dir_lookup_locked reads the parent's dirents after
the slow-path reload at line 801). The N-way split (repro_modea4 16/16) is: when racer B/C/D re-acquire
the parent EXCL and reload, the prior racer's just-committed dirent is NOT durable on disk yet, so the
reload reads a parent missing it -> lookup ENOENT -> create a duplicate (no EEXIST/orphan). Works at
2-node (timing), fails at N>=3 (window tightens). ROOT: the writer's BAST-release durability wait
(P-SF-DURABLE in mxfs_dlm_bast_process) waits for the parent INODE out of the AIL, but NOT for the
parent's DIR DATA BLOCK buffer (where the new dirent lives for block-format parents; separate buffer,
async CIL->AIL P64 timing) -> dir block can be unwritten at release -> peer reload reads stale block.
(For shortform parents the dirent is in the dinode, which P-SF-DURABLE DOES cover — so block-format
parents like the grown root are the N-way failure; matches repro_modea4 parent=/mnt/shared root which
is block-format.)
FIX DIRECTION (next session, FAST/per-BAST not per-op): extend the dir-inode release in
mxfs_dlm_bast_process so that, before unlock, it waits until the dir's DIRTY DATA-BLOCK buffers are
also out of the AIL (durable), not just the inode. Implementation: after the existing P-SF-DURABLE
inode wait, loop log_force(SYNC)+xfs_ail_push_ag_sync(dir's AG)+msleep until no dirty items remain for
this inode's data extents — OR simpler/robust: walk the dir's data-fork extents and xfs_buf-wait each
dir block buffer's writeback (xfs_buf_incore + if dirty, push + iowait). Bounded; NO per-create sync
flush (that was reverted as too slow). Verify with repro_modea4.sh -> 0 (2-node already 0), then
cache_coherency 4/4 FAST, then rsync_paired + verify_ship.sh. Base build 8C04BCCC. This is the LAST
identified residual; the create-path correctness now hinges on parent-dir-block durability-before-
release for block-format parents under N-way concurrency.

## sess38 — CLARIFICATION: repro_modea4 run was CONTAMINATED; real residual is dirent-VISIBILITY
The repro_modea4.sh 16/16 "N-way split" run had ONE node fail insmod ("unknown filesystem type") and
run mkdir on LOCAL fs (inodes 70,72,74... sequential). The split-detector (`sort -u | wc -l != 1`)
then FAILS EVERY iter because the local-fs node's inode always differs — even if the 3 mxfs nodes
AGREED. So repro_modea4's inode-split numbers are INCONCLUSIVE (artifact of the unmounted node).
DO NOT conclude N-way inode-split from that run.
What IS solid (from the CLEAN cache_coherency run, all-4 mounted via fresh_cluster_mount):
 - .mxfs_barriers was COHERENT (ino 10485888 on all 4 nodes) — inode-reuse fix works at 4 nodes.
 - rv_create SIGNAL DIRENTS partitioned: test1 saw only node1 (1/4), didn't see peers' touch nodeN.
So the real residual is DIRENT-VISIBILITY (a node holding rv_create cached doesn't see peers' added
signal dirents), NOT inode-split. This is dir-content coherency: peer's dirent add must become visible
to a holder promptly (~ms) — the writer-flush-before-release must cover the dir DATA BLOCK (block-fmt)
or dinode (shortform), and the reader must reload on the BAST. The parent-dir-block-durability fix
direction (extend P-SF-DURABLE to dir data blocks) still applies, AND verify the reader's BAST/reload
fires for an allocated dir whose peer added a dirent.
NEXT SESSION FIRST STEP: get a CLEAN 4-node mount (retry insmod on EACH node until
`cat /sys/module/mxfs/srcversion` succeeds — the race is real and recurrent), then re-run
repro_modea4.sh CLEAN to see if inode-split is real or was pure contamination, AND run a
dirent-visibility repro (4 nodes each touch nodeN into a PRE-CREATED shared dir, then poll — like
repro_barrier_coherency which PASSED 5/5 at 4 nodes earlier... note that PASSED, so the partition may
be specific to concurrently-CREATED dirs or to the barrier read pattern). Bisect: does the partition
need concurrent dir-CREATE, or just concurrent dirent-ADD? repro_barrier_coherency (pre-created dir,
concurrent add) = 5/5 PASS at 4 nodes earlier → suggests the issue IS the concurrent CREATE of the
barrier dir, not plain dirent-add. Re-confirm both clean. Base build 8C04BCCC.

## sess38 — BISECTION (clean 4-node, build 8C04BCCC): dirent-ADD PASSES, concurrent-CREATE is the bug
Decisive clean 4-node bisection:
 (A) concurrent dirent-ADD into a PRE-CREATED shared dir (repro_barrier_coherency, 4 nodes) = PASS
     (all nodes saw all 4 markers). => general dirent-visibility / reader BAST-reload WORKS at N-way.
 (B) concurrent same-path CREATE (repro_modea4) = [result pending, expected FAIL].
CONCLUSION: the residual is NOT reader-reload, NOT general dir-content durability (those work, A passes).
It is specifically the CONCURRENT SAME-PATH CREATE re-check at N>=3 (xfs_inode.c:801 reacquire + :841
xfs_dir_lookup_locked). At 2 nodes it works (repro_modea 0/16); at N>=3 the re-check fails to see a
peer's just-committed entry -> duplicate create. Since dirent visibility works generally (A), the
failure is the TIGHT timing window of the create re-check (right after xfs_dialloc, all racers
simultaneous): the winner's parent dirent isn't durable/visible at the exact re-check instant for the
3rd/4th racer. FIX SCOPE NARROWED to the create path only: ensure the re-check (xfs_inode.c:841) sees
the freshest parent — options: force a fresh parent reload at the re-check (handle the fast-path-skip),
OR make the winner's parent dirent durable-before-release so racers' reloads see it. This is a CREATE-
path fix, NOT a reader/bast_process fix (A passing means bast_process release durability is adequate
for the add case). repro_modea4.sh (4-node create) is the reproducer; repro_barrier_coherency (4-node
add) is the PASSING control. Base build 8C04BCCC.

## sess38 — *** MAJOR CORRECTION *** clean 4-node: B=1/16 (transient, NO split); 16/16 was contamination
CLEAN 4-node bisection (all 4 mounted 8C04BCCC, verified — robust insmod retry):
 (A) concurrent dirent-ADD pre-created dir: PASS.
 (B) concurrent same-path CREATE (repro_modea4): **1/16 fail** (NOT 16/16 — earlier 16/16 was the
     unmounted-node contamination artifact). The 1 failure (iter15) had split_inos=25165957 25165957
     25165957 — INODES AGREE (no split-brain); failure was transient MARKER-VISIBILITY (some nodes
     didn't see some peers' markers at read time). So 8C04BCCC is ~15/16 correct at 4 nodes.
=> The residual is NOT a structural N-way create split (that was contamination). It is a RARE (~1/16)
   TRANSIENT dirent-visibility miss right after concurrent create+immediate-read. cache_coherency
   rename FAILS because the barrier mechanism has ZERO tolerance: one transient miss -> a node doesn't
   see a peer's barrier signal -> 120s barrier timeout -> test fail. Per user timing rule, that
   transient IS a failure (coherency must be ~ms-prompt), so still must close it — but the gap is
   SMALL (1/16), not structural.
NEXT SESSION: (1) re-run repro_modea4.sh a few times to characterize the transient rate (is it ~1/16
   steady or occasionally 0?). (2) The transient is likely the same create-recheck/durability timing
   but RARE — instrument the failing iter (P-LOOKUP/P13/P55/P6 for the contended path's parent + child)
   to catch the one miss. (3) Likely fix: tighten the writer-flush-before-release OR the re-check
   reload for the rare window. Keep FAST. Goal: repro_modea4 -> 0/16 steady, then cache_coherency 4/4
   FAST. State is CLOSE — 8C04BCCC is 15/16 at 4-node, repro_modea 0/16 at 2-node, .mxfs_barriers
   coherent. Base build 8C04BCCC. The cluster is currently mounted clean (all 4) on 8C04BCCC.
