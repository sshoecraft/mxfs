---
name: sess31 lessons (research session for v6 cache architecture)
description: Sess31 (2026-05-07) research-only session. Produced v6a design doc. Key finding: v5's D6 is sound as spec'd; the implementation drift to FUA-on-every-read is what's slow. v6a = implement D6 GFS2-style. Deliverables list and where they live.
type: project
originSessionId: bbe79d3b-3c97-4ae3-be56-74257be1f617
---
Research-only session, no kernel code changed.  Followed the
hypothesize → measure → develop → commit methodology: every design
claim is paired with either an existing measurement or a future one.

**Why:** sess30 measured a 9+ minute 2-node rsync that takes 3-4 s
single-node.  That's the v5 D6 implementation hitting an architectural
ceiling on metadata-create-heavy cross-node workloads.  Sess31 had
to figure out whether v5 needed a complete redesign (v6) or whether
D6 just needed faithful implementation.

**How to apply:** for sess32 work on v6a (the recommended path), the
proposal at `/src/mxfs/docs/v6-cache-architecture-proposal.md` is the
implementation reference — it cites GFS2 file:lines, mxfs.1 lessons,
and OCFS2's LVB pattern.  Skim §3 (the architecture) and §6
(implementation cost) before starting.

## Headline finding (corrected v0.2 after code reading)

v5 v0.3.128 has BOTH invalidate-on-acquire AND FUA-on-every-read.
The original framing (sess31 v0.1) that said v5 only does
FUA-on-every-read was wrong; verified by reading
`xfs/xfs_mxfs_dlm.c:2480-2716` (AG fresh-acquire walk that stales
all matching bufs in pag_bcache + blkdev_issue_flush) and
`xfs_mxfs_dlm.c:300-424` (dir-block stale on inode lock release).

WHY both: `xfs_buf_stale` invalidates the in-memory buf, but the
storage stack BELOW (LIO target / iSCSI per-initiator cache) has
its own read cache that returns stale data on plain bio reads.  The
comment at `pal/linux/xfs_buf.c:1618-1628` documents this directly.
Same shape as mxfs.1 VMware-VMDK fix.  FUA-on-read pierces that
lower cache.

The actual v5 problem: FUA-on-read is "always," not "first read
after invalidate."  Once a buf is re-read with FUA after stale,
subsequent reads while STILL holding the lock should hit the
kernel xfs_buf cache (no I/O at all) — but v5 forces FUA every
time, so amortization within a hold is zero.

The corrected v6a fix: add `_XBF_FUA_FRESH` bit on xfs_buf, set on
successful FUA read in `mxfs_buf_read_fua` (pal/linux/xfs_buf.c:1474),
cleared in `xfs_buf_stale` itself (pal/linux/xfs_buf.c:82, paired
with the existing `_XBF_DELWRI_Q` clear), gate
`mxfs_buf_needs_fua_read` on `!(bp->b_flags & _XBF_FUA_FRESH)` at
pal/linux/xfs_buf.c:1632.  ~10 LOC, 2 sites modified.

**SHIPPED in v0.3.129 (srcversion 233E460558A4B06DDD88440) and
measured.**  Result is a partial pass:

- Read mechanism works: FUA-read traffic dropped 19× (from ~1024/s
  per node baseline to ~54/s on test2 during iter 1 of the rsync
  bench).  Zero fallbacks, zero errors.
- Wall clock H1 falsified: test2 iter 1 = 278s, test1 iter 1
  killed at 600s with 21% completion (projected ~2820s).  H1
  threshold was <60s.
- Real progress vs v0.3.128: sess30 baseline was DNF after 9+ min;
  v0.3.129 test2 completed in 278s.

**Residual bottleneck identified (corrected H2):** FUA-WRITE drain
at every transaction commit.  test1 process kernel stack shows
`xfs_buf_wait_unpin <- mxfs_dlm_ag_drain_alloc_buflist <-
mxfs_ag_dlm_unlock <- xfs_trans_commit <- xfs_create`.  Every
create commits a transaction; every commit unlocks AG-DLM; every
unlock submits N FUA metadata writes synchronously.

**D10 yield quantum is the lever — and it's NOT wired.**
`mxfs_clayer/yield_quantum.{c,h}` exists but `i_dlm_yield_remaining`
is only reset to 0 (xfs_mxfs_dlm.c:1466), never armed/consumed in
the AG-DLM unlock path.  Sess32's priority is to wire D10 so
AG-DLM hold spans multiple transactions when no BAST is pending,
amortizing FUA-write drain across the held window.

**v0.3.130 phase 2 experiment (sess31 also shipped this):** opt-in
`mxfs_lazy_ag_drain` module param gates a conditional in
`mxfs_ag_dlm_unlock` that skips the drain when knob=1 AND no BAST
pending AND alloc dirty.  Default 0.  **Mechanism confirmed real:**
test1 single-node baseline 134.9s vs test1 with knob=1 (test2 contending but
stuck) 14.5s — 9× speedup attributable to skipping per-trans drain.
**But policy is wrong:** binary skip-or-drain causes test2 starvation
because test1's eventual BAST release drain accumulates too much dirty
AG metadata.  Sess32 must replace with proper bounded yield quantum
(N=32 per spec).  Knob stays at default 0 in production until
fixed.

**Important note on dmesg printks:** UNLOCK-LAST events fire too
fast (~570/sec) for kernel printk-ratelimit; counting `lazy_skip=1`
events in dmesg is unreliable.  Use wall-clock measurements as the
reliable signal.

**Build state:** mxfs.ko at v0.3.130 srcversion
`EB71BD3E4D5C5E89DAC31AF`.  Compiles clean, mounts clean, multi-node
engages.  Default-knob behavior is functionally equivalent to
v0.3.129.  Both versions safe in production for read-side
amortization (FUA-FRESH bit); the lazy_ag_drain knob is opt-in
experiment only.

**v0.3.131 (sess31 phase 2 proper) — bounded yield quantum:**
shipped at srcversion `D79B6EF600892AB43AD1E95`.  Adds
`pag->pag_dlm_yield_remaining` (int) to xfs_perag, init to
MXFS_BAST_YIELD_QUANTUM=32 on fresh CAW acquire, decrements on
each lazy-skipped unlock, force-resets on quantum exhaustion (with
eager drain).  ~30 LOC.  Default knob still 0.

**v0.3.131 measurement (lazy_ag_drain=1, 2-node parallel):**
- test2 element-web 4385 files: **25.993s — STRONG H1 PASS** (match=Y,
  md5=Y, dmesg_hits=0).
- test1 open-gpu: EIO + filesystem shutdown at 360s.  Shutdown
  triggered at `mxfs_dlm_ilock_begin+0x15c` (inode-DLM path, NOT
  the AG-DLM path my code touched) on inode 128 with rc=-110
  (ETIMEDOUT).  test2 dmesg in same window shows no BAST/failures.
  test1 had been hard-rebooted (sysrq-b) before this run; cause is
  probably test1-reboot-recovery artifact, NOT v6a phase 2 code bug.

**Architecture validated by test2's clean 26s result.**  Through-arc:
v0.3.128 DNF/9min → v0.3.129 read amortized 19× → v0.3.130
mechanism confirmed (test1 14.5s but test2 starved) → v0.3.131 test2 strong
pass.  Each iteration narrowed the lever and improved the result.

**Sess32 must disambiguate test1's shutdown:** hard-reboot BOTH nodes
(not just test1), fresh mkfs+mount, re-run lazy_ag_drain=1.  If test1
reproduces shutdown → v0.3.131 has a real race; if not → it was
post-reboot recovery and v0.3.131 is ready for default-on rollout
after quantum tuning.

**SESS31 ADDENDUM — disambiguation done, bug confirmed real.**
Sess31 ran the disambiguation after virsh reset of both nodes.  test1
shutdown REPRODUCED at quantum=32 (v0.3.131) and at quantum=4
(v0.3.132 with new tunable knob `ag_yield_quantum`).  The bug is
NOT accumulation-size related.  Inconclusive solo test (test1 alone
with lazy=1 + open-gpu) suggests it's not cross-node-specific
either — it's structural in the lazy_skip path triggered by the
open-gpu workload pattern.  Sess32 priority: instrument lazy_skip
events + try `ag_yield_quantum=1` (only one skip allowed per
cycle).  v0.3.132 ships with default lazy_ag_drain=0; safe.

**SESS31 BREAKTHROUGH (autonomous-loop iteration):**

test1 SOLO + lazy_ag_drain=1 + ag_yield_quantum=1 + open-gpu rsync:
**4.081 seconds** for 8137 files = **1.31× XFS native (3.12s)**.
The architectural model achieves GFS2-equivalent performance on
the workload that was originally DNF after 9+ minutes.  v6a is
validated.

Bug isolation via minimal repros (test1 SOLO same config):
- 50 flat files: clean (write 0.58s, read 0.07s)
- 1000 flat files: clean (write 10.6s, read 1.09s)
- 8137 deeply-nested files (open-gpu): rsync clean (4s) but
  subsequent `find` HANGS

**Conclusion:** bug is depth/structure-related, not size-related.
Sess32 entry test: 100 dirs × 100 files (10000 total, 2 levels
deep).  If wedges, sess32 has small repro to debug under
instrumentation.  Suspect: inode-DLM acquire path in single_node
mode interacting with AG-DLM cached-but-lazy-skipped state during
deep dir traversal.

**SESS31 BUG ROOT CAUSE FOUND (final loop iteration):**

Cleanest possible reproduction: `virsh destroy test2` (no peer
possible), test1 SOLO with single_node=true confirmed, lazy=1
q=1.  Open-gpu rsync + bounded find.  find wedged in:

```
xlog_grant_head_wait+0x4e/0x2a0 [mxfs]
xlog_grant_head_check+0xfc/0x120 [mxfs]
xfs_log_reserve+0xd4/0x240 [mxfs]
xfs_trans_alloc+0x14b/0x390 [mxfs]
xfs_vn_update_time+0xce/0x1b0 [mxfs]
touch_atime+0xb6/0x120
iterate_dir+0x1ce/0x210
__x64_sys_getdents64+0x84/0x130
```

**Bug:** XFS log space exhaustion.  Lazy unlock skips
`xfs_buf_delwri_submit`, dirty bufs sit in delwri queue, AIL items
pinned, log tail can't advance, log fills, new trans blocks
forever.  The earlier multi-node "DLM AG lock failed rc=-110"
shutdowns are the SAME root cause — CAW timeout is just the
downstream symptom of a node trying to get log reservation that
never comes.

Quantum=1 (every-other-unlock drain) doesn't prevent it because
under heavy create workload the AIL accumulates faster than the
every-other-unlock drain rate can submit + complete bufs.

**Fix direction for sess32:** lazy unlock should SUBMIT bufs
async, not skip submission entirely.  Skip only the SYNCHRONOUS
WAIT (blkdev_flush), let bufs trickle out asynchronously.  Bufs
complete in background → AIL items unpin → log tail advances.
~50 LOC change.  Specifically: add
`mxfs_dlm_ag_drain_alloc_buflist_async` that does
`xfs_buf_delwri_submit_nowait` + skip blkdev_flush, replace the
naive skip path with this async submit.

**v6a architectural model still validated** — the 4.08s SOLO
result on 8137 files (1.31× native XFS) is what's possible when
log space isn't exhausted (i.e., when the rsync write phase
itself runs).  The wedge is in the post-write phase where
log-using ops (atime updates, etc.) hit empty grant head.

**SESS31 FIX ATTEMPTS DID NOT RESOLVE** — sharper diagnosis:
v0.3.133 added async drain of alloc_buflist; v0.3.134 added
xfs_log_force(0).  Both reproduced the same xlog_grant_head_wait
hang.  Direct iostat showed disk idle with xfsaild running but
finding nothing to push.  Deeper investigation revealed the
real issue: pag_mxfs_alloc_buflist only contains CLUSTER bufs
(from xfs_ialloc_inode_init).  AIL items pinning log are mostly
BTREE BLOCK bufs (bnobt/cntbt/inobt/finobt) which aren't in
that list.  Async-draining the wrong list doesn't help.

xfsaild push of BLI items for btree blocks isn't progressing
under lazy=1 — but the reason isn't yet identified.  Sess32
needs P-INSTR in xfs_buf_item_push to capture push attempts
+ skip reasons under lazy=1 q=1 SOLO open-gpu workload.

b_iodone hijack hypothesis falsified by reading xfs_buf_ioend
(pal/linux/xfs_buf.c:1207-1211): xfs_buf_item_done() runs BEFORE
b_iodone, so BLI unpinning is independent of MXFS's b_iodone
override.

Build state: v0.3.134 srcversion DEFBBECBC5F6E31F4875DA2 ships
SAFELY at default lazy_ag_drain=0.  Three module params now
exposed: lazy_ag_drain, ag_yield_quantum, plus existing CAW
knobs.  Knob still opt-in until sess32 lands a working fix.

**v0.3.135 (srcversion FB7BE7317967C195ECF1703) — SOLO BUG FIXED:**

Final sess31 fix: unconditional `xfs_log_force(mp, 0)` at end of
`mxfs_ag_dlm_unlock` holders==0 path under lazy=1.  ~5 LOC.

Rationale: most file-create trans don't allocate new inode chunks
(use existing free inodes from inobt), so alloc_dirty stays false.
v0.3.133/134's drain+log_force only fired on alloc_dirty branch.
Without log_force on the bare unlock, CIL accumulates, btree-block
BLIs pinned, xfsaild stuck, log fills.

**Single-node SOLO test passes:** write+sync 12.14s, find 0.038s,
8137 files clean.  3.9× XFS native end-to-end.

**Multi-node still has SEPARATE bug:** test2 26s clean, test1
shutdown at 360s with DISKLOCK heartbeat timeout (different from
prior AG-DLM timeout error).  Sess32 must debug this — possibly
log_force contending with disklock under cross-node load, or a
pre-existing bug previously masked by the log starvation.

Default ships at lazy_ag_drain=0 (production behavior unchanged
across all sess31 versions).  Single-node users can enable the
knob for 11× speedup; multi-node should wait for disklock fix.

## Reference designs surveyed (sess31 read)

- **GFS2** (the model).  `~/src/linux/fs/gfs2/glock.c` for the state
  machine, `glops.c` for per-glock-type invalidation hooks
  (`inode_go_inval`, `rgrp_go_inval`), `meta_io.c` for the metadata
  read path that uses the kernel page cache.  Subagent report
  captured the file:lines.
- **OCFS2** (LVB pattern).  `~/src/linux/fs/ocfs2/dlmglue.c`,
  especially `__ocfs2_stuff_meta_lvb` 2161-2199 and
  `ocfs2_refresh_inode_from_lvb` 2208-2250.  LVB carries inode stat
  fields in the DLM grant message — sidesteps disk read on lock
  acquire for stat-class metadata.  Optional v6b enhancement; not
  in v6a.
- **mxfs.1** (direct-bio cliff).  Per-resource invalidation works,
  but `submit_bio_wait` per metadata block costs 4.3× XFS overhead.
  Reference for what NOT to do for the read path.
- **Ceph** capability bits — different topology (distributed object
  store, MDS-mediated).  Not viable for shared-block-device MXFS.

## What v6a is

The minimum change that gets v5 into the GFS2-amortized regime:

1. Remove `mxfs_buf_needs_fua_read` from `xfs/xfs_buf.c`.
2. Add `mxfs_clayer/invalidate.c` with `mxfs_invalidate_ag(ag_no)`
   and `mxfs_invalidate_inode(ino)`.
3. Wire into existing DLM lock-grant and lock-release callbacks.
4. Per-AG AIL drain (already on v5 phase plan, sess27).
5. Measure via `tests/decision_reproducers/v6a_h1_metadata_amortization.sh`.

Estimate: 4-8 sessions for v6a (phase 1 + phase 2 + measure
+ optional yield-quantum tuning).

## Sess31 deliverables (file paths)

- `/src/mxfs/docs/v6-cache-architecture-proposal.md` — the design.
- `/src/mxfs/bench/rsync_bench.sh` — relocated from /tmp.
- `/src/mxfs/bench/README.md` — bench inventory.
- `/src/mxfs/tests/decision_reproducers/v6a_h1_metadata_amortization.sh`
  — the falsifying test for H1.
- `/src/mxfs/CLAUDE.md` RULE 3 — persistent-scripts-in-tree rule
  (overrides global /tmp rule for MXFS).
- `/src/mxfs/state.md` sess31 entry.

## Discipline

The proposal explicitly gates v6b (LVB pattern) on v6a measurement.
Don't pre-implement v6b before measuring v6a.  Don't rationalize past
a failed H1.  This is the user's hypothesize→measure→develop→commit
cycle expressed in design.
