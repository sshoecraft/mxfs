---
name: compiled-cc-perf-slowness-starvation
description: Compiled: MXFS perf-as-coherency-failure — rsync IOPS ceiling, lazy AG-drain/yield-quantum, log starvation, CAW writer starvation, force_peer_flush.
metadata:
  type: project
tags: [compiled, performance, caw-starvation, cache-coherency, yield-quantum, rsync, log-starvation]
---

# Performance/slowness as a first-class coherency failure

Central thread across these sessions: in MXFS, **slowness IS a correctness failure**, not
a tuning nicety. Every multi-second stall on this hardware (native XFS does the same work
in 3-4s) traces to a specific coherency mechanism holding a lock too long or a peer never
getting a lock window. The four inputs span two distinct-but-linked problem families:
(a) the **metadata-write IOPS / FUA-drain ceiling** that made cross-node rsync 100×+ slower
than XFS ([[session71-perf-investigation]], [[sess31 lessons (research session for v6 cache architecture)]]),
and (b) **CAW lock writer starvation** producing ~60-120s `cache_coherency` barrier stalls
([[sess49_lessons]], [[sess50_lessons]]).

## The rsync bottleneck is IOPS, not FUA ([[session71-perf-investigation]], sess71, 2026-03-21)

Root cause, measured on real QNAP iSCSI: rsync issues **~43,000 small synchronous writes at
~550us each** (iSCSI round-trip); XFS does the same job in **~1,400 large writes**. The write
COUNT is the whole story — FUA vs non-FUA have identical latency on the QNAP, so FUA is not
the cost. Failed approaches: journal batching (checkpoint frequency defeats it), FUA removal
(no latency delta). XFS wins because it batches hundreds of transactions into one large journal
write every ~5s; MXFS does one synchronous round-trip per transaction. Planned fix:
**write-back metadata caching** — route dir_cache/inode_cache writes through block_cache
(mark dirty, flush on BAST/sync), batch journal writes with a periodic flush timer.
The DLM lock is the coherency gate: nothing needs to hit disk until a peer BASTs. block_cache
already does this for btree nodes; extend to all metadata. This is the v6 direction that
sess31 then formalized.

## v6a cache architecture: FUA-read amortization + lazy AG-drain ([[sess31 lessons (research session for v6 cache architecture)]], sess31, 2026-05-07)

Research-only session (no kernel behavior shipped default-on). Followed
hypothesize→measure→develop→commit. Motivation: sess30's 9+ minute 2-node rsync (3-4s
single-node) = v5's D6 hitting an architectural ceiling on metadata-create-heavy cross-node
workloads. Question answered: v5 does NOT need a full redesign; D6 is sound as spec'd — the
**implementation drift to FUA-on-every-read** is what's slow.

Key code finding (corrected v0.2): v5 v0.3.128 has BOTH invalidate-on-acquire AND
FUA-on-every-read (`xfs/xfs_mxfs_dlm.c:2480-2716` stales matching bufs + blkdev_flush;
`:300-424` dir-block stale on inode-lock release). Both are needed because the LIO/iSCSI
per-initiator read cache below returns stale data on plain bio reads (documented
`pal/linux/xfs_buf.c:1618-1628`; same shape as the mxfs.1 VMware-VMDK fix). The real defect:
FUA is issued on EVERY read, so a buf re-read while STILL holding the lock does needless I/O
instead of hitting the kernel xfs_buf cache — zero amortization within a hold.

Build progression (all default-safe at `lazy_ag_drain=0`):
- **v0.3.129 `233E460558A4B06DDD88440`** — `_XBF_FUA_FRESH` bit: set on successful FUA read in
  `mxfs_buf_read_fua` (`pal/linux/xfs_buf.c:1474`), cleared in `xfs_buf_stale` (`:82`), gate
  `mxfs_buf_needs_fua_read` on `!(_XBF_FUA_FRESH)` (`:1632`). ~10 LOC. Read side works:
  FUA-read traffic dropped **19×** (~1024/s→~54/s), 0 fallbacks/errors. But H1 (<60s) falsified:
  test2 iter1 = 278s, test1 killed at 600s (~21% done). Still real progress (sess30 was DNF).
- Residual bottleneck (H2): **FUA-WRITE drain at every transaction commit**. Stack:
  `xfs_buf_wait_unpin ← mxfs_dlm_ag_drain_alloc_buflist ← mxfs_ag_dlm_unlock ← xfs_trans_commit
  ← xfs_create`. Every create commits→unlocks AG-DLM→submits N FUA writes synchronously.
  The **D10 yield quantum** lever exists (`mxfs_clayer/yield_quantum.{c,h}`) but is NOT wired
  (`i_dlm_yield_remaining` only reset to 0 at `xfs_mxfs_dlm.c:1466`, never armed/consumed).
- **v0.3.130 `EB71BD3E4D5C5E89DAC31AF`** — opt-in `mxfs_lazy_ag_drain` param skips the drain when
  knob=1 AND no BAST pending AND alloc dirty. Mechanism confirmed: test1 solo 134.9s → 14.5s
  (9× from skipping per-trans drain). But binary skip-or-drain **starves** the contending peer
  (test2) because the eventual BAST-release drain accumulates too much dirty AG metadata.
- **v0.3.131 `D79B6EF600892AB43AD1E95`** — bounded yield quantum: `pag->pag_dlm_yield_remaining`,
  init `MXFS_BAST_YIELD_QUANTUM=32` on fresh CAW acquire, decrement per lazy-skipped unlock,
  force-reset+eager-drain on exhaustion. test2 element-web 4385 files = **25.993s STRONG H1 PASS**
  (match+md5 OK). But test1 open-gpu → EIO + shutdown at 360s in `mxfs_dlm_ilock_begin` (inode-DLM,
  NOT the AG path touched) rc=-110 ETIMEDOUT.
- **v0.3.132** — added `ag_yield_quantum` tunable. Disambiguation after virsh reset of BOTH
  nodes: test1 shutdown **REPRODUCED** at quantum=32 and quantum=4 → bug is NOT accumulation-size,
  NOT cross-node-specific; it's structural in the lazy_skip path under the open-gpu pattern.

Breakthrough (autonomous loop): **test1 SOLO + lazy=1 + ag_yield_quantum=1 + open-gpu rsync =
4.081s for 8137 files = 1.31× XFS native (3.12s)** — v6a achieves GFS2-equivalent perf on the
workload that was originally DNF. Bug is depth/structure-related, not size: 50 and 1000 flat
files clean; 8137 deeply-nested rsync clean (4s) but a subsequent `find` HANGS.

**SOLO bug root cause = XFS log space exhaustion.** Cleanest repro (`virsh destroy test2`,
single_node confirmed): `find` wedges in `xlog_grant_head_wait ← xlog_grant_head_check ←
xfs_log_reserve ← xfs_trans_alloc ← xfs_vn_update_time ← touch_atime ← iterate_dir ←
getdents64`. Lazy unlock skips `xfs_buf_delwri_submit` → dirty bufs sit in delwri queue → AIL
items pinned → log tail can't advance → log fills → new trans blocks forever. The multi-node
"DLM AG lock failed rc=-110" shutdowns are the **same** root cause; CAW timeout is the
downstream symptom of a node awaiting a log reservation that never comes. quantum=1 doesn't
prevent it — under heavy create the AIL accumulates faster than every-other-unlock drains.

Fix attempts that did NOT resolve it (sharper diagnosis each time):
- **v0.3.133** async drain of alloc_buflist; **v0.3.134 `DEFBBECBC5F6E31F4875DA2`** added
  `xfs_log_force(0)`. Both reproduced the same `xlog_grant_head_wait` hang. iostat: disk idle,
  xfsaild running but finding nothing to push. Real issue: `pag_mxfs_alloc_buflist` holds only
  CLUSTER bufs (from `xfs_ialloc_inode_init`); the AIL items pinning the log are mostly BTREE
  BLOCK bufs (bnobt/cntbt/inobt/finobt) that aren't in that list — async-draining the wrong list
  does nothing. `b_iodone`-hijack hypothesis FALSIFIED: `xfs_buf_item_done()` runs before
  `b_iodone` (`pal/linux/xfs_buf.c:1207-1211`), so BLI unpinning is independent of MXFS's
  b_iodone override.
- **v0.3.135 `FB7BE7317967C195ECF1703` — SOLO BUG FIXED:** unconditional `xfs_log_force(mp,0)`
  at end of `mxfs_ag_dlm_unlock` holders==0 path under lazy=1 (~5 LOC). Rationale: most
  file-create trans reuse existing free inodes (alloc_dirty stays false), so v0.3.133/134's
  drain+log_force only fired on the alloc_dirty branch; the bare unlock let CIL accumulate and
  pin btree-block BLIs. SOLO now: write+sync 12.14s, find 0.038s, 8137 files clean, 3.9× native.
- **Multi-node still has a SEPARATE bug**: test2 26s clean, test1 shutdown at 360s with DISKLOCK
  heartbeat timeout (distinct from the AG-DLM timeout) — possibly log_force contending with
  disklock, or a pre-existing bug unmasked by fixing log starvation. Handed to sess32.

Instrumentation caveat: UNLOCK-LAST events fire ~570/sec — too fast for printk-ratelimit;
counting `lazy_skip=1` in dmesg is unreliable, use wall-clock as the signal. Reference designs
surveyed: **GFS2** (the model — `~/src/linux/fs/gfs2/glock.c`, `glops.c` `inode_go_inval`/
`rgrp_go_inval`, `meta_io.c`), **OCFS2** LVB pattern (`dlmglue.c` `__ocfs2_stuff_meta_lvb`
2161-2199 / `ocfs2_refresh_inode_from_lvb` 2208-2250 — optional v6b), mxfs.1 direct-bio cliff (4.3× overhead, what NOT to do). v6a = remove
`mxfs_buf_needs_fua_read`, add `mxfs_clayer/invalidate.c`, wire into grant/release callbacks,
per-AG AIL drain, measure via `tests/decision_reproducers/v6a_h1_metadata_amortization.sh`.
Deliverables: `docs/v6-cache-architecture-proposal.md`, `bench/rsync_bench.sh`. Discipline:
gate v6b (LVB) on v6a measurement; don't rationalize past a failed H1.

## cache_coherency barrier stalls: eviction slowness + drevalidate deadlock ([[sess49_lessons]], sess49, 2026-06-02)

`cache_coherency` went 1/4 → 3/4 PASS via two KEEP fixes; builds sess48 `DDF05EA7` →
`D9B3F53A` → `FE42546D` → final `10A04B9E`.

- **FIX #1 reused-inode eviction SLOWNESS (`D9B3F53A`)**: sess48's type-mismatch eviction in
  `xfs_lookup` waited up to 120s (barrier timeout) for a peer's reused dir-inode to become
  durable (gen-gated recycle kept seeing stale disk). Fix: new `mxfs_dlm_force_peer_flush(ip)`
  (`xfs/xfs_mxfs_dlm.c`, by `mxfs_read_coherency_envelope`) — type-agnostic ilock_begin(PR)+
  ilock_end(PR), `i_dlm_stale` MUST be clear (no in-place reload) — called in the xfs_lookup
  eviction block before setting `i_dlm_stale`. A PR acquire BASTs the creator's sticky EX so it
  drains+iflushes the new dinode before downconverting; the next iget's recycle adopts the fresh
  incarnation. Proven: rename 133→26s, unlink 264→35s. Valid because the CREATOR holds inode EX
  (sticky) via `xfs_create→xfs_ilock→ilock_begin(EX)`.
- **FIX #2 drevalidate PERMANENT DEADLOCK, fixed at source (`10A04B9E`)**: `repro_barrier_dir.sh`
  wedged a `touch` D-state forever: `mxfs_drevalidate → xfs_dir_lookup → xfs_ilock(dp,SHARED) →
  ilock_begin → mxfs_dlm_reload_inode → down_write(&dp->i_lock)`. d_revalidate runs in
  lookup_fast() path-walk; the reload's blocking down_write wedges when another holder of
  dp->i_lock is parked (a thread holding ILOCK_SHARED across a CAW poll — the CLAUDE.md
  "ILOCK held across CAW poll" tension). LOCKLESS drevalidate (`FE42546D`) was REVERTED —
  it fixed the deadlock but REGRESSED rename (375s, barriers 1/4) by removing the coordinated
  dir reload and causing a re-lookup storm. FINAL: bound `mxfs_dlm_reload_inode`'s down_write
  (`xfs_mxfs_dlm.c:~1249`) to `down_write_trylock`+cond_resched (1000×), bail on contention
  leaving `i_dlm_stale` set (buffer already staled → next uncontended access re-reads); then
  RESTORE coordinated drevalidate (sess45 version). Result: repro 0/60 no wedge; ALL 4
  sub-tests PASS INDIVIDUALLY (cross_vis 135s, rename 26s, unlink 152s, cwr 135s).

Remaining blocker at sess49 close: the SEQUENTIAL criterion (1 reset, 4 tests on ONE mount)
still FAILS — cross-test contamination plus a flaky 120s barrier stall tips whichever test runs
late. Even passing tests take ~135s = one 120s barrier timeout that eventually resolves. Root
NOT proven. Mid-session "sticky PR mode → peer EX never BASTs" theory flagged LIKELY WRONG
(bast_process sets `i_dlm_mode=NL` at `xfs_mxfs_dlm.c:690` before releasing). Left as
instrument-per-RULE-4 questions; NOT per-op FUA (sess43 too slow).

## Barrier stall ROOT-CAUSED = CAW writer starvation ([[sess50_lessons]], sess50, 2026-06-03)

Build **`86855C4428A26B4D1F068CF`** (test1-4), builds on `10A04B9E` (all sess49 fixes intact).
PROVEN root of the dominant ~60-120s barrier-visibility stall = **CAW lock writer starvation**.

Evidence (RULE 4, quantitative): new `tests/repro_barrier_latency.sh` mimics the cluster.sh
barrier (mkdir+touch nodeN, poll `find -name node*` til 4 seen), reproduces the stall ~1/4
iters on the OLD build — a PURE readdir dir-block visibility miss (no corruption/EIO on a clean
mount; `find` only does readdir(PR)). Non-perturbing `SESS50-STARVE` probe in CAW `bast_poll_fn`
(reuses the already-read slot, no extra I/O): during a 69s stall it fired **130×** on the 3
reader nodes with persistent `our_mode=3(PR) waiter_mode=5(EX)`, slot generation churning
~45→1695 (**~24/sec**). The PR readers across nodes continuously re-grant PR among themselves
(each grant bumps gen) → a peer's EX request never finds a zero-PR-holder window → its dir
modification (barrier marker) stays invisible ~69s until a read lull. COHOLD detector = 0
(refutes sess46 PR+EX co-hold theory; sess49 Q1 "on-disk PR slot dropped" also refuted — census
showed sticky PR keeps the slot). **Heisenberg**: ANY perturbation (dir-ilock fast-path logging,
census double-reads, a 3s idle settle) creates the read lull the writer needs → stall vanishes;
this is why sess36-49 kept losing it. Use poll-thread detectors, never dir-path logging.

**FIX (`86855C4`, KEEP) — anti-starvation in `mxfs_dlm_caw_lock` (`dlm/dlm_caw.c:~1446`)**:
before the compat-grant branch, `defer_for_waiter` = a FRESH acquire (our_mode==NL) of a SHARED
mode (PR/CR/CW) while a PEER waits for an EXCLUSIVE mode (waiter_mode EX/PW) → do NOT grab the
compatible lock; fall through to waiter-register/wait so holders drain and the exclusive waiter
wins. **Readers yield to writers ONLY** — writer-writer and reader-reader never mutually defer.
(v1 deferred ALL fresh incompatible-waiter cases → all-4 stall + writer ENOENT; refined to
shared-yields-to-exclusive.) RESULT: repro stalls **4-5/20 → 1/20**; `cache_coherency.sh
--nodes 4` **passed 0→1** (test_unlink_visibility now PASSES). The remaining 1/20 is NOT
starvation (STARVE fired once, gen=13, no churn). Detectors `SESS50-STARVE` + `SESS50-COHOLD`
in `bast_poll_fn` are always-on, ratelimited, fire only on the bug (KEEP).

Two DISTINCT remaining roots at sess50 close, neither starvation:
1. **Reused-inode ENOTDIR on barrier dir** (cross_write_read): `cwr_verify` dir inode reused
   from a reg file, peer cached it as reg → "Not a directory" → 120s timeout (sess48 family).
   Verify the sess48/49 type-mismatch evict + force_peer_flush (currently in the xfs_lookup
   child path) fire for the barrier-dir lookup.
2. **Dir-block lost-update** (rename 1/240; ~1/20 in repro): two concurrent EX writers each add
   a dirent, one reads a stale dir block before re-adding → loses the peer's entry. Read-side
   `i_dlm_dir_gen` covers READERS; the WRITER under EX may add to its own stale cached block.
   Candidate: on slow-path EX acquire of a dir, invalidate the cached dir DATA block (not just
   bump dir_gen).

## Cross-cutting lessons

- **A timeout is a test FAIL, not a safety net.** ~135s "passing" runs each contain one 120s
  barrier timeout that eventually resolves — treat as a bug, not a pass.
- **Slowness = coherency failure.** Both problem families (FUA-write drain, PR-reader
  starvation) are lock-hold / lock-window bugs, not I/O-bandwidth bugs. Disk is idle during
  the log-starvation hang; the stall is entirely in coordination.
- **Non-perturbing instrumentation only** for these races. Poll-thread detectors that reuse
  already-read slot state (SESS50-STARVE/COHOLD) catch the bug; any dir-path logging or extra
  read creates the very lull that hides it (Heisenberg).
- **Yield/lazy policy is binary-vs-bounded.** Binary skip-or-drain (`lazy_ag_drain`) always
  starves the peer; you need a bounded quantum AND async submission (skip only the synchronous
  `blkdev_flush`, never `xfs_buf_delwri_submit`) so AIL items unpin and the log tail advances.
- **Know which buflist pins the log.** `pag_mxfs_alloc_buflist` holds only cluster bufs; the
  btree-block BLIs (bnobt/cntbt/inobt/finobt) that actually pin the log tail live elsewhere —
  draining the wrong list is a no-op.
