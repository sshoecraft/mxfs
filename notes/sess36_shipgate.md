# sess36 — ship-gate work + Mode A re-diagnosis (2026-05-29)

Build line: v0.4.1 (instrumentation build srcversion D6DEB43284AF1DCD37C7CD2)
→ v0.4.3 reverted-baseline (mount/packaging/criteria fixes; NO coherency change).
Cluster: v5 = test1..test16, SCST iSCSI (vendor SCST_FIO, CAW works), /dev/sda → /mnt/shared.
Coordinator shell is on host `clyde` with full `virsh` access (test1..test32 are VMs).

## Ship-gate status (.criteria_results.json)

FIXED + verified PASS this session:
- **cluster_ops_timing / chk_clean / online_membership** — all were failing on a
  ~16-18s first-mount. Root cause = two avoidable delays in CAW DLM init
  (dlm/v5_mount.c mxfs_dlm_caw_create path):
  1. `mxfs_disklock_get_stale_slot_mask` (dlm/disklock.c) did an **unconditional
     10s sleep** (`HB_INTERVAL_MS*5`) even when no peers were active. FIX:
     poll-with-early-exit — a live peer's heartbeat advances within ~1 interval,
     so return as soon as all snapshot-active slots advance; only genuinely stale
     slots wait the full window. Correctness identical (stale only declared after
     full window). Also short-circuits to 0 when snapshot empty.
  2. `mxfs_dlm_caw_purge_dead_nodes` (dlm/dlm_caw.c) scanned all 65536 CAW slots
     with **one 512B read_slot per slot (~5s)** on every mount. FIX: batch-read
     the table in 32-slot (16KB, kzalloc/contiguous) chunks for the find phase;
     per-candidate purge (CAS+repair) path unchanged.
  Result: first mount ~2.8s, joining node ~5.5s. All three criteria PASS.
- **online_resize** — was failing because a prior aborted run left the module
  loaded + /mnt/resize_mount mounted, and the criterion's `set -e` + `insmod 2>/dev/null`
  aborted on "already loaded". FIX (tests/criteria/online_resize.sh): idempotent
  cleanup of leftover loop/mount up front + `lsmod|grep -q '^mxfs ' || insmod`.
  mkfs.mxfs on loopback works fine. PASS (912MB→1936MB, md5_OK).
- **dkms_install** — packaging was still wired for the old mxfs.1 layout
  (libmxfs/, frontend/, mxfs_common.h version → "0.0.0"). FIX (packaging/common.sh):
  `mxfs_version` reads top-level VERSION file; `mxfs_stage_kmod_source` rsyncs the
  v5 tree (compat include xfs dlm pal mxfs_clayer + Kbuild/Makefile/VERSION, source
  only). Also bumped criterion's per-call SSH timeout to 300s + script timeout 360s
  because the on-node DKMS build of the full XFS fork takes ~76s (> default 60s ssh
  timeout, which truncated INSTALL_RC). PASS.

Already green: mkfs_timing, wedged_unmount, dmesg_clean, cache_caps.

STILL FAILING (all blocked by the one coherency bug below):
- cache_coherency, strong_consistency, zero_silent_loss, posix_semantics(1 & 16),
  crash_consistency, fence_during_write, and the perf criteria (run last).

## THE core bug — concurrent same-name create = lost update (Mode A), re-diagnosed

Reproducer (NEW, fast, reliable): `tests/repro_modea.sh [iters] [n1] [n2]`.
Concurrent `mkdir SAMEPATH; touch nodeN; sync` from both nodes, then each lists.
**19-20/20 fail.** Signature: both nodes' dir has DIFFERENT inode (ino1≠ino2).

What is NOT the bug (proven this session):
- Sequential cross-node visibility WORKS (node1 create+sync, then node2 ls → sees it).
- Concurrent add of DISTINCT names to a PRE-EXISTING dir WORKS (20/20 entries seen).
- It is NOT a storage durability cliff (SCST CAW is sound).

What IS the bug (ground-truth proven):
- Concurrent `mkdir` of the SAME new name from 2 nodes → both pass the not-exists
  check and both dialloc+add → two inodes for one name.
- **Disk ground truth** (unmount BOTH, remount one): root durably keeps only ONE
  node's entry (the last writer's); the other node's entry is silently LOST.
  → It is a **lost update / last-writer-wins on the parent dir block RMW**, not a
  "write never persists" problem.
- Instrumentation (module D6DEB43...): during the concurrent create, BOTH nodes'
  FUA-read of root's dir block returns `P-H16 ACQ-DISK-DIR3 ino=128 lba=120
  magic=0x0` (zeros), so each adds its entry to an empty view and writes,
  clobbering the peer.
- The releasing node's BAST path (`reload_inode`/bast_process in xfs/xfs_mxfs_dlm.c,
  ~line 180-530) does log_force(SYNC)+xfs_ail_push_ag_sync(agno)+blkdev_issue_flush
  (twice, msleep(20) between), THEN the BAST-DIR-STALE walk does `xfs_buf_stale()`
  (DISCARD) on the dir data bufs. `P36-INSTR ... staled=0 skip_locked=1`: the dir
  buf is often LOCKED (P-H12: b_transp=NULL, pin=0, bip_in_ail=-1, flags=0x80030 =
  XBF_DONE|XBF_ASYNC|custom) → an **in-flight async write**, so it is skipped.

Leading hypotheses for next session (RULE 4 — instrument before patching):
- H-A: `xfs_buf_stale()` on a committed-but-home-not-yet-written dir buf **cancels
  the home-block write** (content lives only in the log); peer reads the stale home
  block directly (magic=0x0). Need: ensure dir home block is WRITTEN (not just
  push-initiated) before stale/release. Risk: sess34 tried synchronous push from
  bast and hit lock-inversion with xfsaild — must avoid.
- H-B: the v0.3.148 change in xfs_create (xfs/xfs_inode.c ~771-804) **drops dp ILOCK
  across xfs_dialloc**, opening a window where the BAST releases the parent DLM
  mid-create and the peer sneaks its RMW in. dp ILOCK is re-acquired at line 801
  (which re-runs mxfs_dlm_ilock_begin); check whether that reload actually reads the
  peer's committed dir block or still races. Reverting the drop reintroduces the
  sess33 AG-drain deadlock — need a way to hold the DLM (defer its BAST release)
  across dialloc without holding ILOCK.
- H-C: ail_push_ag_sync runs before the dir buf's BLI is added to the AIL (async
  CIL→AIL race the msleep(20) targets), so the home write never happens, then
  xfs_buf_stale discards it.

DISPROVEN fixes this session (do NOT retry as-is):
- (1) v0.4.3: bounded wait-for-lock + STALE of the skip_locked dir buf in the
  BAST-DIR-STALE walk. 20/20 still failed; `magic=0x0` persisted. Staling DISCARDS
  the buf — it does not WRITE the entry to disk. Reverted.
- (2) v0.4.4 (H-B): hold dp ILOCK_EXCL across xfs_dialloc (revert v0.3.148 drop).
  17/20 (no real change, no deadlock at light load). REFUTED because local ILOCK
  does not serialize across nodes — only the CAW DLM does. Reverted.

DECISIVE DLM-timeline capture (both nodes, one failing iter, module D6DEB43/D1438):
  test2:  bast_notify ino=128 BRANCH=deferred (active holders) — set BAST
          → BAST-MEM-PRE → BAST-DISK → BAST-DIR-STALE staled=0 skip_locked=1
          → P-H22-CALL site=BAST_RELEASE
  test1:  P13 GRANT-POLL ino=128 granted=5 want=3   (root held EX by peer)
          → GRANT-POLL granted=0                     (peer released)
          → ACQ-FRESH mode=3 → mode=5                (test1 acquires AFTER release)
  So the CAW DLM **does serialize** (test2 holds → defers test1's BAST → releases →
  test1 acquires). NOT concurrent. The earlier "<1ms concurrent" read was wrong.

  REAL root cause (consistent with disk ground-truth): test2 RELEASES root's DLM
  with `BAST-DIR-STALE staled=0 skip_locked=1` — its dir-block entry is NOT durable
  on disk at release. The skipped buf (P-H12) has b_transp=NULL, pin=0,
  bip_in_ail=-1 (NO buf-log-item / not AIL-tracked), flags=XBF_DONE|XBF_ASYNC,
  locked. So log_force/ail_push_ag_sync never writes it. test1 then acquires, FUA-
  reads root (magic=0x0 — stale/empty), doesn't see test2's entry, creates a
  duplicate. Last writer wins on disk (ground-truth: test2's version persisted).

  OPEN PUZZLE for next session: WHY does a committed mkdir's dir block have NO BLI
  and is NOT in the AIL (bip_in_ail=-1)? A logged dir-block modification should have
  a BLI in the AIL until written. Two sub-hypotheses to instrument:
    (i)  the buf was ALREADY written (iodone cleared BLI) but to a DIFFERENT LBA
         than test1 reads → test1's reloaded extent map for root is STALE (points to
         old/freed block) → reads zeros. FIX would be on the ACQUIRE side: fully
         re-read the data-fork extents on reload, not just the dinode core.
    (ii) test2's entry lives only in the cached buf and nothing writes it; stale
         discards it. FIX on RELEASE side: WRITE the dir block before release.
  NEXT STEP (RULE 4): add instrumentation logging, on the RELEASING node, test2's
  dir-block WRITE LBA + first 16 bytes (does it contain the new name?), and on the
  ACQUIRING node, test1's dir-block READ LBA + bytes. Compare LBAs. That single
  experiment distinguishes (i) vs (ii) and points to the exact fix. Do NOT patch
  before this.
  CAUTION: a manual xfs_bwrite of the dir buf from the bast worker bypasses XFS's
  AIL/iflush metadata-writeback ordering and may corrupt the log — not a safe fix
  without understanding why the buf left the AIL.

## ⚠️ MAJOR CORRECTION (sess36 end) — `magic=0x0` was an INSTRUMENTATION ARTIFACT

The P-H16 ACQ-DISK-DIR3 diagnostic (xfs/xfs_mxfs_dlm.c ~1026) called
`mxfs_pal_scsi_read_fua_bdev(bdev, lba = XFS_FSB_TO_DADDR(...))` with the RAW XFS
daddr and **forgot to add `bt_sector_offset`**.  XFS daddrs are relative to the XFS
data region, which the MXFS envelope places at device offset 100704256 =
**196688 sectors** (`bt_sector_offset`).  So P-H16 was reading /dev/sda at the raw
daddr (e.g. lba 120 = byte 61440, inside the journal/envelope) → all zeros →
`magic=0x0`.  **This is a read of the WRONG location, not the real dir block.**

- The PRODUCTION read paths are CORRECT: `mxfs_buf_read_fua` (pal/linux/xfs_buf.c
  ~1520), the xfs_buf bio path (~1399), xfs_iomap (~131), and xfs_log all add
  `bt_sector_offset`.  Only the P-H16 diagnostic omitted it.
- Verified storage is COHERENT: read clyde's backing file /home/steve/disk-1.img at
  the CORRECT offset (100704256 + daddr*512) after a failing iter → a VALID `XDB3`
  dir3 block is present (not zeros).  SCST is write_through=1, nv_cache=0, device
  WCE=write-through → writes durable on completion.
- P-H27-SUBMIT-DIR3 confirms BOTH nodes write the SAME LBA (daddr=120) with valid
  XDB3 content, COMPLETE bi_status=0.  No extent-map divergence.

**FIXED the P-H16 instrumentation** (v0.4.5, srcversion E06DB7064C93254CF9EA50A):
added `+ mp->m_ddev_targp->bt_sector_offset`.  Future P-H16 captures now read the
real block.  IMPLICATION: sess34/35's entire "disk reads zeros / durability cliff"
line of investigation was very likely chasing this artifact.  Re-evaluate those
conclusions.

## CORRECTED root-cause picture for sess37

The bug is a genuine LOST UPDATE, but NOT because disk reads zeros:
- DLM serializes correctly (timeline: test2 holds root EX → defers test1's BAST →
  releases → test1 acquires after).  NOT concurrent EX.
- Storage is coherent and durable.
- So: when the acquiring node (say test2) takes root after the peer's create, its
  read-modify-write BASE for root's dir block must already contain the peer's new
  entry.  It does not → test2 clobbers.  Therefore the acquiring node is using a
  STALE CACHED dir buf (its RMW didn't re-read the peer's committed block), i.e.
  the acquire-side cache invalidation for dir DATA blocks is incomplete.
- Candidate sites: the reload path's H18 stale walk (xfs/xfs_mxfs_dlm.c ~1019-1066,
  xfs_buf_trylock → may skip locked bufs) and the `_XBF_FUA_FRESH` /
  `mxfs_buf_in_fua_window` gate (pal/linux/xfs_buf.c ~1707) that decides whether a
  read bypasses lower-layer cache.  If root's dir block isn't covered, the node
  reuses its stale XBF_DONE buf.
- sess37 NEXT STEP (RULE 4): with the FIXED P-H16, capture on the acquiring node:
  does P-H16 (now correct LBA) show the peer's entry on disk at acquire time?  If
  YES → the node has it on disk but uses a stale cached buf → fix = force re-read
  (stale/invalidate the dir buf, incl. locked ones, on acquire).  If NO (peer's
  entry not yet on disk at acquire) → the releasing node released before its dir
  block write landed → fix = ensure dir-block home write completes before DLM
  release.  This single capture decides the fix direction.

## sess36 FINAL mechanism (P67/P68/reload capture, corrected P-H16 build v0.4.5)

Per-acquire DLM state for parent root (ino=128) during a failing concurrent create
(P67-INSTR ILOCK-BEGIN-DIR logs req_mode/cached_mode/state/stale):

  test1 (had root cached EX):
    ILOCK-BEGIN req=3 cached=5 state=1(CACHED) stale=0  → P63 FAST-PATH (NO reload).
      VFS lookup of the new name uses test1's CACHED dir buf. "not found" (correct —
      peer hasn't created yet). Lookup releases; holders→0.
    [deferred BAST now fires — test2 demotes test1, acquires root EX, ADDS its entry,
     commits, releases.  DLM serialization is correct here.]
    ILOCK-BEGIN req=5 cached=5 state=3(DEMOTING) stale=0 → fast-path skipped (state≠
      CACHED) → DEMOTING-wait → slow-path → P13 ACQ-FRESH mode=5.  **NO ACQ-DISK-DIR3
      fired → reload did NOT re-read the dir DATA block.**  xfs_dir_createname's
      EEXIST re-check reads test1's STALE cached dir buf (from the lookup phase,
      pre-test2) → doesn't see test2's entry → creates a DUPLICATE inode.
  test2: req=3 cached=0(NL) state=0 stale=1 → slow path (correct, reloads); creates;
    then req=5 upgrade.  test2's view is fine; it's the LAST writer in some iters.

ROOT DEFECT (precise): two coupled gaps.
  (1) The VFS lookup→create sequence does NOT hold the parent DLM lock continuously.
      Between lookup-release (holders→0) and create's EX-acquire, the deferred BAST
      demotes the parent to the peer, who modifies it.  (mxfs defers BAST only while
      holder count>0; the count is 0 in this gap even though the VFS i_rwsem is held
      exclusive across the whole lookup+create.)
  (2) On the create's EX re-acquire, reload_inode runs (mode!=0, line ~1413-1415) but
      ACQ-DISK-DIR3 did not fire → the dir DATA block was not re-read fresh, so the
      EEXIST re-check used the stale cached buf.  root is fmt=2 (EXTENTS/block dir,
      separate data block at daddr 120), so the H18 stale walk + dir-read SHOULD have
      invalidated+refreshed it — find why it didn't (candidate: H18 trylock skipped a
      locked buf; or the dir-block read path in reload was bypassed for this acquire).

sess37 fix directions (pick via one capture: grep P-H18 + corrected P-H16 magic at the
EX re-acquire to see whether test2's entry is on disk and whether the cached buf was
staled):
  A. Make BAST-deferral track the parent's VFS i_rwsem / a "create-in-progress" flag,
     not just holder count — so the parent DLM lock is NOT demoted across the
     lookup→create gap.  Closes gap (1); most architecturally correct.
  B. On the create's EX-acquire of a directory after a demote, FORCE-invalidate the
     parent's cached dir data bufs (incl. bounded-wait for locked ones) so
     xfs_dir_createname re-reads fresh and the EEXIST check sees the peer's entry.
     Closes gap (2).  Verify the dir block is actually on disk first (corrected P-H16).
  (Do NOT re-try: release-side skip_locked stale [v0.4.3] or ILOCK-across-dialloc
   [v0.4.4] — both disproven.)

## sess36 continuation — pitfalls (avoid these in sess37)

1. **Do NOT call `xfs_dir_lookup()` inside `xfs_create` as a diagnostic.** Tried it
   under the held dp ILOCK_EXCL + active transaction (after the line-801 xfs_ilock) to
   answer "is the peer's entry visible at create time" — it **DEADLOCKED** the mkdir
   (D-state on both nodes; required virsh reset).  Reverted.  For a safe equivalent,
   either (a) log the RETURN of the existing `xfs_dir_create_child`/`xfs_dir_createname`
   (EEXIST vs 0 — no extra locking), or (b) make the corrected P-H16 in reload_inode
   format-agnostic (log entry count / a generic marker) since reload already holds the
   right context.
2. **Do NOT rebuild/replace the NFS-shared `/src/mxfs/mxfs.ko` while any criterion or
   test is running.** Criteria reload the module mid-run (teardown_all + insmod), so a
   swap to a different/broken build corrupts their results or wedges nodes.  This
   invalidated this session's single_node_paired run (mxfs leg loaded the deadlocking
   diagnostic build → wedged → "mxfs run failed") and wedged test1.  Build to a
   separate path or quiesce all node activity before `make modules`.
3. **single_node_paired / posix_semantics --nodes 1 results from sess36 are INVALID:**
   single_node_paired FAIL (xfs=346 mxfs=empty) was the module-swap artifact above, not
   a real perf result.  posix_semantics --nodes 1 was killed by a too-short outer
   `timeout 400` (it runs the full framework incl. the stress phase on one node and
   needs much longer; rely on the criterion's own set_script_timeout, don't wrap).
   Re-run BOTH on the clean E06DB build with no module swaps in flight.
4. The gap-1 (peer entry not durable on disk at acquire) vs gap-2 (visible but EEXIST
   re-check bypassed) question is STILL OPEN — the unsafe diagnostic didn't answer it.
   Use the safe diagnostics in (1) next.

## sess36 continuation 2 — INSTRUMENTATION = ~100x PERF CLIFF (now gated, v0.4.6)

single_node_paired re-run on the clean build measured xfs leg = 4413ms but the mxfs
leg ran **>600s** (killed by the per-call SSH timeout → reported "mxfs run failed").
Diagnosis: the mxfs leg was NOT failing — it was crawling.  The sess20-35 diagnostic
printk's fire per-metadata-op (P-H27-SUBMIT/COMPLETE-DIR3 on EVERY dir-block write,
P9 dialloc per create, P13/P63 per acquire, H40 per create) and at rsync's thousands
of metadata ops/sec they dominate, making mxfs ~100x slower than native XFS.  So the
instrumentation MUST be gated for ANY perf criterion (single_node_paired, rsync_paired,
scaling_curve) AND for a real ship build.

FIX (v0.4.6): added module param `mxfs.instr` (int, default 0) + gate macros
`mxfs_idbg`/`mxfs_idbg_once` in xfs/xfs_mxfs_dlm.h; defined the var + module_param in
xfs/xfs_mxfs_dlm.c.  Converted all hot-path pr_warn instrumentation (P*/MX-INSTR/H tags)
to mxfs_idbg in xfs/xfs_mxfs_dlm.c (36), pal/linux/xfs_buf.c (7), xfs/xfs_inode.c (3),
and gated P9 dialloc in xfs/libxfs/xfs_ialloc.c inline.  These printk's are pure logging
(no side effects) so off-by-default cannot affect correctness; `insmod ... instr=1`
re-enables for debugging.  (Header-comment gotcha: a `*/` inside the comment text
prematurely closed the C comment — avoid `P-*/` literals in comments.)
STILL UNGATED: the multi-line `mxfs_pal_log(MXFS_LOG_*, "mxfs: P55/P56/P58/P59/...")`
bast-path instrumentation in xfs_mxfs_dlm.c (~29) — these fire only on cross-node BAST,
so they don't hurt single-node perf but WILL hurt multi-node perf (rsync_paired,
scaling_curve).  sess37: gate these too (they're 2-line calls: wrap each in
`if (mxfs_instr_enabled) { ... }` or convert to a level-less mxfs_idbg).

NEXT after gating verified: re-run single_node_paired (expect mxfs ≈ xfs now) and
re-confirm repro_modea still ~19-20/20 (gating must not change coherency).  Then resume
the coherency lost-update fix.

## sess36 continuation 3 — SECOND DEEP BUG: single-node log-space WEDGE under heavy metadata

After gating instrumentation (v0.4.6, confirmed 0 P-prints in dmesg), single_node_paired
STILL fails: the mxfs leg WEDGES.  `find`/`ls`/`rsync` on /mnt/shared all go D-state.
Kernel stacks of every wedged proc:

  xlog_grant_head_wait → xlog_grant_head_check → xfs_log_reserve → xfs_trans_alloc
    (rsync via xfs_bmapi_convert_delalloc→xfs_map_blocks→iomap writeback; xfs_log_worker
     via xfs_sync_sb; flush kworker; etc.)

i.e. **the on-disk log is FULL and the tail is not advancing → every transaction blocks
on log reservation → whole FS wedges.**  Critically, `xfsaild/sda` is in state **S
(sleeping), not D** — it is NOT pushing the AIL.  So the log tail isn't moving because
xfsaild isn't draining (items pinned / not woken / slice-LSN accounting off), NOT
because of a lock it's stuck on.

Prime suspect: the per-node journal slice is only **4 MB** (mkfs: "XFS log: 4 per-node
slices, 1024 blocks = 4.00 MB each"; journal region is 64 MB / 64 slots).  4 MB is far
below what XFS expects (a 20 GB fs would normally get a ~10-16 MB log).  A metadata-heavy
rsync (8137 files) fills 4 MB faster than the tail advances → log-full wedge.  This is
consistent with the project's known "AIL push deadlock under load" (sess27: 5×512 hung
in xfs_ail_push_all_sync) and the wedged-unmount history — same family.

This is a SECOND deep blocker, independent of the cross-node coherency RMW bug:
- It wedges SINGLE-NODE (no cross-node involved), so it's purely the mxfs log/AIL/journal-
  slicing machinery vs XFS's log-tail accounting.
- It blocks ALL heavy-metadata criteria: single_node_paired, rsync_paired, scaling_curve,
  soak, and likely contributes to zero_silent_loss / cache_coherency timeouts under load.

sess37 investigation directions (RULE 4):
  1. Confirm size-vs-deadlock: does a LIGHT rsync (e.g. 500 files) complete on single-node
     mxfs, while 8137 wedges?  If light passes, it's log-space exhaustion (fix = larger
     per-node log slice in mkfs_mxfs / journal slicing).  If light also wedges, it's a hard
     log-tail/grant accounting deadlock from the slicing.
  2. Why is xfsaild sleeping while the log is full?  Instrument the AIL push path / log
     grant: is the grant head waiting on a tail LSN that the per-node slice never reaches?
     The journal-slicing remaps each node's log to a slice — verify the grant/tail LSN math
     (xlog_grant_head_wait wakes when tail moves; if mxfs's slice offsetting breaks the
     tail-LSN comparison, it waits forever).
  3. Check whether `xfs_log_worker` being blocked (it tries xfs_sync_sb → log_reserve) is
     part of a self-deadlock: the periodic log worker that would push/cover the log is
     itself stuck needing log space.
  Likely fix: enlarge the per-node log slice (mkfs_mxfs) AND/OR fix the slice LSN accounting
  so xfsaild's tail advancement frees grant space.  This is in the journal-slicing layer
  (dlm/ journal slicing + xfs/xfs_log*.c bt_sector_offset-style remap).

  REFINEMENT (verified): trivial loads do NOT wedge — chk_clean (32 small files) PASSES,
  the concurrent-mkdir reproducer's mkdirs complete.  The wedge needs SUSTAINED DATA
  WRITES (rsync of file contents → delalloc → writeback → xfs_bmapi_convert_delalloc
  needs a transaction → log).  A ~200-file rsync was enough to wedge; once wedged, even a
  subsequent single mkdir goes D-state (downstream of the full log).  dmesg confirms the
  slice: "MXFS: per-node log slice 3/4 offset=20897816 bblks=8192" → 8192 BB = 4 MiB.
  CENTRAL PUZZLE: xfsaild/sda is SLEEPING (state S) while the log is full and writers wait
  on grant — normally xlog_grant_head_wait pushes the AIL / forces the log to free space.
  Either the wakeup path is broken or the sliced-log tail LSN never satisfies the grant.
  Suspect the sess32-33 AIL changes (PUSH_ALL flag, log_force kicker, bounded ag drains)
  altered xfsaild/log-force interaction and/or the per-node slice LSN math.
  CODE MAP: per-node slice setup xfs/xfs_mount.c:~1045 (the slice message) and
  pal/linux/xfs_super.c:~2019; log grant/tail xfs/xfs_log.c (xlog_grant_head_wait,
  xlog_assign_tail_lsn); AIL push xfs/xfs_trans_ail.c (xfsaild, xfs_ail_push*); recovery
  xfs/xfs_log_recover.c.  Compare native XFS log size for a 20 GB fs (~10-16 MB) vs the
  4 MB slice — the slice is almost certainly undersized for metadata/data-heavy workloads.
  NOTE: prior MXFS versions DID run rsync benches (bench.json has single_node_paired_rsync
  + scaling entries), so single-node rsync worked at some point → this may be a REGRESSION
  from a sess20-35 AIL/log change rather than inherent to slicing.  Bisecting the AIL/log
  changes (or testing a larger slice via mkfs_mxfs) is the sess37 starting move.

  EXACT FIX LOCATION (log size): tools/mkfs_mxfs.c:1125-1127
    geom.logblocks = (uint32_t)(geom.dblocks / 2048);
    if (geom.logblocks < 1024) geom.logblocks = 1024;   // 1024 fsb = 4 MiB floor
  The per-node XFS log slice (m_mxfs_log_slice_bblks, written via
  sup.xfs_log_slice_bblks at mkfs_mxfs.c:553-554, read at pal/linux/xfs_super.c:1802-1805)
  is this 4 MiB.  sess37 first experiment: raise the floor (e.g. 1024→4096 = 16 MiB) and/or
  the slice size, ensure log_node_count × slice_bblks still fits the 64 MiB journal region,
  rebuild tools (make -C tools), re-mkfs, remount single-node, and re-run the ~200-file
  rsync — if it no longer wedges, the undersized log was the cause (fix = larger slice).
  If it STILL wedges at a larger log, the bug is the xfsaild-wakeup/tail-advance path
  (xfs_log.c grant→xfs_ail_push, xfs_trans_ail.c xfsaild) — likely a sess32-33 regression.
  Build+test cycle is multi-minute; do NOT swap /src/mxfs/mxfs.ko while any criterion runs.

## sess36 continuation 4 — LOG-WEDGE FIX VALIDATED (16MB log slice)

Enlarged the per-node internal XFS log slice 4MB→16MB (tools/mkfs_mxfs.c:1131-1136,
`log_node_count * 1024`→`* 4096`).  Rebuilt tools (`make -C tools`, OK).  Validated with
tests/repro_logwedge.sh test1 (re-mkfs + escalating single-node rsync):
  200 files  -> DONE_0   (4MB slice WEDGED here)
  1000 files -> DONE_0
  4000 files -> DONE_0
  8137 files -> DONE_11   (rsync rc=11 = file-IO error, NOT a wedge — it RETURNED)
  RESULT: LOGWEDGE NOT reproduced through 8137 files.
=> The single-node log wedge was undersized-log exhaustion, NOT an xfsaild-wakeup
   deadlock.  16MB per-node slice fixes it.  This unblocks the heavy-load criteria.

OPEN follow-ups (sess37):
  - 8137-file rsync returned rc=11 (rsync IO error).  Confirm whether that's a transient
    (rerun) or a real residual data error on mxfs under full rsync; single_node_paired
    needs the mxfs leg to COMPLETE cleanly AND within 1.05x of XFS wall.
  - Re-run single_node_paired --nodes 1 (mxfs leg should no longer wedge).  If the
    perf RATIO fails (mxfs >> xfs), that's a separate perf-tuning problem, not a wedge.
  - 16MB/slice × log_node_count must fit (internal log in a multi-GB middle AG — fine for
    typical node counts; for very large node_count the clamp at mkfs_mxfs.c:1128 (65536)
    is bypassed by min_total, giving a large but valid internal log).

## sess36 continuation 5 — single_node_paired now PASSES (but verify it's not hollow)

After the 16MB-log-slice fix, single_node_paired records PASS:
  measured=xfs=3475ms mxfs=321ms ratio=9%  threshold=ratio<=105%
The wedge is GONE (mxfs leg returns instead of hanging) — real progress.  BUT mxfs=321ms
vs xfs=3475ms (mxfs ~10x FASTER) is implausible for the same rsync and almost certainly
HOLLOW: the mxfs rsync likely aborted early on the rc=11 IO error seen in repro_logwedge
(copied far fewer files → faster).  single_node_paired only measures wall time; it does
NOT check rsync exit code or that source/dest match.

sess37 MUST verify before trusting this PASS:
  1. Run rsync on mxfs single-node to completion and check `rsync` rc==0 AND
     `diff -r /root/open-gpu-kernel-modules <mnt>/dest` (or file-count + du match).
  2. If rsync errors (rc=11) / dest incomplete on mxfs → there is a RESIDUAL single-node
     data-write bug (separate from the wedge) — find it (dmesg EIO? a specific file/op?).
     The perf criterion should arguably also assert rsync rc==0 + dest==src (it's wrong to
     pass on an incomplete copy) — but fix the FS first per SUCCESS_CRITERIA's "FAIL is
     real until proven otherwise".
  3. Only once the mxfs rsync completes cleanly is the ratio meaningful.

## sess36 continuation 6 — instrumentation gating INCOMPLETE (more files have hot prints)

During the integrity rsync, dmesg still shows `P-H14b-INSTR sf_to_block COPY ino=... name=...`
firing PER-DIRENT during shortform→block dir conversion.  P-H14b lives in a libxfs dir
file (xfs/libxfs/xfs_dir2_*.c, NOT one of the 3 files I gated).  So my sess36 gating
(xfs_mxfs_dlm.c, xfs_buf.c, xfs_inode.c + P9 in xfs_ialloc.c) MISSED the libxfs dir prints
and the multi-line mxfs_pal_log bast-path prints.  sess37: grep ALL of xfs/libxfs/*.c +
xfs/*.c + pal/linux/*.c for `pr_warn("mxfs:` and `mxfs_pal_log(MXFS_LOG_*, "mxfs:` with
P*/H*/MX-INSTR tags and gate them (mxfs_idbg for pr_warn; wrap mxfs_pal_log in
`if (mxfs_instr_enabled)`).  Until ALL are gated, heavy-metadata perf is still degraded.
Also: the dmesg/log spam filled test1's /var ("systemd-journald: No space left on device")
— another reason to finish gating.  GOOD NEWS: with the 16MB log slice the rsync PROGRESSES
(sf_to_block COPY advancing, rsync not D-wedged) — the log-wedge fix holds even with the
remaining instrumentation noise.

## sess36 continuation 7 — FULL ungated-instrumentation list (gate ALL in sess37)

My sess36 sed only matched `pr_warn("mxfs: P*` in 3 files.  MANY prints remain, and some
use `pr_warn("P14-INSTR...` WITHOUT the "mxfs: " prefix (my sed missed those even in
xfs_mxfs_dlm.c).  Comprehensive list of files with ungated P*/H*/MX-INSTR prints:
  xfs/xfs_trans_ail.c, xfs/xfs_icache.c, xfs/xfs_mxfs_dentry.c, pal/linux/kern.c,
  xfs/xfs_mxfs_dlm.c (the `pr_warn("P14-INSTR...` ones at ~3421/3454/3472/3515/3539),
  xfs/libxfs/xfs_bmap.c, xfs/libxfs/xfs_inode_util.c, xfs/libxfs/xfs_dir2.c,
  xfs/libxfs/xfs_alloc.c (P14-INSTR @2199), xfs/libxfs/xfs_dir2_block.c (P-H14/P-H14b
  sf_to_block, fires PER-DIRENT during shortform→block dir conversion — hot path).
TWO patterns to gate: `pr_warn[_once]("mxfs: (P[0-9]|P-H|MX-INSTR|H[0-9])` AND
`pr_warn[_once]("(P[0-9]|P-H|H[0-9])` (no mxfs: prefix) AND
`mxfs_pal_log(MXFS_LOG_*, "mxfs: (P|H[0-9]|MX)` (multi-line).
APPROACH: the gate var `mxfs_instr_enabled` is global (extern); for files that include
xfs_mxfs_dlm.h use the mxfs_idbg macro; for libxfs files (portable, don't include it)
add `extern int mxfs_instr_enabled;` + wrap each call in `if (unlikely(mxfs_instr_enabled))`
(as done for P9 in xfs_ialloc.c).  Build full + re-run repro_logwedge + single_node_paired;
with ALL prints gated the rsync should be both fast AND not flood node /var.

## sess36 continuation 8 — remaining ungated prints are NOT rsync-hot

Assessed the remaining ungated instrumentation: P67 (AG-AIL-STALL — only on AIL stall),
P25 (sync-inactive — inode inactivation/delete), P29 (bunmapi — extent unmap/truncate).
NONE fire per-create/per-write in the rsync hot path.  The hot single-node prints (P9
dialloc per-create, P-H14b per-dirent dir conversion) ARE now gated (build 98824FA...).
So single-node rsync perf should already be OK; finishing the remaining gating is for
cleanliness + multi-node (rsync_paired/scaling) + to stop occasional /var log-fill, not a
single_node_paired blocker.  sess37 can prioritize the coherency fix over the rest of the
gating.

## sess36 continuation 9 — log-wedge fix is PARTIAL: full recursive rsync still hangs

IMPORTANT nuance: repro_logwedge.sh (subset rsyncs via --files-from head -N, escalating to
8137) PASSED with the 16MB slice (8137 returned DONE_11, not wedged).  BUT a full
RECURSIVE `rsync -a $SRC/ dest/` (all 8137 at once, max concurrent dirty data) on
single-node mxfs HUNG again (find /mnt/shared/dest went D-state; had to virsh-reset test1).
So 16MB helped (subset/escalating no longer wedges) but is NOT sufficient for the full
concurrent recursive rsync — either the log is STILL too small for peak concurrent load,
or there is a residual tail-advancement issue under sustained pressure.
sess37: (a) try a larger slice (e.g. 8192 fsb = 32MB, or 16384 = 64MB — internal log in a
multi-GB AG, safe) and re-test the FULL recursive rsync; (b) if it still hangs at large
log, the bug is NOT size — it's the xfsaild tail-advance/wakeup under sustained writeback
(xfs_log.c grant→xfs_ail_push, xfs_trans_ail.c xfsaild; suspect sess32-33 AIL changes).
Capture xfsaild + grant-head state during the hang (xfsaild S vs D, ail_target, grant LSN
vs tail LSN) — that distinguishes size-exhaustion from a tail-advance bug.
NOTE single_node_paired's recorded PASS (mxfs=321ms) remains HOLLOW (early rsync abort);
do not trust it until the full rsync completes cleanly (rc=0 + dest==src) without hang.

## sess36 continuation 10 — DEFINITIVE: log-wedge is a TAIL-ADVANCE bug, NOT size

Tested 32MB per-node log slice (mkfs confirmed "8192 blocks = 32.00 MB each").  The FULL
recursive `rsync -a $SRC/ dest/` STILL WEDGES: 3 procs D-state on xlog_grant_head_wait
(log_reserve), rsync etimes=43s, only ~500MB written before hang.  So 4MB→16MB→32MB only
DELAYS the wedge — it does NOT fix it.  CONCLUSION: the single-node log wedge is NOT a
log-size problem; it is a TAIL-ADVANCEMENT / xfsaild-wakeup bug — the log fills and the
tail never advances (xfsaild sleeps; AIL items not pushed to free grant space) under
sustained writeback.  repro_logwedge.sh (subset rsyncs) passed only because the subsets
were small enough not to wrap the log.

REVISED sess37 plan (DROP the log-size angle as the fix — it's a red herring / partial
mitigation only; the 32MB change can stay or revert, it's harmless):
  ROOT CAUSE is in the log-grant → AIL-push → xfsaild path.  Investigate:
  - xfs/xfs_trans_ail.c xfsaild() main loop + xfs_ail_calc_push_target() (~line 420-520):
    when the log is full, does ail_target get set to push enough?  The mxfs sess32-33
    changes (PUSH_ALL flag, log_force kicker gated on lazy_ag_drain, per-AG filters in
    xfs_log_item_in_ag) likely broke the natural-pressure push so xfsaild sleeps with a
    stale/too-low ail_target while writers starve on grant.
  - xfs/xfs_log.c: the grant-wait path (xlog_grant_head_wait/xlog_grant_head_check) — in
    6.x XFS this should push the AIL / force the log when space is short; verify mxfs
    didn't break the wake of xfsaild or the tail-LSN computation for the sliced log.
  - Capture during the hang: is xfsaild in S (sleeping) or D?  What is ailp->ail_target
    vs the actual max AIL LSN?  Are AIL items PINNED (need log_force) vs flushable?
    If pinned: a CIL→log force is needed but can't get space (small-log CIL deadlock) —
    then the fix may combine a larger log WITH fixing the force.  If flushable but
    xfsaild isn't pushing: it's the ail_target/wakeup regression.
  - Likely a regression: prior MXFS versions ran rsync benches (bench.json), so single-node
    rsync worked before the sess32-33 AIL/log-drain changes.  Consider bisecting/reverting
    those (mxfs_lazy_ag_drain default is 0, but the xfsaild PUSH_ALL/log_force kicker and
    xfs_log_item_in_ag per-AG filter changes apply regardless).

## sess36 continuation 11 — PRECISE root-cause area for the tail-advance wedge

xfs_trans_ail.c xfs_ail_calc_push_target() (read it): the BACKGROUND push target uses a
"keep 25% of the log free" heuristic — if free_bytes >= l_logsize>>2 it returns the
EXISTING ail_target (i.e. does NOT push harder).  So under sustained writeback the only
thing that makes xfsaild push aggressively (to max_lsn) is the PUSH_ALL bit (line 432) or
an ail_empty waiter (line 436).  When writers BLOCK on log grant (log full), the GRANT
path in xfs/xfs_log.c MUST set PUSH_ALL (or bump ail_target to max_lsn) AND wake xfsaild —
otherwise xfsaild keeps the low background target and sleeps while writers starve → exactly
the observed wedge (xfsaild S, 3 procs D on xlog_grant_head_wait).
=> sess37 PRIME SUSPECT: the xfs_log.c grant-wait/space-short path no longer triggers the
   AIL PUSH_ALL+wake for the sliced log.  Check xfs/xfs_log.c near the xfs_ail_push_all
   call (~line 214) and xlog_grant_head_wait/xlog_grant_head_check: does it call
   xfs_ail_push_all / set XFS_AIL_OPSTATE_PUSH_ALL / wake xfsaild when need_bytes can't be
   granted?  Compare to upstream 6.19 xfs_log.c.  If mxfs's sliced-log changes dropped or
   mis-LSN'd that trigger, restore it (set PUSH_ALL + wake xfsaild on grant starvation).
   Verify fix: full recursive `rsync -a /root/open-gpu-kernel-modules/ /mnt/shared/dest/`
   single-node completes rc=0 without D-state on xlog_grant_head_wait.

## sess36 continuation 12 — REFINED root cause: alloc-buflist never drains single-node

CONFIRMED: xfs/xfs_log.c xlog_grant_head_wait() DOES call xfs_ail_push_all(log->l_ailp)
before each schedule() (line 214) — so the grant-starvation → PUSH_ALL → wake-xfsaild
trigger is INTACT (upstream behavior).  So xfsaild IS told to push to max_lsn, but the
items don't drain.  STRONG HYPOTHESIS for why:
  mxfs queues freshly-allocated cluster bufs to pag_mxfs_alloc_buflist with both
  _XBF_DELWRI_Q and _XBF_MXFS_ALLOC_QUEUED (see xfs_log_item_in_ag in xfs_trans_ail.c:798
  and the design-tension note in CLAUDE.md).  xfsaild's iop_push for these returns FLUSHING
  (xfs_buf_delwri_queue fails — already _XBF_DELWRI_Q), so xfsaild CANNOT submit them.  They
  are drained ONLY by mxfs_dlm_ag_drain_alloc_buflist in Phase 2 of the AG-bast work fn.
  SINGLE-NODE there is no peer → no AG-BAST → Phase 2 NEVER runs → those bufs never reach
  disk → AIL tail can't advance past them → log fills → xlog_grant_head_wait wedge.
  (Cross-node, a peer's BAST eventually triggers Phase 2, so it drains — which is why the
  cross-node mkdir tests don't hit THIS wedge, and why prior rsync benches that were
  cross-node worked.)
=> sess37 FIX: ensure pag_mxfs_alloc_buflist is drained WITHOUT requiring a peer BAST —
   e.g. drain it from xfsaild/log-worker on log pressure, or on a periodic timer, or when
   single_node (mxfs_dlm_caw single_node=true) submit alloc bufs normally instead of
   queuing them to the mxfs list.  Look at where bufs get _XBF_MXFS_ALLOC_QUEUED (grep
   _XBF_MXFS_ALLOC_QUEUED) and at mxfs_dlm_ag_drain_alloc_buflist; make a non-BAST drain
   path.  Verify with the full recursive single-node rsync (no xlog_grant_head_wait wedge).
   This is almost certainly the sess32-33 lazy/alloc-buflist mechanism interacting badly
   with single-node (no BAST) — a regression vs pre-sess32 behavior.

## sess36 continuation 13 — ROOT CAUSE CONFIRMED (log-wedge), exact code sites + fix

CONFIRMED:
- _XBF_MXFS_ALLOC_QUEUED is set UNCONDITIONALLY at xfs/libxfs/xfs_ialloc.c:450
  (`fbuf->b_flags |= _XBF_MXFS_ALLOC_QUEUED;`) when a new inode cluster is initialized —
  NO single-node gate.  So every freshly-allocated inode-cluster buf is parked on
  pag_mxfs_alloc_buflist and is NOT pushable by xfsaild (iop_push returns FLUSHING).
- The ONLY drain is mxfs_dlm_ag_drain_alloc_buflist (xfs_mxfs_dlm.c:2056), invoked from the
  AG-DLM unlock/bast path (per the comment at line 2401 "via mxfs_ag_dlm_unlock").
- SINGLE-NODE the AG-DLM is acquired once and stays CACHED (held for affinity; no peer ⇒
  no BAST ⇒ no release ⇒ mxfs_ag_dlm_unlock's drain never fires).  So the alloc-buflist
  grows without bound, those bufs never reach disk, the AIL tail can't advance past them,
  the log fills, and writers wedge in xlog_grant_head_wait.  This is why heavy single-node
  metadata (rsync, which allocates many inode clusters) wedges, while cross-node tests
  (where peer BASTs periodically trigger the drain) and light single-node loads (few inode
  clusters) do not.  Enlarging the log only delays it (more headroom before the unbounded
  buflist fills the log).

THE FIX (sess37):
  Drain pag_mxfs_alloc_buflist WITHOUT requiring an AG-DLM unlock/BAST.  Options (pick one):
  (a) When single_node (mxfs_v5_dlm_is_single_node), do NOT set _XBF_MXFS_ALLOC_QUEUED at
      xfs_ialloc.c:450 / don't park on the mxfs list — let xfsaild submit these bufs
      normally (the cross-node coherency reason for parking them doesn't apply with no
      peers).  Cleanest + lowest risk; directly fixes single-node.
  (b) Periodically drain pag_mxfs_alloc_buflist from xfsaild/log-worker under log pressure
      (e.g. in the grant-wait path or a timer), not only on AG unlock.  Helps multi-node
      too but more invasive.
  Either way: after peer-join (single_node→false) the existing AG-unlock drain still
  applies.  Verify: full recursive single-node rsync completes rc=0, dest==src, no
  xlog_grant_head_wait D-state; then re-run single_node_paired for a REAL perf number.
  Caveat: option (a) must handle the single→multi transition (bufs queued while single_node
  then a peer joins) — drain/flush the list at the transition.

## sess36 continuation 14 — RETRACTION: alloc-buflist hypothesis is WRONG

Read xfs/libxfs/xfs_ialloc.c:434-454: the parking onto pag_mxfs_alloc_buflist +
_XBF_MXFS_ALLOC_QUEUED is ALREADY GATED on `mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node()`.
So SINGLE-NODE does NOT park alloc bufs on the mxfs list — they use the ordered-buf/AIL
path (normal xfsaild push).  Therefore continuation-12/13's "alloc-buflist never drains
single-node" root cause is REFUTED.  Do NOT implement the "gate parking on single_node"
fix — it's already gated.

So the single-node log-wedge mechanism is STILL UNPINNED.  Confirmed facts only:
  - Full recursive single-node rsync wedges: 3 procs D in xlog_grant_head_wait, xfsaild S
    (sleeping), ~500MB written, 4/16/32MB log all wedge.
  - xlog_grant_head_wait DOES call xfs_ail_push_all (trigger intact).
  - Single-node cluster bufs are ordered-buf/AIL items (NOT on the mxfs buflist).
NEXT (sess37) — actually capture the hang state (don't theorize):
  During a wedged single-node rsync, dump on the node:
   - `echo w > /proc/sysrq-trigger` then dmesg (blocked-task stacks) — see what xfsaild and
     the writers are really stuck/sleeping on.
   - For xfsaild (pid): /proc/<pid>/stack, and instrument/inspect ailp->ail_target vs
     xfs_ail_max LSN, and whether AIL items are PINNED (xfs_log_force needed) vs FLUSHING
     vs pushable.  Add a temporary printk in xfsaild_push logging count/stuck/flushing/
     target each cycle (gated by mxfs.instr).
  Hypotheses to test with that data:
   (H-L1) AIL items PINNED in CIL; xfsaild can't flush; needs xfs_log_force but the small
          log's CIL can't checkpoint → CIL/log-size deadlock (then a BIGGER log OR forcing
          the CIL differently is the fix; but 32MB already failed, so less likely).
   (H-L2) xfsaild's push is being defeated by a mxfs change to xfsaild_push / push-target /
          the sess32-33 PUSH_ALL+log_force-kicker (gated on lazy_ag_drain — default 0, so
          maybe NOT active; verify) — a regression making xfsaild back off / mis-target.
   (H-L3) iop_push for the ordered cluster bufs returns FLUSHING/stuck for a mxfs-specific
          reason even single-node (e.g. _XBF_DELWRI_Q set on them by the ordered path).
  Pin it with the capture BEFORE patching (RULE 4).  Prior MXFS ran rsync benches, so this
  is likely a sess20-35 regression — `git`-free, but compare against ~/src/mxfs.{1,2,3}
  behavior / the v3-version-history if needed.

## sess36 continuation 15 — HANG CAPTURE (log-wedge): xfsaild stuck-in-loop, items unpushable

Captured a fresh single-node rsync wedge (test1, 32MB log):
  - WEDGED after only ~10s (2 writers D in xlog_grant_head_wait→xfs_log_reserve).
  - rsync task: D in __schedule←xlog_grant_head_wait←xlog_grant_head_check←xfs_log_reserve
    (classic grant starvation — waiting for log space).
  - xfsaild/sda: state S, stack = `xfsaild+0x4c2/0xce0` — i.e. sleeping in its OWN main
    loop's schedule_timeout backoff, NOT blocked on any lock.
INTERPRETATION: the grant path wakes xfsaild (xfs_ail_push_all), xfsaild runs xfsaild_push,
but makes NO PROGRESS (items can't be submitted — PINNED awaiting a log force, or iop_push
returns FLUSHING), so it returns a backoff timeout and sleeps again while the log stays
full → wedge.  Wedging in 10s with little data written suggests the log fills almost
immediately and the tail never advances at all.
NEXT (sess37, RULE 4): add a temporary gated printk in xfsaild_push (xfs_trans_ail.c ~466)
logging each cycle: count, stuck, flushing, and target vs xfs_ail_max LSN; AND in
xfsaild_push_item log the iop_push return (PUSHED/PINNED/LOCKED/FLUSHING) for the first few
items.  Build with mxfs.instr=1, reproduce, read why every item is stuck:
  - If FLUSHING/PINNED dominate and never clear: the bufs are pinned in the CIL and the
    CIL checkpoint isn't happening (or can't get log space) — investigate xlog_cil_push /
    whether the sliced-log grant accounting (l_logsize vs l_logBBsize for the slice) lets
    the CIL ever checkpoint.  This is the small-sliced-log + CIL interaction; may need the
    CIL push to be forced, or the slice grant math fixed.
  - Compare l_logsize/l_logBBsize values the sliced log gets (xfs_log_mount called with
    log_bblks = slice) vs what xlog reservation/CIL sizing expects — a too-small log makes
    xlog_cil_push refuse/stall (XLOG_CIL_SPACE).  This ties back to slice size BUT the
    32MB test still wedged, so also check the grant/tail LSN math for the offset slice
    (xfs_log.c uses bt_sector_offset for I/O but the LSN cycle/block math must be
    slice-relative; if it's whole-device-relative, the tail never "catches" the head).
  THE LSN-MATH-FOR-SLICED-LOG angle (continuation 11) is the strongest remaining suspect:
  if l_curr_block / tail LSN comparisons don't account for the slice offset/size, free
  space is computed wrong → grant never satisfied even as items drain.

## sess36 continuation 16 — narrowed: grant accounting is INTACT; locus is AIL-unpushable

Ruled out the grant/LSN-math suspect:
  - xfs/xfs_log.c xlog_grant_space_left() is STANDARD/unmodified:
    free = l_logsize - l_tail_space - grant.  l_tail_space updates via standard
    xlog_cil_ail_insert.  So free space IS computed correctly and frees as the tail advances.
  - The only mxfs edit near there (xfs_log.c:3472, in the LSN-validity check) just RETURNS
    TRUE early for m_mxfs_dlm (skips a cross-node LSN sanity check) — it does NOT touch
    grant/tail accounting.  Not the cause.
CONCLUSION: the grant side is fine.  The wedge is entirely that the AIL TAIL DOES NOT
ADVANCE because xfsaild's items are UNPUSHABLE (xfsaild runs, pushes, makes no progress,
backs off — captured: xfsaild S at xfsaild+0x4c2 while writers starve).  So the bug is on
the push/iflush side, single-node.
DEFINITIVE NEXT STEP (sess37, the ONE experiment that pins it): gated printk in
xfs_trans_ail.c xfsaild_push (~line 466-540) per cycle: total/stuck/flushing/count and
ail_target vs xfs_ail_max; and in xfsaild_push_item (~351-400) log the iop_push return code
for the first few items.  Build mxfs.instr=1, reproduce the 10s wedge, read the verdict:
  - all items FLUSHING (iop_push returns XFS_ITEM_FLUSHING) → buffers are mid-flush but the
    flush never completes → look at the iflush/buf-submit completion path (does the bio
    complete? is iodone running? is something holding the buf?).
  - all items PINNED (XFS_ITEM_PINNED) → need a log force to unpin; check why
    xfs_log_force / CIL push isn't running or can't make space (xlog_cil_push state).
  - items LOCKED → some thread holds the inode/buf lock and never releases.
This is single-node so NO cross-node/DLM involvement — it's the mxfs iflush/CIL/ordered-buf
machinery vs upstream xfsaild.  Almost certainly a sess20-35 regression (prior versions ran
single-node rsync benches).  Fix at the proven push-stall cause, then re-run
repro_logwedge.sh (full recursive) + single_node_paired for a real number.

## Current build state at sess36 end
- srcversion **E06DB7064C93254CF9EA50A** (VERSION 0.4.5) = all 5 ship-gate fixes
  (mount-speed Fix A/B in dlm/disklock.c + dlm/dlm_caw.c, packaging in
  packaging/common.sh, online_resize.sh idempotency, dkms_install.sh timeouts) +
  corrected P-H16 instrumentation.  NO coherency-logic change vs the verified
  4D993 baseline (only the diagnostic LBA offset differs).  Both disproven coherency
  experiments (skip_locked drain, ILOCK-across-dialloc) are REVERTED.
- test1 + test2 left mounted with this build on the SCST cluster.
- Reproducer: `tests/repro_modea.sh 20 test1 test2` → ~19-20/20 fail (unchanged;
  the bug is not yet fixed).

## Key files / commands
- Reproducer: `tests/repro_modea.sh 20 test1 test2` (needs both mounted first).
- Mount 2 nodes: teardown both, then test1 = prep+insmod+sg_persist clear+mkfs+mount,
  test2 = prep+insmod+mount. (see lib.sh fresh_cluster_mount, or inline.)
- Instrumentation build (rich P-H* dmesg) was srcversion D6DEB43...; the reverted
  v0.4.3 baseline rebuilt after still HAS the sess20-35 instrumentation in
  xfs/xfs_mxfs_dlm.c (45 pr_warn) + dlm + pal — useful for debugging, not stripped
  (dmesg_clean passes since they're not WARNING:/BUG:; node console_loglevel=4 keeps
  them off the serial console so perf impact is negligible). Task #2 (strip/gate)
  deferred — not gating.
- Gate: `tests/criteria/verify_ship.sh` (stops at first FAIL) / `--status` / `--keep-going`.
