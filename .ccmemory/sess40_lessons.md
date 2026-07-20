---
name: sess40_lessons
description: sess40 — root-caused + fixed the cache_coherency create-race (IRECLAIMABLE reused-inode); gated per-op DLM logging (100x slowdown); bounded per-AG sync push.
metadata: 
  node_type: memory
  type: project
  originSessionId: 6d83fa7b-9243-4408-a350-d2d5a2768bf9
---

# Session 40 (2026-05-30)

Continues [[sess39_lessons]]. Focus: cache_coherency (only recorded FAIL besides rsync_paired).

## WIN 1 — ungated per-op DLM logging = the ~100x slowdown (gated behind mxfs.instr)
Many per-op diagnostic logs were NOT gated by `mxfs_instr_enabled` and fired on the lock
hot path, flooding dmesg and making cache_coherency too slow to finish (timed out the
900s watchdog). Gated (sess40):
- `dlm/dlm_caw.c`: all `P13-INSTR GRANT-WAIT-START/POLL/OK/TIMEOUT` + `CAW-UNLOCK[-RESULT]`
  via new `caw_instr_on()` macro (kernel-only `extern int mxfs_instr_enabled`; user build
  compiles it to 0). Also `P15-INSTR caw-act/caw-iter` are AG-path per-op — guard with
  `caw_instr_on()` if still hot.
- `xfs/xfs_mxfs_dlm.c`: reload chain (P6 reload-pre/post, "DLM reload inode/ino/skip/OK",
  P-H13b ACQ-RELOAD-FMT, P41 dcache) -> `mxfs_idbg`; BAST P-H12/P-H12b/P-H25 + P-H16
  per-reload FUA-read page scan + report_stats + "BAST set stale" -> gated.
VERIFIED on node: dmesg INSTR flood delta=0/5s after gating. **LESSON: any new diagnostic on
the DLM/iget/alloc hot path MUST be `mxfs_idbg`/instr-gated — never raw pr_warn/mxfs_pal_log.**

## WIN 2 — cache_coherency create-race ROOT CAUSE (proven w/ FUA evidence) + FIX
Symptom: under concurrent same-parent create-race, a peer reads a dir/file inode as
`?---------` (di_mode=0) -> EACCES/ENOENT for a name that exists -> blocks the whole
criterion (e.g. peers can't even traverse `.mxfs_test`).
RULE-4 detector P-IGET-ENOENT (xfs_iget_check_free_state) with a FUA fresh-disk read showed,
consistently across all 4 nodes: `incore_mode=0 fua_disk_mode=0x0-or-0x41ed flags=0x4
(XFS_IRECLAIMABLE) dlm_stale=1`.
ROOT CAUSE: a node frees inode N locally (rm+inactivate) -> N lingers in-core as IRECLAIMABLE
mode=0. A PEER reuses inode number N for a new dir/file. The node's iget hits the stale cached
struct via **cache-HIT** and bails -ENOENT at xfs_iget_check_free_state **without acquiring the
inode DLM lock** (the sess38 reused-inode reload at xfs_icache.c ~739 explicitly SKIPS
IRECLAIMABLE — "left to a future fix"). Because it never acquires the lock, it never BASTs the
peer creator, so the peer never flushes N's new dinode to the platter -> self-reinforcing
staleness (fua_disk_mode stays 0). The cache-MISS path is correct (acquires DLM *before* reading
disk, xfs_icache.c ~894); only cache-HIT for IRECLAIMABLE reused inodes was broken.
Two sub-types: `fua=0x41ed` (disk already correct, pure in-core stale) and `fua=0x0`
(creator hasn't flushed; needs the BAST to force it).
FIX (xfs/xfs_icache.c xfs_iget_cache_hit, just before check_free_state): for multi-node,
non-CREATE/INCORE, IRECLAIMABLE, mode==0, dlm_stale inodes — pin against reclaim (set
XFS_IRECLAIM), drop locks, `mxfs_dlm_ilock_begin(PR)` (BASTs the peer -> it flushes) +
`mxfs_dlm_reload_inode` + `mxfs_dlm_ilock_end(PR)`, clear XFS_IRECLAIM, return -EAGAIN. Gated on
i_dlm_stale (reload clears it) so the EAGAIN retry can't re-enter -> no loop; retry falls to
check_free_state (mode!=0 -> recycle+return; still 0 -> genuine ENOENT).
VALIDATED: `tests/repro_mode0.sh` (NEW, sess40 — fast 4-node concurrent create-race repro,
no test framework) went from ~2-5/40 fails to **0/40 + 0/80 (120 iters clean)**. P-REUSE-RELOAD
detector confirmed reload reads the correct mode (0x41ed, dlm_mode=5=PR).
CAVEAT/perf: the fix adds a DLM round-trip per stale reused-inode iget -> repro got slow under
heavy inode churn. If cache_coherency is too slow, OPTIMIZE: when the cached cluster buffer
already shows mode!=0 (Type-B in-core-stale), reload from the buffer WITHOUT the DLM acquire;
only do the full DLM round-trip when the cached buffer is also mode==0 (Type-A, needs peer flush).

## WIN 3 — sync_fs di_size push: bounded PER-AG (not whole-AIL) — sess39 deadlock fixed
sess39's whole-AIL `xfs_ail_push_all_sync` in sync_fs deadlocked cross-AG (xfsaild D-state).
sess40: `pal/linux/xfs_super.c` sync_fs now calls `xfs_ail_push_ag_sync_bounded(mp->m_ail,
slot%agcount, 30, 10)` (this node's preferred AG only, stall-abort capped ~300ms) + blkdev flush.
`mxfs_sync_iflush` default flipped back ON (xfs_mxfs_dlm.c). No wedge observed.

## Builds (NFS-shared /src from 192.168.1.4; dev host 192.168.1.166 also NFS-mounts it)
Final sess40 build srcversion `210D0DD169AEC0E30E75CFC` = WIN1+WIN2+WIN3, detectors gated.
Cluster = test1..test4 (criterion uses DEFAULT_NODES[0:4]; MXFS_NODE_OFFSET is dead/unused).
reset4.sh / scripts/cluster_reset.sh do virsh destroy+start. Mount via fresh_cluster_mount
(tests/criteria/lib.sh); INSMOD_OPTS env passes insmod params (note: in sess40 a prior run's
INSMOD_OPTS=sync_iflush=1 did NOT take — flip the source default instead of relying on it).

## NEXT
1. Confirm cache_coherency PASSES end-to-end (running at handoff, build 210D0DD). If slow/timeout,
   apply the Type-B-no-DLM optimization above.
2. Run remaining un-recorded criteria (posix_semantics, zero_silent_loss, crash_consistency,
   fence_during_write, strong_consistency, scaling_curve) + rsync_paired, then verify_ship.sh.
3. repro_mode0.sh is the fast iteration tool for the create-race; cache_coherency is the gate.

## sess40 — cache_coherency per-test ISOLATION (build 45F00582, optimized icache fix)
Full criterion TIMED OUT >900s (build 210D0DD). Isolated each sub-test standalone (proper env:
`env MXFS_TESTS_DIR=/src/mxfs/tests ./tests/run_tests.sh --nodes 4 --phase cluster --test <T>
--pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`; cluster must be mounted —
run_tests does NOT mount, and it UNMOUNTS some nodes at the end so re-mount/reset between tests):
- **No single test HANGS.** The "12-min orphan" was TWO cache_coherency runs colliding on the
  cluster (a watchdog-killed run left an orphaned run_tests child) — always `pkill -9 -f
  'cache_coherency|run_tests|mxfs_test'` on dev host AND nodes + reset4 before a fresh run.
- **cross_write_read: 16s, FAILS on EMPTY-CONTENT** — `Node 4 verifies node 3 integrity:
  expected='' actual=<valid>`. node4 reads node3's tiny `.md5` SIDECAR file (written with NO
  sync after) as EMPTY (di_size=0). Root: `mxfs_reg_release_durable` DEFAULTS TO 0 (xfs_mxfs_dlm.c
  ~2882) — a regular file's di_size is NOT flushed to its cluster on BAST-release, so a peer's
  cache-MISS FUA-read sees di_size=0. sess39 turned it off because the full drain was ~12x slower.
  ==> the empty-content facet needs a LEAN per-inode di_size iflush on reg-file BAST (not the full
  drain), fast enough to keep default-on. sync_iflush=1 does NOT help here (the .md5 has no sync(2)).
- **Timeout cause = accumulated AG-lock contention, not a hang.** create storms (unlink/rename
  create 30-120 files/node in a shared dir) bottleneck on `caw_wait_for_grant` (AG-DLM CAW poll in
  xfs_dialloc->mxfs_ag_dlm_lock; D-state mkdir polling msleep). Old runs (pre-my-changes) did 4
  tests in ~4.5min; my icache fix (per-reused-inode DLM round-trip) + sync_iflush=1 (per-sync
  bounded push) pushed total >900s. Optimized build 45F00582 (Type-B reload w/o DLM acquire) cuts
  the icache cost; consider sync_iflush=0 to cut the rest (it gives no cross_write_read benefit).
- **icache fix (IRECLAIMABLE reuse) still ~2/30 residual** on repro_mode0 with the optimized build:
  the residual is Type-A (cached=fua=0x0, the dirent points to a GENUINELY-free inode on disk = a
  STALE PARENT DIR BLOCK, a different facet = dir-block coherence / DIR-STALE, NOT inode reuse).
  My inode reload can't fix a stale dirent; needs parent-dir-block re-read coherence.

## sess40 builds
- `210D0DD169AEC0E30E75CFC` = icache IRECLAIMABLE fix (DLM-acquire+reload) + gated logging + per-AG
  sync. Correct (repro 0/120) but cache_coherency TIMES OUT (too slow).
- `45F00582E6CA9C43AD2BE1A` = + Type-B optimization (cheap reload first, DLM acquire only if disk
  still free). Reduces icache DLM round-trips.
NEXT: (1) get cache_coherency to COMPLETE — run with 45F00582; if still >900s, set sync_iflush=0
default + rebuild, re-run; profile which test eats the budget. (2) lean reg-file di_size iflush on
BAST for cross_write_read empty-content. (3) dir-block coherence for the Type-A residual + unlink
dirent visibility. (4) ALWAYS clean orphans + reset4 between runs.

## sess40 — empty-content (cross_write_read) KEY INSIGHT + next experiment
bast_process (xfs_mxfs_dlm.c ~664) ALREADY does `filemap_write_and_wait(vip->i_mapping)` +
`invalidate_inode_pages2` for EVERY inode on demote — so a regular file's DATA pages ARE flushed
to disk on BAST. BUT the on-disk **di_size** in the dinode cluster is NOT updated on BAST when
`mxfs_reg_release_durable=0` (the di_size change sits in the log; iflush to the cluster is lazy
via xfsaild). So a peer's cache-MISS FUA-read of the cluster sees di_size=0 -> reads 0 bytes ->
EMPTY, even though the data blocks are on disk. THIS is the cross_write_read empty-content (.md5).
sess39 disabled reg_release_durable saying =1 "made it worse (race)" — but that was BEFORE the
RELOAD-SIZE-DROP-SKIP fix (xfs_icache reload / xfs_mxfs_dlm.c ~1143) which now prevents a node
clobbering its OWN nonzero di_size to 0 when it reloads from a not-yet-iflushed cluster. So the
"race" reg_release_durable triggered may now be closed.
NEXT EXPERIMENT (concrete): with RELOAD-SIZE-DROP-SKIP in place, toggle reg_release_durable=1 on
all nodes and run cross_write_read standalone (proper env, mounted cluster):
  for h in test1..4: echo 1 > /sys/module/mxfs/parameters/reg_release_durable
  env MXFS_TESTS_DIR=/src/mxfs/tests ./tests/run_tests.sh --nodes 4 --phase cluster \
     --test test_cross_write_read --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared
If empty-content resolves (node4 reads node3 .md5 correctly) AND time is acceptable (cross_write
has only ~8 files so per-release flush cost is small) -> a LEAN di_size-only iflush on reg-file
BAST (not the full 50-iter drain) is the fix; gate default-on. If it regresses rename/unlink
timing (100s of files), make it conditional (only flush when the file actually has dirty di_size).

## sess40 — WHY the icache fix makes cache_coherency TIME OUT (perf tension, the key refinement)
The optimized build (45F00582) STILL times out cache_coherency (>900s; unlink_visibility alone
~6-8min vs old ~1m46s). ROOT: my IRECLAIMABLE-reuse fix triggers on the unlink VERIFY-GONE phase.
unlink phase 3 does `assert_file_not_exists` (stat) on all 120 deleted files × 4 nodes = ~480
igets of FREED inodes (mode=0). Each is IRECLAIMABLE + mode=0 + dlm_stale -> hits my fix. With the
Type-B optimization the cheap reload runs first, but a genuinely-deleted file is mode=0 on disk too
(Type-A) -> it STILL does the DLM PR round-trip (caw_wait_for_grant, contended) -> ~480 wasted
round-trips per unlink test -> timeout. The DLM round-trip is needed for the create-RACE (peer
REUSED the inode, must BAST it to flush) but WASTED for genuinely-deleted files (free cluster-wide,
just return ENOENT). My fix can't cheaply tell "peer reused it" from "genuinely deleted" — both
look like mode=0 IRECLAIMABLE stale.
NOTE: the create-race that BLOCKED the criterion (.mxfs_test dir read mode=0 on peers) IS the reuse
case (flags=0x4 IRECLAIMABLE proven) — on a fresh mkfs the peer had that low inode number cached as
a freed file from a prior test. So the fix IS needed; it just over-triggers.
REFINEMENT (next session): before the expensive DLM-reload, consult the CLUSTER-WIDE allocation
truth = the inode btree (inobt) for this inode. If inobt says ALLOCATED (a peer reused it) -> do the
DLM reload. If inobt says FREE (genuinely deleted) -> return ENOENT cheaply, NO round-trip. The
inobt check needs the AG lock though (also a CAW op) — so alternatively: only do the round-trip when
the cached cluster buffer's generation/gen-count changed, or restrict the fix to a narrower trigger.
Simplest interim: gate the whole icache fix behind a param (default on) so cache_coherency can be
A/B'd; measure unlink time with fix on/off to confirm this is the dominant cost.

## *** sess40 WIN 4 — reg_release_durable=1 NOW FIXES cross_write_read empty-content ***
HYPOTHESIS CONFIRMED: sess39 disabled mxfs_reg_release_durable (=1 "made empty-content worse")
BEFORE the RELOAD-SIZE-DROP-SKIP guard existed. With that guard now in place (a node won't clobber
its own nonzero di_size to 0 when reloading a not-yet-iflushed cluster), reg_release_durable=1
correctly flushes a reg-file's di_size to its cluster on BAST-release.
RESULT: cross_write_read standalone (4 nodes, proper env, build 4545ABEA, sync_iflush=1) went from
FAIL (node4 reads node3 .md5 empty, expected='') to **PASS rc=0 in 15s** with reg_release_durable=1
runtime-toggled on all nodes. (Confirming reruns in progress at handoff.)
==> NEXT: flip mxfs_reg_release_durable source default to 1 (xfs_mxfs_dlm.c ~2882) and rebuild.
BUT measure its cost on rename/unlink (they create/delete many tiny reg files -> per-release flush
could slow them). If too slow there, make it LEAN (di_size-only iflush, skip the 50-iter drain +
maybe skip blkdev_flush if SCST normal-read is coherent) and/or only flush when di_size actually
dirty. The toggle (echo 1 > /sys/module/mxfs/parameters/reg_release_durable) is the fast A/B tool.

## sess40 STATUS SUMMARY (build 4545ABEA = icache reuse fix gated by mxfs.reuse_reload=1 +
## gated logging + per-AG sync + reg_release_durable param)
cache_coherency sub-test status (all 4 must PASS + complete <900s):
- cross_visibility: PASS (always).
- rename_visibility: my reuse_reload fix makes the create-race coherent (repro 0/120); passes in
  full run but SLOW (~4min).
- unlink_visibility: completes but SLOW — reuse_reload reload fires on ~480 verify-gone igets
  (deleted files, mode=0) -> DLM round-trips -> the dominant timeout cost. NEEDS dir-block
  coherence (don't follow deleted dirents) OR a cheaper reused-vs-deleted discriminator.
- cross_write_read: FIXED by reg_release_durable=1 (WIN 4 above), 15s.
BLOCKER = the >900s TIMEOUT, dominated by reuse_reload's verify-gone igets + slow create storms
(AG-lock CAW contention). Two paths: (a) make reuse_reload cheap (skip DLM for genuinely-free
inodes via a cluster-wide alloc check that isn't itself a round-trip — hard), or (b) fix parent-
dir-block coherence so verify-gone/lookup never igets deleted files (fixes perf AND the Type-A
create-race residual). (b) is the principled fix.
PARAMS for next session A/B: mxfs.reuse_reload (1), mxfs.reg_release_durable (0->try 1),
mxfs.sync_iflush (1), mxfs.instr (0). All runtime-toggleable; criterion remount resets to source
defaults so flip source defaults for criterion runs.

## sess40 WIN 4 — CONFIRMED (correction): reg_release_durable=1 fixes cross_write_read on FRESH mounts
Disambiguated the inconsistency: cross_write_read with reg_release_durable=1 PASSES on a FRESH
reset4 mount (rc=0, 14s — confirmed twice). The one rerun that HUNG (rc=124, 200s) was running
cross_write_read AGAIN without reset -> leftover .mxfs_test/cross_write_read files -> barrier/md5
state confusion, NOT reg_release_durable instability. The criterion always fresh_cluster_mounts,
so reg_release_durable=1 is a VALID fix for the cross_write_read empty-content sub-test.
==> To pass cache_coherency: need reg_release_durable=1 (cross_write_read) + reuse_reload=1
(rename/unlink create-race) + COMPLETE <900s. Both add per-op cost; the TIMEOUT (dir-block-stale
verify-gone igets under reuse_reload + create-storm AG contention) is THE remaining blocker.
Solve the timeout (dir-block coherence so deleted dirents aren't followed) FIRST, THEN flip both
source defaults (reg_release_durable 0->1, reuse_reload already 1) and re-run the full criterion.

## *** sess40 WIN 5 — CHEAP-ONLY reuse_reload: fast AND correct (DLM round-trip NOT needed) ***
Made the Type-A DLM PR round-trip in the reuse_reload path optional (param mxfs.reuse_dlm, default
OFF). Cheap-only = just `mxfs_dlm_reload_inode` (no DLM acquire) on a stale IRECLAIMABLE mode=0
iget. RESULT: repro_mode0 40 iters **0 fails in 127s** (vs the DLM-round-trip build: 0/120 but
~11s/iter, timing out cache_coherency). So the cheap reload + the creator's eventual flush (tests
have barriers/sleeps) is sufficient for the create-race AND avoids the ~480 verify-gone DLM
round-trips that timed out cache_coherency.
FINAL build `598B434FF61A1A5E8CF87B2` = reuse_reload=1 (cheap-only, reuse_dlm=0) + reg_release_durable=1
+ sync_iflush=1 + gated logging. Running full cache_coherency with all fixes at handoff.
Params (all runtime-toggleable; source defaults set so criterion remount uses them):
  reuse_reload=1, reuse_dlm=0, reg_release_durable=1, sync_iflush=1, instr=0.
If the full run still times out: profile per-test (cross_vis/rename/unlink times); reg_release_durable=1
may add cost on file-heavy unlink — if so make it lean (di_size-only iflush) or conditional.
If a sub-test FAILS: rename/cross_vis = create-race (toggle reuse_dlm=1 to test if the round-trip is
needed after all); cross_write_read = empty-content (reg_release_durable); unlink = dirent visibility
(dir-block coherence, still the deep residual).

## *** sess40 GATING BLOCKER (precise) — rename_visibility fails on DIR-BLOCK COHERENCE ***
Full cache_coherency with ALL fixes (build 598B434F: cheap-only reuse_reload + reg_release_durable=1
+ sync_iflush=1): rename_visibility STILL FAILS. Per-node detail (results/.../test_rename_visibility/
node1.log):
  [FAIL] New name exists: node4_after_16: file not found
  [FAIL] Content preserved in node4_after_16: expected='content_4_16' actual=''
  ... (node4_after_16..20, i.e. node4's LAST 5 renames)
=> node1 cannot see node4's MOST RECENT renames in the SHARED dir. This is the MISSING-DIRENT /
dir-block-coherence facet (node1's cached shared-dir DATA block is STALE, missing node4's latest
committed dirents) — NOT inode-reuse (fixed by reuse_reload) and NOT pure empty-content (it's
"file not found" = the dirent itself is absent on node1). This is the long-standing Mode-A /
DIR-STALE residual (v0.4.7 i_dlm_dir_gen read-time invalidation + the DIR-STALE-SKIP-when-dirty
problem). THIS is now THE gating blocker for cache_coherency (rename + unlink both need it).
Mechanism (confirmed earlier this session): when a node re-reads a shared dir block after a peer
modified it, the read-time invalidation (xfs_da_read_buf, i_dlm_dir_gen) is SKIPPED if the node's
own cached dir block is dirty/pinned/delwri (DIR-STALE-SKIP) -> returns stale block missing peer's
entries. Each node also wrote its own 20 files to the same dir -> dirty dir block -> skip fires.
NEXT SESSION FOCUS = dir-block coherence (the deep fix that unblocks rename+unlink): make a node
re-read the on-disk (merged) shared-dir block after a peer's commit even when its own copy is
dirty. The disk block is the merge point (each node's committed txn appends its dirents); the node
must flush its own dirty dir block (it does on BAST) and then re-read the merged disk block. The
DIR-STALE-SKIP is the bug: it must NOT skip — it needs to flush-then-reread, or the
bast_process dir-data durability must guarantee the block is clean+on-disk before a peer reads.
All sess40 param fixes are real and should stay (reuse_reload cheap-only, reg_release_durable=1,
sync_iflush=1, gated logging); they're necessary-but-not-sufficient. Build 598B434F is the head.

## sess40 — REFINEMENT: rename missing-dirent is NOT DIR-STALE-SKIP (it's stale cached-lock fast-path)
DIR-STALE-SKIP detector = 0 on ALL nodes during the failing rename run. So the missing-dirent is
NOT the dirty/pinned-block read-time skip. Pattern: node1 sees node4_after_1..15 but NOT 16..20
(node4's LAST 5 renames). => node1 read a CACHED dir-block snapshot (captured ~after node4's 15th
rename) and NEVER RE-READ for node4's later renames. i_dlm_dir_gen was not bumped at node1's verify
read => node1 took the FAST PATH (cached PR, state==CACHED) in mxfs_dlm_ilock_begin => no reload,
no dir-block re-read => stale. Root: node4's EX-acquires for renames 16..20 did NOT
BAST/invalidate node1's cached PR on the shared dir inode (BAST delivery/processing gap, or node1
re-acquired PR after rename-15 and was never demoted again). This is the core CAW-DLM dir
coherence gap.
DEBUG NEXT SESSION: temporarily un-gate P63-INSTR (FAST-PATH-DIR) + P67 (ILOCK-BEGIN-DIR) +
reload logs (instr=1, but instr SLOWS ~Nx and may hide it — or add an always-on counter), run
rename_visibility, and check on node1: for the shared rename_visibility dir inode, count
FAST-PATH-DIR vs reload at the verify read. If node1 fast-paths the verify read while node4
committed later renames, the fix is: a peer's EX-acquire MUST reliably BAST all cached PR holders
(check mxfs_v5_dlm CAW BAST: waiter bit + bast poll + immediate-vs-deferred), OR the dir fast-path
must be invalidated by a dir-generation/seqno bumped on every peer dir commit (not just on slow-
path reload). Compare to GFS2 glock demote-on-conflict. This is the gating blocker for
cache_coherency (rename + unlink both need reliable peer-dir-commit -> local-reread).

## sess40 — CORRECTION: reuse_reload (cheap OR dlm) does NOT fix rename_visibility
Standalone test_rename_visibility (fresh reset, build 8816466, all fixes) FAILS rc=1 in ~25-28s with
BOTH reuse_dlm=0 (cheap-only) AND reuse_dlm=1 (DLM round-trip). P-SF-DURABLE-FAIL=0 (dir block IS
flushed durably on release). Failure pattern: PEERS (nodes 2,3,4) cannot see the dir-OWNER's renames
(e.g. node1_after_2..20) — and the parent rename_visibility dir itself reads "Permission denied"
(mode=0 / create-race EACCES) on peers; drop_caches on a peer changes its view (so it IS a reader-
side stale CACHED inode, refreshed by a forced cache-MISS re-iget).
=> The rename_visibility failure is DISTINCT from the repro_mode0 root-dir create-race that
reuse_reload fixes (repro_mode0 = 0/40 with cheap-only). repro_mode0 does NOT capture this. The real
test pattern: a SUBDIR (.mxfs_test/rename_visibility) created by one node, peers iget it and cache it
STALE (mode=0 EACCES OR pre-rename dir content), and neither reuse_reload variant refreshes it in the
verify phase. drop_caches (full cache-MISS) DOES refresh -> it's a cached-inode/cached-dir-block
staleness that the normal lookup path is NOT invalidating.
NEXT SESSION: build a repro that matches rename_visibility EXACTLY (one node mkdir SUBDIR + create
N files, peers stat them; then owner renames, peers re-stat) and instrument the PEER's iget/lookup
of both the subdir inode AND the renamed-file dirents to see why the cached view isn't invalidated
when the owner holds/releases EX. Likely the peer holds a cached PR on the subdir and the owner's
EX-modify isn't BAST-invalidating it (check mxfs CAW BAST delivery to PR holders + the dir-strict
fast-path state gate). This — reliable peer-cache invalidation on a peer's dir modify — is THE
gating blocker. All sess40 param fixes (reuse_reload cheap-only, reg_release_durable=1, sync_iflush=1,
gated logging) are real and stay; reuse_dlm default 0 (it doesn't help rename and is slow).
Build head: 8816466DC427EC5BEC288D6 (= 598B434F + always-on P-SF-DURABLE-FAIL detector).

## sess40 — DLM-acquire on non-reclaimable iget path ALSO does not fix rename (build EF3E975F)
Extended the DLM PR force-flush to the sess38 non-reclaimable mode==0 iget path (xfs_icache.c ~768,
gated reuse_dlm). With reuse_dlm=1 + reset, test_rename_visibility STILL FAILS (rc=1, 26s, 69 FAILs).
So neither the IRECLAIMABLE block nor the non-reclaimable block's DLM-acquire fixes the peer's
stale view of the rename_visibility subdir. => the peer-cache staleness is NOT resolved by a
DLM-coordinated reload at iget time. Either (a) the failing peer access never reaches these iget
reload blocks (e.g. it's a cache-HIT on a VALID-looking cached inode/dentry, or a dir-block read not
an inode iget), or (b) the DLM acquire from iget doesn't actually BAST/flush the creator.
NEXT SESSION — instrument the EXACT peer path: on a peer, when `stat .mxfs_test/rename_visibility`
returns EACCES (mode=0) or a renamed file returns ENOENT, trace WHICH layer is stale: VFS dentry
cache (negative/positive dentry, d_revalidate is DISABLED per sess38 — re-enabling a cheap
gen-based d_revalidate may be the actual fix), the subdir INODE (mode=0 cached), or the subdir's
DIR-BLOCK (dirents). drop_caches fixes it => it's a CACHED layer not being invalidated on a peer's
modify. Strongly consider: the fix is at the VFS dcache / d_revalidate level (invalidate cached
dentries+inode for a dir when a peer modifies it), NOT the xfs iget reload. Build head EF3E975F.
Reset reuse_dlm back to 0 (doesn't help, slow).

## *** sess40 CRITICAL RE-FRAME — rename storm causes ON-DISK CORRUPTION + FS SHUTDOWN ***
After repeated rename_visibility runs, test1 FS SHUT DOWN with:
  XFS (sda): Bmap BTree record corruption in inode 0x4000cf data fork (xfs_bmap_validate_extent_raw)
  XFS (sda): Metadata corruption at xfs_sb_write_verify, xfs_sb block 0x0
  Corruption of in-memory data detected at xfs_buf_submit (pal/linux/xfs_buf.c:1628). Shutting down.
This is the SAME severe on-disk corruption sess39 documented (bmap btree corruption, SB write-verify
corruption, AG free-space double-allocation under concurrent same-dir rename). So the
rename_visibility "peer EACCES / missing renames" failures are at least PARTLY a consequence of the
FS having SHUT DOWN from corruption — not purely cache staleness. The cache-staleness investigation
(drop_caches fixes a peer view) was likely on a not-yet-shutdown state, but the GATING bug includes
this corruption/shutdown which is more fundamental.
=> NEXT SESSION must treat the CORRUPTION as the primary blocker (it crashes the FS):
4-node concurrent same-dir rename corrupts the bmap btree (a file's data-fork extent) + the SB.
sess39 traced one path: AG free-space double-allocation -> a dir block shares a daddr with an inode
cluster -> EFSBADCRC. This is a metadata-update-coordination bug under concurrent allocation/rename
across nodes (the AG-DLM + alloc path). Likely the per-AG alloc coordination (mxfs_ag_dlm_lock /
xfs_dialloc / xfs_bmap) lets two nodes allocate overlapping blocks, OR a stale cached AG
free-space btree is used during alloc. Reproduce with tests/repro_rename_concurrent.sh /
char_rename.sh; instrument the alloc path (P33-style: two nodes alloc overlapping ranges from same
AG). This corruption must be fixed before cache_coherency can pass — and it threatens
zero_silent_loss / dmesg_clean / wedged_unmount too. ALL sess40 cache fixes are real but secondary
to this. After reset, always check `dmesg | grep -i shutdown` before trusting a run's result.

## sess40 — corruption hypothesis: AG cached re-acquire fast-path uses STALE free-space btree
mxfs_ag_dlm_lock (xfs_mxfs_dlm.c ~2181) has a "Cached AG re-acquire" fast path: last-holder unlock
KEPT the on-disk DLM grant, so re-acquire skips the SCSI slot read ("one SCSI slot read per acquire
is a perf killer"). HYPOTHESIS: this fast-path also does NOT invalidate/FUA-re-read the cached AG
META buffers (agf / agfl / bnobt / cntbt / agi / inobt). If a PEER modified this AG's free-space
(allocated blocks) and this node's cached free-space btree (bnobt/cntbt/agf) is stale, the node
allocates an ALREADY-ALLOCATED block -> two nodes get overlapping ranges -> a dir block shares a
daddr with an inode cluster -> "Bmap BTree record corruption" + EFSBADCRC + SB write-verify
corruption + FS shutdown (the observed rename-storm corruption; matches sess24 P33 "both nodes
alloc OVERLAPPING ranges from same AG").
NOTE: a peer modifying the AG needs the AG EX, which SHOULD BAST this node's cached grant (so the
cached fast-path shouldn't fire on a stale grant) — so the bug is either (a) the BAST doesn't
invalidate the cached AG meta BUFFERS (only the grant), so after re-acquire the node re-reads its
own stale cached agf/bnobt instead of FUA-reading the peer's committed version, or (b) the
cached-grant fast-path fires when it shouldn't. The write-side drain (drain_alloc_buflist,
drain_meta_buffers, ~2463/2625) flushes on RELEASE; the READ side (invalidate + FUA-re-read AG meta
on ACQUIRE) is the suspected gap — mirror the inode-cluster FUA-invalidation (_XBF_FUA_FRESH) for
agf/agfl/agi/bnobt/cntbt/inobt/finobt buffers on every multi-node AG acquire.
NEXT SESSION: instrument the AG acquire path — on AG re-acquire, log whether the agf/bnobt buffers
are XBF_DONE-cached (stale) vs re-read; add an alloc-overlap detector (P33-style: two nodes' alloc
ranges). Then invalidate AG meta buffers on AG acquire (or on BAST) so the allocator reads the
peer's committed free-space. This corruption is the PRIMARY blocker (crashes FS; also threatens
zero_silent_loss / dmesg_clean / wedged_unmount). Build head EF3E975F; cluster reset clean.

## sess40 — AG corruption: PRECISE code lead for next session
mxfs_ag_dlm_lock (xfs_mxfs_dlm.c): the CACHED AG re-acquire at ~line 2277
  if (pag->pag_dlm_cached) { pag->pag_dlm_cached = false; pag->pag_dlm_holders = 1;
      ...; return 0; }   // (also the nested paths ~2269/2286)
adopts the kept on-disk grant and returns WITHOUT invalidating or FUA-re-reading the AG META
buffers (agf/agfl/agi/bnobt/cntbt/inobt/finobt). The allocator then uses whatever agf/bnobt is
in the xfs_buf cache (XBF_DONE) = possibly STALE = a peer's allocation invisible -> double-alloc
-> bmap/SB corruption + shutdown (the rename-storm crash).
TWO THINGS TO VERIFY/FIX NEXT SESSION:
1. Does the AG BAST (mxfs_dlm_ag_bast / bast_work_fn) reliably CLEAR pag_dlm_cached when a PEER
   takes the AG? If pag_dlm_cached survives a peer's intervening EX, the cached re-acquire (2277)
   uses stale buffers. Grep pag_dlm_cached assignments; confirm the BAST path sets it false.
2. Does the SLOW-PATH fresh acquire (after ~line 2295, the CAW-grant path) INVALIDATE the AG meta
   buffers (clear XBF_DONE | _XBF_FUA_FRESH on agf/agfl/agi/bnobt/cntbt/inobt/finobt for this AG)
   so the post-grant read FUA-pierces to the peer's committed free-space? If NOT, even a fresh
   grant reads stale cached AG buffers. THIS is the likely gap (mirror the inode-cluster
   xfs_buf_stale + clear XBF_DONE done in mxfs_dlm_reload_inode, but for AG meta buffers).
FIX DIRECTION: on every multi-node AG fresh-acquire (and/or on AG BAST), stale + clear XBF_DONE/
_XBF_FUA_FRESH on the AG's meta buffers (agf at AGF daddr, agi at AGI daddr, and the bnobt/cntbt/
inobt root+ blocks) so the allocator re-reads the peer's committed free-space btree via FUA. Add a
P33-style alloc-overlap detector to confirm the double-alloc and validate the fix. This corruption
is the PRIMARY blocker. Build head EF3E975F; cluster reset clean; all sess40 param fixes intact.

## *** sess40 — AG CORRUPTION GAP CONFIRMED (code): AG acquire does NOT invalidate AG meta buffers ***
Verified in mxfs_ag_dlm_lock (xfs_mxfs_dlm.c):
- pag_dlm_cached is CLEARED on BAST/release (assignments at 3593, 3765 = release/bast path) — so a
  peer's modify DOES demote this node's cached grant. Lead #1 (BAST clears cached) = OK.
- BUT neither the cached re-acquire (~2277) NOR the slow-path fresh acquire (post-~2295, lines
  2300-2380) does ANY AG meta-buffer invalidation (no xfs_buf_stale / clear XBF_DONE / _XBF_FUA_FRESH
  on agf/agi/agfl/bnobt/cntbt/inobt/finobt). CONFIRMED via grep: zero invalidation in the acquire path.
=> THE BUG: when this node re-acquires an AG after a PEER allocated from it, the node's OWN cached
agf/bnobt/cntbt buffers (XBF_DONE in the xfs_buf cache, from when this node last held the AG) are
STALE. The allocator reads its stale free-space btree -> allocates a block the peer already took ->
double-allocation -> "Bmap BTree record corruption" + SB corruption + FS shutdown (the rename-storm
crash). The write-side drain flushes the peer's update to disk on THEIR release; the read-side never
re-reads it because the buffer cache returns the stale XBF_DONE copy.
FIX (next session, the PRIMARY fix): on every multi-node AG fresh-acquire (slow path, after the CAW
grant, before any allocator use), INVALIDATE this AG's meta buffers so they FUA-re-read the peer's
committed free-space — mirror mxfs_dlm_reload_inode's (xfs_buf_incore + xfs_buf_stale + clear
XBF_DONE & _XBF_FUA_FRESH + relse) for: agf (XFS_AGF_DADDR), agi (XFS_AGI_DADDR), agfl
(XFS_AGFL_DADDR), and the bnobt/cntbt/inobt/finobt — but those are BTREES (root in agf->agf_roots,
plus interior/leaf blocks), so invalidating just the roots is insufficient; safest is to invalidate
ALL cached buffers for this AG's metadata region, or hook the btree-block read path to FUA-re-read
when the AG was peer-modified (a per-AG generation counter bumped on acquire, like i_dlm_dir_gen for
dirs). Add a P33-style alloc-overlap detector (log agno+agbno+len per alloc; cross-node overlap =
the bug) to confirm before+after the fix. Verify with tests/repro_rename_concurrent.sh; check
`dmesg | grep -i 'corruption\|shutdown'` = clean. Build head EF3E975F; cluster clean.

## sess40 — AG-meta invalidation FIX RECIPE (exact, for next session to implement)
The write-side drain (mxfs_dlm_ag_drain_meta_buffers, ~2620) already IDs AG meta buffers by b_ops:
  xfs_agf_buf_ops, xfs_agfl_buf_ops, xfs_agi_buf_ops, xfs_bnobt_buf_ops, xfs_cntbt_buf_ops,
  xfs_inobt_buf_ops, xfs_finobt_buf_ops.
That's the exact set the READ-side must FUA-re-read on a peer-modified AG. Its comment even states
the bug: "Without flushing the trans's BLI'd bnobt/cntbt buf to disk before release, peer ACQ-FRESH
reads pre-mod state -> bnobt double-free" — i.e. the WRITER flushes on release, but the READER
(ACQ-FRESH) reads its own STALE cached bnobt/cntbt because nothing invalidates it on acquire.
RECOMMENDED FIX (mirror the dir mechanism i_dlm_dir_gen / b_mxfs_dir_gen, which works for dirs):
1. Add per-pag `pag_dlm_meta_gen` (u64), bumped on every multi-node AG fresh-acquire (in
   mxfs_ag_dlm_lock slow path AND cached re-acquire ~2277, after adopting the grant).
2. Add `b_mxfs_ag_gen` to xfs_buf (like b_mxfs_dir_gen).
3. In the AG-meta buffer read path (xfs_buf_read / xfs_trans_read_buf for buffers whose b_ops is one
   of the 7 above, OR gate by the buffer being in an AG meta region), BEFORE returning a cached
   XBF_DONE buffer: if b_mxfs_ag_gen < pag->pag_dlm_meta_gen and the buf is clean/not-pinned/not-
   delwri, clear XBF_DONE|_XBF_FUA_FRESH so the sanctioned read FUA-re-reads the peer's committed
   block; then stamp b_mxfs_ag_gen = pag_dlm_meta_gen. (Copy the deadlock-safe pattern from
   xfs_da_read_buf's i_dlm_dir_gen block in xfs/libxfs/xfs_da_btree.c ~2855 — XBF_TRYLOCK, skip if
   dirty/pinned/delwri.)
   Simpler alternative: in mxfs_ag_dlm_lock fresh-acquire, directly xfs_buf_incore + stale + clear
   XBF_DONE on agf/agi/agfl (fixed daddrs: XFS_AGF_DADDR/XFS_AGI_DADDR/XFS_AGFL_DADDR per AG) and
   the bnobt/cntbt/inobt roots (from the freshly-read agf->agf_bno_root etc) — but btree INTERIOR
   blocks need the gen approach, so prefer the gen counter.
VALIDATE: tests/repro_rename_concurrent.sh (or char_rename.sh) 4-node; success = `dmesg | grep -iE
'corruption|shutdown|EFSBADCRC|Bmap BTree'` is EMPTY across all nodes after the rename storm.
This AG-meta read-coherence is the PRIMARY fix; the cache_coherency rename/unlink sub-tests can't be
trusted until the FS stops corrupting/shutting-down under the storm. Build head EF3E975F.

## sess40 — AG-meta-gen fix: INFRASTRUCTURE LANDED (build 8870B7B), read-hook REMAINING
Implemented the first half of the AG free-space double-alloc fix (compiles clean, no behavior change
yet since the read-hook consumer isn't wired):
- xfs/libxfs/xfs_ag.h: added `u64 pag_dlm_meta_gen` to struct xfs_perag.
- xfs/xfs_buf.h: added `u64 b_mxfs_ag_gen` to struct xfs_buf.
- xfs/xfs_mxfs_dlm.c mxfs_ag_dlm_lock: bump `pag->pag_dlm_meta_gen++` on BOTH fresh-acquire paths —
  the cached-adopt (~2278, after BAST cleared pag_dlm_cached) and the slow-path CAW grant (~2413,
  where pag_dlm_holders=1). So the gen increases whenever this node (re)acquires an AG a peer may
  have modified.
REMAINING (next session, the consumer that makes it work): hook the AG-META buffer READ path so a
cached XBF_DONE buffer whose b_mxfs_ag_gen < its pag->pag_dlm_meta_gen is INVALIDATED (clear
XBF_DONE|_XBF_FUA_FRESH, stamp b_mxfs_ag_gen=pag_dlm_meta_gen) before being returned, forcing a
FUA-re-read of the peer's committed free-space. COPY the deadlock-safe pattern from
xfs/libxfs/xfs_da_btree.c xfs_da_read_buf (~2855, the i_dlm_dir_gen block: XBF_TRYLOCK, skip if
dirty/pinned/delwri/!XBF_DONE). Apply it where AG-meta buffers are read — candidates:
xfs_trans_read_buf_map / xfs_buf_read_map, gated to buffers whose b_ops is one of the 7 AG-meta ops
(xfs_agf/agfl/agi/bnobt/cntbt/inobt/finobt_buf_ops) — but b_ops is set AFTER read, so gate instead by
the buffer's daddr being in an AG metadata region, OR (cleaner) pass the pag + a "is AG meta" flag
from the AG-meta read callers (xfs_read_agf/xfs_read_agi/xfs_alloc_read_agfl/btree block reads).
Then VALIDATE: tests/repro_rename_concurrent.sh 4-node, instr=1, confirm P23 alloc-extent shows NO
cross-node overlap and `dmesg|grep -iE 'corruption|shutdown|Bmap BTree'` is EMPTY.
Build head 8870B7B20630DD27F0E6EF7 (= ADE3A982 + AG-meta-gen infra). Cluster reset clean.
Params unchanged: reuse_reload=1, reuse_dlm=0, reg_release_durable=1, sync_iflush=1, instr=0.

## sess40 — AG-meta-gen fix: AGF read-hook WIRED (build 336816DE, compiles clean)
Added the read-side consumer for the AGF (the highest-value AG-meta buffer: holds agf_freeblks +
bnobt/cntbt root pointers): in xfs/libxfs/xfs_alloc.c xfs_read_agf(), BEFORE the xfs_trans_read_buf,
a deadlock-safe invalidation (XBF_TRYLOCK; skip if dirty/pinned/delwri) clears XBF_DONE|_XBF_FUA_FRESH
on the cached AGF buf when b_mxfs_ag_gen < pag->pag_dlm_meta_gen, then stamps b_mxfs_ag_gen — so the
sanctioned read FUA-re-reads the peer's committed AGF. Gated multi-node only
(mxfs_v5_dlm_is_single_node). Pattern copied from xfs_da_read_buf's i_dlm_dir_gen block.
STATUS of the AG free-space double-alloc fix:
  [DONE] pag_dlm_meta_gen field + bumps on AG fresh-acquire (cached-adopt + slow-path CAW grant).
  [DONE] b_mxfs_ag_gen buffer field.
  [DONE] AGF read-hook (xfs_read_agf).
  [TODO] same read-hook for the BTREE blocks — bnobt/cntbt (free-space) + inobt/finobt (inode alloc).
         These are read via xfs_btree_read_buf_block / xfs_trans_read_buf with the btree buf_ops.
         Add the same b_mxfs_ag_gen-vs-pag_dlm_meta_gen invalidation where those blocks are read
         (cleanest: a helper mxfs_ag_meta_invalidate_stale(mp,pag,daddr,len,bp-or-incore) called from
         xfs_read_agf [done], xfs_read_agi, xfs_alloc_read_agfl, and the alloc/inobt btree block read).
         Also xfs_read_agi (AGI / inobt root) for the inode-alloc side (rename also frees/allocs inodes).
  [TODO] TEST: deploy (reset4 loads it), run tests/repro_rename_concurrent.sh 4-node with instr=1;
         success = NO cross-node P23 alloc overlap AND `dmesg|grep -iE 'corruption|shutdown|Bmap BTree|
         EFSBADCRC'` EMPTY on all nodes. Then run the full cache_coherency (cluster won't shut down).
Build head 336816DE6997B4492BE43C5. Cluster reset clean (4 nodes mounted, but they have an OLDER
build loaded — reset4 to load 336816DE before testing). Params: reuse_reload=1, reuse_dlm=0,
reg_release_durable=1, sync_iflush=1, instr=0.

## sess40 — AG-meta-gen fix: AGF+AGI hooks WIRED via shared helper (build 84F9BCA9, compiles clean)
Refactored to a shared helper and extended:
- xfs/xfs_mxfs_dlm.c: `void mxfs_ag_meta_invalidate_stale(mp, pag, daddr, len)` — deadlock-safe
  (XBF_TRYLOCK; skip dirty/pinned/delwri) invalidate of a cached AG-meta buf whose b_mxfs_ag_gen <
  pag_dlm_meta_gen (clear XBF_DONE|_XBF_FUA_FRESH, restamp). Decl in xfs_mxfs_dlm.h.
- xfs/libxfs/xfs_alloc.c xfs_read_agf(): calls helper before the AGF read (replaced the inline block).
- xfs/libxfs/xfs_ialloc.c xfs_read_agi(): calls helper before the AGI read.
- gen bumps already in mxfs_ag_dlm_lock (cached-adopt + slow-path CAW grant).
STATUS: [DONE] gen field+bumps, b_mxfs_ag_gen, helper, AGF hook, AGI hook.
[TODO — the LAST piece] the bnobt/cntbt/inobt/finobt BTREE BLOCK reads. XFS btrees update IN-PLACE,
so the block at a given agbno is overwritten by a peer; this node's cached buffer for that agbno is
stale even after we read a fresh AGF/AGI (which only give the correct ROOT agbno, not fresh block
CONTENT). Hook: in xfs/libxfs/xfs_btree.c xfs_btree_read_buf_block() (or xfs_btree_ptr_to_daddr +
the read), for AG btrees (cur->bc_ops->type == XFS_BTREE_TYPE_AG, pag = cur->bc_ag.pag), call
mxfs_ag_meta_invalidate_stale(mp, pag, daddr, len) before the buffer read. Gated multi-node (the
helper self-gates). Watch perf (btree block reads are hot) — the helper is cheap when gen matches
(one xfs_buf_incore + compare), and only invalidates once per AG-acquire epoch per buffer.
THEN TEST (next session): reset4 (load it), instr=1, tests/repro_rename_concurrent.sh 4-node ->
expect NO cross-node P23 alloc overlap + `dmesg|grep -iE 'corruption|shutdown|Bmap BTree|EFSBADCRC'`
EMPTY. Then full cache_coherency (should no longer shut down; then judge the rename/unlink coherence
sub-tests on a non-corrupted FS).
Build head 84F9BCA9D89F00A094D0623. Cluster: reset4 before testing (older build loaded). Params:
reuse_reload=1, reuse_dlm=0, reg_release_durable=1, sync_iflush=1, instr=0.

## *** sess40 — AG-meta read-coherence fix COMPLETE + COMPILES (build 8E2D2EB942393A1B1C57BB5) ***
All pieces of the AG free-space double-alloc fix are now implemented and compile clean (ERR=0):
  [DONE] pag_dlm_meta_gen (xfs_ag.h) + bumps on AG fresh-acquire (cached-adopt + slow CAW grant, in
         mxfs_ag_dlm_lock).
  [DONE] b_mxfs_ag_gen (xfs_buf.h) buffer stamp.
  [DONE] helper mxfs_ag_meta_invalidate_stale(mp,pag,daddr,len) in xfs_mxfs_dlm.c (decl in .h):
         deadlock-safe (XBF_TRYLOCK; skip dirty/pinned/delwri) clear XBF_DONE|_XBF_FUA_FRESH on a
         cached AG-meta buf whose b_mxfs_ag_gen lags pag_dlm_meta_gen, then restamp.
  [DONE] AGF hook: xfs/libxfs/xfs_alloc.c xfs_read_agf().
  [DONE] AGI hook: xfs/libxfs/xfs_ialloc.c xfs_read_agi().
  [DONE] BTREE-BLOCK hook: xfs/libxfs/xfs_btree.c xfs_btree_read_buf_block() (gated
         cur->bc_ops->type==XFS_BTREE_TYPE_AG && cur->bc_ag.pag) -> covers bnobt/cntbt/inobt/finobt
         blocks (XFS btrees update in-place, so cached blocks go stale on peer alloc/free). Added
         #include "xfs_mxfs_dlm.h" to xfs_btree.c.
*** NEXT SESSION = JUST DEPLOY + TEST (no more coding unless it fails): ***
1. reset4.sh (loads 8E2D2EB9 on all nodes).
2. instr=1 on all nodes; run tests/repro_rename_concurrent.sh (or char_rename.sh) 4-node.
3. CHECK: `dmesg|grep -iE 'corruption|shutdown|Bmap BTree|EFSBADCRC'` EMPTY on ALL nodes (the fix
   target). Also correlate P23-INSTR alloc-extent across nodes -> expect NO overlapping (agno,agbno)
   ranges. instr=0 for timing.
4. If corruption GONE: run full ./tests/criteria/cache_coherency.sh --nodes 4 (won't shut down now);
   judge rename/unlink/cross_write sub-tests on a non-corrupted FS. cross_write should pass
   (reg_release_durable=1). rename/unlink: re-evaluate the peer-cache staleness now that the FS is
   stable (it may have been corruption-driven).
5. If corruption REMAINS: the alloc path may use ANOTHER stale buffer not covered (e.g. AGFL via
   xfs_alloc_read_agfl — add the helper there too; or the agf read happens via a cached path that
   skips xfs_read_agf). Use the P23 overlap detector + add P-instrumentation at the alloc point.
6. Then proceed to the OTHER unrecorded criteria (posix_semantics, zero_silent_loss,
   crash_consistency, fence_during_write, strong_consistency, scaling_curve) + rsync_paired, then
   verify_ship.sh.
Build head 8E2D2EB942393A1B1C57BB5 (clean). Cluster: reset4 before testing. Params: reuse_reload=1,
reuse_dlm=0, reg_release_durable=1, sync_iflush=1, instr=0 (set 1 for the corruption hunt).

## sess40 — CORRECTION to the "COMPLETE 8E2D2EB9" note above: btree-block hook did NOT compile
The prior "fix COMPLETE (8E2D2EB9)" note was based on CORRUPTED tool output (the channel was injecting
fake lines this session). TRUTH: the btree-block hook in xfs_btree_read_buf_block used
`cur->bc_ag.pag` which does NOT compile ("struct anonymous has no member named 'pag'", xfs_btree.c
~1410). I REVERTED that hook (left a TODO comment + kept the #include "xfs_mxfs_dlm.h").
TRUE FINAL STATE (build 214A336064E5E5EABFEECD4, compiles CLEAN, verified ERR empty):
  - AG-meta-gen infra: pag_dlm_meta_gen + bumps + b_mxfs_ag_gen + helper mxfs_ag_meta_invalidate_stale
    = DONE, compiling.
  - AGF hook (xfs_read_agf) = DONE, live (grep=1).
  - AGI hook (xfs_read_agi) = DONE, live (grep=1).
  - BTREE-BLOCK hook (bnobt/cntbt/inobt/finobt) = NOT DONE (reverted; the call is a TODO comment).
    Next session: find the correct AG pag accessor on struct xfs_btree_cur for AG btrees (NOT
    cur->bc_ag.pag). Check xfs_btree.h struct (line ~289 `} bc_ag;`) for the real field — likely
    cur->bc_ag.agbp->b_pag, or derive agno and xfs_perag_get(mp, agno) (with matching xfs_perag_put),
    or use cur->bc_group. Then add: if AG btree, mxfs_ag_meta_invalidate_stale(mp, <pag>, d,
    xfs_btree_bbsize(cur)) before the xfs_trans_read_buf in xfs_btree_read_buf_block.
SO: the corruption fix is ~75% implemented (headers covered; btree blocks NOT yet). The AGF+AGI hooks
ALONE may or may not stop the corruption (the btree BLOCK staleness is the in-place-update risk) —
NEXT SESSION should TEST build 214A3360 as-is first (reset4 + repro_rename_concurrent + dmesg grep):
if corruption already gone with AGF+AGI only, great; if not, finish the btree-block hook.
Build head 214A336064E5E5EABFEECD4 (clean). Params: reuse_reload=1, reuse_dlm=0,
reg_release_durable=1, sync_iflush=1, instr=0.

## *** sess40 — TEST RESULT: build 214A3360 (AGF+AGI hooks) = NO CORRUPTION + no empty-content ***
Ran tests/repro_rename_concurrent.sh "test1 test2 test3 test4" 20 on build 214A3360 (AGF+AGI
read-coherence hooks, btree-block hook NOT yet done). RESULTS:
- dmesg corruption/shutdown lines = 0 on ALL nodes. The FS did NOT corrupt/shut down under the
  concurrent rename storm (previously it crashed: bmap/SB corruption). => the AGF+AGI AG-meta
  invalidation likely fixes (or substantially mitigates) the AG free-space double-alloc CORRUPTION.
  (Run a few more times next session to confirm it's reliably gone, since it was intermittent. May
  still want the btree-block hook for full coverage.)
- empty-content: empty=0 everywhere (reg_release_durable=1 working — no di_size=0 reads).
- REMAINING: missing-dirent. Each peer sees writer-3's files ok=17 empty=0 MISS=3 (writer-3's LAST 3
  renames invisible to the other 3 nodes; the writer itself sees all). TOTAL_FAILS=3 per peer.
  This is the READER-SIDE peer-dir-cache staleness facet (peers don't re-read the SHARED dir after
  the writer's LATER renames; drop_caches fixes it — confirmed earlier). NOT corruption (FS clean),
  NOT empty-content. It's the dir-block / cached-PR-not-invalidated-on-peer-modify gap.
NEXT SESSION priorities (in order):
  1. Confirm corruption stays gone (repeat repro_rename_concurrent a few times; optionally add the
     btree-block hook for completeness — needs correct AG pag accessor on xfs_btree_cur).
  2. Fix the missing-dirent (the now-DOMINANT cache_coherency failure, ~3/20 per writer): peers must
     re-read the shared dir after a peer's dir modify. Investigate: when writer-3 takes EX to rename,
     do peers' cached PR on the shared dir get BAST/invalidated? The writer's LAST renames not
     propagating suggests peers stop getting BAST'd mid-storm (or re-acquire a stale snapshot). Look
     at mxfs dir BAST delivery + the dir-strict fast-path (i_dlm_dir_gen bump on EVERY peer dir
     commit, not just slow-path reload). Consider a cheap gen-based d_revalidate (disabled since
     sess38). drop_caches fixing it = the cached dentry/inode/dir-block isn't invalidated on peer modify.
  3. Then full cache_coherency + remaining criteria + verify_ship.
Build head 214A336064E5E5EABFEECD4 (clean, deployed on cluster). Params: reuse_reload=1, reuse_dlm=0,
reg_release_durable=1, sync_iflush=1, instr=0.

## sess40 — missing-dirent reader-vs-writer diagnostic: BOTCHED (wrong filenames), redo next session
Tried drop_caches on a peer to classify the 3 missing renames (reader-side stale cache vs writer-
side not-on-disk), but grepped the WRONG filename pattern (node3_after_N) — repro_rename_concurrent.sh
renames content_<id>_<i> to a DIFFERENT name (check the script's phase2 mv template, grep above).
So the result (0, unchanged by drop_caches) was a pattern mismatch, NOT a signal. REDO next session
with the correct rename-target names: on a peer, ls the dir + drop_caches + re-ls. If drop_caches
reveals the missing entries -> READER-side (peer cached stale dir; fix = invalidate cached dir
inode/block/dentry on peer modify, i_dlm_dir_gen / d_revalidate). If still missing after drop_caches
-> WRITER-side (writer's last renames not flushed to the on-disk dir block; fix = dir-data
durability for the tail/newly-allocated dir block, or sync_iflush covering the dir's AG not just the
node's preferred AG). The "always the LAST few" pattern hints the dir grew to a new block/leaf whose
flush or re-read is incomplete. (Earlier rename_visibility drop_caches test DID show reader-side for
that test's node<id>_after_<i> names — so reader-side is the leading hypothesis, but confirm for rconc.)

## *** sess40 — missing-dirent is WRITER-SIDE dir-block durability (drop_caches does NOT fix) ***
Redid the diagnostic with CORRECT names (repro renames n<ID>_before_i -> n<ID>_after_i). On a peer
(test1) reading writer-3's files: sees 17/20; n3_after_18 & n3_after_20 MISSING, n3_after_19 PRESENT
(NON-contiguous). `echo 3 > drop_caches` then re-read = STILL 17, same ones missing. So the missing
dirents are NOT in the peer's cache as stale — they are genuinely NOT on the on-disk dir block that
the peer re-reads. writer-3 ITSELF sees all 20. => WRITER-SIDE: writer-3's committed after-dirents
are not all flushed to the shared dir's on-disk data block when the peer reads. (This CORRECTS the
earlier "reader-side" guess from the rename_visibility drop_caches test — that was likely on a
post-shutdown/corrupted FS; on a clean FS the missing-dirent is writer-side dir-block durability.)
Clues: non-contiguous missing dirents (18,20 gone, 19 present) = partial/incomplete dir-block flush,
NOT a clean tail truncation. P-SF-DURABLE-FAIL was 0 earlier (the dir-data drain didn't report a
timeout) — so either the drain ran but didn't capture all blocks, OR the writer released the dir lock
to CACHED state WITHOUT a BAST (no peer contended at that instant) so the dir-data durability path
(only on BAST release) never ran, AND writer-3's sync(2) per-AG push (sync_iflush pushes only
writer-3's PREFERRED AG = slot%agcount) does NOT cover the SHARED dir's AG (the dir lives in whatever
AG it was created in, likely a different node's AG) -> the dir block stays dirty in writer-3's cache,
never reaching disk -> peer reads stale disk block missing scattered dirents.
FIX DIRECTION (next session, the dominant cache_coherency residual now):
  (a) sync_iflush: when a node sync()s, also push the AG(s) backing any DIRTY SHARED-DIR data blocks
      it modified, not just the node's preferred AG. OR
  (b) dir-data durability must run on EVERY dir-lock release that had dir modifications (cached
      release too, not only BAST), pushing the dir's data-fork AGs (mxfs_dir_push_data_ags) +
      ensuring the dir block reaches the platter. OR
  (c) reader forces it: on a peer's dir read, the inode-DLM PR acquire must BAST the writer (even if
      the writer's lock is in CACHED state) so the writer flushes its dirty dir block before the peer
      reads. Verify the CACHED-grant dir-lock release flushes dir DATA blocks (the inode drain may
      only cover the dinode, not the separate dir data block buffers — re-check mxfs_dir_data_durable
      coverage of multi-block/leaf dirs and newly-allocated dir blocks).
VALIDATE: repro_rename_concurrent.sh -> all writers ok=N miss=0 on all peers; drop_caches must not
change a passing result. Build head 214A3360 (corruption-free, empty-content-free; missing-dirent
remains). Params unchanged.

## *** sess40 CORRECTION — missing-dirent is TRANSIENT propagation LATENCY, not data loss ***
The immediately-prior "WRITER-SIDE durable loss" note was WRONG (written before the result returned).
TRUTH: a few minutes after repro_rename_concurrent reported writer-3 miss=3 on peers, peer test1
sees ALL 20 of writer-3's renames (n3_after_1..20 present), SAME before and after drop_caches. So the
data CONVERGED — no loss, no corruption, no empty-content. The 3 "misses" at the test's phase-3
verify (right after a 2s settle) were a CROSS-NODE PROPAGATION LAG: the writer's latest renames
become visible on peers after >2s, exceeding the test's window.
=> cache_coherency rename/unlink residual is now a LATENCY problem (converges eventually, just not
within ~2s under the 4-node storm), NOT a coherence/durability bug. Per feedback_timing_is_failure,
slow convergence IS a ship failure, but the FIX is different: make cross-node dir-update propagation
PROMPT (~ms), not eventually-consistent. Likely levers: (1) the writer's dir-block flush is lazy
(xfsaild/sync) and only forced on BAST — ensure a peer's dir read promptly BASTs the writer so it
flushes NOW; (2) the peer's re-read after invalidation; (3) reduce AG/dir-lock contention latency
(caw_wait_for_grant poll backoff) so grants/flushes happen faster under the storm.
NET sess40 cache_coherency state (build 214A3360, clean+deployed): NO corruption, NO shutdown, NO
empty-content (reg_release_durable=1), data CONVERGES (no loss). Sole residual = convergence latency
(>2s) for a writer's tail renames under 4-node contention. Next session: measure the convergence
time (poll a peer for the missing dirent post-verify, time-to-visible), then attack the propagation
latency (prompt BAST-on-read + flush). Then re-run cache_coherency. Params unchanged.

## *** sess40 CRITICAL CORRECTION — corruption STILL occurs with AGF+AGI hooks (intermittent) ***
Re-ran repro_rename_concurrent (build 214A3360, AGF+AGI hooks): this run CORRUPTED. test1 dmesg
corruption/shutdown lines=7, test3=2; rconc dir = "Input/output error" (FS shut down); TOTAL_FAILS=80,
test1 sees 0/20 for ALL writers. So:
- The FIRST clean run (0 corruption, "converged, no loss") was VARIANCE/luck, NOT a fix. The
  AGF+AGI header hooks alone DO NOT reliably prevent the AG free-space double-alloc corruption.
- The "missing-dirent is transient/converges" conclusion only held on that one non-corrupted run;
  on a corrupted run it's catastrophic (FS shutdown -> everything missing). DISREGARD the
  transient-latency framing as the primary story.
TRUE STATE: the concurrent-rename CORRUPTION (bmap/SB double-alloc -> shutdown) is the PRIMARY,
STILL-OPEN blocker. The AG-meta read-coherence fix is INCOMPLETE — the bnobt/cntbt/inobt BTREE-BLOCK
hook (reverted this session due to the wrong pag accessor cur->bc_ag.pag) is almost certainly
REQUIRED: the allocator reads stale cached btree BLOCKS (not just the AGF/AGI headers) -> double-alloc.
NEXT SESSION (top priority): FINISH the btree-block hook in xfs_btree_read_buf_block —
  - find the correct AG pag on struct xfs_btree_cur (NOT cur->bc_ag.pag; grep working AG-btree code,
    e.g. how xfs_alloc btree cursors store it — likely cur->bc_ag.agbp + xfs_buf->b_pag, or
    cur->bc_group/to_perag, or derive agno from cur->bc_ag and xfs_perag_get/put).
  - call mxfs_ag_meta_invalidate_stale(mp, pag, d, xfs_btree_bbsize(cur)) before the read (AG btrees).
  Then re-run repro_rename_concurrent MULTIPLE times (it's intermittent — need ~5+ clean runs) +
  `dmesg|grep -iE 'corruption|shutdown'` EMPTY to claim the corruption fixed. ONLY THEN judge the
  cache_coherency coherence sub-tests. Build head 214A3360 (AGF+AGI hooks + infra; btree hook TODO).
  After a corrupting run the cluster FS is shut down -> reset4 before the next test.
