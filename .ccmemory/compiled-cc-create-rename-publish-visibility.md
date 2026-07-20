---
name: compiled-cc-create-rename-publish-visibility
description: Compiled: rename/create visibility is a publish-side bug — deferred-publish gap, divergent-base mkdir, reg-file reuse-adopt, chokepoint arch.
metadata:
  type: project
tags: [compiled, cache_coherency, rename_visibility, deferred-publish, chokepoint, dlm, mode-a]
---

# Create/rename visibility as a publish-side bug

Consolidates the multi-session arc that re-framed the `cache_coherency`
criterion's `rename_visibility` failure from a "durability/stale-read" problem
into a **publish-side coordination bug**: new inodes granted EX locally are
never given an on-disk CAW slot, so peers reaching them never BAST the creator,
two nodes hold EX on divergent bases, and the parent dir suffers durable
lost-update. Sources: [[sess39_lessons]] (initial root-characterization,
2026-05-30) → [[sess103_lessons]] → [[sess105_lessons]] → [[sess106_lessons]] →
[[sess107_lessons]] → [[sess108_lessons]] (all 2026-06-06, ccloop run
29df431e). All target the same criterion; treat this as the authoritative
thread over the individual session notes.

## The central mechanism (proven across sess105–108)
`rename_visibility` loss is a **CREATE-phase bug, not a rename lost-update**
([[sess105_lessons]] reframe). The harness (`run_tests.sh:258`) has ONE node
`rm -rf .mxfs_test/<test>; mkdir`, then ALL 4 nodes `mkdir -p $TESTDIR`
concurrently (test line 14, NO barrier; note the pre-create uses a DIFFERENT
name `test_rename_visibility` so the path is NOT pre-created). Two nodes both
create the same name into parent `.mxfs_test` (ino 131, shortform fmt=1), each
allocating a DISTINCT child inode → parent-dir-block lost-update → the loser
keeps a stale dentry pointing at an orphaned child → its files are invisible
cluster-wide and its later `mv` ENOENTs ([[sess106_lessons]] decisive evidence:
node3 new_ino=12583041, node1 new_ino=135, node1 created child 135 INSIDE
node3's EX-held window on ino 131 via the fast path).

### Root cause — the deferred-publish design gap (FULLY PROVEN, [[sess107_lessons]])
`mxfs_dlm_grant_local_new` (`xfs/xfs_mxfs_dlm.c:4010`, from `xfs_icache.c:1114`
on IGET_CREATE) grants a new inode EX **locally only**: `i_dlm_mode=EX`,
`state=CACHED`, `i_dlm_unpublished=true`, on `m_mxfs_unpub_list`, with **NO
on-disk CAW slot**. Publish (`mxfs_dlm_publish_unpublished`, which acquires real
slots) fires ONLY on an incoming BAST (inode `bast_notify:2077`, AG `bast:7066`).
Flaw: an unpublished inode has no on-disk slot, so a peer reaching it acquires
the empty slot CLEANLY and never BASTs the creator → publish never fires → both
nodes hold EX → concurrent dir-block RMW → durable lost-update, escalating to
inobt-AG4 / `xfs_defer_finish_noroll` corruption shutdown.

This is the same "in-memory EX without on-disk slot" state [[sess106_lessons]]
saw as **stale-cached-EX**: the fast path (`xfs_mxfs_dlm.c ~3254/~3874`)
`if (i_dlm_mode==EX || (PR&&PR)) { cache hit; return; }` trusts in-memory mode,
does no on-disk CAW, no ownership re-check. Consistent with sess52 `ex_pop=1`:
CAS exclusion is correct; the bug is in-memory state divergence, not a
double-grant.

## Fixes landed (chronological, by build)

### sess39 (build progression `5FDB1F91`→`570290DA`→`79FB2484`)
Re-characterized rename_visibility from sess38's false "1/16 transient" to
SEVERE on-disk-metadata corruption + FS shutdown under 4-node concurrent
same-dir rename ([[sess39_lessons]]). Landed and KEPT:
- **Dir-data-block durability barrier** (`mxfs_dir_data_durable()` +
  `mxfs_dir_push_data_ags()`, dir-inode BAST release): release drain now waits
  on dir DATA-fork block durability + pushes their AGs, not just the dinode's
  AIL/pin state.
- **Scoped inode-lock CAS backoff** (`caw_inode_backoff()` in `dlm/dlm_caw.c`,
  INODE locks only): node-phased jittered sleep `(retry + local_node*5) % 7` ms
  at retry≥2, desyncs the same-slot CAS storm that exhausted
  `MXFS_CAW_MAX_RETRIES=100` → -ETIMEDOUT force-shutdown. Scoped to inode locks
  so it does NOT regress the dd/AG path (the v0.3.46/50 GLOBAL-backoff revert).
- **di_size reload-skip** (`mxfs_dlm_reload_inode`): a BAST-driven re-acquire was
  reading the STALE allocation-time on-disk dinode (di_size=0/nblocks=0, because
  the create's di_size update hadn't iflushed) and CLOBBERING the good in-memory
  size → own-file empty-content. Fix: for S_ISREG with `i_disk_size>0 &&
  disk_di_size==0 && nblocks==0`, SKIP the reload (detector RELOAD-SIZE-DROP →
  SKIP; unskipped count → 0). NOTE: this is later generalized by sess103's
  gen-checked reuse-adopt — see below.
- **sync_fs iflush fix** (`pal/linux/xfs_super.c`): multi-node `xfs_fs_sync_fs`
  with wait=1 only did `xfs_log_force(SYNC)` (commits di_size to LOG, not to the
  on-disk inode cluster a peer FUA-reads) → cross-node empty-content. Added
  `xfs_ail_push_all_sync` + `blkdev_issue_flush`; A/B: rename fails 15→~5
  (empty-content 36→~3). **BUT** whole-AIL push WEDGES cross-AG (xfsaild
  D-state DLM deadlock — the documented per-AG-push hazard) and times the full
  criterion out >900s. Gated behind `mxfs.sync_iflush`. Bounded variant
  `xfs_ail_push_all_sync_bounded(2s)` (`xfs/xfs_trans_ail.c`) still wedged under
  `unlink_visibility`'s `xfs_inactive_ifree`→`ail_push_all_sync`; **default
  flipped to 0** at session end. Correct next form = PER-AG bounded push of this
  node's preferred AG (`slot % agcount`), never whole-AIL.

sess39 FALSIFIED (do not re-try): CAW double-grant (`caw_check_exclusion()`
detector = 0 always — EX exclusion is CORRECT), AG-cached-vs-disk divergence
(`mxfs_v5_dlm_ag_held` detector div=0), FUA not covering bnobt (it does),
deferred-AG-release missing-flush (`pag_dlm_release_work` added + KEPT as a real
latent Invariant-#1 fix, but REL-DEFERRED-FLUSHED fired 0× — inert for rename),
torn-read (P-TORN 220 attempts, 0 recovered → corruption is persistent-on-disk-
looking), regular-file durability extension (net regression), and raw surgical
FUA-write of the inode cluster (`mxfs_buf_write_fua()` — REGRESSED to 46 fails +
3-4 node shutdowns: **never raw-FUA-write a shared metadata buffer out-of-band**;
it bypasses CRC/verifier and races xfsaild's own iflush of the same LBA). Two
bugs had OPPOSITE latency sensitivity (double-alloc→shutdown got BETTER when
slower; empty-content got WORSE when slower) so no single global flush/slow lever
fixes both. **Biggest sess39 finding:** `xfs_repair -n` at the envelope offset
(byte 88 → 196688 sectors / 100704256 bytes) proved the "double-alloc" is NOT
on-disk (Phase 4 clean) — it is an **in-memory stale dir-inode extent map
(`ip->i_df`)** pointing at a block since freed and reused as an inode cluster
(magic "IN", err74 EFSBADCRC) → the whole on-disk bnobt/AG-free-space-coherence
line was chasing a phantom; root is inode/block-REUSE i_df coherence.

### sess103 (head build `C0BB2B4F`) — three proven KEEP fixes
- **FIX A — reload-size-drop needs a GENERATION check** (`xfs_mxfs_dlm.c ~2323`):
  generalizes sess39/45 size-drop-skip. Under inode-number REUSE the old skip
  kept a STALE prior incarnation → unlink/inactivate the ghost → bnobt
  double-free (`xfs_alloc.c:2244`) / AGI corruption. Fix: gate skip on
  `di_gen == VFS_I(ip)->i_generation`; gen differs ⇒ **adopt** the peer's
  incarnation (fall through). Probe `P103-RELOAD-REUSE-ADOPT`, proven via
  ino=6291588.
- **FIX B — RESTORE the `!in_ail` exclusion** (`~4242`, `mxfs_ag_meta_invalidate_stale`
  discard branch; REVERTS a sess102 change). A committed-not-written-back buffer
  is `!dirty && in_ail`; discarding it loses this-node-ahead work. Proven chain:
  P82-ADD → P102-INVAL-INAIL-DISCARD (AGI daddr=2) → P71 head=NULLAGINO →
  `xfs_iunlink_remove_inode:632` shutdown. Restoring `!in_ail` eliminated P71
  sig-3.
- **FIX C — MODIFY-path acquire-side dir cold-read**: new
  `mxfs_dlm_dir_modify_refresh()` (no-relock sibling of
  `mxfs_dlm_dir_consumer_refresh`, caller holds ILOCK_EXCL), wired into
  `xfs_remove`. sess97 added the dir cold-read only to the READ path
  (`xfs_lookup`); MODIFY paths RMW'd the shared dir block from a STALE cached
  base across a DLM tenure boundary → resurrected a peer's already-deleted
  dirents = all-nodes-agree durable lost-update (all 4 saw the SAME 35 leftover
  files; remount→EFSCORRUPTED). Fix = gen-keyed evict of clean cached dir blocks
  before the RMW. `unlink_visibility` PASSES in ISOLATION. Probe
  `P103-MODIFY-REFRESH`. **TODO (carried): wire `mxfs_dlm_dir_modify_refresh`
  into `xfs_rename` and `xfs_create` too — only `xfs_remove` was done.**

sess103 standing: `passed=2 failed=2` — cross_visibility PASS,
rename_visibility PASS, unlink_visibility FAIL (node1, cumulative only — passes
alone; sess86 cumulative-fragility), cross_write_read FAIL (node4, SESS50-STARVE
writer-starvation rc=-110). A `xfs_buf.c:1701 xfs_buf_submit` shutdown appeared
in the full run (suspected cross-sub-test state carryover). Refuted:
P103-FUA-DIVERGE 0× (inactivation-guard read is NOT stale-platter).

### sess105 (build `3911B884`, probes only) — the CREATE-phase reframe
Proved (P-DIRWR per-dir-block write trace) the loser NEVER writes the live
shared dir block during create/rename (only at teardown `rm`); its 20
before-files are absent cluster-wide; `mv: cannot stat` confirms they were never
visible. Gemini's multi-block-overflow theory REFUTED (dir stayed nextents=1,
size=4096). Root hypothesis: concurrent-mkdir / stale-dentry directory-inode
DIVERGENCE — d_revalidate is DISABLED (per CLAUDE.md) so stale dentries aren't
rechecked after a peer's rmdir+mkdir of the same name. Added probe
`P105-CREATE-PARENT` (logs `dp=<parent ino> name=<child>`) to compare the
parent ino across nodes. Confirmed sound: `reload_inode` (`~2282`) rebuilds
i_df + i_disk_size but reads the on-disk home block (stale if peer's change only
logged); slow-path EX acquire evicts all dir data-fork blocks + publish-before-
notify flushes them — so per-block coherence is NOT the hole; divergence is at
directory-entry/inode-IDENTITY level.

### sess106 (builds `07665752`→`6BBE18ED`→`44EF4535`, probes; KEEP src)
Confirmed the divergence (P106-MKDIR + P106-EXGRANT/EXREL merged timeline, see
mechanism above). Ruled out (dmesg of failing run): reclaim, heartbeat-expiry,
epoch-change, GRANT-WAIT-TIMEOUT, caw exclusion-violation. Introduced the
targeted primitive: `mxfs_v5_dlm_inode_held(ctx, ino)` (mirror of
`mxfs_v5_dlm_ag_held`, builds `MXFS_LTYPE_INODE` resource_id, calls
`caw_held` at `dlm_caw.c:1857`) — verify on-disk ownership on the dir-EX
fast-path cache-hit; if 0 → fall through to slow-path re-acquire. Gemini design
(RULE 5): jiffies-bound (~1s) in-memory lease so only ~1 cheap slot read/sec/
inode, not per-op. Separate OPEN bug noted: AGI/iunlink corruption shutdown on
`rm -rf` (`xfs_iunlink+0x283`).

### sess107 (build `B64499C5` probe → `0DB3BA32` FIX, deployed)
STEP 1 (probe `B64499C5`): `mxfs_v5_dlm_inode_held` at dir-EX fast-path logged
`P106-STALE-EX on_disk_held=0 cached_mode=EX` repeatedly — confirms in-memory
EX w/o on-disk slot (also fires for legit brand-new unpublished inodes = same
mechanism, not a separate bug). STEP 2 FIX (`0DB3BA32`, Gemini design D=A+B,
implemented backstop B only) — KEEP, partial win:
- `xfs_mxfs_dlm.c ~3286` fall-through: a dir at `pin_count==0` now falls to slow
  path when `state!=CACHED` OR `(i_dlm_unpublished && mode==EX)` → forces a real
  on-disk EX acquire before modifying an unpublished dir.
- Slow-path acquire (~3600): if `i_dlm_unpublished`, `mxfs_dlm_unpublish_drop(ip)`
  + `P107-PUBLISH` log, then ALWAYS do the real acquire. Safe: caw_lock
  "already held" (`dlm_caw.c:1413`) self-heals, not a shutdown.
Result: **corruption shutdowns ELIMINATED** (no inobt-AG4, no defer_finish, no
"Shutting down" — the broken mutual exclusion was the corruption driver).
P107-PUBLISH fired 1-4×/node. RESIDUAL: P106-STALE-EX still fires 29× on test1
only (0 elsewhere) — NOT covered by the pin==0/mode==EX gate. Next hypotheses:
(a) unpublished inodes hit at pin>0 or mode==PR; (b) a real release path leaving
mode stale; (c) node-role asymmetry. Gemini Part A (proactive post-commit
publish in create/mkdir/symlink/mknod) still TODO to close the
background-AIL/reclaim hole.

### sess108 (NEWARCH Phase 0+1) — chokepoint + publish-on-create LANDED
Head build `F591E7A5D1CF12192F0B0B4` (rebuild via `make clean && make modules &&
make tools`). Two load-bearing changes ([[sess108_lessons]]):

**Publish-on-create (Phase 1.4, KEEP, = Gemini Part A):**
`mxfs_dlm_publish_inode(struct xfs_inode *ip)` (`xfs/xfs_mxfs_dlm.{c,h}`), called
in `xfs_create` (`xfs/xfs_inode.c`) after `xfs_trans_commit` +
`mxfs_dlm_dir_durable_signal(dp)` and BEFORE `*ipp = du.ip` / the iunlocks.
Synchronously promotes the new inode to a real on-disk EX CAW slot, so peers
reaching it via a cached parent dirent find a real slot to BAST. Closes the
deferred-publish hazard AT create time. Probes `P109-PUBLISH-OK` (instr-gated),
`P109-PUBLISH-FAIL` (always-on warn). Result: P107-PUBLISH=0 (eager),
P106-STALE-EX=0 in every chokepoint run — **the stale-cached-EX class is CLOSED.**

**Chokepoint (Phase 1.3 proper, Gemini codebase-aware design, RULE 5, KEEP):**
the local "fence the slow-path entry" attempts each collided with a
bast_notify/bast_process assumption (Phase 1.3 v1 NL-clobber → all 4 shutdown;
v2 state=DEMOTING dropped peer BASTs → caw_lock timeout; v3 state=UPGRADING →
SESS50-STARVE on ino=128). Gemini's design:
1. `mxfs_dlm_caw_lock` UPGRADE-DDL removed: when `our_mode != NL` and compat
   fails, return **-EDEADLK** instead of clearing our bit and becoming a waiter;
   caw_lock now upgrades-in-place atomically OR acquires from NL (no silent
   demote). Probe `P109-CAW-EDEADLK`.
2. New state `MXFS_DLM_ISTATE_ACQUIRING` (`xfs_inode.h` #define 4): set in the
   upper-layer slow path before dropping `i_dlm_lock` to call caw_lock, cleared
   on return; blocks concurrent same-node fast-path acquires.
3. Upper-layer -EDEADLK handler (`mxfs_dlm_ilock_begin`): state→BAST,
   `schedule_work(&ip->i_dlm_bast_work)`, wake_up_all, then **recursively
   re-enter** `mxfs_dlm_ilock_begin(ip, mode)` → blocks until bast_process
   drains+unlocks+sets state=NONE, then a fresh slow path acquires from NL
   (cannot hit -EDEADLK). Probe `P109-EDEADLK`.
4. `bast_notify` ACQUIRING branch: set `i_dlm_stale=true`, do NOT queue
   bast_process (queuing strips the on-disk slot out from under caw_lock's poll
   loop — the v3 failure shape).
5. Slow-path wait loop extended to wait on DEMOTING || ACQUIRING || BAST.
6. Post-acquire publish: ACQUIRING→CACHED, or ACQUIRING→BAST + schedule
   bast_work if `i_dlm_stale` was set during the acquire.

Results (build `F591E7A5`): 20-file 4-node concurrent rename repro **13s,
TOTAL_FAILS=0 on all 4**; 100-file stress 35s, 20 consistent fails/node (5%,
consistent across nodes = REAL durable lost writes, NOT stale-read), NO
shutdowns, P109-EDEADLK 5-17×/node, P106-STALE-EX=0; cache_coherency 4-node
**cross_visibility PASSED 4/4**; test_rename_visibility WEDGED → 900s SIGKILL.

**The remaining wedge (handoff):** test1 `rm` on ino=4194433 → caw_lock
-EDEADLK → chokepoint scheduled bast_work → bast_process's AG-AIL push wedged at
`iter=75520` (75K no-progress) on `stuck_ino=4194433, iflags=0x0 buf_locked=0`
(clean inode, no locked buffer the existing P67-INSTR AG-AIL-STALL code can't
push). `rm` hung in `mxfs_dlm_ilock_begin+0x279 → schedule` 900+s. This is a
**pre-existing AG-AIL push bug** (sess67's P67-INSTR named the path; sess20+
wrote the drain code). The chokepoint hits it reliably because EVERY -EDEADLK now
routes through bast_process, correctly demanding NEWARCH §4 invariant #1 ("no
on-disk unlock without completed drain") that the drain code can't yet deliver —
the old silent UPGRADE-DDL sidestepped the AIL push entirely.

## Phase 1.5+ next steps (from sess108)
1. Fix the AG-AIL push wedge on `iflags=0x0 buf_locked=0` inodes
   (`mxfs_dir_push_data_ags` / `xfs_mxfs_dlm.c` drain must handle clean-but-
   stuck-AIL). This should land the chokepoint cleanly.
2. Add Gemini's permanent-divergence assertions:
   `WARN_ON_ONCE(!(slot.holders & ctx->node_bit))` pre-CAS in
   `mxfs_dlm_caw_unlock`, and `WARN_ON_ONCE(i_dlm_mode==0 && i_dlm_state !=
   ACQUIRING)` in `mxfs_dlm_bast_notify` — fire the moment in-core and on-disk
   diverge, zero extra I/O.
3. Wire `mxfs_dlm_dir_modify_refresh` into `xfs_rename` + `xfs_create` (sess103
   TODO still open).
4. Re-run Phase 0 `force_coherent` gate with chokepoint engaged; if 4/4 →
   multinode metadata fio bench vs GFS2/OCFS2. Phase 2 (TCP invalidation mesh)
   unblocks after (1).

## Methodology / infra invariants (recurring)
- **instr=0 for correctness AND timing.** `instr=1` per-op printk = ~100× slow,
  acts as a serializer that HIDES races (sess38's false "1/16"; sess39). Use
  `tests/repro_rename_concurrent.sh` (10s inner loop); reserve the 900s
  `cache_coherency.sh` for end-of-cycle gate. Any test >60s where it should be
  seconds IS a failure regardless of eventual PASS.
- **Verify a CLEAN loss, not a shutdown cascade:** `grep -c "not mounted"` must
  be 0 — once a node shuts the FS, later runs falsely "fail" on not-mounted.
- **`reset4.sh` re-mkfs+mounts but does NOT reboot → dmesg PERSISTS.** ALWAYS
  `dmesg -C` per node right after reset and before each run, or stale "Shutting
  down" reads as a false fresh shutdown. `bash tests/reset4.sh 4` (not
  `./tests/reset4.sh` — exec bit drops on NFS).
- **ALWAYS `strings mxfs.ko | grep <probe>` after build** — incremental builds
  leave stale objects (sess105 `3911B884` shipped with `P105-CREATE-PARENT`
  never compiled; sess106 same for `xfs_inode.c`). `make clean && make modules
  && make tools` when changes span .c+.h.
- **`tools/mxfs_sshpass.sh <host> <PASSFILE=/tmp/.mxfs_pass> <cmd>` — THREE
  args**; a 2-arg call HANGS on a password prompt (looks like all nodes wedged;
  they're fine). Full clean cycle: `virsh -c qemu:///system destroy+start` all 4
  → wait ssh → `reset4.sh 4` → `dmesg -C` per node → run.
- Run-to-run variance is huge (sess39 rename fails swung 2..42/240 on the SAME
  build) — use `tests/measure_rename.sh` (≥3 runs); single-run A/B is unreliable.
- Non-perturbing on-disk audit: `umount`; `losetup -fP -o 100704256 /dev/sda`;
  `xfs_repair -n <loopdev>` (envelope offset = byte 88 of on-disk super =
  196688 sectors / 100704256 bytes). Instrumentation that adds I/O to the
  alloc/acquire path perturbs the (former, now-refuted) double-alloc Heisenbug
  away.
