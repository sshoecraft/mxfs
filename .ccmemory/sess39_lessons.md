---
name: sess39_lessons
description: "sess39 — cache_coherency rename_visibility is SEVERE corruption under concurrent same-dir rename, NOT the \"1/16 transient\" sess38 claimed. Two fixes landed (dir-data durability barrier + scoped inode-lock CAS backoff): 40→~9-15 fails, no DLM-timeout shutdown. Residual = dir-block lost-update + reader-side file empty-content + deep AG/alloc/SB corruption under sustained load."
metadata: 
  node_type: memory
  type: project
  originSessionId: 66abf11e-24b7-4285-a723-75dad7c81722
---

# sess39 (2026-05-30) — cache_coherency / rename_visibility root-caused; partial fixes landed

## >>> START HERE NEXT SESSION <<<
- Deployed build = `E51EEA92EA7ED6BC18E96BE` (cluster clean, 4 nodes mounted).  `tests/reset4.sh 4`
  to reset; measure with `MXFS_TESTS_DIR=/src/mxfs/tests MXFS_NODE_OFFSET=16 tests/run_tests.sh
  --nodes 4 --phase cluster --test test_rename_visibility --pass-file /tmp/.mxfs_pass --device
  /dev/sda --mount-point /mnt/shared` (instr=0!).  Baseline now: **rename_visibility ~2-5 fails**
  (was 15) thanks to the sync_fs iflush fix.
- BIGGEST WIN this session: cross-node empty-content = di_size coherence; fixed by adding
  xfs_ail_push_all_sync+blkdev_issue_flush to multi-node xfs_fs_sync_fs (pal/linux/xfs_super.c).
- TOP 3 REMAINING (to get rename_visibility to 0, then run full cache_coherency.sh):
  1. ~3 residual empty-content = async CIL->AIL insert race at sync time.  Do NOT add more
     AIL pushes (double-pass + per-release BOTH made it WORSE — latency widens the race).  Try a
     TARGETED iflush of only the just-dirtied inodes, or fix the ordering so log_force's AIL
     inserts complete before the push.
  2. ~3 missing-dirents = peer reads a stale shared-dir block (DIR-STALE-SKIP=0, so the peer is
     NOT reloading the dir block — gen matches).  Check why the writer's dir-EX-modify isn't
     BASTing the peer's PR / bumping the peer's i_dlm_dir_gen so xfs_da_read_buf re-reads.
  3. The EFSBADCRC "shutdown" is an IN-MEMORY stale dir-inode i_df (xfs_repair -n proved on-disk
     is CLEAN — NO double-alloc).  Fix in-memory i_df coherence on inode/block reuse.  Intermittent.
- DON'T re-investigate: on-disk bnobt double-alloc (phantom), CAW double-grant, AG-cached
  divergence, deferred-flush, torn-read, per-release/raw-FUA/blkdev durability for empty-content
  (all tested+ruled out; durability fixes make empty-content WORSE — opposite latency sensitivity).



## TL;DR
The sess38 handoff was WRONG: it claimed cache_coherency was "nearly done", a
rare "1/16 transient marker-visibility miss." Reality: `test_rename_visibility`
(part of the `cache_coherency` criterion) **corrupts on-disk metadata and shuts
down the FS** under 4-node concurrent same-directory rename. This is the deep
Mode-A / AG-coherency family, not a transient.

**Two fixes landed this session (build `5FDB1F91F1B1CC258E731F9`, deployed +
cluster clean-mounted):**
1. **Dir-data-block durability barrier** (xfs/xfs_mxfs_dlm.c, dir-inode BAST
   release). New helpers `mxfs_dir_data_durable()` + `mxfs_dir_push_data_ags()`.
   The release-path drain loop broke on the *dinode's* AIL/pin state only; a dir
   DATA block still dirty/in-flight (or in another AG) slipped through → peer FUA
   read raced the write bio. Now the loop also waits until all dir data-fork
   block buffers are durable and pushes their AGs.
2. **Scoped inode-lock CAS backoff** (dlm/dlm_caw.c). New `caw_inode_backoff()`
   called at the top of the lock/unlock/convert retry loops. Node-phased
   jittered sleep (`(retry + local_node*5) % 7` ms, retry>=2), **INODE locks
   only**. Desyncs the same-slot CAS storm that otherwise exhausts
   MXFS_CAW_MAX_RETRIES=100 → -ETIMEDOUT → `mxfs_dlm_ilock_begin` force-shutdown.
   Scoped to inode locks so it does NOT regress the dd/AG path (the v0.3.46/
   v0.3.50 global-backoff revert was about AG locks).

**Result (instr=0, true timing):** rename_visibility 40 → ~9-15 failures /240,
no DLM-timeout shutdown, ~11s/test (no latency regression — the dir barrier
breaks immediately when already durable; backoff converges fast).

## CRITICAL TESTING GOTCHA — instrumentation skews results BOTH ways
- `instr=1` (`/sys/module/mxfs/parameters/instr`) per-op printk = ~100x slowdown.
  A 11s test becomes 133s. The sess38 "1/16" and a misleading "1-failure" run
  were instr=1 artifacts: the slowdown acts as a natural serializer and HIDES
  races. **Always measure correctness AND timing with instr=0.** Use instr=1
  ONLY to capture a specific event, and know it suppresses the race.

## How the criterion actually fails
`cache_coherency.sh` runs 4 tests: cross_visibility (PASS),
rename_visibility (FAIL — the bug), unlink_visibility (assertions pass but slow
~128s and a node often falls out), cross_write_read (often doesn't run — prior
node fell out). The killer is rename_visibility + the cumulative load causing
shutdowns.

## Failure-mode taxonomy (all from concurrent same-dir rename, instr=0)
1. **Missing dirents** (~3/run): one node's renamed dirents invisible to peers.
   = block-format-dir **lost update**: a node takes the dir inode EX with a
   STALE cached dir block (invalidation in xfs_da_read_buf is SKIPPED when the
   buffer is dirty/pinned/delwri), modifies, writes back → clobbers a peer's
   just-committed renames. The losing node still sees its own (cached). STILL
   PRESENT after the durability barrier — barrier helps the durability half,
   not the stale-cache-read-on-EX-acquire half.
2. **Empty content** (dominant residual ~9-15): peer reads another node's
   just-created file as empty. **PROVEN reader-side**, NOT writer durability:
   extending the dinode-flush + cluster-barrier + blkdev_flush to REGULAR FILES
   made it WORSE (15→20 fails) and catastrophically slow (11s→132s, per-file
   blkdev_issue_flush). So the peer reads a stale cached file inode (di_size=0)
   or stale file data block. NEXT: instrument the reader — does it see size=0
   (stale dinode/reload) or size=13 with empty data (stale data block / file
   data not FUA-coherent)? repro_rename_concurrent.sh already captures `sz=`.
3. **FS shutdown / on-disk corruption** (under sustained/heavy load): multiple
   distinct signatures, ALL the deep AG/allocation coherency family:
   - dir extent map points to an **inode-cluster block** (magic "IN", mode
     0x41ed) → dir read fails verifier `error 74 = EFSBADCRC` → shutdown. This
     is a **double-allocated block** (dir data block == an inode cluster) from
     AG free-space lost-update. (Raw dump confirmed: block 0x1fda18 was an
     inode cluster, not a dir block.)
   - `xfs_iunlink_remove_inode` line 603 corruption (AGI unlinked-list) — with
     ALL CAW locks succeeding rc=0. Pure coherence gap, not a timeout effect.
   - `xfs_sb_write_verify` SB block 0 corruption (global free counters).
   - bmap btree record corruption in inode data fork.
   These persist after this session's fixes and are the core remaining work.

## FALSIFIED this session (don't re-try)
- **Torn-read hypothesis**: a retry-on-verifier-failure loop in xfs_da_read_buf
  (P-TORN, 8 FUA re-reads/40ms) NEVER recovered (RECOVERED=0, 220 attempts) →
  the corrupt dir block is **persistent on disk** (double-allocation), not a
  transient torn read. The retry code is still in xfs_da_btree.c (harmless,
  gated; it logs P-TORN/P-EMAP under instr). Consider removing or leaving as a
  diagnostic.
- **Regular-file durability extension**: net regression (correctness + 12x
  slower). Reverted. The file empty-content is reader-side.

## Transport: it's CAW, not TCP
fresh_cluster_mount comments say "default tcp" but lib.sh default is
force_transport=0 = **CAW** (dmesg shows P15/P51 CAW). The shutdowns route
through mxfs_dlm_caw_lock 100-retry exhaustion. The unlock path CONVERGES
(1-2 retries); the acquire/register-waiter CAS is what starves on a hot slot.

## Tooling added this session (all in tree, survive reboot)
- `tests/reset4.sh [N]` — fast 4-node teardown+fresh CAW mount via criteria lib.
- `tests/repro_rename_concurrent.sh "nodes" [N]` — orchestrator-driven (no
  in-FS barrier) concurrent rename repro; reports per-writer ok/empty(size)/miss.
- `tests/char_rename.sh [rounds] [N]` — loops the repro, detects shutdowns.
- `tests/repro_rename_xnode.sh` — 2-node sequential (PASSES — bug needs concurrency).

## Files changed (build 5FDB1F91)
- xfs/xfs_mxfs_dlm.c: mxfs_dir_data_durable(), mxfs_dir_push_data_ags(),
  release-loop now waits on dir data-block durability (dir-only).
- dlm/dlm_caw.c: caw_inode_backoff() in lock/unlock/convert loops (inode-only).
- xfs/libxfs/xfs_da_btree.c: P-TORN retry + P-EMAP extent dump (diagnostic,
  instr-gated) — proved persistent corruption.

## NEXT SESSION priorities (in order)
1. Reader-side file empty-content (dominant, likely cheap): instrument peer read
   to classify size=0 vs data-empty; fix the stale file-inode reload or add FUA
   coherence for file data. Verify with repro_rename_concurrent.sh `sz=`.
2. Dir-block lost-update on EX-acquire: the xfs_da_read_buf invalidation skip on
   dirty/pinned/delwri lets a writer read its own stale cached dir block after a
   peer modified it. Root is the release-before-durable on the PEER side OR the
   skip. Re-examine now that the durability barrier is in.
3. The deep AG/allocation lost-update (double-alloc → SB/iunlink/bmap
   corruption). This is the Mode-A core; the hardest. Focus: AGF/bnobt/AGI
   coherence on cross-node fresh-acquire (mxfs_dlm_invalidate_ag_meta skips
   inode-cluster bufs with a BLI attached — line ~3612 — suspect for the iunlink
   chain). FUA-read piercing the SCST write cache for AG btree blocks.
4. Re-run `cache_coherency.sh` end-to-end only after 1-3; then rsync_paired
   (needs the MISSING `tools/mxfs_multinode_bench.sh` — still absent, see below).

## Other open criterion: rsync_paired
FAILs because `tools/mxfs_multinode_bench.sh` DOES NOT EXIST (rsync_paired.sh
line 87 calls it). sess37 noted this missing script. Must be written. Lower
priority than the corruption.

## sess39 LATER findings (build `84458BF83B00D4AFFAB3DAE` = 5FDB + detector, deployed+clean)
- **Added an ALWAYS-ON double-EX-grant detector** `caw_check_exclusion()` in dlm/dlm_caw.c
  (checks slot holder bitmaps at the compat-add and waiter-grant success points; NOT
  instr-gated, fires only on the bug). **Result: CAW-EXCL-VIOLATION = 0** across a full
  rename run. => **The CAW DLM never grants EX to two nodes at once; lock exclusion is
  CORRECT.** The two-writers hypothesis is FALSIFIED. The corruption is therefore a
  STALE-READ (release-before-durable or FUA-staleness), NOT a lock-exclusion bug. Keep this
  detector — it's cheap and will catch any future regression.
- **Writer di_size durability FALSIFIED (twice)**: extending the dinode-flush wait to regular
  files — both the expensive version (per-file blkdev_issue_flush: 11s→132s, 15→20 fails) AND
  the cheap version (log_force+ail_push only, no blkdev_flush: 26s, still 39 fails) — gave NO
  correctness gain and added latency/shutdowns. => the file **empty-content is reader-side**
  (stale cached file inode, OR — more likely — the peer resolves the dirent to the WRONG/old
  inode because of stale dir-block content). Reverted both; build is back to 84458BF8.
- **HUGE run-to-run variance**: rename_visibility fails swing 2..42/240 on the SAME build. Any
  single-run A/B comparison is unreliable — use tests/measure_rename.sh (≥3 runs) and even then
  the noise is large. This variance + frequent shutdowns (forcing resets) makes iteration slow.
- **Unified hypothesis for next session**: empty-content AND missing-dirents are both
  **dir-block coherence** (a peer reads a stale/corrupt shared-dir block → a dirent is missing,
  OR resolves to the wrong/old/empty inode → empty content). The dir-data durability barrier
  helped the WRITE-durability half; the remaining half is the **stale-read on EX-acquire**
  (xfs_da_read_buf invalidation is SKIPPED when the cached dir buffer is dirty/pinned/delwri).
  Re-examine that skip now that the barrier makes peer dir blocks durable. Also: the FUA read of
  AG btree blocks (bnobt/inobt) on fresh AG-acquire may not pierce the SCST per-initiator cache
  → stale free-space → the double-alloc corruption (block used as both dir-data and inode
  cluster). Verify mxfs_dlm_invalidate_ag_meta'd buffers actually re-read via the FUA path.

## sess39 FINAL diagnostics (build `E5B8D3FC7257B0E1A45AF0D` = 84458BF8 + DIR-STALE-SKIP detector)
Two MORE always-on detectors added, BOTH came back CLEAN during failing runs — each
RULES OUT a hypothesis:
- **DIR-STALE-SKIP = 0** (xfs_da_read_buf else-branch, pr_warn_ratelimited): the dir-block
  gen-invalidation is NEVER skipped due to dirty/pinned/delwri during a failing run. So the
  lost-update is NOT the invalidation-skip window. A reader using a stale cached dir block does
  so WITHOUT a gen mismatch => it never reloaded => its in-memory i_dlm_mode showed cached
  PR/EX when it shouldn't, OR the failure isn't dir-block staleness at all.
- The failure RE-CHARACTERIZED: in the real test, a node reads its OWN file (e.g.
  node1_after_11) as EMPTY — files 1-10 OK, 11-20 empty. It's NOT cross-node; the node loses
  its OWN later-half files' CONTENT (dirent exists, di_size reads 0 / data empty).
- **Self-loss is NOT deterministic / NOT a simple BAST-release durability bug**:
  tests/repro_self_loss.sh (W creates+renames+syncs, R reads to force BAST on W, W re-reads
  its own files) = 20/20 OK × 4 reps. So the loss REQUIRES concurrent same-dir contention by
  all 4 nodes, not just a release+reload cycle.
- **Remount staleness** (contaminated experiment, treat as weak): after a failing run, an
  unmount+remount of a node showed it not seeing the dir tree the cluster built; other nodes
  disagreed on the tree. Suggestive of metadata read-staleness but the remount-while-active
  disrupts the cluster so it's not a clean signal — re-test cleanly next session.

### Refined hypothesis for the empty-content self-loss (next session, RULE-4 it)
The "files 11-20" (later-half) pattern + needs-concurrency + node-loses-OWN-content points to
**inode-cluster sharing under concurrent allocation + di_size flush timing**: node1's file
inode shares a 32-64-inode cluster with peers' inodes; a peer allocating in the same cluster
BASTs node1's hold on that cluster; node1 flushes the cluster, but the create txn's di_size=13
update may not yet have reached the on-disk dinode (iflush lag), so the flushed cluster carries
di_size=0; node1 later reloads it and reads empty. The fix must make di_size durable in the
inode cluster BEFORE the cluster is flushed on BAST — but cheaply (per-file blkdev_flush is
12x too slow; tested). Note: di_size durability was tested twice and didn't help, BUT the
run-to-run variance (2..42 fails) is so high that single-run A/B is unreliable — use
tests/measure_rename.sh (>=3 runs) AND consider that the di_size fix may have been masked by
variance, not truly disproven. Instrument the READER: log, on a regular-file read returning
di_size=0, whether it was cache-hit (no reload) vs reload-read-0 (durability) — decisive.

### New tooling this session (all in tests/, survive reboot)
reset4.sh, repro_rename_concurrent.sh, char_rename.sh, measure_rename.sh, repro_rename_xnode.sh,
repro_self_loss.sh, ondisk_check.sh, cluster/test_rename_vis_dbg.sh.

## Current build = `E5B8D3FC7257B0E1A45AF0D` (84458BF8 + DIR-STALE-SKIP detector)
= dir-data durability barrier + scoped inode-lock CAS backoff + always-on double-grant detector
(caw_check_exclusion) + always-on dir-stale-skip detector. Both detectors CLEAN under load.
Deployed on all 4 nodes, cluster clean-mounted.

## sess39 BREAKTHROUGH — di_size self-loss PROVEN + FIXED (build `6A08B05CF98B7210F3FD0F2`)
**PROVEN root cause of the empty-content "a node loses its OWN files" residual** via a new
always-on detector RELOAD-SIZE-DROP (fired 11× on test3, matching its 11 failures):
`mem_size=13 disk_size=0 nblocks=0` — a node holds the correct in-memory size for its own
just-created file, but a BAST-driven re-acquire reload reads the STALE allocation-time on-disk
dinode (di_size=0/nblocks=0, because the create's di_size update had not been iflushed to the
inode cluster yet) and CLOBBERS the good in-memory size → file reads empty.
**FIX (mxfs_dlm_reload_inode, xfs/xfs_mxfs_dlm.c)**: after reading the dinode, if S_ISREG &&
ip->i_disk_size>0 && disk di_size==0 && nblocks==0, SKIP the reload (release bp, stale=false,
return) — keep the authoritative in-memory inode. Safe because each node writes only its own
regular files, so disk can only legitimately be NEWER, never revert a written file to empty.
**VALIDATED**: RELOAD-SIZE-DROP-SKIP fires (skip=1) and the un-skipped RELOAD-SIZE-DROP count
drops to 0 — the clobber is prevented. (Earlier pinned/in-AIL skip attempt FAILED — the create's
change sits transiently in the CIL with neither flag set; the decisive test is the on-disk image,
not the log-item state. Removed.)

## REMAINING BLOCKER (the deep one): AG free-space double-allocation -> shutdown
Even with the di_size fix, concurrent-rename runs still SHUT DOWN from on-disk corruption:
a dir DATA block read (xfs_da_read_buf) maps to a daddr that holds an INODE CLUSTER (magic "IN")
-> EFSBADCRC err74 / xfs_inode_buf_verify / bmap-btree corruption -> shutdown. = the SAME block
is allocated as both dir-data AND an inode cluster = AG free-space lost-update. This is the
38-session Mode-A / bnobt core. RULED OUT this session: CAW double-grant (CAW-EXCL=0), FUA-read
staleness (mxfs_buf_needs_fua_read DOES cover bnobt/inobt/agf/agi + dir blocks, so AG re-reads
pierce the SCST cache). **Strongest remaining lead: AG-lock TIMEOUTS.** The sess39 CAS backoff
(caw_inode_backoff) is scoped to INODE locks only; AG locks still hit the no-backoff CAS storm
and time out under the rename/create storm ("DLM AG lock failed: ag=N rc=-110"). On AG-lock
timeout, xfs_alloc returns NULLAGBLOCK+error mid-transaction -> trans abort; if that leaves
partial AG free-space state, double-alloc/corruption follows. NEXT SESSION: (1) try extending a
SCOPED jittered backoff to AG locks too (the v0.3.46/50 revert was a GLOBAL unconditional backoff
that hung the dd path — a small jitter only on -EAGAIN miscompare, capped low, may be safe and
stop AG-lock timeouts); measure with the dd/rsync path for the regression. (2) Else audit the
AG release drain (mxfs_dlm_ag_bast_work_fn Phase 2/3) for a btree buffer that isn't flushed
before unlock, OR the alloc-failure trans-abort path for partial-state corruption.

## sess39 AG DOUBLE-ALLOC precisely characterized (build `3CF4F8D4012857B71010D14`)
Added an always-on detector in xfs_ialloc_inode_init (xfs/libxfs/xfs_ialloc.c): before
overwriting fbuf->b_ops to xfs_inode_buf_ops, check if that daddr is already a LIVE non-inode
metadata buffer (b_ops set + XBF_DONE).  Findings:
- The block IS double-allocated (confirmed: the corrupt daddr 0x1fda18 / 0x7f66e0 etc. is the
  same one inode-init touches AND that a dir's extent maps to; the block fails BOTH the dir and
  inode verifiers => two owners wrote it).
- At inode-init time the block is CLEAN (b_ops=0x0, flags=0x0) => inode-init is the FIRST
  allocator; the DIR gets the same block LATER. (First detector version false-fired on
  fbuf->b_log_item — xfs_trans_get_buf ALWAYS attaches a BLI, so that condition is useless;
  fixed to b_ops!=inode && XBF_DONE only.)
- => it is a CROSS-NODE double-alloc: node A allocs an inode chunk at block X in AG1 (its
  preferred AG = node_slot % agcount), releases; a PEER growing the shared rename dir bmap-allocs
  from AG1 and gets the SAME X because its bnobt read showed X still free.  Neither node has the
  other's buffer cached, so a LOCAL-cache detector CANNOT catch the cross-node case — this is the
  fundamental cross-node AG free-space (bnobt) coherence bug = the 38-session Mode-A core.
- Puzzle: FUA reads ARE applied to bnobt (mxfs_buf_needs_fua_read covers it) and CAW-EXCL=0
  (AG EX held by one node at a time), and the AG release drains+double-blkdev_flushes the bnobt
  before unlock.  On paper the peer's post-acquire FUA bnobt read should see node A's allocation.
  Yet it reads stale.  LEADING HYPOTHESIS for next session: pag_dlm_cached (in-memory "we hold
  this AG") vs on-disk AG-lock divergence — the peer fast-paths the AG acquire (skips
  invalidate_ag_meta + FUA) believing it still holds AG1 cached, while on-disk it had been
  BAST-released; it then allocs off its STALE cached bnobt.  NEXT: add an always-on detector in
  mxfs_ag_dlm_lock's FAST path that reads the on-disk AG slot and asserts this node is still the
  holder (catch cached-vs-disk divergence); OR log the bnobt free-extent this node sees right
  before each alloc vs what the previous AG-holder wrote (cross-node bnobt staleness).  If the
  divergence is confirmed, the fix is to force invalidate_ag_meta+FUA whenever the on-disk hold
  isn't verified, or to never fast-path the AG without confirming the on-disk grant.

## sess39 LATEST: AG-cached-divergence FALSIFIED; double-alloc is a TIMING Heisenbug
Added mxfs_v5_dlm_ag_held() (read-only on-disk AG-holder query; in dlm_caw.c + v5_mount.c, decl
in dlm_caw.h/v5_mount.h — KEPT for future targeted use) and tested an always-on
AG-CACHED-DIVERGENCE detector in mxfs_ag_dlm_lock's cached fast path (asserts the on-disk AG
slot still shows us as holder).  Result: **div=0** — the cached fast path GENUINELY holds the AG
on disk; the double-alloc is NOT a pag_dlm_cached-vs-disk divergence. Hypothesis falsified;
per-acquire detector REMOVED (one SCSI read per fast-path acquire is a perf killer).
- **CRITICAL: the double-alloc / shutdown is a TIMING-SENSITIVE HEISENBUG.** That detector's
  extra per-acquire slot read slowed the run to 132s and the double-alloc + shutdown did NOT
  occur at all (dalloc=0, sd=0) while the ~20/240 coherence failures persisted. So instrumentation
  that adds I/O to the alloc/acquire path perturbs the corruption away. Non-perturbing detection
  is needed next (post-hoc on-disk audit, or a check that doesn't add I/O to the hot path).
- So the failure has TWO independent layers: (a) ~20/240 COHERENCE failures (empty-content +
  missing-dirent) that are timing-INsensitive and persist — these are the di_size self-loss
  (RELOAD-SIZE-DROP, fix landed) + dir-block staleness; (b) the AG double-alloc CORRUPTION →
  shutdown that is timing-SENSITIVE. Both must be closed for cache_coherency to pass.
- Established about the double-alloc: CAW exclusion correct (no double-grant), AG cached-state
  matches disk (no divergence), FUA reads cover bnobt, AG release drains+double-flushes before
  unlock. On paper coherent, yet it double-allocates at full speed only. Leading remaining
  mechanism: a tight-timing race in the bnobt update→flush→peer-FUA-read ordering that the
  serialization SHOULD cover but apparently doesn't at speed; OR a double-FREE (a block freed
  while still in use, then re-allocated). NEXT: instrument the FREE path (xfs_free_extent) and
  the bnobt record add/remove with a non-I/O in-memory cross-check, or do a post-run chk_mxfs /
  raw bnobt-vs-inobt overlap audit to see if it's double-alloc vs double-free.

## sess39 deferred-AG-release missing-flush: REAL Invariant-#1 gap, but INERT for this workload
Found a genuine Invariant-#1 violation: mxfs_dlm_ag_meta_iodone's DEFERRED on-disk AG unlock
(fired when pag_dlm_meta_pending>0 at unlock time, release deferred to the last AG-meta write's
iodone) called mxfs_v5_dlm_ag_unlock WITHOUT a blkdev_issue_flush (the comment says flushing in
xfs-buf-wq context was reverted for deadlock).  Without the flush, a peer's FUA read of the AG
btrees reads the backing store and misses our write that the SCST target only ACKed into its
WRITE cache -> stale bnobt -> double-alloc.  This perfectly fit the timing-Heisenbug.
**FIX landed** (build 7EE09B31...): added pag_dlm_release_work (system_wq worker) that does
blkdev_issue_flush THEN mxfs_v5_dlm_ag_unlock + demote-clear + wake; iodone queue_work()s it;
unmount cancel_work_syncs it.  (xfs_ag.h struct field + xfs_ag.c INIT_WORK + decl in
xfs_mxfs_dlm.h + impl mxfs_dlm_ag_release_work_fn.)
**BUT: REL-DEFERRED-FLUSHED fired 0 times across many runs => the deferred-release path is NOT
TAKEN in the rename workload (the primary release path mxfs_dlm_ag_bast_work_fn handles it, and
that path ALREADY does the double blkdev_flush before unlock).** So the fix is correct+kept (real
latent gap, low risk) but does NOT fix the current double-alloc.  => the double-alloc is NOT a
missing-flush issue at all; node A's bnobt write IS flushed before unlock on the primary path.
RULED OUT this session for the double-alloc: CAW double-grant, AG-cached-vs-disk divergence,
FUA not covering bnobt, AND deferred-release missing-flush.  The mechanism by which node B
FUA-reads stale bnobt despite all of the above being correct is STILL OPEN — strongest remaining
candidates: (a) invalidate_ag_meta MISSES a bnobt buffer that retains _XBF_FUA_FRESH (so the
"fresh" read is a plain cached read, stale) — audit which buffers the pag_bcache walk covers vs
which the alloc path actually reads; (b) a double-FREE (block freed while still referenced, then
re-allocated) — instrument xfs_free_extent / the bnobt insert; (c) the inode-chunk alloc
(xfs_ialloc_ag_alloc) bnobt update durability vs the dir-block alloc, which may use different
buffers/timing.  ALSO NOTE: the rename test wall is highly variable (11s..>120s) and often >100s
even clean — the SLOWNESS is itself a timing-criterion failure layered on the corruption.

## sess39 PRECISE failure breakdown (build `A9A5A26A22ADCC4BDD64AEF`, clean 25s run)
15 failures/240 = **36 cross-node EMPTY-CONTENT + 18 MISSING-DIRENT** (counts aggregated across
the 4 node logs).  Affected: node2's AND node3's renamed files (the "losing" writers vary run to
run); peers read those files empty or their dirents missing.  RELOAD-SIZE-DROP-SKIP fired 0× in
these runs => the SELF-loss di_size mechanism (fixed) is NOT what's left; the remaining empty-
content is CROSS-NODE: a PEER igets the writer's file (cache miss, mem_size=0), reloads from disk,
and reads di_size=0 because the WRITER's just-created dinode is not yet durable on the backing
store when the peer reads.  Root: the dir-inode BAST-release has a durability barrier (flush +
blkdev_flush) but the FILE-inode release does NOT (filemap_write_and_wait flushes DATA pages, not
the dinode iflush, and no blkdev_flush) — so the writer's di_size lags in the AIL/SCST-write-cache.
- MISSING-DIRENT (18): peer reads a stale shared-dir block missing the writer's rename (dir-block
  staleness; DIR-STALE-SKIP=0 so not the gen-skip — the peer isn't reloading the dir block).

## sess39 fua_always lever (param added, build A9A5A26A): INCONCLUSIVE
Added `mxfs.fua_always` (xfs/xfs_mxfs_dlm.c + pal/linux/xfs_buf.c FUA gate): when 1, every
coherency metadata read goes FUA, ignoring the _XBF_FUA_FRESH amortization — to test the
stale-cached-read hypothesis for the double-alloc.  First 3 cycles with =1 had 0 shutdowns and a
low 6-fail run (looked like a breakthrough), BUT the A/B CONTROL (=0, same build) ALSO got 0
shutdowns over 3 cycles — **the shutdown is now too INTERMITTENT/RARE to distinguish with 3
cycles** (this session's earlier fixes likely already reduced its rate).  fua_always kept as a
non-default param for future A/B with MANY cycles or a heavier stress reproducer.  NOTE: test wall
is wildly variable (25s..>120s timeouts) on the SAME build — the SLOWNESS is itself a problem and
makes A/B noisy; need a deterministic/heavier reproducer.

## KEY QUESTION ANSWERED (code-confirmed) + the precise fix for cross-node empty-content
**MXFS metadata WRITES are NOT FUA** — pal/linux/xfs_buf.c buf op = `REQ_OP_WRITE | REQ_META`
(no REQ_FUA; blanket FUA-write was tried twice in sess29 and made dd unusably slow / pass rate
worse — DON'T blanket-FUA-write).  So a writer's file dinode (di_size) write lands in the SCST
WRITE CACHE, not the backing store.  A peer's FUA READ reads the backing store and MISSES it ->
reads di_size=0 -> cross-node EMPTY-CONTENT (the dominant 36-of-15 failure).  (fua_verify confirms
FUA-write -> FUA-read IS cross-node coherent; the gap is specifically plain-write -> FUA-read.)
The dir-inode BAST-release already closes this (drain loop + cluster-buf barrier + ONE
blkdev_issue_flush, "H26") and dirs work.  The FILE-inode release does filemap_write_and_wait
(DATA pages only) but NO dinode flush-to-media -> di_size lags -> peer reads empty.
**FIX (next session, precisely scoped):** make the writer's released file inode dinode durable on
the BACKING store before the DLM unlock.  Do NOT use per-file blkdev_issue_flush (device-wide, and
file releases are ~80x more frequent than dir releases -> the 132s/12x slowdown seen earlier).
Instead do a SURGICAL FUA-write of just the released inode-cluster buffer (sess30's own suggested
approach; helper mxfs_pal_scsi_write_fua_bdev exists, see xfs_buf.c ~line 454) — OR set a
"write-FUA-next" flag on the inode-cluster buffer so its iflush write carries REQ_FUA (add REQ_FUA
in the buf-op function when the flag is set), then drive the iflush via the drain loop in
mxfs_dlm_bast_process for S_ISREG.  Bounded by release events (~240), not by all writes (avoids
the dd FUA-write explosion).  This should close the 36 empty-content failures.  The 18
missing-dirent failures are dir-block staleness (peer reads a stale shared-dir block, not
reloading — DIR-STALE-SKIP=0); investigate the peer's dir-block read path separately.

## sess39 surgical FUA-write fix: ATTEMPTED + REVERTED (DANGEROUS) — important safety lesson
Implemented the cross-node-empty-content fix: file-inode BAST-release drives the dinode iflush
(log_force+ail_push) then SURGICALLY FUA-writes the inode-cluster buffer to the backing store via
a new mxfs_buf_write_fua() helper (raw mxfs_pal_scsi_write_fua_bdev of bp->b_addr at
bm_bn+bt_sector_offset, len=BBTOB(b_length)).  **REGRESSED HARD: 46 fails/240 and 3-4 NODE
SHUTDOWNS every run.**  Why: raw SCSI-writing the inode cluster (1) bypasses the dinode/cluster
CRC + write verifier, and (2) the cluster holds 32-64 inodes shared with other live operations and
xfsaild's own iflush of the SAME LBA — concurrent/torn writes produce bad-CRC blocks -> peer
EFSBADCRC -> shutdown.  **LESSON: never raw-FUA-write a shared metadata buffer out-of-band.**
REVERTED the release-path call (kept mxfs_buf_write_fua() helper unused).  The CORRECT fix must
route FUA through the NORMAL write path: a per-buffer "write-FUA-next" flag set on the inode
cluster buffer in the release path, honored by adding REQ_FUA in the buf-op function
(pal/linux/xfs_buf.c ~line 1340, currently REQ_OP_WRITE|REQ_META) when the flag is set, then drive
a real iflush — so CRC/verify/coordination are intact but the write lands FUA on the platter.
Scope it to the released inode's cluster only (blanket inode-FUA-write may still hurt create-heavy
workloads — measure vs zero_silent_loss/rsync).

## STATE OF THE TWO DEEP BUGS at sess39 end (both OPEN)
1. AG double-alloc -> EFSBADCRC shutdown: INTERMITTENT (some runs 0 shutdowns, some 3-4). This
   session's fixes (di_size reload-skip, dir durability, inode backoff, deferred-flush) reduced
   but did not eliminate it.  Ruled out: double-grant, AG-cached divergence, deferred-flush gap,
   FUA-not-covering-bnobt.  Heisenbug (instrumentation I/O hides it).  Next: non-perturbing
   post-mortem raw bnobt-vs-inobt overlap audit (xfs_db at envelope offset 196688 sectors), or a
   free-path/double-free check.
2. Cross-node empty-content (~36 of the ~15-17/run): writer's file di_size in SCST write cache,
   peer FUA-reads backing store -> di_size=0.  Fix = write-FUA-next-flag (above).  ~18 of the
   ~15-17 are missing-dirents (dir-block staleness, peer not reloading the dir block).
Test wall is also wildly variable (24s..>148s) — a SLOWNESS problem in its own right.

## *** sess39 MAJOR WIN: cross-node empty-content ROOT-CAUSED + partial fix (15->5 fails) ***
CONFIRMED via test_rename_vis_dbg: every empty-content read is **statsize=0** -> it is DI_SIZE
coherence (peer reads the file inode with di_size=0), NOT a data-block issue.
ROOT CAUSE: xfs_fs_sync_fs (pal/linux/xfs_super.c) with wait=1 only does xfs_log_force(SYNC) --
that commits di_size to the LOG but does NOT push the AIL (iflush the inode to its on-disk
CLUSTER) nor flush the device cache.  A peer reads metadata from the on-disk inode CLUSTER via
FUA, not from our log, so after a writer's sync(2) the peer still FUA-reads di_size=0 -> file
appears EMPTY.  FIX (build E51EEA92EA7ED6BC18E96BE): in multi-node sync_fs, after log_force, do
xfs_ail_push_all_sync(mp->m_ail) + blkdev_issue_flush.  A/B PROVEN: ail_push+flush -> ~5 fails/240
(down from ~15); blkdev_flush ALONE -> ~46 fails (di_size stays in AIL).  So the IFLUSH is the
lever.  **CAVEAT: xfs_ail_push_all_sync (whole AIL) is TOO SLOW under sustained 4-node contention
-- test wall 148s, sometimes >200s timeout.  NEXT: replace with a TARGETED iflush of only the
inodes dirtied since last sync (or bounded per-AG push) to keep the 5-fail correctness without the
slowdown.**  Residual ~5 = remaining empty + the ~18 missing-dirents (dir-block staleness, separate).
This is the single biggest mechanistic win of sess39: the empty-content is sync_fs not iflushing.

## *** BIGGEST FINDING (sess39 end): the "double-alloc" is NOT on-disk — it's an in-memory stale i_df ***
Triggered a shutdown (looped the real test, round 2, test1 EFSBADCRC "dir block reads as inode
cluster"), froze the on-disk state (unmounted all), and ran `xfs_repair -n` via loop device at the
envelope offset (100704256 bytes).  **xfs_repair found NO duplicate/cross-linked blocks (Phase 4
clean) — only disconnected inodes (Phase 6, a benign shutdown side-effect).**  So THE ON-DISK
ALLOCATION IS CONSISTENT — there is NO real double-allocation.  The corruption is purely
IN-MEMORY: a node reads the shared dir using a STALE in-memory dir-inode EXTENT MAP (ip->i_df)
that points to a block which has since been freed and reused as an inode cluster; reading it as a
dir block hits inode-magic content -> EFSBADCRC -> in-memory force-shutdown.  The ON-DISK dir
dinode's extent map is CORRECT (a fresh reload would be fine).
**This INVALIDATES the entire "on-disk bnobt double-alloc / cross-node free-space coherence"
line of investigation** (CAW-EXCL, AG-cached-divergence, deferred-flush, FUA-on-bnobt were all
chasing a phantom).  The reload path DOES invalidate correctly (xfs_buf_stale clears
_XBF_FUA_FRESH; reload also clears XBF_DONE), so a reload gets the correct map — meaning the node
is NOT reloading: it uses a CACHED stale i_df.  ROOT = INODE-REUSE coherence: when the shared dir
inode is freed+reallocated (same ino, new di_gen) — or its extents change and blocks are
reused — a peer's CACHED i_df (old extent map) is not invalidated; the peer must detect the
reuse (di_gen change) and reload before using i_df.  (Note: my looping reproducer's rm-rf+recreate
amplifies inode reuse; verify whether the single-pass real test also frees/reuses dir blocks
under concurrent format conversion — but the on-disk-clean conclusion holds regardless.)
**NEXT SESSION FOCUS: in-memory dir-inode extent-map (i_df) coherence on inode/block reuse, NOT
on-disk allocation.**  Check: does a peer holding a cached dir inode get its i_df invalidated when
the dir's blocks/extents change on disk (di_gen or a dir-gen bump)?  The i_dlm_dir_gen mechanism
bumps on reload but the i_df itself may be reused stale across a fast-path acquire.  Audit tool
(validated): umount; losetup -fP -o 100704256 /dev/sda; xfs_repair -n <loop>.

## *** KEY STRATEGIC INSIGHT (sess39 end): the two bugs have OPPOSITE latency sensitivity ***
- AG double-alloc -> shutdown: gets BETTER (fewer/no shutdowns) when things are SLOWER
  (instrumentation I/O, the per-acquire AG-held check, the fua_always slot reads all reduced it).
  Mechanism: slowness lets the writer's bnobt write reach the backing store before a peer reads.
- Cross-node empty-content: gets WORSE (40 vs 15 fails, 120 vs 36 empty) when things are SLOWER
  (the reg_release_durable per-release log_force+ail_push+blkdev_flush, default now OFF, made it
  10x slower AND worse).  Mechanism: per-release flushing DELAYS the writer's commit of OTHER
  files' di_size, widening the window in which a peer reads di_size=0.
=> A single global "flush more / slow down" or "speed up" lever CANNOT fix both — every durability
   fix I tried helped one and hurt the other (or just hurt).  The next session must fix each
   mechanism SPECIFICALLY and WITHOUT changing global latency:
   * double-alloc: find the exact stale-bnobt-read path (non-perturbing post-mortem bnobt/inobt
     overlap audit via xfs_db at envelope offset 196688 sectors; or a free-path double-free check).
   * empty-content: it is a coherence/RACE, NOT missing durability (durability fixes make it
     worse).  Re-examine: is the peer reading di_size=0 because (a) it igets the WRONG inode from a
     stale dir block, or (b) it reloads the inode before the writer's create transaction has even
     COMMITTED (not just flushed)?  Instrument the peer read non-perturbingly (an in-memory-only
     check, not added I/O) to tell which.  STOP trying durability/flush fixes for empty-content.

## sess39 reg_release_durable: tested =1, REVERTED to default 0 (made empty-content WORSE+slower)
Added mxfs.reg_release_durable param + a SAFE (no raw write) file-inode release durability block
(iflush via log_force+ail_push, cluster-buf quiesce, blkdev_issue_flush).  =1 gave 40 fails /
120 empty-content / 151s wall (vs ~15 / 36 / ~11-25s).  Default 0 (inert).  Code + param kept.

## NEXT-SESSION TOOLING: non-perturbing double-alloc post-mortem audit (verified available)
xfs_db, xfs_repair, losetup all present on the nodes.  XFS envelope offset = 100704256 bytes
(196688 sectors), read from on-disk super at byte 88.  To audit after a double-alloc shutdown
WITHOUT perturbing the live run: on a node, `umount /mnt/shared` (device must be UNMOUNTED — the
loop setup failed here only because /dev/sda was still mounted), then
`losetup -fP -o 100704256 /dev/sda` and `xfs_repair -n <loopdev>` (or xfs_db) — xfs_repair -n
reports cross-linked blocks (a block owned by two structures = the double-alloc) read-only.  This
tells double-alloc vs double-free definitively without adding I/O to the live race.

## CURRENT build = `E8DE05217D58CC5B181E1BE` — supersedes 13D07033/A9A5A26A
= all validated fixes + 5 detectors + params (fua_always=0, reg_release_durable=0, both default
off/inert) + unused mxfs_buf_write_fua/mxfs_v5_dlm_ag_held helpers.  Baseline behavior: ~15-17
coherence fails/240, intermittent double-alloc shutdown, wall variable 11-150s.

## OLDER build = `13D070331A904B9B0AB0F78` — superseded
= A9A5A26A (all fixes + detectors + fua_always param) with the dangerous surgical FUA-write
release call REVERTED; mxfs_buf_write_fua() helper present but unused.

## OLDER build = `A9A5A26A22ADCC4BDD64AEF` — supersedes 7EE09B31
= 7EE09B31 (dir durability + inode backoff + di_size reload-skip + deferred-AG-flush worker
+ detectors + ag_held helper) PLUS the mxfs.fua_always param (default 0).

## OLDER build = `7EE09B31D1933D78255741A` — supersedes F1844E73/3CF4F8D4/6A08B05C
= dir-data durability barrier + scoped inode-lock CAS backoff + di_size reload-skip fix
+ deferred-AG-release flush worker (correct latent Invariant-#1 fix, inert for rename)
+ lightweight always-on detectors (caw_check_exclusion / DIR-STALE-SKIP / RELOAD-SIZE-DROP[-SKIP]
/ inode-init DOUBLE-ALLOC) + mxfs_v5_dlm_ag_held() helper.

## PRIOR build = `F1844E737E5D0B301B3DFA5` (superseded)
= dir-data durability barrier + scoped inode-lock CAS backoff + di_size reload-skip fix
+ lightweight always-on detectors (caw_check_exclusion / DIR-STALE-SKIP / RELOAD-SIZE-DROP[-SKIP]
/ inode-init DOUBLE-ALLOC) + mxfs_v5_dlm_ag_held() helper (unused, available). No perf-killer
per-acquire I/O. This is the session's final, most-complete build.

## OLDER build = `3CF4F8D4012857B71010D14` (superseded)
Adds the (corrected) inode-init double-alloc detector on top of 6A08B05C's fixes+detectors.

## PRIOR build = `6A08B05CF98B7210F3FD0F2`
= dir-data durability barrier + scoped inode-lock CAS backoff + di_size reload-skip fix
+ 3 always-on detectors (caw_check_exclusion / DIR-STALE-SKIP / RELOAD-SIZE-DROP[-SKIP]).
All detectors and the fix validated. Build is a strict improvement; the AG double-alloc is the
sole remaining hard blocker for cache_coherency.

## OLD build note = `84458BF83B00D4AFFAB3DAE`
= dir-data durability barrier + scoped inode-lock CAS backoff + always-on double-grant detector.
Deployed on all 4 nodes, cluster clean-mounted. New harness: tests/measure_rename.sh (N-run
avg), tests/cluster/test_rename_vis_dbg.sh (logs stat size/ino on empty — for reader-side dx).

See also [[feedback_timing_is_failure.md]], [[sess37_lessons]], [[sess38 via CLAUDE.md]].

## sess39 sync_fs fix VALIDATED as a major win (update)
A clean fast run with the sync_fs iflush fix (build E51EEA92): **wall=27s, fails=2** (3 empty +
3 missing-dirent aggregated across nodes).  So the earlier 148s/200s-timeout runs were VARIANCE,
not inherent to the fix.  Net: rename_visibility 15 -> 2-5 fails, empty-content 36 -> ~3.  The
sync_fs ail_push+flush is a strong keeper.  REMAINING for a clean pass: ~3 residual empty-content
(a few inodes still not iflushed by sync time — the targeted-iflush refinement may close these
too) + ~3 missing-dirents (dir-block staleness: a peer reads a stale shared-dir block missing a
peer's rename; DIR-STALE-SKIP=0 so the peer isn't reloading the dir block — the dir-block read
coherence is the next target).  cache_coherency also still runs unlink_visibility (slow ~128s) +
cross_write_read.  Current build = E51EEA92EA7ED6BC18E96BE.

## sess39 double-pass sync_fs: TESTED, REVERTED (worse). Build reverts to single-pass.
A second log_force+ail_push pass in sync_fs (to catch the async CIL->AIL insert race for the
residual ~3 empty) made it WORSE (14 fails, cluster degraded) — extra AIL contention widens the
race.  Reverted to single pass.  The residual ~3 empty + ~3 missing-dirent need a DIFFERENT,
non-latency-adding approach (targeted iflush of just the dirtied inodes; dir-block read-coherence
for the missing-dirents).  Final single-pass build srcversion below.

## sess39 WARNING: whole-AIL-push sync_fs makes the FULL cache_coherency criterion TOO SLOW
Running ./tests/criteria/cache_coherency.sh --nodes 4 with the sync_fs xfs_ail_push_all_sync fix
did NOT complete within ~15-20 min (the script's own 900s watchdog) — the heavy sub-tests
(unlink_visibility creates+unlinks 100s of files, cross_write_read) call sync(2) repeatedly and
each whole-AIL push under 4-node contention is slow, compounding.  So the whole-AIL-push is a
CORRECTNESS win (rename 15->2-5) but a TIMING regression for the full criterion.  ==> the TARGETED
iflush (only the inodes dirtied since last sync) is REQUIRED to make sync_fs both correct AND fast
enough for the full cache_coherency run.  This is the #1 next-session task.  (Alternative: only do
the heavy push when the AIL actually has dirty inode items, or bound it per-AG.)

## sess39 — exact primitives for the sync_fs targeted/bounded iflush refinement (#1 next task)
The slow part is xfs_ail_push_all_sync (xfs/xfs_trans_priv.h:121) = UNBOUNDED blocking wait until
the whole AIL drains; under 4-node DLM contention each iflush blocks on locks -> the full
cache_coherency criterion (many sync(2) calls in unlink/cross_write_read) doesn't finish in 15min.
Available alternatives in xfs/xfs_trans_priv.h:
- xfs_ail_push_all(ailp)  (line 110) = ASYNC: set push target to AIL max + wake xfsaild, returns
  immediately.  But a blkdev_issue_flush right after is PREMATURE (inodes not yet written) -> racy.
- xfs_ail_push_all_sync(ailp) (line 121) = blocking until drained (correct but slow).
PROPOSED FIX: BOUNDED sync push — xfs_ail_push_all(ailp) to kick it, then poll the AIL emptiness
with a cap (~2s; a node's ~20 dirty inodes drain fast), THEN blkdev_issue_flush.  Bounds the wait
so the criterion completes, keeps most correctness.  Pattern to copy: xfs_ail_push_ag_sync_bounded
already exists in xfs/xfs_trans_ail.c (per-AG bounded drain with stall-abort) — generalize it to
whole-AIL, or just push this node's preferred AG(s) (slot % agcount) which hold most of its dirty
inodes.  Test: rename_visibility fails should stay ~2-5 AND ./tests/criteria/cache_coherency.sh
should COMPLETE (not time out).  Current sync_fs code is in pal/linux/xfs_super.c ~line 866.

## sess39 FINAL handoff build = `570290DA6ADBC84DC2677FE` (deployed, cluster clean)
The di_size sync_fs fix is now GATED behind module param `mxfs.sync_iflush` (default 0 = OFF) so
the full cache_coherency.sh criterion COMPLETES by default (the whole-AIL push timed it out >900s).
- To use the validated empty-content fix: `echo 1 > /sys/module/mxfs/parameters/sync_iflush` on all
  nodes -> rename_visibility drops to 2-5 fails (but slow; full criterion times out).
- NEXT SESSION #1 TASK: rewrite the sync_fs push (pal/linux/xfs_super.c ~line 866, gated by
  mxfs_sync_iflush) as a BOUNDED iflush (xfs_ail_push_all async + capped wait, or push only this
  node's preferred AG), validate rename stays 2-5 AND cache_coherency.sh COMPLETES, then flip
  mxfs_sync_iflush default to 1.  Params now: instr, fua_always, reg_release_durable, sync_iflush
  (all default 0).

## *** sess39 BOUNDED sync_fs iflush LANDED + VALIDATED — build `79FB2484B435A1A3D51076A` ***
Implemented xfs_ail_push_all_sync_bounded(ailp, max_ms) (xfs/xfs_trans_ail.c, decl in
xfs_trans_priv.h) = xfs_ail_push_all_sync with an iteration cap.  sync_fs (pal/linux/xfs_super.c)
now calls it with a 2000ms cap (gated by mxfs_sync_iflush, NOW DEFAULT 1).  RESULT: rename_visibility
**wall=27s, fails=6** -- keeps the correctness win (down from 15) AND fixes the slowness (was 148s
unbounded).  Each sync(2) is capped at 2s so the full cache_coherency criterion should COMPLETE now
(unbounded version timed it out >900s).  Deployed, cluster clean, sync_iflush=1.
NEXT SESSION: (1) run ./tests/criteria/cache_coherency.sh --nodes 4 to confirm it COMPLETES and see
the new per-subtest pass/fail (rename should be much closer; cross_write_read/unlink may now pass
too since they share the di_size mechanism); (2) drive the residual rename fails (~6: a few empty +
~3 missing-dirents) toward 0 — empty via tuning the 2s cap / catching the async-CIL stragglers
WITHOUT global slowdown; missing-dirents via dir-block read coherence; (3) rsync_paired missing
tools/mxfs_multinode_bench.sh.  Params: instr/fua_always/reg_release_durable=0, sync_iflush=1.

## sess39 — full cache_coherency.sh did NOT complete in ~15min even with bounded fix
A background ./tests/criteria/cache_coherency.sh --nodes 4 run (build 79FB2484, sync_iflush=1
bounded) did not write a RESULT / update .criteria_results.json within ~15 min (wrapper timeout
880s).  The criterion's own cost (teardown_all w/ possible virsh restarts + fresh_cluster_mount +
4 tests incl. unlink_visibility ~128s) plus the per-sync bounded push is the total.  NEXT SESSION:
run it foreground with a longer budget and WATCH where the time goes (which sub-test); if the
bounded sync is still too slow, narrow it further (push only THIS node's preferred AG via
xfs_ail_push_ag_sync, slot%agcount, instead of whole-AIL-bounded — a node's dirty inodes are
mostly in its own AG).  The PRIOR completed criterion result (passed=1 failed=3, rename+unlink+
cross_write_read failing) is the last known full-criterion state; the bounded fix should improve
rename (15->6) and likely cross_write_read (shares the di_size mechanism) once it can complete.

## sess39 CORRECTION: tools/mxfs_multinode_bench.sh ALREADY EXISTS + is complete (do NOT recreate)
It is a full 119-line script (created a prior session; the "missing" note was from a STALE
failure log predating its creation).  It does fresh mount + parallel per-node rsync of
/root/open-gpu-kernel-modules into per-node subdirs + appends correct JSON rows
(.[$BENCH_KEY].results[] = {iter,node,wall_s,rsync_ec,dst_files,expected_files,md5_match,
dmesg_flagged}) — exactly what rsync_paired.sh parses.  So rsync_paired just needs to be RUN
(./tests/criteria/rsync_paired.sh --nodes 4); it FAILs on the wall-ratio (>1.2x XFS ref) or a
corruption flag, NOT on a missing script.  NEXT SESSION: run it and read the actual ratio/flags.

## sess39 CAVEAT + easy diagnostic: full cache_coherency.sh did NOT complete with sync_iflush=1
A backgrounded cache_coherency.sh run (build 79FB2484, sync_iflush=1) was still running/stuck after
~18 min (no RESULT, JSON unchanged).  UNCERTAIN whether the bounded sync_iflush hangs the heavy
unlink_visibility/cross_write_read tests OR it's the criterion's inherent slowness (teardown_all
virsh restarts + unlink ~128s + a fallen-out node — it was already passed=1 failed=3 + slow BEFORE
my changes).  The RENAME test alone is fine with the fix (27s, 6 fails).
EASY DIAGNOSTIC (sync_iflush is RUNTIME-toggleable, no rebuild): next session, after reset4.sh,
run ./tests/criteria/cache_coherency.sh FOREGROUND with `echo 1 > .../sync_iflush` on all nodes,
watch which sub-test hangs; then A/B with `echo 0 > .../sync_iflush`.  If =1 hangs and =0 completes,
the bounded sync push hangs under unlink load -> narrow it (push only this node's preferred AG via
xfs_ail_push_ag_sync, slot%agcount) and/or flip the source default (xfs_mxfs_dlm.c:2848
`int mxfs_sync_iflush = 1;` -> 0).  Current deployed build = 79FB2484 (sync_iflush default 1).

## *** sess39 CRITICAL: whole-AIL sync_fs push WEDGES (cross-AG xfsaild deadlock) — default flipped OFF
The backgrounded cache_coherency.sh run WEDGED in uninterruptible (D) state — neither the 880s
wrapper nor the 900s script watchdog could kill it (D-state ignores SIGTERM); a node-side mxfs_test
process is stuck.  This is the DOCUMENTED hazard: xfs_ail_push_all_sync (whole AIL) under MXFS DLM
deadlocks cross-AG (the bast worker uses per-AG push specifically to avoid this — see Design
Tensions / sess18).  My sync_fs xfs_ail_push_all_sync_bounded(2s) STILL triggers it under the
unlink test's heavy inactivation (xfs_inactive_ifree itself calls ail_push_all_sync) — the 2s cap
doesn't help because xfsaild itself blocks in D-state on a DLM lock, not in the push loop.
ACTION TAKEN: flipped source default `mxfs_sync_iflush` to 0 (xfs_mxfs_dlm.c:2848) and rebuilt.
NEXT SESSION: the cluster is likely WEDGED — hard-reset (reset4.sh / cluster_reset.sh do virsh
destroy+start retries; or sysrq-b).  Then REIMPLEMENT the sync_fs di_size push as a PER-AG bounded
push (xfs_ail_push_ag_sync of THIS node's preferred AG = slot%agcount, where its dirty inodes
live) instead of whole-AIL — this avoids the cross-AG deadlock AND is faster.  THEN re-enable
default.  The di_size ROOT CAUSE + the rename 15->6 result still stand; only the whole-AIL
mechanism is deadlock-prone.
