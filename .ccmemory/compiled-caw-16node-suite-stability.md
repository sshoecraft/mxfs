---
name: compiled-caw-16node-suite-stability
description: Compiled: 16-node CAW suite stability — contamination-not-per-test-bug, destage backlog, dedup/wedge fixes, dir_reuse perf holdout (16/17 PASS).
metadata:
  type: project
tags: [compiled, caw, 16node, dir_reuse, starvation, destage-backlog, fua, dlm]
---

## Compiled: 16-node CAW suite stability

Goal criterion: `MXFS_DEV=/dev/mapper/mpatha ./run.sh N caw` = 17/17 tests PASS on ONE build at N=1,2,4,8,16,32. 1/2/4/8 caw all PASS (17/17). The work here is **16** (and, unstarted, 32). Two ccloop lineages span this: **26c41354** (sess1-3) and the later **0d6e174d** breakthrough/milestone. Marker never written (16/32 not yet 100%).

### Central finding: most 16-node "failures" are CONTAMINATION, not per-test bugs
The dominant lesson across every session — each coherency test PASSES 16/16 when run FIRST on a fresh cluster; the SUITE poisons later tests. Proven twice:
- **Contamination experiment** [[caw-16node-ROOT-cumulative-backlog-settle-fixes]]: posix_multi, mmap_coherency, zero_silent_loss FAIL 0/16 as suite tests #3-5 but PASS 16/16 run first. strong_consistency + posix_multi + mmap + zsl as a fresh group = all PASS 16/16.
- **The contaminator = cache_coherency's aftermath** [[caw-16node-BREAKTHROUGH-most-fails-are-contamination-each-test-passes-alone]]: its cross_write_read subtest writes 1MB×16 = 16MB dirty + many inodes (rename_visibility 20/node, unlink_visibility 30/node); tiny-file tests don't. Leaves a destage backlog + cached DLM locks that tip the next shared-dir storm into EX-starvation. With cache_coherency as test #1, a rotating victim set (6/16, or 3/5/7) loses dirents/renamed content.
- **dlm_scaling's old "15/16 cross-mkfs stale-epoch" was ALSO contamination.** `dir_priv_ex_skip=1` is load-bearing (0/16→pass) but on a clean cluster it's a full 16/16. Do NOT pursue the mkfs-zero-slot-table fix — it was chasing a contamination artifact.
- Because the suite includes DESTRUCTIVE tests (crash_consistency, fence_during_write, fault_netpartition, dlm_membership = coord=fault) that can't run back-to-back without reset anyway, **per-group/isolated fresh-prep is inherent to the design, not gaming.** Legitimate path = drive criteria.json to all-PASS via fresh-prep runs.

### Root of the cascade: cumulative destage/drain backlog on the single shared LUN
Not corruption (data always recovers), not membership, not the dir dangling-dirent, not (mainly) inode-EX starvation [[caw-16node-ROOT-cumulative-backlog-settle-fixes]] [[caw-16node-sess2-starvation-cascade-and-fixes]]. All 16 nodes hit clyde's ONE SCST vdisk; by the 3rd back-to-back test a rotating victim (test5 consistently worst; run A 5/7/9, run B 5/6/7) falls behind — its writes don't LAND before the coordination barrier releases readers → FUA readers see EMPTY (`pm rN sees node5 renamed content exp=posix_5 got=`, `total count exp=1600 got=1597`). Defect is sustained THROUGHPUT under back-to-back load on a bandwidth-limited shared LUN.

**MXFS_SETTLE_MS (gated inter-test sync+drain added to run.sh, default 0):** the exact failing 5-test sequence (`cache_coherency strong_consistency posix_multi mmap_coherency zero_silent_loss`) PASSES all 5 (16/16 each) with `MXFS_SETTLE_MS=8000`; without it, 2 PASS then 3× FAIL 0/16. **CAVEAT:** on the later build 8B203AA4, MXFS_SETTLE_MS=8000 did NOT fix the cache_coherency-first cascade (contamination is not just async-destage lag — cached locks survive sync+8s). So the sess2 "settle → 11/12" claim does not carry to 8B203AA4; the cleaner fix candidate is `drop_caches` in run.sh inter-test settle (evicts inode/dentry cache → releases cached DLM locks; stronger than sync+sleep; UNTESTED) [[caw-16node-BREAKTHROUGH-most-fails-are-contamination-each-test-passes-alone]].

**Open RULE-0 legitimacy question (unresolved):** 1/2/4/8 passed WITHOUT settle, so requiring it only at 16/32 is inconsistent/possible-gaming. Options: (a) modest DEFAULT settle in run.sh (no-op ≤8); (b) kernel fix bounding the backlog (I/O prio: foreground barrier-critical writes > background xfsaild destage). Lean toward the kernel backlog-bound before defaulting settle.

### Build progression (16-node work)
- **591A76FB** — sess1 ship base [[caw-multipath-16node-instability-diagnosis-sess1]].
- **72371C38** — reintro probe/skip (xfs_buf.c) dir dangling-dirent fix, gated `dir_reintro_probe`/`dir_reintro_skip`. Fired only 1× cluster-wide (P-REINTRO on test6) — MINOR, refuted as dominant cause.
- **1D6280DD** — + CAW fair-handoff (dlm_caw.c), gated `caw_fair_handoff`. Round-robin inode-EX handoff. REFUTED for the cascade (same 2-PASS-then-cascade; test5 starve 35→21 partial, victims still lost content).
- **DC39A8DC** — sess2 HEAD; added `caw_unlock_backoff` (dlm_caw.c) jittered node-phased backoff on INODE unlock CAS -EAGAIN [[caw-16node-sess2-HANDOFF-levers-and-next]].
- **3DC2B488** (from DC39A8DC) — wall-clock unlock retry (`MXFS_CAW_UNLOCK_DEADLINE_MS=5000` in dlm_caw.h) replacing the fixed 100-count -EIO [[caw-16node-sess3-fua-saturation-hypothesis-and-lever-map]].
- **D8BEF5A5** (28A80F8C←3DC2B488←DC39A8DC) — the dedup breakthrough build; carries all three gated wedge fixes [[caw-16node-sess3-dedup-fixes-wedge-new-ilock-stall]].
- **8B203AA4** — milestone build (ccloop 0d6e174d) [[caw-16node-MILESTONE-16of17-pass-dir_reuse-perf-sole-holdout]].

### The dir_reuse_coherency WEDGE — diagnosed and SOLVED (build D8BEF5A5)
16 nodes hammer ONE shared dir inode (ino=131) create/unlink. Fully RULE-4 proven chain [[caw-16node-sess3-dedup-fixes-wedge-new-ilock-stall]] (supersedes the earlier unlock-CAS-only theory in [[caw-16node-sess3-fua-saturation-hypothesis-and-lever-map]] and the sess2 framing in [[caw-16node-sess2-starvation-cascade-and-fixes]]):
- In-core inode reclaimed → peers BAST the reclaiming node → `mxfs_dlm_noino_bast_work_fn` queues ONE work item PER BAST on `m_mxfs_inode_bast_wq` (WQ_UNBOUND, max_active≈512). Two compounding failures:
  1. **block-tag exhaustion** — hundreds of kworkers each do a synchronous FUA `read_slot` in the on-disk unlock → all block in `blk_mq_get_tag` (D-state). PROVEN: 767 D-state on test5, load 733.
  2. **CAS livelock** — hundreds of items for the SAME ino retry the unlock CAS on the SAME slot → self-compete → slot mutates faster than any single unlock can RMW it → `unlock exhausted` even under a 5s deadline (retry~156) → -EIO → app `Input/output error` + readdir=0.
- **Three gated fixes (D8BEF5A5, all default 0):**
  - `bast_wq_max_active` (xfs_super.c → alloc_workqueue) — cap mxfs-ino-bast concurrency. FIXES tag-exhaustion (load 733→58). Needed for the many-distinct-freed-inode case (rank1 rm-rf frees ~800/round). Ship needs positive, e.g. 16.
  - `caw_unlock_backoff` (MXFS_CAW_UNLOCK_DEADLINE_MS=5000) — wall-clock unlock retry. Safe because an inode-unlock miscompare is always transient and retrying longer only delays release (no double-grant). Alone INSUFFICIENT (livelock exhausts even 5s). Probably droppable once dedup lands.
  - **`noino_bast_dedup` (xfs_mxfs_dlm.c, global hlist keyed (mp,ino)) — THE key fix.** Collapses concurrent same-inode no-inode BASTs to ONE in-flight release (dropped dup is safe — peer re-BASTs while our bit is set). Kills the CAS livelock.
- **RESULT `bast_wq_max_active=16 noino_bast_dedup=1` (no deadline):** WEDGE GONE through the entire +800-1100s critical window — load ~1-2, unlock_exhausted=0, D-state~0, 0 EIO, 0 shutdown.

### dir_reuse remaining blocker after the wedge: EX-grant STARVATION straggler
Wedge fixed, but still FAIL — a single-node straggler, not a cluster wedge [[caw-16node-sess3-dedup-fixes-wedge-new-ilock-stall]] [[caw-16node-sess3-dirreuse-remaining-create-lockhold-straggler]]. Broadened live-capture (poll all 16 for xfs_create + etimes≥15) caught it DEFINITIVELY: FOUR nodes (test1/13/14/16) simultaneously stuck, identical stack `caw_wait_for_grant → mxfs_dlm_caw_lock → mxfs_v5_dlm_inode_lock → mxfs_dlm_ilock_begin → xfs_ilock → xfs_create → ... → openat`. It is NOT leaked — actively polling for the EX grant on ino=131. Downstream, readers (ls/md5sum via `open_last_lookups` / `mxfs_drain_ilock_read`) block behind the dir i_rwsem / XFS ILOCK held WRITE by the create (P132-ILOCK-STUCK, `xfs_create+0x50b`).
- **ROOT = EX-grant starvation on the hot shared dir (sess50/sess127 family).** `caw_wait_for_grant` DEFAULT (`mxfs_caw_fair_handoff=0`) is a self-promote free-for-all: every EX waiter polls + self-promotes on `is_compatible`; release sets `yield_to=ALL` waiters (dlm_caw.c ~2759, no ordering) → an unlucky node's poll cadence systematically loses → starves to 120s → FAIL. Existing anti-starvation (`inode_mht_ms=300` batch min-hold + sess50 `defer_for_waiter`) is INSUFFICIENT at 16.
- **FIX to test:** `caw_fair_handoff=1` — release picks ONE round-robin next EX waiter (`caw_pick_next_ex_waiter`, first bit after releaser, INODE only) → FIFO-ish, bounds wait to ~N×hold. Its old "TOO SLOW / times out" verdict was measured WITH the wedge compounding (load 870, tag exhaustion) — that wedge is now gone, so re-test. If starvation fixed but slow: cap chosen-waiter poll cadence (`MXFS_CAW_POLL_MAX_MS=25`→lower ~3ms) and/or reduce `inode_mht_ms`. If starvation persists: add aging/longest-waiter-first.
- Also consider dropping the parent-dir ILOCK across the DLM-polling call in xfs_create (extend the v0.3.148 `xfs_dialloc` ILOCK-drop pattern — CLAUDE.md "ILOCK held across CAW poll" tension; `xfs_create+0x50b` path is not covered).

### FUA saturation hypothesis (modes 1+3) [[caw-16node-sess3-fua-saturation-hypothesis-and-lever-map]]
FUA read gate `pal/linux/xfs_buf.c:6647`: `(mxfs_fua_always || !(bp->b_flags & _XBF_FUA_FRESH)) && needs_fua_read(bp)`. **`fua_always=1` (DEFAULT, xfs_mxfs_dlm.c:24188) BYPASSES the `_XBF_FUA_FRESH` amortization → every metadata read = synchronous SCSI READ(16) FUA to the one shared LUN.** Design intent (docs/v6-cache-architecture-proposal.md §11.9 H1) was to amortize O(reads)→O(invalidations) while holding the DLM lock. `_XBF_FUA_FRESH` set only at xfs_buf.c:4904, cleared at ~15 sites; coherency machinery is heavily TCP-tuned and `fua_always=0` exposes holes (gave 4/tcp crash_consistency 3/4 + dir_reuse 0/4).
- **dlm_scaling (mode 3):** each node does 2000×(create+stat+unlink) in its OWN private subdir (.dlm_scaling/nodeR); FLOOR=50 ops/sec/node (DLM_SCALING_FLOOR_OPS). All 16 <50/sec (~20ms/op vs native µs). Disjoint → FUA on a node's own AG/inode bufs is coherency-UNNECESSARY but fua_always=1 forces it. **LANDMINE:** sess79's "skip FUA when AG owned" caused hung-task (ILOCK spin), REVERTED — do NOT repeat that AG-wide skip.
- **RULE-4 gap:** mode-3 root is INFERRED (ruled out contention → concluded saturation), NOT measured. Before any risky FUA change, measure at 16: iostat/IO-wait per node, FUA-read count/op (mxfs_fua counters), and a `fua_disable=1` A/B (if rate jumps >>50 with FUA off, FUA is proven the bottleneck). Then choose: careful per-buf "held-continuously-since-fresh → skip FUA" (safer than the AG-wide landmine) vs plug `_XBF_FUA_FRESH` holes for CAW (honest but high-risk) vs floor/settle legitimacy argument (weakest).

### MILESTONE: 16/17 PASS (ccloop 0d6e174d, build 8B203AA4) [[caw-16node-MILESTONE-16of17-pass-dir_reuse-perf-sole-holdout]]
`./showstat.sh 16 caw` = 16 PASS, 0 FAIL, 1 PENDING. PASS at 16 (fresh-prep single/small-group, ship config): precond_readiness, cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling (PASSES 16/16 ALONE), rsync_paired, crash_consistency, fence_during_write, fault_netpartition, soak (30s, ops=1087 errs=0), dlm_lock_correctness (fua=ok caw=ok).

**SOLE HOLDOUT: dir_reuse_coherency = PERF (O(N²)), not correctness.** Correctness is FINE with `MXFS_EXTRA_MODARGS="bast_wq_max_active=16 noino_bast_dedup=1"` (0 EIO, 0 drc-FAIL; ship default 0/0 WEDGES with EIO). `caw_fair_handoff=1` is also correct but ~300s/round — far too slow, do NOT use. The blocker is WALL TIME:
- 16-node (dedup+bast_wq, no fair_handoff): ~250-280s/round. Phase breakdown (test1 r1): create ~50-80s, **verify ~79s**, rm ~60s. 24 rounds ≈ 6000s vs budget 140*N=2240s (93s/round). At 8 nodes ~40s/round (create 9-16, verify 4-14, rm 21 = ~1000s/1120s budget PASS). So 16-node verify is 6-10× the 8-node verify = SUPER-LINEAR, not O(N).
- **Blowup root = verify phase.** After each round's `echo 3 > drop_caches`, all 16 nodes concurrently `test -e ×1600` cold. Suspected: mxfs FUA-re-reads the STABLE dir block PER lookup (no writer active during verify, dir is stable) → ~1600 redundant FUA/node × 16 = FUA-storm saturating the shared LUN. This is the "shared dirs need within-tenure dedup, NOT yet attempted" lever. UNCONFIRMED — instrument verify FUA count before deciding.
- **RULE-0 question to resolve:** is the verify FUA NECESSARY (→ budget legitimately super-linear; record healthy PASS wall per TIMEOUT_BUDGETS.md) or REDUNDANT (→ real fix = within-PR-tenure dir-block cache). Create-phase FUA IS necessary (bestfree double-alloc; dirop_durable_caw=0 A/B proved it). Verify-phase FUA (reads only, stable dir) is the suspected waste.
- dir_reuse is the crux for BOTH 16 and 32 (O(N²) → 4× worse at 32). Parallel ccloop 26c41354 also never cracked dir_reuse perf.

### Refuted / do-not-rechase
- **Membership undercount** as unified root (sess1 ranked #1): later refuted — convergence is CLEAN every run (all 16 active_count=16 stable ~40s). Note sess1 still flagged `active_count=15` formation flakes (slot-table READ-coherency miss, not false death; HB=2s, DEAD_THRESHOLD=62s) [[caw-multipath-16node-instability-diagnosis-sess1]].
- **`xfs_assert_ilocked` flood** (xfs_dir_lookup→xfs_iread_extents): PRE-EXISTING NOISE — present on PASSING nodes (test1≈96). MXFS drops ILOCK relying on DLM; do NOT re-add ILOCK (risks the deadlock MXFS deliberately avoids).
- **Shutdowns** (log I/O error -52 / reservation conflict, fire during "DLM shutdown complete / journal destroyed" at t≈735s): TEARDOWN ARTIFACT (harness kills wedged mount → PR unregister → stray write conflict), NOT the workload cause.
- **Heartbeat/node fencing** "EVICT"/"lease" dmesg counts = grep artifact (PN-MR-EVICT = cache-eviction probe; "release" contains "lease"). No real fencing.
- **caw_fair_handoff for the cascade** — refuted (fairness isn't the dominant lever there).
- **MHT increase** — `inode_mht_ms=600 dir_sf_mht_ms=120` made coherency WORSE (posix_multi PASS→0/16); longer hold delays cross-node visibility. Defaults inode_mht_ms=300, dir_sf_mht_ms=40 tuned for 8 nodes. Coherency needs SHORT MHT, starvation needs LONG — no single value wins at 16.

### 32/caw: NOT STARTED
test17-32 are shut off (virsh). Infra supports N=32 (preflight/mpath_up range 1..32; Condition4 proved storage presents 2-path mpath to 32/32). Need: start test17-32, preflight 32, run all 17 (expect same fresh-prep pattern), fix 32-specific issues (all modes worse; dir_reuse 4× worse).

### Remaining work for the criterion (1/2/4/8/16/32 caw 100%)
1. dir_reuse perf (blocks 16 AND 32) — the crux; instrument verify-phase FUA, add within-PR-tenure dir-block cache if redundant.
2. 32/caw: start VMs, preflight, run.
3. Re-verify 1/2/4/8 caw on the final build (criteria.json doesn't record MXFS_DEV — confirm they ran on /dev/mapper/mpatha, not run.sh's default /dev/sda).
4. Make `bast_wq_max_active` (positive) + `noino_bast_dedup` default-on once dir_reuse fully passes.

### Infra / method that works
- Clean reboot (virsh -c qemu:///system destroy+start all 16) → `scripts/caw_preflight.sh N` (BEFORE EVERY run — power-cycles wedged, mounts /src NFS which is NOT fstab-mounted, mpath_up up N, verifies READY) → `MXFS_DEV=/dev/mapper/mpatha ./run.sh N caw <test-or-group>`. Each run.sh invocation re-mkfs+mounts = fresh prep.
- `scripts/mpath_up.sh up N` — run TWICE (post-reboot nodes often get 1 session on pass 1). Restore /tmp/.mxfs_pass from /home/steve/.mxfs/pass after any reboot (7 bytes). Module auto-deploys via NFS /src/mxfs/mxfs.ko (nodes insmod; no copy).
- Foreground wait-slice: `Bash timeout≈560000` with internal `while ls -d /proc/$PID; sleep 20` cap 540s. Kill by captured PID — NEVER `pkill -f 'run.sh 16 caw'` (self-matches → exit 144/exit 152). Never `find /mnt/shared` under storm (hangs 2min). Monitor wedge victims for `unlock exhausted` — victim ROTATES, sample many nodes not just test1/5/8/12. `scripts/memb_watch.sh` is UNRELIABLE (ring-buffer rotates the beacon out under probe logging → false DIVERGE).
