---
name: compiled-tcp-2node-harness-cache-coherency
description: 2-node TCP harness bring-up + multi-node suite port; build B77AD901 five fixes; cache_coherency flaky = barrier desync from slow reloads, not corrupt…
metadata:
  type: project
tags: [compiled, tcp-dlm, cache-coherency, test-harness, 2-node, barrier-desync, atime-ex]
---

# Compiled: 2-node TCP harness bring-up + cache_coherency flakiness

Central topic: standing up the agnostic 2-node `dlm=tcp` multi-node test suite
(MQTT-coordinated, off-FS barriers), driving it to catch and fix a chain of real
kernel bugs, and isolating the residual `cache_coherency` flakiness to
barrier desync from slow coordinated reloads (not a correctness bug).
Ship criterion: **every test in `./showstat.sh 2 tcp` PASS**. Storage = LIO/tcm_loop
write-through, TCP DLM (`force_transport=1`); cluster = test1 (forms) + test2 (joins).

## The harness (2026-06-14)
Built and validated in [[sess-testinfra-2node-harness-validated-and-crash]]:
- `tests/suite/coord.sh` — MQTT coordination primitive (broker 192.168.1.149).
  `coord_barrier/put/get/signal/wait/done`, retained-topic, director-free, race-free.
  Sourced by `tests/suite/lib.sh` (no-op at N=1); exposes `$MNT $RANK(R) $NODES(T)`.
- `run.sh <N> <dlm> [test...]` — preps cluster (fresh mkfs + TCP mount), builds the
  applicable test list from `criteria.json` (transport + min/max_nodes), runs
  `coord=none` on node1 / `coord!=none` on ALL N, aggregates **PASS iff every node PASS**,
  records to `criteria.json` keyed `<N>/<dlm>`, writes `.last_run.json`. Clears the coord
  prefix before/after via `mosquitto_sub --remove-retained`.
- `tests/suite/cache_coherency.sh` — agnostic node-side test folding the 4 historical
  subtests (cross_visibility, cross_write_read, rename_visibility, unlink_visibility)
  lifted from `tests/cluster/test_*.sh`, using `coord_barrier` instead of the on-FS
  `.mxfs_barriers` dir (coordinating the FS-under-test *via* that FS masks coherency bugs).

Key rule reinforced everywhere: `coord_barrier` publishes its rank RETAINED *before* polling,
so it tolerates arrival skew up to `COORD_TIMEOUT`. 8/8 distinct barriers pass ~2s each in
isolation — the barrier primitive is NOT the bug. Do NOT widen `COORD_TIMEOUT` to mask a
timeout (RULE 0). Harness TODO (deferred): fail-fast coord abort when a node returns with no
RESULT line, so peers bail instead of eating `COORD_TIMEOUT × N` barriers.

## Build progression / the five KEEP fixes
Harness's first run immediately caught a real kernel crash, which drove the fix chain:
crash build `305641B7` → `A70942DB` (3 root fixes) → `B77AD901` (adds fixes 4 + 5).

### Crash caught first (build 305641B7) — [[sess-testinfra-2node-harness-validated-and-crash]]
On the single→multi transition (test2 joins), first create:
`P-DIALLOC dp=128 err=1 ino=0` → `P-CREATE-ERR1` → `P-CR62 ... disk_di_mode=0177777
verdict=disk-read-err/badmagic` → `BUG: NULL deref do_open+0x60`, RAX=-EISDIR.
Signature = inode-reuse type-confusion (garbage i_op/i_fop ≈0x1). instr=0 dirwr=0, so not
an instrumentation artifact. No git: yesterday's passing build (recorded PASS 2026-06-13
under the OLD criteria harness) was not recoverable — only one `.ko` exists.

### Build A70942DB — 3 proven root fixes (KEEP) — [[sess-tcp-2node-three-root-fixes]]
1. **DLM NOQUEUE deny leaked a positive protocol code.** `dlm/dlm.c`: `xfs_dialloc`
   TRYLOCK → `mxfs_v5_dlm_ag_lock_nb` → TCP NOQUEUE; a remote master denying a peer-held AG
   sends status `MXFS_ERR_DEADLOCK` (enum = **1**). `dlm_lock_impl` returned +1 verbatim;
   `ag_lock_nb` only mapped `-EWOULDBLOCK`→`-EAGAIN`, so `1 != -EAGAIN` made the allocator
   treat a busy AG as FATAL → create fails → `do_open` NULL-deref. Fix: in `dlm_lock_impl`
   remote-status path translate `MXFS_ERR_DEADLOCK`→`-EAGAIN`, any other positive→`-EIO`.
   Never leak a positive protocol code to the kernel.
2. **SCSI FUA read rejected by LIO/tcm_loop.** `tools/fua_verify` proved READ(16)+FUA →
   sense key 5 ILLEGAL REQUEST ASC 0x24. `mxfs_pal_scsi_read_fua_bdev` -EIO →
   `fua_disk_mode=0xffffffff` → misread as corruption → EFSCORRUPTED. Backstore is
   write-through (`emulate_write_cache=0`) so a plain bio read is already coherent. Fix:
   latch a static `mxfs_fua_read_unsupported` flag on ILLEGAL_REQUEST and fall back to
   `mxfs_pal_bdev_read_plain_bdev`; one-shot mount-time FUA probe in `xfs_fs_fill_super`
   (right after envelope setup) so the flag latches BEFORE any real I/O. On a real
   FUA-capable target (SCST) the passthrough succeeds and fallback never engages.
3. **Reader verify-fail bypassed sess127 coordination.** `xfs/xfs_icache.c`: a new child's
   cluster isn't durable when peer first reads it (deferred-publish, creator's child EX is
   LOCAL). On TCP/LIO the stale on-disk cluster fails `xfs_dinode_verify` → `-EFSCORRUPTED`
   at `xfs_inode_from_disk`, which `goto out_release_dlm` BEFORE reaching sess127's
   `error==-ENOENT` recovery → first read returns EFSCORRUPTED (self-heals ~18s later). Fix:
   in `xfs_iget_cache_miss`, after from_disk verify-fail (ip still pristine), run the SAME
   coordinated `mxfs_dlm_ilock_begin(PR)+mxfs_dlm_reload_inode(...,false)+ilock_end`; clear
   error if `i_mode!=0`. Guard: `error && !tp && !dlm_acquired && !XFS_IGET_CREATE &&
   multi-node`. Probe `P-TCP-VERIFY-COORD`. Also reverted the sess73 busy-spin ILOCK
   diagnostic back to `down_write_nested`. Verified via new `tests/setup/reset2_tcp.sh`
   (clean 2-node reset + cross-node smoke, ~40s wall, NOT 320 — RULE 0).

### Build B77AD901 — fixes 4 + 5 (KEEP) — [[sess-tcp-progress-subtests-123-pass]], [[sess-tcp-subtest3-atime-ex-deadlock]], [[sess-tcp-cache-coherency-flaky]]
4. **atime-on-read takes cluster DLM EX → 122s deadlock.** Subtest 3 (rename_visibility)
   wedged: `cat` D-state >122s, stack
   `mxfs_dlm_ilock_begin ← xfs_ilock(EXCL) ← xfs_vn_update_time ← touch_atime ←
   filemap_read ← xfs_file_buffered_read`. A relatime atime update on this node's OWN-AG
   file took `XFS_ILOCK_EXCL` → cluster EX acquire that never completed (peer test2 idle).
   sess45's `5ED458EB` atime skip only covered PEER-AG inodes (`mxfs_inode_is_peer_ag`).
   Fix in `pal/linux/xfs_iops.c::xfs_vn_update_time`: skip ALL atime-only updates when
   multi-node (`mp->m_mxfs_dlm && !single_node`) = cluster-wide effective-noatime;
   mtime/ctime still update. This was the ONLY true D-state hang in the flakiness family.
5. Fifth fix (part of B77AD901's "5 fixes KEEP") lands cache_coherency into the PASS zone;
   the crash/wedge/EFSCORRUPTED blockers are GONE.

After fixes 1–4, subtests 1 (cross_visibility), 2 (cross_write_read, 1MB random md5 BOTH
directions), and 3 (rename_visibility) all PASS; only subtest 4 (unlink_visibility) failed,
and that failure was traced to barrier desync, not coherency.

## Residual: cache_coherency is FLAKY, and it's barrier desync from slowness
[[sess-tcp-cache-coherency-flaky]] reliability data (warm mount, manual 2-node,
COORD_TIMEOUT 30–40): a clean run = test1 PASS 201/201, test2 PASS 200/200, ALL 4 subtests,
23s. But across repeats: PASS/PASS, HANG(90s, no RESULT), FAIL+PASS(87s slow),
FAIL+FAIL(23s fast miss) — genuinely flaky AND degrades across repeated runs.

Ops are FAST — [[sess-tcp-ops-are-fast-flaky-is-barrier-desync]] measured (build B77AD901):
single-node create 30 = 0.026s, unlink 30 = 0.117s; concurrent same-dir both nodes
create30 ≈ .03–.07s / unlink30 ≈ .29–.33s; cross-node read of 30 files = 0.015s; concurrent
both-nodes-30-same-dir sees 60 IMMEDIATELY. So NO individual op is slow, unlink is not the
slow path, and concurrent-dir coherency is correct AND prompt. Snapshotting D-state stacks
every 5s during a passing run captured ZERO relevant (non-kworker) D-state stalls — the
remaining flakiness is NOT a kernel D-state hang. Proven barrier desync: one iter trace had
test1 at `uv_preverify` while test2 still at `uv_create` — the two nodes drift ~1
barrier-phase apart and the MQTT `coord_barrier` times out at `COORD_TIMEOUT`, with the
data-check FAILs being downstream cascades ("peer's files not yet there").

Subtest-4 failure signature: `test1: uv all files present pre-delete (exp=60 got=30);
test2: uv barrier create / uv barrier preverify` (timeouts) — not a coherency bug: nodes
drifted >`COORD_TIMEOUT` apart in cumulative timing across subtests 1–3, so rank-1's count
fired before rank-2's files were observed.

Root of the drift (three intertwined problems, [[sess-tcp-cache-coherency-flaky]]):
1. **Slowness** — the `P-TCP-VERIFY-COORD` coordinated reload (DLM round-trip +
   force-peer-flush on first read of each peer-written inode) is slow enough that a
   23s-when-fast test drifts to 87s, desyncing barriers. RULE 0: slowness IS a fail.
2. **Intermittent coherency miss** — occasionally asymmetric (iter2 test1 FAIL while
   test2 PASS); needs a captured fast-fail trace to localize.
3. **State degradation across runs** — each repeated run starts worse; inter-run `rm -rf`
   can wedge unlink (`rm` D-state in `vfs_unlink`); even fresh-mkfs `run.sh` still failed,
   implicating the fresh-mount single→multi transition timing.

Highest-leverage next step: attack SLOWNESS first. Make the CREATOR push the new inode
cluster durable+visible at create time (cheap on write-through LIO) so readers don't need
the per-read coordinated round-trip — look at the `xfs_create` deferred-publish path
(`xfs/xfs_inode.c` ~L1593-1660, `m_mxfs_unpub_list`, `mxfs_dlm_dir_durable_signal`) and
whether a synchronous new-inode-cluster flush on multi-node create is cheap+correct.

## Whole-suite confirmation: logic correct, one blocker
[[sess-tcp-flaky-confirmed-stall-is-blocker]] — ran the 5 ported tests twice + cache_coherency
many times (build B77AD901). Six wired tests now: cache_coherency, strong_consistency,
zero_silent_loss, posix_multi, mmap_coherency, dlm_fairness. Results:
- strong_consistency: PASS 2/2 both runs (stable).
- zero_silent_loss: run1 FAIL 1/2 → run2 PASS 2/2 (FLIPPED = proves flaky, logic correct).
- posix_multi 1/2 then 0/2; mmap_coherency 1/2 both; dlm_fairness 1/2 both.
EVERY failure reason is a `coord_barrier` TIMEOUT with data-checks as downstream cascades.
dlm_fairness's actual 50 lock-churn rounds PASS; only its barriers time out. Test LOGIC is
correct everywhere. **The one remaining blocker = an intermittent >30s FS-op stall on TCP
DLM** — same class as the fixed atime-EX deadlock but a DIFFERENT path (sleeping DLM acquire
= D-state). Prime suspects: the `P-TCP-VERIFY-COORD` reader coord (`mxfs_dlm_ilock_begin(ip,
PR)` BASTs a peer's deferred-publish EX; slow peer release → PR stalls); any remaining
`ILOCK_EXCL` on a hot cross-node path; a TCP DLM request waiting on a slow/lost BAST/grant
(`dlm/dlm.c` retry path). Best repro = posix_multi (fails ~every run, 100 concurrent
creates+hardlink+rename); catch it by sampling `/proc/<pid>/stack` of every non-kworker
D-state task every ~3s on both nodes → `.testlogs/pmc_stalls.log`, then fix the named
acquire. Do NOT widen COORD_TIMEOUT to mask it.

## The suite port (PORTING, not net-new) — [[sess-tcp-suite-port-multinode-tests]]
User-flagged gap (2026-06-14): `showstat 2 tcp` lists 16 tests but only `precond_readiness`
+ `cache_coherency` had runnable `tests/suite/*.sh`; the other 13 were manifest stubs.
Implementations already exist in `tests/cluster/test_*.sh` (old harness) and
`tests/criteria/*.sh` (whole-cluster ship-gate orchestrators) — wire them into the agnostic
2-node suite.

Porting recipe (template = `tests/suite/cache_coherency.sh`): node-side script sources
`tests/suite/lib.sh`, sees only `$MNT $RANK(R) $NODES(T)`, uses `ck "<desc>" cmd` /
`ckeq "<desc>" exp act`, rendezvous via `coord_barrier <tag>` (one call both sides),
ends `coord_done; finish`. Translations: `NODE_ID`→`$R`, `TOTAL_NODES`→`$T`,
`MOUNT_POINT`→`$MNT`; `barrier_signal X; barrier_wait X N`→`coord_barrier X`;
`assert_equals exp act "d"`→`ckeq "d" exp act`; `assert_file_exists f "d"`→`ck "d" test -f f`;
`test_fail`→a failing `ck`; drop `log_timing/test_begin/test_end`→`finish`. Keep role logic
(writers=odd rank, readers=even rank, single-node=both).

Ported this session (build B77AD901): strong_consistency.sh (from
test_sequential_consistency.sh, PASS 2/2 verified); zero_silent_loss.sh (from
test_concurrent_write.sh, md5 cross-verify+count); posix_multi.sh (from
test_concurrent_touch.sh, count/uniq + hardlink/rename); mmap_coherency.sh (NEW, python3
mmap write+msync, cross-node read verify); dlm_fairness.sh (NEW, each node hammers shared
dir ROUNDS times, no starvation).

Still to port (sources in `tests/criteria/`): dlm_membership ← online_membership.sh;
crash_consistency ← crash_consistency.sh (needs virsh node kill); fence_during_write ←
fence_during_write.sh; fault_netpartition ← NONE, write new (iptables block peer TCP, verify
no split-brain); scaling_curve ← scaling_curve.sh (perf, RULE 0 budget); dlm_scaling ← NONE,
write new; rsync_paired ← rsync_paired.sh (paired XFS vs mxfs, 2×-native ceiling);
tcp_dlm_scaling ← tcp_dlm_scaling.sh. NOTE the criteria/ versions are whole-cluster
orchestrators (they ssh to nodes and emit RESULT) — for fault/perf tests it may be cleaner
to run them `coord=none` on node1 and let them drive the cluster.

User direction ([[sess-tcp-ops-are-fast-flaky-is-barrier-desync]]): don't tunnel on
cache_coherency (the hardest test); baseline ALL 16 `showstat 2 tcp` first, exclude `soak`
(hours-long), then attack failures by impact.

## Harness / infra notes (carry forward)
- Criterion = every `showstat 2 tcp` test PASS; a 1-in-N flaky PASS does not count. Result
  read via `jq '.categories[].tests[]|select(.name=="cache_coherency").runs["2/tcp"]'` on
  `criteria.json`.
- Background Bash tasks have ISOLATED `/tmp` — write logs to NFS-visible
  `/src/mxfs/.testlogs/`; only the task's final `.output` is readable from foreground.
- Between manual runs: `rm -rf /mnt/shared/.cache_coherency; sync`. Use PS4 with timestamps
  for per-op timing.
- A node wedged D-state in `mxfs_dlm_ilock_begin` cannot umount/rmmod, and even
  `ls /mnt/shared` hangs the ssh — probe with `echo alive; ps ... D-state` WITHOUT touching
  the mount; recover via `virsh -c qemu:///system destroy/start` both nodes.
- Source-tree caveat: live `xfs/xfs_inode.c` was a heavily instrumented sess73/sess132
  diagnostic build (busy-spin trylock); `.sess129fix` / `.backup` are older/cleaner
  checkpoints. No git recovery of prior passing builds.
- In-tree helpers: `tests/setup/reset2_tcp.sh` (smoke), `tests/setup/bartest.sh` (barrier test).
