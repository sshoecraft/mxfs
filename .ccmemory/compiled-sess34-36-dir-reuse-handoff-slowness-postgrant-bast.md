---
name: compiled-sess34-36-dir-reuse-handoff-slowness-postgrant-bast
description: sess34-36: dir_reuse_coherency 2/tcp — 6s dir handoff root=missing post-grant BAST on ACQUIRING defer; fixed via prompt-BAST honor+MHT batching+mht30…
metadata:
  type: project
tags: [compiled, dir_reuse_coherency, dlm, bast, tcp-transport, slowness, dir-block-lost-update]
---

## dir_reuse_coherency 2/tcp — the 6s dir handoff, its root, and the timing fix (sess34→36)

Central topic: across sess34-36 `dir_reuse_coherency` was the **only** remaining 2-node/TCP
ship-criterion failure (16/17 → 16 PASS + 1 PENDING). The test: 24 rounds, both nodes write 100
entries (50 data + 50 md5) into ONE shared dir, barrier, both cold-read (`echo 3 > drop_caches`) and
assert `readdir==200` + every name lookup-able; rank1 `rm -rf`s and recreates the dir every round
(inode-number + daddr REUSE stressor). Two independent faces, BOTH must pass: **(1) TIMING**
(300s TEST_TIMEOUT budget; ~16s/round × 24 ≈ 390s = RULE-0 FAIL) and **(2) CORRECTNESS** (drc-FAIL=0).
By sess36 **TIMING is SOLVED (span 284s)**; correctness (durable dir-DATA-block lost-update) is the
last blocker.

### sess34 — three faces, and proving the 6s slowness root
[[sess34-dirreuse-three-faces-slowness-and-leafhole]] (ccloop 8ddb16a2). Builds: baseline DBD3A375
→ instrumented **A815A103** (+P34-ACQ-SLOW: logs inode DLM acquire >1s ino/isdir/req_mode/dur/attempts/rc;
+`mxfs-DRCph` per-phase /dev/kmsg markers create-start/create-done/verify-done/rm-done, pure logging)
→ **BDD203F2** (+P34-LEAF-DRAIN, P34-TRYLOCK-STALE, DRCph). Three faces (extreme variance, run 3-5×):
(1) corruption shutdown [sess33], (2) SLOWNESS ~16s/round → 300s hit before 24 rounds, (3)
LEAF-HASH-HOLE (round 17, both nodes readdir 200/200 but lookup_fail=6, durable on disk).

Ruled OUT this session: allocator double-alloc (AG affinity `node_slot%maxagi` for dirs AND files +
strict AG partition already in `xfs_dialloc_pick_ag`, `xfs_ialloc.c:2070`; TCP `mxfs_v5_dlm_ag_lock`
is a real EX). **MHT REFUTED as the slowness lever**: `inode_mht_ms=0` modarg → still ~16s/round, 6s
stalls persist. (This refutation is later inverted — see sess36, where MHT=300 becomes THE fix; the
sess34 error was testing MHT=0 not MHT-large.)

PROVEN slowness chain [[sess34-6s-dir-handoff-is-LOCK_ACQUIRE_WAIT_MS-deferred-bast]]: the ~6s stalls
are ALL dir inode (ino=131) acquires — P34-ACQ-SLOW isdir=1 dur **5992/6142/6233ms attempts=1 rc=0**,
i.e. ONE blocking `mxfs_v5_dlm_inode_lock` returns success after ~6s. The requester's grant wait is
`pending_wait(pend, MXFS_LOCK_ACQUIRE_WAIT_MS)` (`dlm/dlm.c:912`) with `#define
MXFS_LOCK_ACQUIRE_WAIT_MS 6000` (`include/mxfs/mxfs_dlm.h:255`) — the ~6s IS that timeout exactly.
Holder-side release is FAST (P138-BAST dir=1 count=0; bast_process dir drain <5ms). So the 6s is the
requester waiting the full grant timeout because **the holder does not HONOR the dir BAST promptly**.
Leaf-hole lead: **P21F-RELFLUSH-LEAF = 0 on BOTH nodes** — release-drain (`mxfs_dir_flush_data_blocks`,
`xfs_mxfs_dlm.c:1185`) NEVER flushes a LEAF block (it gates on needs_flush; leaf is clean/uncached at
release, left to async xfsaild landing AFTER handoff) → peer reads a stale leaf missing tail entries.

GPT-5.5 architectural plan [[sess34-GPT-plan-dlm-acquire-boundary-coherency-and-prompt-bast]] (implement
INCREMENTALLY per RULE 4). SLOWNESS items: (1) make "revoke pending" ORTHOGONAL to ISTATE_ACQUIRING —
a peer BAST must set a revoke flag honored regardless of state (today the ACQUIRING branch only sets
`i_dlm_stale` at `xfs_mxfs_dlm.c:5482-5489`); (2) `ilock_end` must honor revoke_pending, not only
`state==MXFS_DLM_ISTATE_BAST` (`:8972`); (3) bounded fairness window (min-hold + max-hold-after-BAST /
max-ops) so a fresh holder makes progress before yielding; (4) acquire PARENT DIR DLM in EX DIRECTLY
for modify ops instead of PR-then-upgrade (kills P-CONVBLK-DENY conversion thrash → EDEADLK, ~80/run);
(5) replace 3×6000ms acquire retries (`:8652`) with EVENT-DRIVEN waits (do NOT merely shrink the wait —
outer loop is only 3 attempts then FORCE-SHUTDOWN at `:8720`). CORRECTNESS items: (6) **move dir-block
invalidation from read-time `xfs_da_read_buf` XBF_TRYLOCK-skip (racy) to the DLM ACQUIRE boundary** —
walk the WHOLE dir data fork (data+leaf+free, not just block 0) and invalidate stale incore buffers
before publishing/admitting local users, when no txn/ilock is held so a blocking buf lock is safe;
(7) remove XBF_TRYLOCK skip as a correctness mechanism; (8) tag dir buffers {fsid,ino,di_gen,fork,
dabno,dlm_epoch} to defeat ABA (same-ino di_gen reuse AND same-daddr owner reuse); (9) make the sess43
AIL keep-guard (`xfs_da_btree.c:3210`) generation-aware; (10) DLM resource key = fsid+ino+di_gen.

### sess35 — PROVEN root of the 6s, and the fix
[[sess35-PROVEN-root-dir6s-is-missing-postgrant-bast-on-upgrade]] (traces on build 24144BB4). The
slow-path inode-EX acquire (`mxfs_dlm_ilock_begin`) does, in order: (1) `~8816 ip->i_dlm_stale=true`
(unconditional "reload needed"); (2) `~8840 mxfs_dlm_reload_inode()` which **CLEARS i_dlm_stale** on
success; (3) `~8906` post-publish `if (i_dlm_stale) → BAST+drain; else → CACHED`. `bast_notify`'s
ACQUIRING branch (`~5512`) deferred a peer BAST by setting the **SAME `i_dlm_stale` flag** — so a BAST
arriving while the node is ISTATE_ACQUIRING is CLEARED by the step-2 reload, post-publish sees false →
goes CACHED → **the deferred BAST is silently swallowed**. Holder keeps EX cached idle; peer stalls the
full 6000ms until `mxfs_dlm_lock`'s retry (`dlm.c ~1344`) re-fires the BAST — then honored in ~14µs.
Decisive evidence: test2 (holder) received 40 P-DIRBAST for ino=131, honored only 31; the ~9 unhonored
== 9× `state=4(ACQUIRING) mode=5(EX)` arrivals. CACHED-state BASTs honor in 14µs (this is what sess35
first MISread as "H1 refuted"). Refuted alternatives (don't retry): H2 upgrade-grant-without-BAST, H3
immediate-grant-jump (P35-POSTGRANT-BAST ~1×/run).

FIX (build **A970F10B**, KEEP): dedicated `i_dlm_bast_during_acq` flag on `struct xfs_inode`
(`xfs_inode.h`, next to `i_dlm_stale`, init false at `~9922`). ACQUIRING branch sets BOTH `i_dlm_stale`
(reload) AND `i_dlm_bast_during_acq` (BAST); post-publish `acq=i_dlm_bast_during_acq; clear it; if
(i_dlm_stale||acq) → BAST+drain`. Reload never touches the new flag → the deferred BAST survives. Logs
`P35-ACQBAST-HONOR`. Also KEEP the `collect_grantee_bast_if_waiters` post-grant-BAST additions in
`dlm.c` (upgrade/immediate/reaffirm sites — harmless, fire rarely, correct defense).

Result [[sess35-fix-result-and-residual-asymmetric-slowness]]: fix WORKS — P35-ACQBAST-HONOR fired 11×
(t1=3,t2=8); test2 create phase dropped to ~1.3s, test2 P34-ACQ-SLOW=0. But test STILL times out at
300s. Per-round phase (from unwrapped DRCph): **test1 (MASTER for ino=131) create ~6.5s / verify ~3.2s
/ rm ~2.6s; test2 (remote) create ~1.3s / verify ~8.4s / rm ~2.0s**; barrier-coupled round ≈ 6.5+8.4+2
+~4.6 gap ≈ 16s × 24 ≈ 390s. Two residual ASYMMETRIC bottlenecks: (1) **test1 create ~6.5s** —
P34-ACQ-SLOW=3 on test1, ~1 lost-BAST/round STILL on the MASTER side. Asymmetry root: test1-as-requester
fires a REMOTE (network) BAST to holder test2; test2-as-requester triggers a LOCAL BAST on test1
(always delivered) → residual loss is on the remote-BAST-delivery / remote-holder-honor path (a test2
state other than the now-fixed ACQUIRING, OR remote BAST msg lost, OR test2's LOCK_RELEASE
STALEGEN-dropped at master). (2) **test2 verify ~8.4s** = 200 lookups after drop_caches = ~42ms/lookup
cold FUA inode reads; native XFS = µs. The sess38 fix (invalidate inode-cluster buffer on EVERY
multi-node cache-miss iget, `xfs_icache.c xfs_iget_cache_miss`) forces a FUA per-iget, defeating
cluster-read amortization (~200 files ≈ 8 clusters SHOULD be ~8 FUA reads ≈ 300ms). FUA gate:
`pal/linux/xfs_buf.c ~3929 (!_XBF_FUA_FRESH)`. Fix direction: invalidate once-per-cluster-per-grant-epoch,
not per-iget (don't fully revert sess38 — it fixed a real create-race).

MHT-batching addition [[sess35-batching-fix-and-next-steps]] (build **68B7C405** = A970F10B + GPT item
3): A970F10B removed the 6s stall but also removed accidental batching → per-create dir-EX ping-pong
(~65ms/op × 100 ≈ 6.5s create phase). At post-publish, when honoring an ACQUIRING-deferred BAST on a
FRESH EX **dir** grant, keep state CACHED + set `i_dlm_bast_pending` + arm `i_dlm_bast_dwork` (batch_arm)
for the remaining `mxfs_inode_mht_ms` window instead of releasing after ONE op (logs `P35-ACQBAST-BATCH`;
edits `xfs_mxfs_dlm.c` post-publish ~8888-8995 + struct field). Coherency-safe (DLM still gates peer;
release drain unchanged; starvation bounded by MHT). Tooling introduced: `tests/drc_run_capture.sh`
(full per-node dmesg → /tmp/drc_full.log, setsid + `</dev/null` fixes the stdin-detach bug).

### sess36 — TIMING SOLVED (build BC6D7A5E, span 284s)
[[sess36-timing-solved-mht300-and-stall-fixes]]. Timing root = dir-EX lock THRASHING (~20 handoffs/round;
XFS drops/re-acquires the dir ILOCK per file). Four levers landed (all KEEP, build **BC6D7A5E**):
1. **inode_mht_ms=300** (was 50) — THE timing fix. Larger MHT batching window → each node holds dir-EX
   across its whole burst → ~2-4 handoffs/round not 20. Span 314s→**284s** (<300); create totals
   40s→14s. Set via `MXFS_EXTRA_MODARGS='inode_mht_ms=300'` (`module_param`, no rebuild;
   `xfs_mxfs_dlm.c:3510`). **NOT yet the code default — make `mxfs_inode_mht_ms=300` the default or pass
   the modarg in prep.** (This overturns the sess34 "MHT refuted" claim: MHT=0 was the wrong direction.)
2. **dwork re-arm** (`mxfs_dlm_bast_dwork_fn ~5306`): the sess35 batching dwork, when it fired mid-burst
   (holders>0), CONSUMED `i_dlm_bast_pending` + set state=BAST and bailed; a re-acquire reset state→CACHED,
   losing the BAST → holder held EX IDLE 6s. FIX: keep bast_pending, stay CACHED, RE-ARM the dwork until
   quiescent (logs P36-MHT-REARM). Eliminated test2's 6s stalls.
3. **collect_post_promotion_basts unconditional** (`dlm.c process_remote_release ~2935` + `mxfs_dlm_unlock
   ~1597`): was inside `if (grants)`, so a release with promoted=0 (waiter BLOCKED behind a holder that
   re-acquired ahead of it) fired NO BAST → 6s strand. Now fires whenever this node is master.
4. **MXFS_LOCK_ACQUIRE_WAIT_MS 6000→1000** (`mxfs_dlm.h:268`) + retries 10→60 (`dlm.c:1385`, keeps ~60s
   budget). Residual stranded waiters recover in ~1s not 6s; test1 stalls 6s→~1s.
Result: test1 P34-ACQ-SLOW=0, test2=1 (one residual mutual-standoff 6s), span 284s → **TIMING PASSES**.

CORRECTNESS — the remaining blocker (flaky drc-FAIL 0..10 across runs; =1 in the MHT=300 run). ROUND 15,
both nodes: readdir=**188/200, missing exactly node1_f1..node1_f12** (rank1's first 12 DATA files; their
.md5 sidecars + f13..f50 + all node2 entries survived), lookup_fail=0 → **durable on-disk dir-DATA-block
loss** (both nodes agree after drop_caches), NOT a leaf-hash hole — the earliest entries in the reused
dir's first data block get clobbered. Smoking-gun marker **P31E-DATAINIT-ABA** (get_buf/init about to
ZERO a block holding live peer dirents, on the REUSED daddr): a node creates into round-15's reused dir
using a STALE cached round-14 block (acquire-side stale dir-block RMW). Fix = GPT plan item 6: invalidate
the WHOLE dir data fork at the DLM-acquire boundary (blocking-safe) instead of the lazy read-time
XBF_TRYLOCK hook (`xfs_da_read_buf`, gated `!owned_ex`, `xfs_da_btree.c ~3101`). The correctness face's
under-read signature appears as **P26-DSCAN-MISS scanned~120/200** across sess35-36. NEXT: instrument
P31E-DATAINIT-ABA in the failing round.

### Build progression (all KEEP unless noted)
DBD3A375 (baseline) → A815A103 (P34-ACQ-SLOW + DRCph logging) → BDD203F2 (P34-LEAF/TRYLOCK probes) →
24144BB4 (P37/P-DIRBAST traces that proved the root) → **A970F10B** (dedicated `i_dlm_bast_during_acq`
fix; kills the 6s ACQUIRING-BAST loss) → **68B7C405** (+ MHT batching, GPT item 3) → **BC6D7A5E**
(+ inode_mht_ms=300 default-candidate + dwork re-arm + unconditional collect_post_promotion_basts +
WAIT_MS 6000→1000/retries→60; TIMING PASSES at 284s).

### Recurring lessons / failure modes
- **One flag serving two meanings is a trap.** `i_dlm_stale` conflated "needs reload" and "deferred
  BAST"; the reload that cleared the former silently swallowed the latter. Fix = a dedicated flag.
- **Removing a stall can remove accidental batching** → different slowness (ping-pong). A970F10B needed
  68B7C405/BC6D7A5E batching to actually pass timing.
- **A batching dwork that consumes state on a mid-burst fire loses the BAST** unless it re-arms and keeps
  state CACHED (sess36 lever 2).
- **BAST-collection gated on `if(grants)` strands waiters** when promoted=0; must fire whenever master.
- **Don't merely shrink MXFS_LOCK_ACQUIRE_WAIT_MS** without raising retries — 3 attempts then
  FORCE-SHUTDOWN would convert contention into shutdowns (sess36 raised retries to 60 alongside).
- **Per-iget FUA invalidation defeats inode-cluster read amortization** (sess38 fix vs sess31
  `_XBF_FUA_FRESH`); invalidate per-cluster-per-epoch instead.
- **RULE 4 discipline:** MHT=0 (sess34) was tested and refuted; MHT=300 (sess36) was the fix — the lever
  was right, the direction wrong. Test both directions before declaring a lever dead.
- **Tooling / env:** dmesg ring WRAPS on a 24-round run (counts undercount) — capture full via
  `tests/drc_cap2.sh` (sess36, host-side streaming → `tests/_cap/<host>.log`, survives prep's rmmod/insmod;
  supersedes sess35's `drc_run_capture.sh` node-side follower which lost the file). `tests/drc_analyze.py
  t1 t2` = per-round critical-path timing. `reset2.sh` before every run (D-state unmount wedge).
  `make clean` DELETES tools → `make tools` after. Run: `export MXFS_EXTRA_MODARGS='inode_mht_ms=300';
  bash tests/drc_cap2.sh` OR `./run.sh 2 tcp dir_reuse_coherency`.
- **Still-open correctness face:** acquire-side stale dir-block RMW (durable dir-DATA loss of first block's
  earliest entries under inode/daddr reuse). GPT item 6 (invalidate whole dir fork at DLM-acquire boundary)
  is the standing fix direction; P31E-DATAINIT-ABA is the marker to chase.
