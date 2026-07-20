---
name: compiled-tcp-2node-posix-multi-lost-dlm-grant
description: Compiled TCP 2-node posix_multi stall thread: theory arc from dir lost-update→ifree-drain→lost DLM grant msg; -ETIMEDOUT retry fix → 8 PASS.
metadata:
  type: project
tags: [compiled, tcp-dlm, posix_multi, cache_coherency, lost-grant, dir-ex, 2node]
---

## Central topic
The 2-node `dlm=tcp` `posix_multi` / `cache_coherency` failure — a flaky ~60s stall that
presented alternately as a durable dir lost-update, a dir-EX ping-pong livelock, and an
ifree-drain AG-hold wedge, and whose TRUE root was an intermittently lost DLM grant/release
message on a contended dir-EX handoff. Fixed by a `-ETIMEDOUT` retry + shortened acquire-wait,
which turned the whole 2/tcp coherency suite green. Build arc: **B77AD901 → 23E19A81 → F22321508E13160ACFD9A41**.

## Investigation arc (each stage refuted or refined the prior)

### 1. First repro — "durable concurrent-dir lost-update" (build B77AD901)
[[sess-tcp-posix-multi-concurrent-dir-visibility-gap]]: `./run.sh 2 tcp posix_multi` — both
nodes concurrently create 100 files (`node${R}_file1..100`) into one shared dir
`/mnt/shared/.posix_multi`, `coord_barrier` (PASSES), rank1 counts. Every node persistently saw
ONLY its own 100 (`count exp=200 got=100`); proven stable across repeated reads minutes later
on both nodes → looked like a DURABLE lost-update (not read-staleness — doesn't self-heal), the
same core dir-coherency bug fought 30+ sessions, now reproduced on TCP/LIO (so NOT CAW/infra
specific). `strong_consistency` (per-node counter files) + `zero_silent_loss` (10 own-named
files/node) PASS 2/2; the lost-update needs enough concurrent same-dir entries to collide.
Also flagged a second, separate failure mode: intermittent `coord_barrier` desync (one node
lags >COORD_TIMEOUT, no captured FS D-state — suspected MQTT-broker latency).

### 2. Narrowed to multi-block dirs (build B77AD901)
[[sess-tcp-dir-lostupdate-is-multiblock]]: convergence is VOLUME-dependent. 10 files/node →
both see 20, CONVERGES (`P62-RELOAD-FORK-SHRINK`, shortform fmt=1→block fmt=2 reload works).
100 files/node → durable divergence. So the lost-update is specific to MULTI-BLOCK
(block/leaf-format, >1 4K dir-data block, roughly >50-60 short names) directories: EX-acquire
reload and release drain covered shortform + block 0, but not dir data blocks beyond that.
Candidate fix site named: `mxfs_dlm_dir_modify_refresh(dp)` (xfs/xfs_mxfs_dlm.c:1981, called at
create EX-acquire xfs_inode.c:1355 and rename/remove 3420/3807/3809) — make it bump
`i_dlm_dir_gen` so EVERY dir data block re-reads via the `xfs_da_read_buf`
`b_mxfs_dir_gen<i_dlm_dir_gen` invalidation (v0.4.7), and drain every dir data block on release.

### 3. CORRECTED — not durable, it's a livelock (build B77AD901)
[[sess-tcp-posix-multi-hang-is-dirEX-pingpong-livelock]]: instrumented phase timing
(tests/repro_pm_timed.sh) refuted the durable-lost-update framing — NO op is slow in isolation:
single-node 100 creates=0.015s; concurrent 100/node=0.07s; cross-node readdir count=0.01s
SEEING ALL 200 (dir CONVERGES post-hoc); peer content read correct. posix_multi (FPN=100) fails
3 FLAKY ways: (a) full HANG → both nodes ~60s silent then `DLM inode lock failed ino=<dir>
mode=3/5 rc=-110` (ETIMEDOUT on 60s MXFS_LOCK_WAIT_TIMEOUT_MS); (b) `count=100` (premature read
after barrier desync); (c) rename/unlink-visibility miss. 30-file case (FPN=10) PASSES → the
multi-block dir is the TRIGGER but the bug is slowness, not on-disk divergence. Frozen capture
(tests/catch_hang.sh): NO test process kernel-blocked, only idle workers → NOT a pure D-state
deadlock. Proposed mechanism: dir-EX ping-pong (`i_dlm_dir_gen` 2→4→…), EACH handoff runs the
full release fence (xfs_mxfs_dlm.c ~L3370-3456: `xfs_log_force(SYNC)` + `xfs_ail_push_ag_sync`
+ `mxfs_dir_flush_data_blocks`, unbounded until data_durable); `DIR-STALE-SKIP … buf_gen=0`
spam is a false-positive (evict set b_mxfs_dir_gen=0, local modify re-pinned without bumping it
back). Also noted lock-order AB-BA risk in xfs_create (xfs_dialloc AG-DLM first, then re-acquire
dir ILOCK). Fix hypothesis TESTED: raise `inode_mht_ms` 50→3000 to batch each node's 100 creates
into ~1 tenure. **REFUTED next stage.**

### 4. Proven root #1 — ifree-drain wedge holds the AG DLM lock (build B77AD901)
[[sess-tcp-posix-multi-root-ifree-drain-wedge-holds-AG]]: tests/repro_burst_timed.sh (per-create
ms) was the decisive tool — test1 all 100 creates fast (max 3ms), test2 **create #1 = 62028ms**
then 99 fast. So it's a ONE-TIME ~60s stall on a single lock acquire, not per-create ping-pong.
dmesg: test1 `P137-IFREE-TIME ino=2097382 … drain_us=62569` — inode inactivation/free drain
(`mxfs_ail_drain_inode_sync`, xfs_ifree path xfs/xfs_inode.c:2446, between xfs_trans_commit and
`out_unlock_ag: mxfs_ag_dlm_unlock`) wedged 62.5s while HOLDING the AG DLM lock → starves test2's
`xfs_dialloc` (`DLM inode lock failed ino=256 mode=5 rc=-110`) → create#1 blocks 62s → barrier
desync → FAIL. The freed inode's cluster buffer is orphaned in AIL (IFLUSHING/delwri-queued not
written home); xfsaild is busy churning the contended DIR inode (`P78-FMT-TORN-FIX` every create,
`DIR-STALE-SKIP pin=1` spam) so it doesn't destage; `P136-DRAIN-RESCUE` (iter>=512) guards skip
the delwri-queued/locked buf → loops 62s. TRIGGER: posix_multi/cache_coherency start with
`rm -rf $D` → frees ~200 inodes → async inodegc inactivation → recycled by the create burst →
collision. 30-file tests don't pile enough inactivations. Same family as sess128 ailstuck +
sess43 P136, but here it HOLDS the AG DLM lock = cross-node starvation. `inode_mht_ms` 50→3000
REFUTED again (iter1 138s). Fix direction: actively destage the freed inode's cluster buffer
(bounded, process ctx) instead of passively waiting on xfsaild.

### 5. FINAL root — intermittent LOST DLM grant/release msg (build 23E19A81, frozen-stack proven)
[[sess-tcp-posix-multi-FINAL-root-lost-dlm-grant-msg]]: supersedes the ifree-drain theory for the
FRESH-format case (fresh format has NO ifree → ifree bound doesn't fix posix_multi). Frozen
capture (tests/catch_create_stall.sh) at a 62-63s single-create stall:
- REQUESTER (test2): blocked `pending_wait → dlm_lock_impl → mxfs_dlm_lock →
  mxfs_v5_dlm_inode_lock → mxfs_dlm_ilock_begin → xfs_ilock → xfs_create`, waiting DIR inode EX (mode=5).
- HOLDER (test1): COMPLETELY IDLE — no blocked task, burst done in ~590ms, holds dir-EX cached,
  doesn't hand off for ~60s.
- Always-on `P-DIRBAST` proves the holder DOES receive the BAST (state=1 CACHED → immediate
  branch → queue bast_work) and DOES release (later state=4 mode=0).
=> The lost link is the GRANT/RELEASE NOTIFICATION back to the waiter. `send_grant` retries once
after 10ms (dlm.c:566); an intermittently dropped/delayed TCP grant/release leaves the waiter's
pending entry unsignaled the full 60s `MXFS_LOCK_WAIT_TIMEOUT_MS` (mxfs_dlm.h:235). **KEY GAP:**
`mxfs_dlm_lock` (dlm.c:1163-1188) retries only on MXFS_DLM_RETRY / -ENOTCONN/-EPIPE/-ECONNRESET —
NOT on -ETIMEDOUT → a lost grant is never promptly recovered by the DLM layer. This is
intermittent (most handoffs fast, occasional drop) → the flaky 60s stall → barrier desync → FAIL.
Fixes carried in 23E19A81 (SAFE but INSUFFICIENT alone, all KEEP): bounded xfs_ifree drain
(`mxfs_ail_drain_inode_sync_bounded` + module param `ifree_drain_ms`=200, used at the xfs_inode.c
ifree site — fixes the contaminated rm-rf recycled case, #4); bast_notify NONE_mode_held branch
now idle-releases cached holders (ex=0/pr=0/pin=0) via DEMOTING+bast_work instead of dead-defer;
always-on `P-DIRBAST` diagnostic. `mht=3000` REFUTED (reset 50). Candidate fixes ranked:
(1) master-side WATCHDOG re-drive of pending waiters (robust, no masking); (2) cheaper -ETIMEDOUT
retry + cut wait timeout; (3) find/fix the actual grant-msg drop (seq/ack/resend in send_grant +
LOCK_GRANT/LOCK_RELEASE recv; check master assignment for the dir ino).

### 6. THE FIX — -ETIMEDOUT retry + 6s acquire-wait (build F22321508E13160ACFD9A41)
[[sess-tcp-FIX-etimedout-retry-posix-multi-PASS]]: 3 small edits (KEEP):
1. `include/mxfs/mxfs_dlm.h`: new `MXFS_LOCK_ACQUIRE_WAIT_MS 6000` (separate from the 60s
   membership timeout).
2. `dlm/dlm.c`: both `pending_wait()` sites in `dlm_lock_impl` (remote-master ~L785,
   local-master ~L1093) now wait MXFS_LOCK_ACQUIRE_WAIT_MS instead of 60000.
3. `dlm/dlm.c` `mxfs_dlm_lock()`: added `-ETIMEDOUT` to the retry set — re-runs dlm_lock_impl
   (re-checks compat, now free since holder released, and re-fires the BAST). Bounded by the
   existing 10-retry loop; last attempt still returns -ETIMEDOUT.
Evidence (tests/repro_burst_timed.sh): before, test2 create#N = 62000ms; after, ~6300ms (6s
wait + retry grant), EXACTLY one ~6.3s recovery per burst, 3/3 runs. posix_multi then PASS 4/4
(29.4/29.8/17.2/17.1s) — was hang / count=100 / rename-miss.

### 7. MILESTONE — full 2/tcp suite green (build F22321508E13160ACFD9A41)
[[sess-tcp-MILESTONE-full-suite-8pass-0fail]]: the one -ETIMEDOUT retry fix fixed the ENTIRE
2-node coherency family in one shot. `./run.sh 2 tcp` = **8 PASS / 0 FAIL / 8 PENDING**:
precond_readiness PASS, **cache_coherency PASS 2/2 (the 90-session ship blocker)**,
strong_consistency 2/2, posix_multi 2/2, mmap_coherency 2/2, zero_silent_loss 2/2, dlm_fairness
2/2, soak PASS (30s, 1643 ops, 0 errs). The 8 PENDING are NO-SCRIPT STUBS (not failures):
dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency, fence_during_write,
fault_netpartition, tcp_dlm_scaling — no script in tests/suite|tcp so run.sh prints PEND.
criteria.json 2/tcp matrix has exactly 16 entries; 8 ran PASS, 8 stubs. Single-node P1 tests
(posix_single, fsx, fio_verify, integrity_filetypes, fio_perf, fault_enospc) are NOT in the
2/tcp matrix. Marker NOT written: substantive goal (coherency suite green) met, but not 100% of
the declared matrix — port the 8 PENDING (tcp_dlm_scaling←tests/cluster/test_tcp_mesh.sh;
membership/crash/fence/netpartition need fault injection modeled on the coord 'fault' class +
virsh destroy; scaling/rsync near-noop at N=2), re-run, confirm 16/16, and re-run for reliability
(prior state was FLAKY).

## Carry-forward follow-up (RULE 0 — the retry MASKS, doesn't cure)
~1 grant msg is lost PER burst (100% of bursts) — high and SYSTEMATIC, not random; likely a
specific state transition drops the first grant. The -ETIMEDOUT retry recovers in ~6s, but 6s
for an instant op is still a stall. Real fix = reliable grant/release delivery: master-side
re-drive watchdog OR seq/ack/resend in `send_grant` + the LOCK_GRANT/LOCK_RELEASE recv path
(`mxfs_peer_recv_fn`/dlm handlers). Optionally lower MXFS_LOCK_ACQUIRE_WAIT_MS toward ~2000 (keep
it > a healthy handoff and > the release-fence drain, cap 30s).

## Tooling & env (all in tests/, persistent per RULE 3)
`repro_burst_timed.sh` (per-create ms — THE decisive tool), `catch_create_stall.sh` (freeze
stacks+dmesg mid-stall), `catch_hang.sh`, `repro_pm_timed.sh` (phase timing), `repro_pm_loop.sh`
(N iters no reformat), `stall_catch.sh`. Cluster reset: `tests/setup/reset2_tcp.sh`. A wedge can
leave umount D-state in `xfs_buftarg_drain` → recover via virsh destroy+start
([[reference-node-power-control]]). Nodes test1+test2.
