---
name: compiled-mode-a-ail-drain-early
description: Compiled sess20-37/38: Mode A peer-coherency arc — dir3-buf drain, adaptive quantum, disklock AIL drain, single-node log wedge, build hashes.
metadata:
  type: project
tags: [compiled, mode-a, coherency, ail-drain, log-wedge, adaptive-quantum, dlm, bast]
---

# Compiled: Early Mode A peer-coherency + AIL-drain work (sess20 → sess37/38)

Central topic: the multi-session hunt for **"Mode A"** — MXFS's cross-node
metadata-coherency bug where one node's just-committed directory/inode change
is not seen by a peer that reads immediately after — plus the drain-pipeline,
yield-quantum, and log-grant machinery built around the DLM release path to
make it correct and fast. Threads: dir3-buf-not-flushed-before-DLM-unlock,
adaptive yield quantum, multi-node disklock-timeout AIL drain, and the
single-node log wedge (the last of which was a distinct latent-upstream bug,
not a coherency bug).

Sources: [[Sess20 MXFS debugging — Mode A is multiple races, not dir-stale]],
[[Sess32 lessons — multi-node disklock-timeout root cause + partial fix]],
[[Sess33 lessons — adaptive yield quantum + ordered bast wq + AIL stall-abort; lock-inversion deadlock identified as structural]],
[[sess34 lessons (parallel mkdir bug isolation)]],
[[sess35 lessons — H22-H26 isolation and v5-v6 architectural confirmation]],
[[sess36-lessons-ship-gate-5-fixes-mode-a-re-diagnosis-magic-0x0-was-an-artifact]],
[[sess37_lessons]].

---

## The one durable reframe (read this first)

"Mode A" is **not** a single dir-stale bug. It is a family of distinct races
that share one external symptom (`xfs_remove → xfs_trans_cancel(0x8)` /
duplicate-create / lost dirents). Every session that treated it as one bug
burned cycles. Confirmed decompositions across the arc:

1. Multiple inode/AG-side races, not dir content persistence
   ([[Sess20 MXFS debugging — Mode A is multiple races, not dir-stale]]).
2. Sustained AG-DLM contention starvation, not simultaneous-mkdir coherency
   ([[Sess32 lessons — multi-node disklock-timeout root cause + partial fix]]).
3. A structural ILOCK-across-CAW lock-inversion deadlock
   ([[Sess33 lessons — adaptive yield quantum + ordered bast wq + AIL stall-abort; lock-inversion deadlock identified as structural]]).
4. dir3-buf delwri-queued-but-not-on-disk at DLM unlock
   ([[sess34 lessons (parallel mkdir bug isolation)]]).
5. Create-path stale-view / lost-update / inode-reuse cache-hit staleness
   ([[sess36-lessons-ship-gate-5-fixes-mode-a-re-diagnosis-magic-0x0-was-an-artifact]],
   [[sess37_lessons]]).

**Two instrumentation artifacts corrupted earlier diagnoses and MUST be
remembered as phantoms:**
- `P21-INSTR` (sess20) already proved `bast_process` persists dir content
  correctly: every PRE-UNLOCK showed `mem_size == DISK_size`. The
  "dir-stale Mode A" hypothesis of sess14/16/19 was WRONG.
- The `magic=0x0` "disk reads zeros / LIO durability cliff" signal that drove
  ALL of [[sess34 lessons (parallel mkdir bug isolation)]] and
  [[sess35 lessons — H22-H26 isolation and v5-v6 architectural confirmation]]
  was an **instrumentation offset bug**: `P-H16` read the raw XFS daddr via
  SCSI without adding `bt_sector_offset` (=196688 sectors, the MXFS envelope),
  so it read the zeroed journal region. Production reads all add the offset and
  are correct. Fixed in v0.4.5. The "durability cliff" was a phantom
  ([[sess36-lessons-ship-gate-5-fixes-mode-a-re-diagnosis-magic-0x0-was-an-artifact]]).

RULE 4 (hypothesis → instrument → prove → patch → loop) was added to CLAUDE.md
in sess34 precisely because prior sessions patched from code-reading and kept
re-surfacing the same bug ([[sess34 lessons (parallel mkdir bug isolation)]]).

---

## sess20 (2026-05-02) — v0.3.37→v0.3.52, 16 versions, all reverted

Final tree = v0.3.36 baseline + inert "Approach A" scaffolding (v0.3.52). Big
finding above (P21-INSTR). Mode A decomposed into ≥4 distinct root causes: AGI
bucket recycled-inode (`xfs_droplink -117`, `next_agino==agino`), bnobt
corruption (`xfs_free_ag_extent ltbno+ltlen > bno`), free-inode-has-blocks in
`xfs_create`, and rare `dir_removename` ENOENT (hash/dirent staleness, not disk
staleness).

**Do-NOT-repeat list (each already cost a build cycle)**:
`xfs_buf_lock` on a cluster buf in `bast_process` (deadlock via xfsaild on
shared `b_sema`; root ino 128 + ino 131 share blkno 128); `xfs_buftarg_wait`
in bast (bt_io_count never drains); `blkdev_issue_flush` from the xfs-buf wq
(serializes queue); any wait/diagnostic added to `bast_process` (triggers peer
CAW-timeout regression, `MAX_RETRIES=100` tight loop); CAW exponential backoff
1ms→32ms (dd hangs; >100ms/acquire too much); `xfs_inodegc_flush` from AG bast
(re-entrant AG-DLM disrupts bnobt); the Approach A premise itself
(`current->journal_info` is NULL at iunlock — xfs_create/xfs_remove have no
active trans when iunlock fires, so defer-to-trans-free never runs);
`xfs_log_force_seq(ili_commit_seq)` in bast (commit_seq usually 0 by bast time
= no-op). ([[Sess20 MXFS debugging — Mode A is multiple races, not dir-stale]])

---

## sess32 (2026-05-08) — multi-node disklock-timeout; ship v0.3.143; srcversion C39653544EDACD271B36CF5 (v0.3.145)

Three sequential bugs found+fixed in the `lazy_ag_drain=1` multi-node path:
- **v0.3.137** — inode-bast per-AG drain: replaced cross-AG `xfs_ail_push_all_sync`
  with `xfs_ail_push_ag_sync(ino_AG)` in `mxfs_dlm_bast_process` (AG-bast was
  fixed in v0.3.112; inode-bast still used the deadlock-prone whole-AIL push).
- **v0.3.138** — `log_force(SYNC)` before the synchronous eager drain in
  `mxfs_ag_dlm_unlock` (else `drain_alloc_buflist` blocks in
  `xfs_buf_wait_unpin` on CIL-pinned bufs).
- **v0.3.139** — orphan re-splice in `..._drain_alloc_buflist_nowait`:
  `xfs_buf_delwri_submit_nowait` skips pinned bufs and leaves them on the local
  list; without re-splice to `pag_mxfs_alloc_buflist` they orphan
  (`_XBF_DELWRI_Q`+AIL-referenced but unreachable).
- **v0.3.140** — set `XFS_AIL_OPSTATE_PUSH_ALL` each iter so xfsaild has a
  non-NULL push target under low log pressure.
- **v0.3.141/142 — REVERTED**: bounded 5s/500ms timeout on `xfs_ail_push_ag_sync`
  broke cross-node coherency (T2 mkdir lost when T1 released the grant before
  AIL writes hit disk). This confirms **architectural invariant #1: no DLM
  unlock until the drain pipeline completes** — bounded push that proceeds on
  timeout is a Mode A regression (sess27 finding restated; repeated again in
  sess33).
- **v0.3.143** — ship: per-AG inode-bast + log_force-before-drain + orphan
  re-splice + PUSH_ALL kicker, no timeout.
- **v0.3.144/145** — added `xfs_log_force(mp,0)` every 4th poll iter to both
  `xfs_ail_push_all_sync` and `xfs_ail_push_ag_sync` (throttled to avoid SCSI
  queue contention). This **definitively fixed the rm -rf wedge** in
  `xfs_inactive_ifree → xfs_ail_push_all_sync` (CIL items stayed pinned with no
  one forcing log writes).

**Perf (the load-bearing numbers), all md5=Y / dmesg_hits=0 unless noted**:

| Config | Wall avg | vs baseline |
|---|---|---|
| lazy=0 q=32 (default) SOLO | ~32s / ~13.5s (v0.3.147) | regression-free |
| lazy=1 q=1 SOLO | **5.9s** | ~5.4× faster (optimal SOLO) |
| lazy=1 q=16 SOLO | 26.4s | larger drain hurts SOLO |
| lazy=1 q=1 multi-node | T1 25s, T2 starved | partial |
| lazy=1 q=4 multi-node | T1 24s, T2 ~30 files/s | both progress, T2 doesn't finish |
| lazy=1 q=8 multi-node | T2 PASS 12.7s / **T1 corruption-shutdown** | see below |
| lazy=1 q=32 multi-node | T1 setup mkdir starves | quantum too large |

**Quantum tension**: SOLO wants small q (q=1 = 5.9s); multi-node wants larger q
for fairness (q=1 starves T2, q=32 starves the BAST'ing node). No single static
value works → motivates adaptive quantum (prescription E, built in sess33).

**q=8 "corruption" is NOT a unique bug**: `P-CREATE-ERR1 dialloc/icreate err=-110`
(-ETIMEDOUT from `mxfs_ag_dlm_lock` 120s CAW timeout) bubbles up from
`xfs_dialloc`; when the trans had accrued dirty state before the timeout,
`xfs_trans_cancel` fires the `xfs_trans.c:1060` corruption-detection shutdown.
Root = the SAME sustained T1↔T2 AG-DLM contention starvation; the shutdown is a
recoverable symptom. Fix the starvation, the "corruption" goes away.

**Reframe delivered to sess33**: Mode A on tight sequential root-mkdir is NOT a
kernel coherency bug (not reproduced on a clean cluster; earlier "test2 lost"
cases were bench-script setup races on corrupt-storage state). The real blocker
is **sustained AG-DLM contention starvation** under parallel rsync: T2 dirties
pages faster than writeback drains (`balance_dirty_pages` back-pressure) and T1
starves on AGs T2 has cached. Default `lazy_ag_drain=0` ships safe; lazy=1 is
opt-in experimental. Six candidate fixes listed (E adaptive-q → A proactive
release → B cap cache → D priority → C smaller drain steps). Also flagged: LIO
target drops the SCSI FUA bit (`target_core_iblock.c:772`); mkfs zero not
durable on LIO. ([[Sess32 lessons — multi-node disklock-timeout root cause + partial fix]])

---

## sess33 (2026-05-08) — v0.3.147, srcversion 40FE985FD379F1460B45D73

Three layered changes:
1. **Adaptive yield quantum** (`ag_yield_adaptive` default 1). New per-pag
   `pag_dlm_yield_quantum_eff` + `pag_dlm_skips_no_bast`. Halve eff on peer BAST,
   double after `MXFS_AG_YIELD_DOUBLE_THRESH=4` non-contended drains. **KEY:
   lazy-init starts at 1, not at cap** — starting at cap=32 wedged immediately
   (32 unlocks of dirty state accrued before the first BAST → drain exceeds the
   peer's 120s CAW timeout). SOLO cost: adaptive settles to cap=32 → ~16.5s vs
   the 5.9s peak; recover peak with explicit `ag_yield_adaptive=0
   ag_yield_quantum=1`.
2. **Dedicated ordered workqueue** `m_mxfs_ag_bast_wq` (`alloc_ordered_workqueue`)
   for AG BAST work. `system_wq` had spawned 7+ parallel `bast_work_fn` all
   polling `xfs_ail_push_ag_sync`, saturating concurrency. Serialized to one.
3. **Bounded AIL drain with stall-abort** `xfs_ail_push_ag_sync_bounded`
   (`ag_bast_stall_iters` default 600 ≈ 6s @ 10ms). On no-progress for
   stall_iters (and iter > min 64), returns -EAGAIN; `bast_work_fn`
   **aborts the release WITHOUT dropping the AG-DLM grant** (invariant #1;
   sess32 v0.3.141-142 reverted the alternative) and reschedules.

**The structural deadlock, proven** (`P67-INSTR AG-AIL-STALL ... buf=2(pinned=0)
inode=1 other=0`, constant across every wedge): items are NOT pinned, CIL is
current, log_force drained, xfsaild idle in S — yet the items won't push. Root =
**lock-inversion on ILOCK**. T2's user-process holds ILOCK on inode-X and is
blocked in `mxfs_dlm_caw_lock` CAW poll on AG-Y (held by T1); T2's
`bast_work_fn` for AG-Z calls `xfs_ail_push_ag_sync`, whose AIL items include
inode-X's pending iflush; xfsaild's `iop_push` ILOCK-trylock fails because T2's
own process holds it. Mirror cycle on T1. Stall-abort breaks the SYMPTOM
(wq saturation) but NOT the dependency cycle — needs a deeper XFS refactor.

Prescriptions handed forward: **(F)** drop ILOCK during the AG-DLM CAW poll
(architecturally correct, invasive); **(G)** detect ILOCK contention in the CAW
poll and inline-drain+release our own BAST-pending cached AGs (less invasive,
try first); **(H)** reduce ILOCK hold scope before AG-DLM acquire. Default knobs
all ship-safe (lazy=0). Touchpoints: `xfs_ag.h:152-170`, `xfs_ag.c:244-247`,
`xfs_mount.h:357-371`, `xfs_super.c:632-651`, `xfs_mxfs_dlm.c` (params + adaptive
+ queue_work + bounded drain), `xfs_trans_ail.c:806-905`, `xfs_trans_priv.h:136-146`.
([[Sess33 lessons — adaptive yield quantum + ordered bast wq + AIL stall-abort; lock-inversion deadlock identified as structural]])

---

## sess34 (2026-05-08) — sharp repro; dir3-buf-not-flushed root; all fixes reverted; v0.4.1 srcversion F1F98A5087D510F83EF32D5

**Sharp reproducer** (the real one, replacing the ad-hoc rsync bench):
`tests/cluster/test_concurrent_mkdir.sh`, 2 nodes, ~18s. Signature: ~99/100
dirs visible to node1; **missing entries are a contiguous range starting near
`node2_dir1`**; node2 sees everything; subsequent iters degrade catastrophically
(must virsh-destroy+start+remkfs each iter).

**Smoking gun** (test2 dmesg at BAST): `P36-INSTR ... BAST-DIR-STALE ... staled=0
skip_locked=1` + `P70 ... flags=0x80020` (`_XBF_DELWRI_Q|XBF_DONE`) +
`P59 ... BAST-LOGITEM in_ail=0 pinned=0`. **The dir3 buf holding the just-mkdir'd
entries is delwri-queued but NOT yet on disk at the moment of
`mxfs_v5_dlm_inode_unlock`**; the BAST-DIR-STALE walk `xfs_buf_trylock` fails
(buf locked) and skips it without staling or forcing it out. Peer's FUA-read
goes to disk, gets pre-mkdir content, CAS-overwrites. The bug is at the BUF log
item layer, not the inode log item.

Falsified: H1 (Phase-3 forced-release timeout not dominant), H2 (LIO stale-LBA —
dd all-zero after fresh mkfs), H4 (FUA rc=0 with no fill — 0xCD pre-fill),
H5 (partial fill). Reverted fixes (each narrowed the search): F2 memset(0) before
read_slot (drove SCSI MISCOMPARE up), H7 push extra AGs (no-op, dir is in inode's
own AG), H8 blocking `xfs_buf_lock`+`xfs_bwrite` (6m/50% regression, lock
inversion vs xfsaild), H8b trylock+bwrite (bug surface IS the locked buf), H8c
list_move+delwri_submit (racy vs ail_buf_list), H9 `XFS_ILOCK_EXCL` across drain
(same 6m/50% inversion). **Lesson: any lock the bast handler takes that overlaps
xfsaild deadlocks; any lock it skips misses the buggy buf.** The fix must
coordinate WITHOUT taking BLI lock or ILOCK during the drain. The sess33
`_XBF_MXFS_ALLOC_QUEUED` flag was a real fix for cluster bufs (new inode chunks);
the analogous dir3-buf fix hadn't landed.
([[sess34 lessons (parallel mkdir bug isolation)]])

---

## sess35 (2026-05-08) — H22–H29; magic=0x0 phantom; srcversion 43CA28E08F7AA051002C892

Instrumented under strict RULE 4 (user directed: stop patching v5). Results in
dependency order: kmsg follower (`scripts/sess35_capture.sh`) needed because
test1's ring buffer wraps in ~150s under load (invalidates sess34's "test1 never
gets bast_notify"). **H22 (invisible release) DISPROVEN** — clean
ACQ-FRESH→bast_notify→BAST-DIR-STALE→BAST_RELEASE→CAW-UNLOCK chain, no silent
slot-clear. **H23 DISPROVEN**. **H24/H25 PROVEN**: at skip_locked, `P-H25-MEM`
dumps `"XDB3"` + valid dir3 content — **memory is correct**; peer's FUA-read of
the same LBA shows `magic=0x0`. **H26 (extra `blkdev_issue_flush` before unlock)
FALSIFIED** — flush rc=0 but peer still reads zeros.

This drove a WRONG "LIO durability cliff" conclusion — then **CORRECTED late in
the same session**: `scripts/sess36_e1_xinit_durability.sh` +
`sess36_e1b_concurrent_xinit.sh` (single + 100-concurrent cross-initiator writes)
both PASS. Storage stack is sound. **H29 (REQ_META) FALSIFIED** (removed
`|REQ_META` from `xfs_buf_bio_op`, srcversion `2F9DBB1B8E82C8D96B4CFDD`, same
failure; reverted to `6875590D9985DCD9DE56208`). Real shape = the sess34 H7/H24
timing race: test2's dir3 iflush queued in delwri, buf locked at BAST-DIR-STALE,
not synchronously submitted, DLM released, test1 FUA-reads the freshly-allocated
extent's zero pre-content → lost entries. `mxfs.1` on 16 nodes loses ~50% of 800
mkdirs (381-385) — same magnitude → bug lives in a SHARED layer both versions
share. Forward hypotheses H30 (xfs_buf reuse race, best guess) / H31 (refcount
imbalance) / H32 / H33 / H34. v6a direction confirmed as the right SHAPE (uniform
invariants, single chokepoint), not because of a storage cliff.
([[sess35 lessons — H22-H26 isolation and v5-v6 architectural confirmation]])

---

## sess36 (2026-05-29) — 5 ship-gate criteria fixed; magic=0x0 unmasked; VERSION 0.4.5 srcversion E06DB7064C93254CF9EA50A

Ship-gate PASSes: **slow first-mount** (~16-18s → ~2.8s mount / ~5.5s join) —
root cause two avoidable CAW-init delays: `mxfs_disklock_get_stale_slot_mask`
slept a fixed 10s even with no peers (→ poll-with-early-exit + skip when empty),
and `mxfs_dlm_caw_purge_dead_nodes` did 65536 single-slot reads ~5s every mount
(→ batch 32-slot/16KB reads). Fixed cluster_ops_timing / chk_clean /
online_membership. **dkms_install** (packaging wired for old mxfs.1 layout →
read VERSION file, rsync v5 tree, SSH timeout 300s for the ~76s on-node build).
**online_resize** (idempotent leftover cleanup). Already green: mkfs_timing,
wedged_unmount, dmesg_clean, cache_caps.

**Core Mode A re-diagnosed on SCST (CAW works, write-through)** as a
**lost-update**, and the magic=0x0 artifact unmasked (see reframe section; fixed
P-H16 in v0.4.5). Reliable reproducer `tests/repro_modea.sh` (concurrent
`mkdir SAMEPATH; touch nodeN; sync`): **19-20/20 fail**, both nodes get a
DIFFERENT inode (lost-update / duplicate-create). Proven NOT the bug: sequential
cross-node visibility, distinct-name concurrent add, storage durability. DLM
serializes correctly (peer holds root EX → defers our BAST → releases → we
acquire). So the bug = the acquiring node's RMW base for the parent dir block
lacks the peer's committed entry → **incomplete acquire-side cache invalidation
for dir DATA blocks**. Two fixes DISPROVEN+reverted: bounded-wait+stale of the
skip_locked dir buf (staling discards, doesn't write; 20/20), and holding dp
ILOCK across `xfs_dialloc` (local ILOCK doesn't serialize across nodes; 17/20).
([[sess36-lessons-ship-gate-5-fixes-mode-a-re-diagnosis-magic-0x0-was-an-artifact]])

---

## sess37 (2026-05-29) — SOLVED the single-node log wedge; Mode A partial

### The single-node log wedge (fully solved) — VERSION 0.4.6, fix build 3CF4D8DAD71DD73C509C462

Consumed all of sess36 (16 wrong size/AIL theories). RULE-4 capture:
`P-LWEDGE` showed xfsaild `count=0` because `ail_target` stuck at `0x100000000`
below the whole AIL; `P-LGRANT` showed `rgrant≈4.26GB` on a 32MB log → free
clamps to 0 → every writer wedges in `xlog_grant_head_wait`; `P-LGRANT2`/
`P-LSUBNEG`+dump_stack pinned `xlog_grant_return_space(old=0x0, new=0x100000540)
diff=-4260724736` from `xlog_cil_ail_insert` on the FIRST checkpoint.

**ROOT CAUSE**: `ail_head_lsn` starts at 0 (cycle 0). `l_tail_lsn` is seeded to
`0x100000000` in `xlog_alloc_log` but `ail_head_lsn` is NOT. A freshly-mkfs'd
mxfs log is ZEROED, so mount's `xlog_find_tail` hits the fresh-log special case
(`xfs_log_recover.c ~1261`) and leaves `ail_head_lsn=0`. First CIL checkpoint's
`xlog_lsn_sub` sees `hi_cycle(1)!=lo_cycle(0)`, takes the cross-cycle branch,
uint32 `(0 - hi_block)` underflows → ~-4GB → grant += ~4GB → permanent wedge.
Upstream mkfs.xfs stamps the log (cycle 1 + unmount record) so the special case
never fires; mxfs leaves it zeroed. **Kernel code is byte-identical upstream —
this is a latent upstream bug only mxfs's zeroed-log mkfs triggers.** Log SIZE
(4/16/32MB) only delayed the wedge (more grant headroom) — never about
xfsaild/AIL/slice-LSN math.

**FIX (1 line)**: in the `xfs_log_recover.c` fresh-log special case, before
`goto done`: `log->l_ailp->ail_head_lsn = atomic64_read(&log->l_tail_lsn);`.
VERIFIED: full recursive `rsync -a open-gpu-kernel-modules → /mnt/shared`
single-node rc=0, 8137/8137, `diff -r` clean, no wedge. Reproducer:
`tests/repro_logwedge_full.sh` (the subset `repro_logwedge.sh` did NOT reliably
wedge). Gated instrumentation (`P-LWEDGE`/`P-LGRANT`/`P-LRET`/`P-LSUBNEG` +
counters) left in behind `mxfs.instr=0`.

### Mode A (cross-node concurrent same-name create) — partial

Proven root: `xfs_create` trusts the VFS negative dentry from `->lookup` and
never re-checks existence; cross-node a peer creates the same name in the
lookup→create window → two inodes (split-brain). Fresh-mkfs root is SHORTFORM
(reload refreshes the inode fork, coherency works once re-checked); after ~15
entries root converts to BLOCK dir and the acquire-side reload's H18 stale-walk
`xfs_buf_trylock`-SKIPS the locked dir data block → stale → split-brain.

- **B9A6EC22** — first pin/check attempt (wired the dormant D9 pin in
  `pinned_resource.c`: defer BAST when `i_dlm_pin_count>0`; new helper
  `xfs_dir_lookup_locked` lock-free). 19-20/20 → 11/20.
- **REVERTED to 9C72EEFE** — CRITICAL LESSON: the pin/check did a SECOND EX DLM
  acquire on a slot the pin still held EX → CAW compare expects free, finds
  EX-owned-by-us → `dlm_caw: caw_slot N I/O error -5` → `xfs_force_shutdown`.
  **Never double-acquire the inode DLM same-mode on a pin-held slot** (a PR→EX
  upgrade is fine; a same-mode re-acquire breaks CAW slot accounting).
  d_drop-on-EEXIST made it WORSE (20/20, cascaded the shutdown). Baseline
  9C72EEFE = 16/20 fail.
- **4ADC786A** — re-applied v2 with the CAW fix: allow the dir fast-path when
  `i_dlm_pin_count>0` (`xfs_mxfs_dlm.c ~1349`) so the pin-held BAST-deferred lock
  doesn't take the slow CAW re-acquire. 8/20, NO shutdown.
- **2A5CCF1E90ACC43EB77A31D** (VERSION 0.4.6 + fixes) — sess37 FINAL for the
  log-wedge+ModeA-v2 combo: log-wedge fix + pin/check + d_drop-on-EEXIST +
  `xfs_dir_lookup_locked`; H18 left as trylock-skip (blocking `xfs_buf_lock`
  DEADLOCKS — confirmed twice). 16/20 → ~1/12 shortform / 8/20 with block-dir.
- **622ADB5B** — heartbeat-priority: added `REQ_PRIO|REQ_SYNC` to
  `mxfs_pal_bdev_write_fua` (`pal/linux/kern.c:757`) so disklock heartbeat +
  CAW/metadata FUA jump ahead of bulk data. **Prevents the 4-node load-induced
  false-fence cascade**: under heavy load a node's heartbeat FUA (every
  `HB_INTERVAL_MS=2000`, under `ctx->lock`) starves; after `DEAD_THRESHOLD=31`
  missed checks (62s) survivors fence it (preempt its SCSI PR) → its next
  heartbeat gets `reservation conflict` → DLM shutdown → can't touch barriers →
  all framework tests timeout. 4-node IDLE 75s is stable; only heavy load
  triggers it. This gates ALL multi-node criteria.

### The robust Mode A create-path fix (design that stuck)

Do the existence re-check at the SINGLE existing acquire (`xfs_inode.c:801`,
`xfs_ilock(dp,EX)` held through commit) — holders>0 defers peer BAST, so NO
gap-1, NO double-acquire (no CAW issue), NO pin. The only obstacle: `xfs_dialloc`
already dirtied the tp, so cancel-on-EEXIST force-shuts-down (`XFS_TRANS_DIRTY`).
**Solution: on EEXIST, orphan the dialloc'd inode O_TMPFILE-style**
(`XFS_ICREATE_TMPFILE`, nlink=0, `xfs_iunlink`, clean commit, irele →
inactivation frees it — NO dirty-tp cancel). Builds **D89D508ED00CC56511652B9**
(robust re-check + tmpfile-orphan + d_drop-on-EEXIST + heartbeat-priority):
cache_coherency `cross_visibility` + `rename_visibility` dropped from 245-265s
EACH (timing out) to **~5s total**; `unlink_visibility` (block-dir barriers)
still ~120s residual.

### Block-dir lost-update — the two halves, and the fix that landed in sess38

DEFINITIVE workload-A measurement (`sess88` script, 4 nodes × 40 DISTINCT names,
no same-name): expected=160, pre_drop=42, post_drop=49, silent=111. Two proven
components: pre<post (drop_caches reveals ~7 entries the cache missed but disk
HAD = acquire-side staleness) and post≪expected (~111 missing from DISK =
**block-format parent-block RMW lost-update**: nodes concurrently RMW the shared
parent dir BLOCK, read a stale parent block, add their entry, clobber peers'
entries). This is why even distinct-name workload-A loses ~70%.

- **(A) Release-side**: BAST-DIR-STALE walk STALES (discards) dir data bufs, but
  a committed-but-not-home-written block (different AG than the inode, or
  CIL→AIL not yet inserted) gets discarded → on-disk home stays stale. Must
  durably WRITE dir DATA home blocks before release, THEN stale.
- **(B) Acquire-side**: DECISIVE `P-H18-LOCKED ino=128 d=120 flags=0x30 pin=0`
  (`XBF_DONE|XBF_ASYNC`, NOT WRITE, NOT DELWRI_Q, pin=0) → the locked parent
  block is thread/completion-held, NOT under active write I/O. This RULES OUT
  release-side writeback-drain and explains the blocking-lock deadlock (real
  lock inversion with the holder). **Blocking `xfs_buf_lock` in H18 re-tested
  under the no-pin structure: STILL DEADLOCKS** → the entire reload-time-stale
  approach (trylock/blocking/bounded-retry) is exhausted and ruled out.

**THE FIX = read-time lazy gen-counter invalidation** (deadlock-free): per-inode
`i_dlm_dir_gen` (`xfs_inode.h`, bumped on slow-path DLM reload for S_ISDIR at
`xfs_mxfs_dlm.c ~1549`) + per-buf `b_mxfs_dir_gen` (`xfs/xfs_buf.h`); in the
dir-block read path, when the caller already holds the buf lock, force a FUA
re-read + invalidate when `buf.gen < inode.gen`. Foundation laid across builds
**99A1B4E0BE1EDEFF6B43680** → **6E90A6D1DE71255D441046B** → **094235AAFA30611E56FE934**
(both fields added; read-path hook remained). The safe hook point is where the
buf is already locked (`xfs_buf_read`, `pal/linux/xfs_buf.c:714`), not at reload
time. sess37 ship-gate confirmed: **PASS=10, FAIL=2** (cache_coherency block-dir
barriers; rsync_paired needs `mxfs_multinode_bench.sh`). ([[sess37_lessons]])

---

## sess38 continuation (same memory body) — the coherency bug closed, then N-way residual

The `[[sess37_lessons]]` body runs into sess38. Build progression and findings:

- **1AFD468549F9289BF3B08DF** — block-dir read-time gen-invalidation LANDED in
  `xfs_da_read_buf` using `xfs_buf_incore(..., XBF_TRYLOCK, ...)` + dirty/pin/
  delwri guards, then normal `xfs_trans_read_buf_map` re-reads via FUA. Three
  dead-ends proven (RULE 4, sysrq evidence): in-place `_xfs_buf_read` on the
  tp-joined buffer LEAKED the ino-DLM holder count → peer BAST deferred forever →
  ETIMEDOUT shutdown; clearing XBF_DONE on a dirty/pinned buffer → CORRUPT_INCORE
  shutdown (fixed by the guard); blocking `xfs_buf_lock` in incore → cross-node
  rename deadlock (fixed by `XBF_TRYLOCK`). cross_visibility coherent, no wedge.
- **5691526E2AC8675B07C8E95** — writer-flush durability wait in `bast_process`
  for S_ISDIR (`P-SF-DURABLE`: bounded `log_force(SYNC)+ail_push_ag_sync+msleep`
  until inode out of AIL + unpinned; NO early release on dirty — invariant #1).
  Closes the P64 async-CIL→AIL race (BLI added to AIL by kworker AFTER log_force
  returns). repro_modea 6/12 → 4/16.
- **B33B0B2F** — 4 fixes (gen-inval, writer-flush, d_revalidate installed via
  `s_d_op`, cross-AG new-inode push); none moved repro_modea out of ~25-37%.
- **6B03A06CB6B634C28C1BFEF — *** COHERENCY BUG FIXED *** repro_modea 0/16.**
  ROOT (via `P-IGET-ENOENT ino=0x200083 ... buf_flags=0x80020`): a cross-node
  create-race loser's `xfs_iget` of the peer-allocated CHILD inode read a STALE
  CACHED cluster buffer that was `_XBF_FUA_FRESH` from when the inode was FREE
  (mode=0); the FUA gate SKIPS re-reading a `_XBF_FUA_FRESH` buf → peer's
  allocation never seen → `xfs_iget_check_free_state` returns -ENOENT
  (`xfs_icache.c:541`). FIX in `xfs_iget_cache_miss`: invalidate the stale cached
  cluster buffer for EVERY multi-node cache-miss (`if (dlm_acquired)` →
  `if (dlm_acquired || (m_mxfs_dlm && !single_node))`; `xfs_buf_incore` is a
  no-op when not cached).
- **441DB1DBD3FD016FD854E25** — d_revalidate REVERTED (took
  `xfs_ilock(dp,SHARED)→CAW poll` on EVERY cached path-walk → 4-node barrier
  timeouts). The icache cache-miss fix ALONE gives repro_modea 0/16.
- **8C04BCCCF72F31A5785BAE1** — cache-HIT reused-inode fix (`xfs_iget_cache_hit`
  before the line-711 `check_free_state`): for multi-node non-CREATE, cached
  `i_mode==0`, `igrab`+drop locks+`mxfs_dlm_reload_inode`+one-shot -EAGAIN/-ENOENT
  (loop-guarded). CLOSED the `.mxfs_barriers` grandparent split-brain (same inode
  10485888 on all 4 nodes). CAVEAT: `xfs_reinit_inode` PRESERVES cached mode
  (line 341/351), so the recycle path also reads stale — but `check_free_state`
  runs at line 711 BEFORE recycle at 721, so the fix belongs in cache_hit.
- **Final residual** (build 8C04BCCC): CLEAN 4-node bisection —
  concurrent dirent-ADD into a pre-created dir PASSES; concurrent same-path
  CREATE (`repro_modea4`) = **1/16, inodes AGREE (no split-brain)**, a transient
  marker-visibility miss right after create+immediate-read. The earlier "16/16
  N-way split" was CONTAMINATION (one node failed insmod — `unknown filesystem
  type 'mxfs'`, must retry — and ran mkdir on its LOCAL fs). State: repro_modea
  0/16 at 2 nodes, repro_modea4 15/16 at 4 nodes, `.mxfs_barriers` coherent.
  cache_coherency's zero-tolerance barriers still fail on the ~1/16 transient
  (per the user's timing rule, a transient IS a failure). ([[sess37_lessons]])

---

## Invariants / recurring failure modes (carry forward)

- **Invariant #1 — no DLM unlock before the drain pipeline completes.** Any
  bounded push that proceeds on timeout, or any early release on dirty, is a Mode
  A regression (sess32 v0.3.141-142; restated sess33; honored by sess38
  P-SF-DURABLE). Fresh cluster bufs use `_XBF_MXFS_ALLOC_QUEUED`; dir data blocks
  need the release-side durable-write-before-stale.
- **Never take a lock in bast_process / reload that overlaps xfsaild** — blocking
  `xfs_buf_lock` / `XFS_ILOCK_EXCL` across the drain deadlocks (sess20, sess34
  H8/H9, sess37 H18, sess38). The only deadlock-free invalidation is at READ time
  when the caller already holds the buf lock (gen-counter / `XBF_TRYLOCK`).
- **Never double-acquire the inode DLM same-mode on a pin-held slot** — breaks
  CAW slot accounting → `caw_slot I/O error -5` → force_shutdown (sess37).
- **ILOCK-across-CAW-poll is the structural deadlock vertex** (sess33) and the
  reason d_revalidate destabilizes (sess38) and dp-ILOCK-across-dialloc regresses
  (sess36). Drop ILOCK across the CAW poll; do existence re-checks under the
  single continuously-held EX at `xfs_inode.c:801` with O_TMPFILE-orphan-on-EEXIST.
- **Two instrumentation phantoms**: P21-INSTR (bast persists correctly) and
  P-H16 magic=0x0 (missing `bt_sector_offset`). Distrust any raw-LBA SCSI read
  that doesn't add the envelope offset.
- **Timing IS correctness**: slowness/timeouts are first-class failures; adaptive
  quantum, batched slot reads, and heartbeat-priority all exist to keep coherency
  ~ms-prompt, not eventually-consistent.
- **Cluster hygiene**: fresh mkfs + reboot-to-clean-slate before any criterion
  run; retry `insmod` until `cat /sys/module/mxfs/srcversion` succeeds (the
  `unknown filesystem type 'mxfs'` race is real and recurrent and silently
  contaminates 4-node results); `echo 1 > .../instr` needs the space.
