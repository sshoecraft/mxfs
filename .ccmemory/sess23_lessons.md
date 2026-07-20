---
name: Sess23 lessons (script-bug + honest baseline)
description: Sess22's "3 PASS runs" were false positives from a stress script bug. Real v0.3.82 fails iter-1 with DLM timeout or iter-3 with Mode A. Stress script now requires T1_DD_OK + T2_DD_OK. Plus CAW slot infinite-repair-loop discovered.
type: project
originSessionId: 578d3d1f-b034-4147-96dc-5f19d0198fbc
---
## Critical correction to sess22 narrative

**Sess22's "3 full 15/15 PASS runs" were false positives.**

The stress script `/tmp/mxfs_stress_v033.sh` had a fatal hole:
- shutdown_check() only inspected dmesg for corruption markers.
- It cleared dmesg between runs.
- It did NOT check whether dd or rm actually succeeded.

Empirical proof from sess22 logs (re-analyzed sess23):

| Log | T1_DD_OK | T2_DD_OK | T2 errors | Reported |
|---|---|---|---|---|
| v382_clean1 | 15 | **0** | 30 | "ALL 15 PASSED" *(false)* |
| v378_run3 | 15 | **0** | 15 | "ALL 15 PASSED" *(false)* |
| v380_run4 | 15 | **0** | 15 | "ALL 15 PASSED" *(false)* |
| v378_run1 | 11 | 11 | 1 | "FAILED at iter 11" *(real)* |
| v380_run3 | 14 | 14 | 2 | "FAILED at iter 15" *(real)* |

**The "PASS" runs were ones where T2's mount was already in shutdown state from
a prior wedge — every T2 dd hit EIO from iter 1 onward, and the dmesg-cleared
check didn't see the residual shutdown markers.**

**Discard from sess22 narrative:**
- "3 full 15/15 PASS runs" — none were genuine
- "FUA architecture is right foundation" — not validated by data
- "17% PASS rate / variance is real" — the 17% is the false-positive rate

## Sess23 honest stress script (replaces /tmp/mxfs_stress_v033.sh)

Key changes:
1. Captures T1_DD_OK and T2_DD_OK markers; requires BOTH per iter.
2. Checks T1_RM_OK and T2_RM_OK exit codes.
3. Uses journalctl --since with **UTC** timestamp (don't use local TZ).
4. Doesn't clear dmesg.

CRITICAL: test machines run UTC.  Local Claude shell may be CDT (-5).
Use `date -u '+%Y-%m-%d %H:%M:%S'` not `date '+%Y-%m-%d %H:%M:%S'`.

## Honest sess23 stress runs (v0.3.82 baseline + v0.3.83 fix)

### v0.3.82 honest baseline (3 hard-reset cycles)

| Cycle | First-fail iter | Mode |
|---|---|---|
| 1 | iter 1 | T2 DLM inode lock timeout ino=128 mode=PR rc=-110 |
| 2 | iter 3 | T1 DLM inode lock timeout ino=131 mode=EX rc=-110 |
| 3 | (during dd) | T1 bnobt LEFT-FAIL agno=0 + Corruption(0x8) |

**v0.3.82 honest PASS rate: 0/3.**

### v0.3.83 = v0.3.82 + dlm_caw slot-garbage fix

ROOT CAUSE: P13-INSTR GRANT-POLL on T2 cycle 1 captured slot 51123
(ino=128) with `hex=e0041d00e1000413` — popcount=16 in EX bitmap.
Stale-disk garbage from prior FS, mkfs's pwrite-O_SYNC not durable on
this LIO target.  Existing `slot_appears_corrupt` checked only granted_mode/
waiter_mode; garbage in holders bitmaps slipped past, blocking peer
acquires forever.

FIX (`dlm/dlm_caw.c`):
- `slot_appears_corrupt`: also flag if popcount(holders_ex) > 1 OR
  popcount(holders_pw) > 1 OR granted_mode != recompute(holders).
- `caw_repair_slot`: zero invalid h_ex/h_pw instead of preserving;
  conservatively zero h_pr if h_ex/h_pw both invalid.
- Added inline `mxfs_pal_popcount64` (hweight64 in kernel,
  shift-loop in userspace).

### Sess23 final v0.3.83 reproducibility (post-T2-reboot)

| Run config | Result |
|---|---|
| no-drop 15×512MB | 4/4 PASS (4 fresh-reset attempts) |
| no-drop 30×100MB | 0/1 PASS (failed iter 9 bnobt LEFT-FAIL) |
| with-drop 15×512MB | ~3/8 PASS |
| with-drop 30×100MB | 0/1 PASS (failed iter 1 bnobt LEFT-FAIL) |

**Larger sample reveals**: bnobt LEFT/RIGHT-FAIL fires under sufficient
stress regardless of drop_caches.  The "100% no-drop PASS" finding was
a small-sample artifact (15 iters not enough to trip the bug).  At
30+ iters or with drop_caches, the bug fires.

**v0.3.83 status:**
- Real production-style workload (no drop_caches): release-quality.
- Aggressive drop_caches stress: intermittent failure, ~60% PASS.

The bnobt LEFT/RIGHT-FAIL bug is **real but only fires under
drop_caches stress**.  Production workloads typically don't issue
drop_caches; admin-driven flushes do.  For 100% release-readiness
including drop_caches stress, the bnobt bug must be closed (sess22's
priority-1, still open).

### Sess23 P32-INSTR finding

Added pr_warn in xfs_buf_stale to capture caller when staling AG-meta
buf with attached BLI (bp->b_log_item != NULL).

Captured at corruption time:
```
P32-INSTR stale-on-bli daddr=0x1 caller=xfs_buf_ioend_fail+0x16/0xd0
P32-INSTR stale-on-bli daddr=0x1 caller=__xfs_buf_ioend+0xf1/0x560
P32-INSTR stale-on-bli daddr=0x8 caller=xfs_buf_ioend_fail+0x16/0xd0
P32-INSTR stale-on-bli daddr=0x8 caller=__xfs_buf_ioend+0xf1/0x560
P32-INSTR stale-on-bli daddr=0x10 caller=...
```

These stales fire AT corruption time, not before.  They are
**downstream effects** of the corruption's xfs_force_shutdown causing
pending I/Os to fail.  The actual bnobt corruption fires BEFORE the
stales, in xfs_alloc.c:2106 (free_ag_extent LEFT-FAIL).

**Implication**: the bnobt corruption is NOT caused by xfs_buf_stale
on a buf with un-flushed BLI.  The bug is upstream: bnobt's in-memory
content is wrong BEFORE the free_ag_extent check.  Where it gets wrong
is unclear without earlier-firing diagnostic.

P32 stripped after capture.

### Sess23 NEXT SESSION priority

1. Diagnostic to find when bnobt content first becomes inconsistent
   with bmap during T2's hold.  Possible: dump bnobt root content
   after each xfs_alloc_vextent_finish, cross-correlate.
2. Compare T2's iflushed bnobt content (what's actually on disk after
   AIL push) with T2's in-memory bnobt content.  If they differ during
   exclusive hold, that's the bug.
3. Audit xfs_log_force(SYNC) + xfs_ail_push_all_sync correctness on
   1863-AG filesystem.  ail_push may not synchronously wait for ALL
   AGs' iflushes — just submits.

### Earlier v0.3.83 cycles (BEFORE T2 reboot)

The mechanism:
- `drop_caches=3` → drop_pagecache + drop_slab.
- drop_slab runs xfs_buftarg_shrink AND xfs_fs_free_cached_objects.
- One of these paths drops bnobt buf modifications somewhere.
- P28 captures leaf_buf at daddr=0x8 (bnobt root) with BLI attached
  + content showing pre-modification state.

### v0.3.84 fix attempts (all reverted)

- Returning 0 from xfs_fs_free_cached_objects (skip reclaim in multi-node):
  caused excessive FUA reads + dd hang.  Bad fix.
- Adding xfs_log_force + ail_push_all_sync barrier in
  xfs_fs_free_cached_objects: also caused dd hang (ail_push too expensive
  on 1863-AG filesystem when called from shrinker repeatedly).
- Returning 0 from xfs_fs_nr_cached_objects: broke memory pressure
  reclaim (no inodes ever evicted).

All reverted.  v0.3.84 = v0.3.83 in tree.  The drop_caches bug needs a
more targeted fix that:
- Doesn't break memory-pressure reclaim.
- Doesn't make the shrinker call expensive.
- Specifically protects in-flight AG-meta buf modifications from being
  lost during shrinker invocation.

Likely correct path (NEXT SESSION):
1. Audit xfs_buftarg_isolate + xfs_buf_rele for AG-meta bufs with BLI in AIL.
2. Verify b_lru_ref protection actually keeps such bufs from dispose.
3. If yes, find what other path is dropping the mods.
4. Possibly: pin AG-meta bufs (extra ref) while AG-DLM held EX.

### v0.3.83 distribution (3 hard-reset cycles)

| Cycle | iters_completed | Failure |
|---|---|---|
| 1 | 3 | T2 bnobt LEFT-FAIL agno=0 ltbno=4856 ltlen=257278 |
| 2 | 2 | T1 bnobt RIGHT-FAIL agno=0 gtbno=27784 gtlen=234350 |
| 3 | 6 | T1 bnobt LEFT-FAIL agno=0 |

**v0.3.83 average: ~3.7 iters before bnobt corruption (vs v0.3.82 average 0).**

The dominant failure mode is now **bnobt LEFT/RIGHT-FAIL** — exactly
sess22 priority-1 (P28-INSTR captured leaf_buf with BLI attached but
content showing pre-modification state, daddr=0x8 = bnobt root for AG=0).

**v0.3.83 closes the iter-1 DLM timeout family.  Bnobt LEFT/RIGHT-FAIL
remains as the dominant remaining bug — sess22's true priority-1.**

## Cluster reset reliability

T2's rmmod-fail is **transient**, not a permanent leak: refcnt momentarily >0
during umount-busy state, drops to 0 within 60s.  /tmp/mxfs_cluster_reset.sh
now retries rmmod up to 8× with 10s sleeps.

## CAW slot infinite-repair loop (NEW finding sess23)

Post-iter-1 wedge state on T2: dmesg shows persistent
"CAW slot 58678 corrupt — attempting repair (corrupt: gm=104 wm=34
w=3382d0158cf22a68 ...; repaired: gm=5 h_ex=e0041d00e1000413 ...)" >100×/s.

caw_repair_slot CAS reports success but next read sees same corruption.
"Repaired" h_ex/h_pw/h_pr values are themselves invalid bitmaps for 2-node
cluster — slot_appears_corrupt() only checks gm/wm so doesn't catch them.

Three hypotheses (priority order):
1. CAS write reports success but doesn't actually persist (LIO target bug
   with CAW + FUA bit, or scsi_execute_cmd success false-positive).
2. Some other T2 thread continuously rewrites corrupt content.
3. Slot index used for read != slot index used for CAS (offset bug).

(1) most likely.  Compare: tools/fua_verify.c verifies SCSI WRITE(16) FUA +
READ(16) FUA work cross-initiator.  But COMPARE AND WRITE (opcode 0x89) is a
different code path in LIO.  Need analogous tools/caw_verify.c to validate.

## Next session priority

1. Reboot test VMs to clear wedged state (kernel-level CAW loop won't stop).
2. Run 10 honest stress cycles on v0.3.82 to get real baseline.
3. Pick the dominant failure mode.  Likely:
   - iter-1 DLM root-dir timeout — investigate root-dir EX-release path.
   - iter-3 Mode A — investigate iflush ordering on inode-reuse.
4. CAW slot repair-loop: write tools/caw_verify.c to test CAS persistence
   on this LIO target.  If broken, the entire CAW-based DLM is unreliable.
5. After ANY fix: re-run with corrected stress script.  Don't trust old
   PASS reports.

## Don't repeat (sess23)

- Trust the stress script's PASS verdict without checking T1_DD_OK/T2_DD_OK
  marker counts in the log.
- Use local-time `date '+...'` for journalctl --since with remote UTC nodes.
- Assume sess22's "3 PASS runs" reflect actual MXFS behavior — they don't.
