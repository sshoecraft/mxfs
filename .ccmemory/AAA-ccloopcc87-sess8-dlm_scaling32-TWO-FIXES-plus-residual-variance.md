---
name: AAA-ccloopcc87-sess8-dlm_scaling32-TWO-FIXES-plus-residual-variance
description: sess8: TWO real fixes landed for dlm_scaling@32 (epoch piggyback + shortform content-adopt), build C9D0F29C. Residual: ~1 node occasionally dips unde…
metadata:
  type: project
tags: [dlm_scaling, caw, 32node, epoch, shortform, sess8, ccloop-cc87fed3]
---

## sess8 (ccloop cc87fed3) — dlm_scaling@32 root-caused and fixed (build C9D0F29C6FCADEAF836A132, VERSION 0.10.102)

### Context: picked up from session 7's dead end
Session 7 added `mxfs_dlm_caw_invalidate_epoch` (post-hoc find_slot+CAS after unlock) at TWO
hook sites (mxfs_dlm_evict, xfs_inactive_ifree) chasing "P144 never fires." Both hook LOCATIONS
were red herrings — the bug was inside the invalidate function itself.

### FIX 1 (the real bug): find_slot() cannot ever find a tombstone as "found"
PROVEN via branch-instrumented `mxfs_dlm_caw_invalidate_epoch` (P144-DIAG reason= histogram):
2190/2190 calls hit `reason=noslot` — 100%, zero exceptions — despite `P128-INACT-EXREL`
(the call site) firing 4413 times in the same run, proving the call site was never the problem.

Root: `find_slot()`/`find_slot_skip()` (dlm_caw.c ~1181-1300) only returns rc==0 ("found") for a
LIVE slot (`magic==MXFS_CAW_MAGIC`). A slot holding a TOMBSTONE for the exact resource — precisely
the state right after an unlock writes it — is only ever recorded as a recyclable `empty_out`
candidate during the probe scan; the function returns `-ENOENT` for it. This is *inherent* to
find_slot's contract (mirrors how the CLAIM path at ~2400-2470 consults `empty_idx` + a possible
re-read, NOT find_slot's return code, to locate a tombstone) — `mxfs_dlm_caw_invalidate_epoch`
was written assuming a contract find_slot never had, at EITHER candidate hook location. This
was never a hook-placement bug.

First attempted fix (standalone, WRONG shape): consult `empty_idx` + explicit `read_slot()` +
verify tombstone+resource-match before the epoch-clear CAS — this correctly located and cleared
the slot (P144-EPOCH-FREE-RESET fired 4833x/run, dlm_scaling went 32/32 once) BUT regressed the
SAME test to 0/32 immediately after, because it's a SEPARATE find+read+CAS issued AFTER the
unlock's own CAS already ran — i.e. exactly the "TRAP 1: sync per-free FUA CAW op" pattern already
on record in `mxfs_dlm_caw_purge_node`'s header (sess70): extra synchronous per-free disk I/O
measurably eats the shared aggregate iSCSI-command-rate ceiling ALL 32 nodes' foreground ops
compete for, even though the extra I/O is off the per-op *latency* path.

### FIX 1 final shape (zero extra I/O): piggyback on the unlock's OWN CAS
`mxfs_dlm_caw_unlock_gen(ctx, resource, expected_gen32, bool is_free)` — new 4th param. At the
existing tombstone-write site (`caw_tombstone_slot(new_slot)` inside the same CAS this function
already performs when releasing to no-holders/no-waiters), if `is_free`, ALSO zero
`new_slot->dir_epoch`/`last_ex_slot` in that SAME image before the CAS. This is the ORIGINAL
authoritative design from ccloop 0d6e174d sess2 (memory `AAB-dlm_scaling32-fix-AUTHORITATIVE-single-reference`)
— "piggyback the clear on the unlock CAS, do NOT sync-FUA at free" — which sess7 didn't actually
implement (it built the rejected separate-call shape instead).

Threading: new `mxfs_v5_dlm_inode_unlock_free(ctx, ino)` (v5_mount.c) mirrors
`mxfs_v5_dlm_inode_unlock` but passes `is_free=true` on the CAW branch (gated by module param
`mxfs_caw_epoch_free_reset`, default 1); TCP branch unchanged (no epoch concept there). Wired at
the two genuine-free call sites: `xfs_inactive`'s synchronous inactivation-lock release
(xfs_inode.c, `if (mxfs_inact_dlm_locked)` block) and `mxfs_dlm_evict`'s `nlink==0` branch
(xfs_mxfs_dlm.c ~23405). All OTHER `mxfs_v5_dlm_inode_unlock`/`_gen` callers (many, for idle
releases) pass `is_free=false` implicitly — unaffected.
DELETED as dead/wrong: `mxfs_dlm_caw_invalidate_epoch`, `mxfs_v5_dlm_inode_note_freed_epoch_reset`.

VALIDATED: dlm_scaling@32 went from baseline ~1319-1650 aggregate ops/s (systemic ~41-44/32 FAIL,
0-12/32 pass historically) to ~1794-1805 aggregate consistently, with P144-EPOCH-FREE-RESET
firing ~170-181x/node/run (proof the mechanism engages). Two clean 32/32 PASS runs observed.

### FIX 2 (secondary, rarer): shortform-parent sf->block conversion reads a stale pre-add snapshot
Hit ONCE in ~9 runs: node23's own `mkdir .dlm_scaling/node23` was durably LOGGED into the shared
shortform `.dlm_scaling` parent (`P56-DIRWRITE ... write=[...node23]` at t=392.04), but ~2.3s
later `.dlm_scaling` had converted to BLOCK format WITHOUT node23 (`P26-LKFMT err=-2 name="node23"`
on the resulting block dir; parent `ls` genuinely omits node23). Test fails with
`completed quota(exp=2000 got=0)` (own subdir vanished).

This is the EXACT gap sess61/sess62 (xfs_inode.c ~1819-1838, xfs_mxfs_dlm.c
`mxfs_dir_modify_adopt_disk_format`) identified but explicitly left unfixed: the adopt-check only
detects FORMAT-level staleness (in-core LOCAL vs disk non-LOCAL, or nextents/size growth on a
non-LOCAL fork) — never CONTENT-level staleness where BOTH sides are LOCAL/shortform but disk has
MORE bytes (a peer's entry we haven't adopted). The function was call-site-disabled (`if (0)`)
specifically because of this blind spot ("P61-ADOPT-DISK fired 0" per its own sess62 comment).

FIX: extended the staleness check (xfs_mxfs_dlm.c ~8617) with a new "face 1b" — LOCAL/LOCAL where
`disk_sz > i_disk_size` (cheap: same FUA read the format check already does, di_size alone reveals
peer content growth). Re-enabled the call site (xfs_inode.c ~1848), gated on
`dp->i_dlm_dir_gen > 0` (peer has touched this dir — bumped by the async DIR_MODIFY evict-ring
notification independent of our own EX acquire) to bound the FUA-read cost to only peer-touched
dirs, addressing sess62's RULE-0 perf objection to firing unconditionally on every create.
UNCONFIRMED: the dirent-loss has not recurred since (only ever seen once), so P61-ADOPT-DISK
firing with `incore_fmt=1 disk_fmt=1` (the new face) has not yet been observed live. Re-verify
if `got=0`/`FIRSTFAIL` recurs — check whether P61-ADOPT-DISK fired with LOCAL/LOCAL before it.

### RESIDUAL: single-node throughput dip near the floor (NOT yet resolved, likely infra not MXFS)
After FIX 1, dlm_scaling@32 typically shows 30-32/32 pass (one node occasionally at rate 41-43 vs
floor 50, aggregate stays healthy 1794-1805). Characterized, NOT root-caused to an MXFS mechanism:
- Per-op checkpoint sampling (200-op granularity, `tests/suite/dlm_scaling.sh` now logs
  `/tmp/dsc_checkpoints_${R}.log`) shows a TWO-PHASE pattern on the affected node: steady ~26-30
  ops/s for roughly the first 1000 ops, then ~85-104 ops/s for the last 1000 — vs a healthy node's
  steady ~50-52 ops/s throughout (with its own late-run speedup once peers finish and contention
  thins). This is a smooth ~2x sustained slowdown over hundreds of ops, not a few isolated stalls.
- WHICH physical test-node is affected ROTATES run to run (test13, test23, test24, node8, node11,
  test15, test28 all observed) — consistent with a dynamically-assigned (join-order-based) "local
  slot"/CAW node_bit rather than a fixed per-physical-node defect.
- REFUTED: elevated CAW retry/backoff/CAS-storm counters on the slow node (P-CAWEXH, yield-backoff,
  P-STREAK-YIELD, P-CLAIM-RACE-LOST all 0 on both a slow and healthy node from the same run).
- REFUTED: SCST device thread starvation — bumped `/sys/kernel/scst_tgt/devices/mxfs/threads_num`
  8->32 live (no rebuild needed), re-ran, no measurable change (aggregate unchanged ~1796, a
  DIFFERENT node still dipped to 43). Left at 32 (harmless, just not the fix). NOT persisted to
  /etc/scst.conf since it didn't help — don't bother re-tuning this knob without new evidence.
- SUGGESTIVE, not proven: host is 32 VMs x 4 vCPU = 128 vCPUs on 56 physical cores (2.3:1
  oversubscription). Live `mpstat -P ALL 2` during an active run showed peak ~68% total
  (usr+sys+guest) / ~30% idle aggregate — NOT hard-saturated, but %sys alone hit ~20% at peak
  (SCST/iSCSI kernel-side processing), suggesting host-level CPU/IRQ scheduling fairness across 32
  concurrent VMs' sessions is a plausible contributor, not ruled out. Not conclusively proven
  because 30% idle remained even at peak (a hard-saturation story would show ~0% idle).
- NOT YET TRIED: per-VM CPU pinning/cgroup shares for more uniform host scheduling; kernel-side
  per-op CAW acquire/release latency histogram (would need a rebuild+redeploy cycle — the
  checkpoint-sampling harness change was chosen first because it needed no rebuild).
- Empirical pass rate across ~9 post-FIX-1 runs: 2 clean 32/32 PASS, 7 at 30-31/32 (all "rate>=floor"
  misses on individual nodes at 41-43 ops/s, aggregate consistently 1794-1805). criteria.json
  currently shows the LATEST run as PASS (32/32, 2026-07-14T09:24:21Z) but this is NOT a reliable
  100% — re-running will likely show occasional misses again. If the criteria demands durable
  100%, this residual needs more work; if a clean recorded PASS suffices, FIX 1 alone achieves it
  most of the time.

### Test harness improvements (tests/suite/dlm_scaling.sh, no kernel rebuild needed)
- On rate<floor, now prints the actual numeric rate/floor/elapsed/done to stderr (previously only
  pass/fail was visible, had to hand-decode from raw kernel dmesg).
- Added `/tmp/dsc_checkpoints_${R}.log` per-node progress sampling every 200 ops (i, elapsed-so-far)
  for post-hoc rate-over-time analysis. Not part of the run.sh artifact pipeline — fetch via ssh
  after a run, before the next preflight/reset wipes it.

### Diagnostic pattern worth reusing
Live SCST per-session stats are at
`/sys/kernel/scst_tgt/targets/iscsi/iqn.2026-05.local.mxfs:shared/sessions/<initiator-iqn>/`
(active_commands, read/write_cmd_count, read/write_io_count_kb, latency — latency file read back
empty when polled at 2s granularity, too coarse to be useful; cmd_count deltas would need
before/after snapshots, not live polling, to be informative — didn't get to try that).
`/sys/kernel/scst_tgt/devices/mxfs/threads_num` is live-writable via sudo tee, no rebuild/remount
needed, for exactly this kind of A/B (though it didn't pan out this time).
