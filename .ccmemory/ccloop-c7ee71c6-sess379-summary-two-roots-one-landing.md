---
name: ccloop-c7ee71c6-sess379-summary-two-roots-one-landing
description: sess379 final: #526B root-caused and corrected, PAL I/O budget + verify governor landed 0.15.3 (181.5s->60.6s, board 27/27), 2 new critical defects f…
metadata:
  type: project
tags: [sess379, summary, 526B, 379, handoff]
---

# sess379 final state

Build: **VERSION 0.15.3**, `mxfs.ko` srcversion **4160A71E7B8987119991EA4**,
deployed and mounted on all 32 nodes. Full 32/caw board **27/27 PASS** (only
the RULE-6 `open_defects` policy cell red). Ledger: **open=50 of 109**, 36
critical (was 48 of 107 at session start — two filed, none closed).

## What was root-caused

**D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B** — the entry's stated mechanism
("root inode EX handoff chain, 2 s/hop") was WRONG and is corrected. The real
one: every node blocks in `umount`'s **initial `statx()`**, inside
`mxfs_dlm_ilock_begin`'s cached-grant ownership verify, which issues a
synchronous `READ(16)+FUA` of the root directory's CAW slot. Requested mode is
**PR (3)**, not EX. Both entering hypotheses were REFUTED by the same sweep
(zero P73-WAITSTALL / P139-LOCKTOTAL / P34-ACQ-SLOW fleet-wide, print caps not
exhausted).

Then the dominant term turned out to be a **separate, general** defect — see
memory `sess379-hot-slot-caw-serializes-one-lba-root-cause`.

## What was LANDED (0.15.2, carried into 0.15.3)

- **PAL per-task absolute I/O budget** — `mxfs_pal_io_budget_enter/exit`
  (`pal/linux/kern.c`, `pal/pal.h`), consulted in
  `mxfs_pal_scsi_read_fua_bdev`. Replaces `30 s × 1 SCSI retry × 20 wrapper
  retries` (~20 min per probe) with one deadline; `P302-FUA-READ-DEADLINE` →
  `-ETIME`. Unbudgeted callers keep the old policy verbatim, deliberately.
- **DLM verify governor** (`xfs/xfs_mxfs_dlm.c`): `dlm_verify_deadline_ms`
  (1000), circuit breaker 1 s→60 s (`P303-VERIFY-BREAKER`),
  `dlm_verify_max_inflight` (2), ±25 % jitter on both per-inode throttles.
  A skipped/abandoned probe is NO SAMPLE — cached grant kept, throttle not
  re-armed, and it may **never** demote. Wired at all three fast-path verifies;
  all three ENFORCE (P108-REACQUIRE / P106-STALE-EX / P-TCPEX-REACQ), which is
  why they were bounded in place rather than deferred.
- 0.15.3 adds `budget_ms=`, `cmd_ms=`, `comm=`, `pid=` to `P-FUA-READ-RETRY`
  (attribution) and raises its print cap 50→400.

Measured: **181.5 s → 60.6 s** max; board 27/27 after. The residual ~60 s is
SCSI error-recovery latency, not the budget — the block layer returns only
after EH, so the breaker bounds the RATE of stalls, not the first one.

## Two new critical defects filed

1. **D-HOT-SLOT-CAW-SERIALIZES-LUN-PER-LBA-379** — N nodes CAWing ONE slot
   serialize that LBA at the target. Conclusive: during a 28-of-32 storm a
   non-participant issued 9,837 direct `READ(16)+FUA` to the hot slot
   (worst **40,272 ms**) interleaved one-for-one with 9,837 to a cold LBA on
   the same device and nexus (worst **39 ms**). Leading candidate root for
   D-32NODE-SHARED-DIR-CREATE-PACE and D-READDIR-PEER-CACHED-DIR-PACE.
2. **D-DIRTY-SLICE-DEPARTURE-RETIRES-FENCE-KEY-UNMOUNTABLE-379** — retiring the
   PR key over a dirty slice makes the filesystem **permanently unmountable**;
   28 of 32 nodes could not rejoin. See its own memory.

## Two RULE-5 rulings banked

- `ccloop-c7ee71c6-sess379-GPT-ruling-detector-io-off-the-fast-path`
- `ccloop-c7ee71c6-sess379-GPT-ruling-hot-slot-caw-fix-shape`

The second corrected a real overclaim of mine (a 3 ms `stat` does not prove the
other LBA was healthy — it may issue no SCSI command at all). The ledger was
qualified, then the conclusive `sg_raw` form was run and it held.

## Harnesses added (all in-tree)

`tests/mass_umount_stall_probe.sh` (env `STAGGER_S`, `DEPART_N`, `SAMPLE_AT`),
`tests/mass_umount_reps.sh`, `tests/hotslot_contention.sh`,
`tests/lba_probe.sh`. Awareness docs updated: `pal.md` (the new API + its
contract), `tests.md` (the harnesses + two pitfalls).

## Where to pick up

The ledger `next` fields for both new entries are written as executable steps.
The single highest-value one, per the RULE-5 ruling: **make membership
departure logically invalidate every grant of the fenced incarnation** so stale
bits never block progress — it removes work rather than scheduling it better —
but it is UNSAFE with node-ID-only bitmap semantics (ABA on node-ID reuse), so
read the ruling's ordering and preconditions first.

## Measured constants worth reusing

- 32/caw board chunk walls held exactly to
  `board-32caw-chunking-measured-walls-and-harness-overhead`; the 5-chunk split
  (210/224/291/400/120 s wrappers) ran clean twice this session.
- `prep_cluster` at 32/caw: 50-118 s against an unmounted fleet; 188 s once when
  a stuck slot forced claim retries.
- The mass-unmount storm is **highly variable** — 27/28 nodes over budget in one
  rep and 1/28 in the next, same build. Never judge a fix on one run; that is
  what `mass_umount_reps.sh` exists for.
