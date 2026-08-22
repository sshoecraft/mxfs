---
name: sess379-hot-slot-caw-serializes-one-lba-root-cause
description: sess379 ROOT CAUSE: N nodes CAWing ONE CAW slot serializes that LBA at the target; non-departing node saw 59,742ms on the root slot vs 3ms on another.
metadata:
  type: project
tags: [sess379, 526B, caw, rule0, root-cause, hot-slot, scsi, pace]
---

# sess379 — the mass-unmount stall is a PER-LBA CAW serialization, not an unmount bug

Ledgered as **D-HOT-SLOT-CAW-SERIALIZES-LUN-PER-LBA-379** (new, critical);
**D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B** is now one symptom of it and its
entry's original mechanism ("root inode EX handoff chain, 2s/hop") is WRONG and
has been corrected in the ledger.

## The one measurement that settles it

`tests/mass_umount_stall_probe.sh 32 5` with `DEPART_N=28`: 28 nodes unmount at
once, test32 does **not** unmount and just alternates two stats for 90 s.

| what test32 stat'ed | worst |
|---|---|
| `/mnt/shared` — the ROOT dir, ino 128, the slot every departing node CAWs and reads | **59,742 ms** |
| `/mnt/shared/.mus_probe` — a different file, different slot | **3 ms** |

Same node, same mount, same code path, same window. **The LUN is not saturated;
one LBA is.**

## Mechanism

SBC requires COMPARE AND WRITE to be atomic, so the target blocks commands
overlapping an in-flight CAW range. MXFS's CAW DLM keeps a resource's whole
holder bitmap in ONE 512 B slot, so every node that holds / acquires / releases
a grant on inode X reads and CASes the SAME LBA. For a resource N nodes share —
the mount root above all — the offered load on that one LBA is O(N) CAWs plus
O(N) FUA reads, mutually serialized. Past the service rate the queue exceeds the
initiator SCSI timeout, the initiator escalates to ABORT_TASK, and the EH cycle
sets the ~60 s quantum.

This is the leading candidate mechanism for **D-32NODE-SHARED-DIR-CREATE-PACE**
(~42× at 32 nodes for creates into ONE shared dir) and
**D-READDIR-PEER-CACHED-DIR-PACE**. If it is, closing it closes three entries.

## The elimination chain (all measured this session, 32/caw)

1. **Blocking site, captured stack**, identical on 30/32 nodes, D-state:
   `blk_execute_rq < scsi_execute_cmd < mxfs_pal_scsi_read_fua_bdev < read_slot
   < find_slot_skip < mxfs_dlm_caw_held < mxfs_v5_dlm_inode_held_rawmode <
   mxfs_dlm_ilock_begin < xfs_ilock < mxfs_getattr_dlm_lock < vfs_statx`.
   The block is in `umount`'s **initial statx()**, not in unmount. Requested
   mode is **PR (3)**, not EX.
2. **35 P-FUA-READ-RETRY fleet-wide, every one on the same LBA**, `ret=0x30000`
   = host_byte 0x03 = **DID_TIME_OUT**.
3. **Both entering hypotheses REFUTED**: zero P73-WAITSTALL, zero P139-LOCKTOTAL,
   zero P34-ACQ-SLOW fleet-wide — so neither a leaked `ISTATE_ACQUIRING` with no
   owner nor a slow `caw_lock`. Print caps were not exhausted (P73 had fired 0
   times ever this boot).
4. **Stagger control**: same fleet, `STAGGER_S=3` → all 32 nodes unmount in
   **0.04–0.09 s**. Unmount itself is ~50 ms; teardown once reached is ~0.5 s.
5. **Read-only control** (`tests/hotslot_contention.sh 32 30 200`): 32 nodes
   stat'ing the same root for 30 s = 79,459 stats, worst 166 ms, mean 5 ms, ZERO
   FUA retries. The read half alone on the same hot LBA is harmless.
6. **Participant scaling** (no middle ground — a node either gets through in
   ~0.2 s or eats whole ~60 s EH units): 8 simultaneous departures → 0/8
   stalled; 24 → 10/24 at 60.3 s; 28 → 27/28, max 180.9 s; 32 → 31/32.
7. **Target side**: clyde runs SCST `3.11.0-pre+caw-abort-reclaim.2`, i.e. the
   known CAW↔READ scsi_atomic wedge fix IS installed — not that infra bug.
   Stall window = 330 `scst_abort_cmd` + 165 ABORT_TASK TMFs, continuous from
   storm+15 s to storm+45 s; the clean control window = no target entries at all.
   **PR is not the mechanism**: 32 READ KEYS total in the stall window, no
   `P301-PR-UNREG-*` on any node, retirement loop (6 attempts / 20 s) succeeded
   first try everywhere.

## What was LANDED this session (0.15.2, sv C46FD856C41CB8A33B1CB35)

Not the fix for the above — the fix for the **amplification**, per the sess379
RULE-5 ruling (ccmemory
`ccloop-c7ee71c6-sess379-GPT-ruling-detector-io-off-the-fast-path`):

- **PAL per-task absolute I/O budget** — `mxfs_pal_io_budget_enter/exit` in
  `pal/linux/kern.c` + `pal/pal.h`, consulted inside
  `mxfs_pal_scsi_read_fua_bdev`. Replaces `30 s timeout × 1 SCSI retry × 20
  wrapper retries` (~20 min for ONE slot probe) with one deadline; per-attempt
  budgets capped by what is left; `P302-FUA-READ-DEADLINE` on exhaustion,
  returning `-ETIME`. Unbudgeted callers keep the historical policy verbatim —
  deliberately, because turning a transient target stall into `-EIO` on an
  authoritative read is how a healthy node manufactures a shutdown (-356).
- **DLM verify governor** in `xfs/xfs_mxfs_dlm.c`: 1000 ms deadline
  (`dlm_verify_deadline_ms`), exponential circuit breaker 1 s→60 s after a
  timeout (`P303-VERIFY-BREAKER`), 2-deep in-flight cap
  (`dlm_verify_max_inflight`), ±25 % jitter on both per-inode throttles.
  A skipped/abandoned probe is **NO SAMPLE**: cached grant kept, throttle NOT
  re-armed, and it may never demote.
- Wired at all three fast-path verifies. **All three ENFORCE** (P108-REACQUIRE,
  P106-STALE-EX, P-TCPEX-REACQ demote the cached grant to NL) — they are not
  pure detectors, which is why they were bounded in place rather than deferred.

Measured: max wall **181.5 s → 60.65 s**, and the 0/60/121/181 staircase
collapses to a single step. Full **32/caw board 27/27 PASS** after (only the
RULE-6 policy cell red) — no regression from putting the ilock fast path under
a deadline.

The residual 60 s is **not** the verify's budget: with a 1000 ms command timeout
the block layer still returns only after SCSI EH completes. The breaker bounds
the RATE of stalls, not the first one. That is the ruling's own warning about
short SCSI timeouts, and it is why the real fix has to remove the convergence,
not just bound the wait.

## Reusable harnesses added

- `tests/mass_umount_stall_probe.sh <N> [BUDGET_S]` — env `DEPART_N=<k>` (k<N
  arms the non-departing observer that times the root slot against another
  slot), `STAGGER_S=<s>`, `SAMPLE_AT="<s> <s>"` (in-flight `/proc/<pid>/stack`
  sampling — comm and stack only, never cmdline/maps).
- `tests/hotslot_contention.sh <N> [SECONDS] [BUDGET_MS]` — the read-only
  control.
