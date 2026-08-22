---
name: sess380-hot-slot-reads-are-the-probe-walk-not-the-cas
description: sess380: 93% of traffic on a contended CAW slot is READS, and 83% of those are find_slot's probe walk — not the CAS collision. Four hypotheses refute…
metadata:
  type: project
tags: [sess380, pace, caw, find_slot, measurement, refuted, 380]
---

# sess380 — the shared-directory pace cost is READS, and they are the probe walk

Serves `D-32NODE-SHARED-DIR-CREATE-PACE`. New harness
`tests/shared_dir_slot_cost.sh <P> <F>` counts every SCSI command the cluster
issues to the ONE CAW slot of a shared directory during a concurrent create
burst. Stable across 6 runs, 0.15.6-0.15.10, 32 nodes, 256 creates:

```
READ(16)+FUA       5,844 - 8,587   = 23 - 34 per create
COMPARE AND WRITE    424 -   515   = 1.7 - 2.0 per create (50-52% MISCOMPARE)
```

**Reads are 93% of all traffic on that sector and outnumber writes 13-16:1.**

`P383-SLOTREAD` (0.15.10+) tags each such read with `%pS` of its caller.
7,653 tagged reads in one run:

```
find_slot_skip             6,373   83.3%   <- the open-addressing PROBE WALK
caw_wait_for_grant           880   11.5%   <- the grant poll loop
caw_count_resource_slots     398    5.2%
bast_poll_fn                   2    0.0%
```

~25 of ~30 reads per create are slot RESOLUTION, re-walked from scratch on
every lookup. The resource's home slot IS the hot sector, so every walk reads
it. **The grant poll loop — what this defect's history blamed for four
sessions — is 11.5%.**

## Four hypotheses refuted by measurement (do not re-run these)

1. **"The unlock CAS loses to peers registering interest."** Built an exact
   transition classifier (reconstructs byte-for-byte the only image a pure
   registration could produce, then memcmps) and ran it with the acting knob
   OFF. Of 475 unlock miscompares: **1 benign (0.2%)**, 7 holder changes,
   **0 yield_to moves**, **467 (98.3%) MULTI-GENERATION**. The optimisation
   would fire on 0.2% of cases. `mxfs.caw_unlock_fastretry` ships **default 0**
   and should stay there; the classifier is kept because its histogram is what
   produced the finding.
2. **"Releases wake the whole waiter field."** `P382-WAKE`: the
   wake-the-field branch is taken **0.0%** of the time — 75.7% mint a single
   successor, 24.3% use an existing ticket, mean **1.25** nodes woken against
   4.70 waiters present.
3. **"The 2ms fastpoll window is the amplifier"** (a suspicion written into
   `mxfs.caw_inode_fastpoll`'s own comment long ago). Turning it OFF made reads
   **worse**: 26.6 → 32.9 per create.
4. **"The reads are backstop timeouts; the nudge carries the grants anyway"** —
   supported by `P297-TKT` showing 96.6% of ticketed waiters wake by nudge with
   **zero** swallowed nudges. Raising `mxfs.caw_poll_max_ms` 25 → 200 made
   **both** worse: reads 22.8 → 29.6, per-node wall 1577 → 2612 ms. Also
   removing the fastpoll window on top: 33.5 reads, 2767 ms.

Also settled structurally: there is **no I/O and no blocking call** between the
slot read and the CAW in the unlock loop, so that collision window is pure CPU
and cannot be narrowed.

## Why this matters for the planned fix

The sess379 RULE-5 format design (writer GATE + incarnation-tagged per-node
reader records) removes **CAS collisions**, which are **7%** of the traffic. It
does not by itself remove the probe-walk reads, which are **83%**. Re-score it
against these numbers before committing to an on-disk format change.

## Next thread

A create needs one acquire and one release. **Why are there ~25 `find_slot`
calls per create?** Count them per logical operation and name their callers
(acquire outer-retry loop, cached-grant ownership verify, unlock's per-retry
re-resolve, `caw_count_resource_slots`). There is already a slot-hint cache
(`caw_slothint`); establish whether it is consulted and why it does not remove
the read. It cannot remove the read entirely — the slot must be re-read to
validate the binding and build a compare image — so the win is
one-read-per-logical-operation, not zero.

## New knobs (all default to the historical constants)

`mxfs.caw_poll_max_ms` (25), `mxfs.caw_fastpoll_window_ms` (64),
`mxfs.caw_fastpoll_interval_ms` (2), `mxfs.caw_unlock_fastretry` (0),
`mxfs.caw_unlock_fastretry_max` (4), `mxfs.caw_unlock_fastretry_ms` (8),
`mxfs.caw_locktotal_ms` (800), `mxfs.caw_watch_slot` (-1).
