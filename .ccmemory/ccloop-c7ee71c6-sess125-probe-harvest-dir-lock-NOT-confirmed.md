---
name: ccloop-c7ee71c6-sess125-probe-harvest-dir-lock-NOT-confirmed
description: sess125 NEGATIVE RESULT: P70-BP harvest does NOT confirm dir-EX ping-pong as the 22ms/create mechanism. Only 25 events on the shared dir. Do not patc…
metadata:
  type: reference
tags: [rule4, negative-result, instrumentation, dir-create-pace, crash_consistency]
---

# sess125 — RULE 4 step 2a: dir-EX-clamp hypothesis NOT CONFIRMED

The recipe and the re-attribution stand. **The proposed MECHANISM does
not.** Recording this so the next session does not patch the MHT clamp
on a hypothesis the instrumentation failed to support.

## What was solid (unchanged)
Deterministic recipe (3/3 FAIL, hostload 16.35 / 8.16 / n-a), the
empty-vs-populated A/B, and the arithmetic (3200 creates, ~22ms each,
~70s). See `ccloop-c7ee71c6-sess125-ROOTED-crash-consistency-354-empty-dir-recipe`.

## What the probes did NOT support

Hypothesis was: the shared dir's EX lock ping-pongs once per create
because `i_dlm_tenure_ops <= 1` clamps the MHT window to 15ms
(xfs_mxfs_dlm.c:18518, 18569; q_ns twin at 18429).

Harvest from the FAILING run (test5, watch_ino = **31457408** = the
`.crash_consistency` dir):

- `P70-BP ino=31457408` — only **25 events on the whole run**.
- Top P70-BP inodes are 537899 (183), 537894 (163), 537857 (140),
  27800483 (118), 128 (93), 56623232 (74) — the shared dir is not even
  in the top 6.

So the shared directory inode is NOT undergoing thousands of
BAST/tenure cycles. 3200 creates cannot be explained by 25 dir-lock
tenures. **The dir-EX ping-pong mechanism is refuted as the dominant
cost.**

Aggregate `P70-BP held_ms/tops` histograms (all inodes, per node) also
cut against it: dominant bucket is `held_ms=0 tops=0` (~2000-2400/node),
plus a `tops=1 held_ms=2..6` family (SHORTER than the 15ms clamp — the
"~5ms grace" path), AND genuinely batched tenures `tops=8,9,12,13`.
Batching is working in many places.

## Where to look next — probe census from the failing run (test5)

    12069 P68-EVDECIDE      <- BY FAR the largest; start here
     8728 P70-BP
     6671 P165-AFFINE-STALE
     5646 P50-RD
     5429 P144-WR
     4762 P71-HOLD
     2751 P150-ALLOC-UI / 2751 P150-ALLOC-FIN
     2495 P82-REM / 2495 P150-FREE-IBT / 2485 P150-FREE-FIN
     2309 P145-ALLOC
     2047 P9-NLEDGE
     1369 P7B-BASTNOTIFY

Note the ~2500-2750 counts on the P150 ALLOC/FREE families and P82-REM
track the ~3200-create scale closely — inode allocation/free, not
directory locking, is the better-matching suspect. P68-EVDECIDE at 12069
(~4x the create count) and P165-AFFINE-STALE at 6671 (~2x) deserve
identification first.

## Method note
`P70-BP` is NOT gated to watch_ino — it fires for all inodes. Any future
harvest must filter by `ino=` before drawing conclusions. The first
aggregate histogram in this session was misleading for exactly that
reason.

## Next step
Identify what P68-EVDECIDE / P165-AFFINE-STALE / P50-RD are and get
per-phase (datawrite-window) counts rather than whole-run counts, then
re-form the mechanism hypothesis. Do NOT edit the MHT clamp until a
probe directly ties the wall time to a named wait.
