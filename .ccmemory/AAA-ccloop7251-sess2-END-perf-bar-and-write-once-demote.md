---
name: AAA-ccloop7251-sess2-END-perf-bar-and-write-once-demote
description: sess2 END: user perf bar (≤120s/test@32, enforce, never widen); cold foreign stat 6.1ms = creator's cached EX handoff; 0.11.11 write-once EX demote B…
metadata:
  type: project
tags: [mxfs, performance, budgets, dlm, handoff]
---

# sess2 END (ccloop 72513a13) — perf bar reset + write-once demote

## User directive (governs all future work)
No test may take 1-2 hours EVER. 32 nodes of users reading/writing must see
seconds-to-minutes. Budgets = enforced product requirements: ≤120s/test at
32 nodes, 32-rung ≤20 min, ladder <1h. NEVER widen a budget toward a
measured wall (the dir_reuse 60*N→90*N→140*N history is the named
anti-pattern; that override is DELETED from run.sh, manifest flat 120 is
authoritative). Debug with bounded minutes-scale experiments (8 nodes,
DRC_ROUNDS=6), not hour-scale boards.

## RULE-4 ledger for dir_reuse 22.5s/round at 8 nodes
Phase split (mxfs-DRCph markers): create 3.2s / verify 8.5s / rm 7.4s /
3s barrier gap.
- REFUTED: dirop_durable_caw per-op publish (A/B no diff) — the sess6
  "round-17 dirent loss" cost model is obsolete; newer guards changed the
  economics. Knob left ON (costs nothing measurable now).
- REFUTED: atime-EX (noatime no diff), lock waits (no P138-WAIT), FUA
  volume (no FUA-COUNT).
- PROVEN: cold foreign stat 6.1ms avg/33ms max (open 0, read 0.3ms, device
  ~0.8ms) = on-demand EX→PR handoff because the CREATOR keeps cached EX on
  every fresh file. Produce-then-consume workloads pay it per file per
  first reader.

## Fix landed (0.11.11 srcversion 5621731E17F26DFAC3BCFB5 — BUILT, NOT TESTED)
Write-once EX demote: mxfs_dlm_queue_ex_demote + ex_close_release_ms
(default 250ms) in xfs_mxfs_dlm.c (~27360, next to the proven PR sibling);
xfs_file.c release hook now fires for WRITE closes too (DLM layer routes).
Shape lesson: pr_idle_release_ms default was REFUTED at 32 (per-STAT timer
storm during verify); this arm is per-written-file at CLOSE, creator-only,
delay absorbs write-then-reread. Dwork runs the full Invariant-1 drain
(same as MHT-deferred EX releases) — durability unchanged.
NEXT: deploy to 8/cawd, rerun microbench (expect stat ~1ms) + 6-round
dir_reuse (expect verify ≪8.5s). Then rm phase + barrier gap → ≤6s/round.

## Also this session (earlier)
- 0.11.8 mmap-ABBA fix PROVEN (mmap 0/32→32/32 6s).
- 0.11.9 AIL-wedge tripwires armed (P-BUF-FREE-WITH-ITEMS + gen stamps).
- 0.11.10 CAW liveness extension PROVEN (fio board-killer → PASS;
  P-WAIT-EXTEND; hard cap 480s).
- AG Phase-2 claim livelock (P12-READOPT while bast_pending → minutes-long
  AG holds under fio) — deadlock-safe bounded-admission design in sess2
  transcript ~19:30-19:45Z, NOT yet implemented.
- Host health gates boards: clyde swap full + load ⇒ everything degrades
  (LUN = fileio in page cache). Hygiene: drop_caches + swapoff/swapon.
- Idle mounted node burns 10% guest CPU (mxfs-worker poll) — open debt.
