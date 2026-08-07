---
name: ccloop-c7ee71c6-sess33-starvation-fix-and-coldread-split
description: 292: strikeout→1s-downshift (intervention-proven idle-holder starvation root, D-CAW-YIELD); NEW OPEN D-CRASH-COLDREAD-STALE-SPLIT (5-node bimodal sta…
metadata:
  type: project
---

# sess33 pt2 — the starvation root fix + the cold-read split

## D-CAW-YIELD-STARVATION: idle-holder mechanism PROVEN + FIXED (0.11.292)
Chain (all live-rig evidence): collision injection (fix26/27_delay_ms=25)
parked admits 20s+ → P36-STRIKEOUT (2500 strikes @4ms) fleet-wide → dwork
STOPS re-arming with bast_pending SET → holders go IDLE → **no re-fire
exists for an idle holder (CAW cannot push a BAST)** → test1's EX waiter
starved 23.7 min (P-ACQ-STUCK gm=3 hpr=4 frozen gen; P-WAIT-EXTEND
"holders alive; extending") → **manual `ls` on one holder granted it in
seconds (P34-ACQ-SLOW dur_ms=1420998 rc=0)** — the intervention proof.
FIX: strikeout DOWNSHIFTS to 1s keep-alive (strikes 2500..4300 ≈ 30min
hard cap; P36-STRIKEOUT-SLOW prints each 60 ticks; evict still cancels
both arms at teardown). A/B: same injection provocation on 292 → 16
downshifts engaged, mass-contention episode PROGRESSED (gen 141→223,
waits ≤63s), full self-recovery after disarm (strong 5s, dir_reuse 109s
65/65) with NO manual touch. Also 291: P152 punt extended to
ioend/writepages contexts (why=ioend-ctx, src=17) — 0 engagements so far;
the knob=1 conv wedge root remains uncaptured (full-stack protocol in the
icluster memory).

## Injection findings triage
- readdir undercount (117/128, lookup_fail=0, every node): **knob=1 ONLY**
  (2/2 at icluster=1; 0/2 at knob=0 under identical injection) → ICLUSTER
  Phase-B blocker, NOT the D-DIR-REUSE-32-FLAKY reproducer, not shipped.
- 292 knob=0 clean board: strong 4s posix 7s mmap 6s membership 5s
  fairness 15s fence 20s zsl 21s cache 27s dd 66s dir_reuse 101-112s ×2;
  crash: see below.

## NEW OPEN: D-CRASH-COLDREAD-STALE-SPLIT (critical, 1 occurrence)
crash_consistency (NO kills — it's write+fsync → barrier → drop_caches →
all-verify; 'cc rN'=RANK N) on 292-knob0 @load35: observers rank2..6 ALL
read the SAME wrong md5 for node5_f1 AND node6_f1; ranks 1,7..32 fresh.
Fresh-mkfs boot ⇒ not prior-lap content ⇒ PRIMARY candidate =
cold-iget-lagging-home dinode (journal-durable ≠ in-place-durable; the
5 readers consumed a pre-landing image; .md5 companions read fresh).
3 immediate repro laps PASS incl. @load 31-36 ⇒ load alone insufficient;
failing lap uniquely followed the injection prelude. Evidence:
tests/logs/sess33_crash_md5_mismatch/ + full run dir (this boot only)
/tmp/run_crash_consistency_20260731T131837Z. PR-failure lines in-window
('sd 4:0:0:0: PR command failed: 2') = environmental until correlated
(crash_consistency does not fence). Watch EVERY future crash lap; on
recurrence capture the failing observer's extent map + i_dlm state +
P207 platter read BEFORE re-prep.
