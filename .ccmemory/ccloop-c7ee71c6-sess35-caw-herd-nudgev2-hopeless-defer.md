---
name: ccloop-c7ee71c6-sess35-caw-herd-nudgev2-hopeless-defer
description: sess35: create-convoy herd rooted = waiter POLL cadence (>1100 FUA reads/s); nudge v2 wake_mask + 250ms hopeless-defer shipped 300/301; cc 32/32 PASS…
metadata:
  type: project
tags: [caw, pace, dlm, nudge, convoy, sess35]
---

# sess35 — 32-node create convoy: herd rooted and halved, floor named

## Wrong lever first (measure before believing a design)
Nudge v2 alone (300: UDP wake_mask targeted wakeups, 32-entry ring, seq-continuity fallback, v1 compat, EX-promote nudges suppressed, PR-promote targets PR class) moved NOTHING — the herd was not wake-driven. Gemini design consult was still right that the wire change is prerequisite: it enables the real fix.

## The actual herd
Waiter POLL cadence: inode fastpoll 2ms (first 64ms) then 1→25ms backoff × ~28 excluded waiters ≈ **>1100 serialized FUA slot reads/s at the one SCSI target** — the reads themselves were the measured 21.6ms/handoff (3200 creates/69s cc md5 phase).

## The fix (301) — HOPELESS-DEFER
`MXFS_CAW_DEFER_POLL_MS=250`: a waiter whose slot read proves it cannot be granted until someone else's release (yt ticket names another node — the yt-defer branch; or foreign EX holder — generic branch) sleeps 250ms and relies on the targeted nudge for instant wake. Stale-ticket 5s + PR patience clocks tick at the new cadence; lost UDP costs ≤250ms one handoff.
**Result: crash_consistency 32/32 PASS 71s** (after two 90s-budget FAILs at clean load, 56-core host, zero steal — the "external load" theory was DEAD for these rows). dw+md5 63-70s → 47-53s. dir_reuse 6→7 rounds (bar ≥8, still FAIL).

## The remaining floor (302 P138 su split)
`sx` (the `mxfs_v5_dlm_inode_unlock_gen` call) = **12.7–54ms on CLEAN file releases** during the rm storm; sw≈0. It is shared-target QUEUE time for the unlock's read+CAW under aggregate load = the documented TRAP-1 ceiling (see mxfs_dlm_caw_unlock_gen header: extra per-op FUA I/O eats the aggregate iSCSI command-rate ceiling all 32 nodes share). Also: handoffs ≈ 2× creates in dir_reuse (dir lock bounces beyond creates — readdir-pace entangled). grace 40→80 A/B flat (tenure ends not grace-bounded).
NEXT (unchanged, ledger): per-node reader state + central writer gate/epoch = protocol-IO reduction. Episode clock (sess24) confirmed live and working.

## Rig facts
- cc phase markers: `dmesg | grep mxfs-CCph` (start/datawrite/md5write/dropcaches/verify/count + barriers); dir_reuse: `mxfs-DRCph r=N`. Phase-wall extraction one-liner in sess35 transcript.
- dir_reuse round anatomy at 32: creates ~9s + verify ~4.5s + rm ~1.6s + barrier/mkdir ~2.3s ≈ 15s; bar needs ≤13.1s.
- P138-WAIT has per-grant `reads=` counter (slot_reads) — the herd census instrument.
- Wire format: caw_bast_notify version=2 appends wake_mask; receiver accepts v1-sized prefix (offsetof check). Ring under nudge_lock; scan in caw_nudge_ring_wants_wake.
