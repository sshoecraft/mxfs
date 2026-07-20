---
name: AAA-ccloopa864-sess2-two-sided-dir-starvation-and-B4-fix
description: sess2: dir_reuse@32 = TWO-SIDED starvation on shared dir ino=131 DLM lock. B2 EX-starve, B3 PR-starve. B4 (v0.10.41 8D9718DB) upgrader-defers-to-PR-y…
metadata:
  type: project
---

# dir_reuse@32/caw — two-sided starvation on the shared-dir DLM lock

## The single criteria gap
dir_reuse_coherency@32/caw is the ONLY remaining test (all other node counts & the other 16 tests PASS). 24 rounds, NFILES=50, EXP=2*32*50=3200 entries/round. rank1 owns dir lifecycle: **rm-rf's + recreates the whole dir each round** (the reuse stressor → dir ino=131 epoch advances every round, e.g. 505→513). Per-test timeout 140*N=4480s. coord barrier COORD_TIMEOUT=120s.

## ROOT (instrumented, this session): two-sided starvation on ino=131
The shared dir lock has interleaved EX (create/unlink) + PR (stat/readdir/verify + epoch-reload) requests from 32 nodes. The ad-hoc yield_to hint favors ONE class → the other starves. PROVEN by moving the victim class with fairness knobs:
- **B2** (v0.10.39 streak-yield, srcver B7A8BCAB): EX starvation. `dd` (mode=5 create) starved 360s at r3 → 20 nodes rc=-110 shutdown ~t730. Merged P44-MODGRANT (15167 grants): ALL mode=5 EX, ZERO PR in P44 (P44 only logs dir-MODIFY=EX; PR reads are invisible there). test1(rank1)=6700 modifies (its creates + whole-dir rm-rf ~10ms/op), peers ~250-300 then starved.
- **B3** (v0.10.40 streak-reset + yield_set_ms fix, srcver B54889D8): EX now OK (5.5s), but PR STARVES. test5 `comm=stat mode=3` starved 360172ms → shutdown t1040. 31 nodes down. Slower rounds (rank1 only r2 by t1040).

## Why: the upgrader-bypass (sess130 conversion-priority, dlm_caw.c ~2560)
An UPGRADER (holds PR, wants EX for create) BYPASSES yield_to (our_mode!=NL). So when streak-yield sets yield_to=pr_w to serve the starving stat readers, the PR→EX creators bypass it, grab EX, and the fresh PR `stat` (our_mode=NL) can't promote (EX held) → 360s starve. yield_set_ms also "never goes stale" because peers re-arm it every release (sess130 comment) → 5s stale-clear never fires for a persistent pr_w ticket.

## B4 FIX (v0.10.41, srcver 8D9718DB, RUNNING) — 3 changes in dlm_caw.c
1. **yield_set_ms don't-re-arm** (chooser ~3050): only set yield_set_ms=now when yield_to VALUE changes → a stuck ticket ages out in 5s → stale-clear breaks deadlock.
2. **streak-reset on yield** (chooser): reset ex_grant_streak=0 the moment we yield to pr_w (not when PR promotes) → bounds PR-yield to once per 3 EX grants; EX round-robin serves everyone between.
3. **upgrader defers to pure-PR yield** (consumer B ~2560): if yield_to is PR-only (yield_to & waiters_ex == 0) AND our held mode is PR-compatible (PR/CR), the PR→EX upgrader DEFERS instead of bypassing — PR waiters share our PR (no sess130 livelock), promote, reset streak, then we upgrade. THE key fix.

Probes (pr_warn_ratelimited, print with dirwr=1): P-STREAK-YIELD (streak/pr_w/ex_w/armed), P-YT-STALECLR (yt/age), P-UPG-PRYIELD (upgrader deferred).

## Watch in B4
- Get past r3 (B2 died) and past t1040 (B3 died). Full 24 rounds ≈ needs <186s/round.
- P-UPG-PRYIELD firing = upgraders deferring (fix active). If PR still starves → windows too infrequent (lower streak threshold) or upgrader-defer not catching the path.
- Pace: B3 was slow (starvation stalls). If fixed, pace should recover to ~100-150s/round.
- NOTE age_ms in P-YT-STALECLR underflows (UINT64_MAX-ish) when yield_set_ms is recycled-slot garbage — pre-existing, mostly harmless (fires stale-clear).

## Run mechanics
`nohup timeout 5200 env MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS='dirwr=1 dirland=1 close_release=0 caw_inode_fastpoll=1 caw_fair_handoff=1' ./run.sh 32 caw dir_reuse_coherency`. Prep power-cycles shutdown nodes (fresh dmesg.stream). After a kill: pkill run_id + './run.sh 32' + per-node dir_reuse; leftover mxfs_sshpass cleanup subshells can hold /tmp/mxfs_run.lock (fuser it). Recover SSH-dead nodes: virsh destroy+start (iscsi auto-logs-in on boot, mpath auto-up ~12-18s).
