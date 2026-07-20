---
name: AAA-ccloop7251-sess8-cc32-anatomy-SOLVED-mechanisms
description: sess8: cc@32 dead-time RULE4 loop closed — 4 mechanisms proven (fragmentation under client jitter is THE variance driver); UDP flood counter-lesson;…
metadata:
  type: project
tags: [ccloop-72513a13, sess8, cc32, anatomy, performance]
---

# sess8: cc@32 rotation anatomy — mechanisms PROVEN via P138/P139 instrumentation

## Instrumentation landed (keep): 0.11.28 prints
- `P138-WAIT` (caw_wait_for_grant grant, >5ms, capped 4000/node/boot, NOT ratelimited): `elapsed_ms ffw_ms ytd poll realms`. ffw = time since slot first seen grantable; ytd = fair-handoff ticket deferrals; realms = wall-clock ms for cross-node hop pairing (±40ms skew).
- `P139-COLDCLAIM` (mxfs_dlm_caw_lock compat-add on contended slot): `yt ytself wex realms` — fires when a node claims a slot that has a ticket/EX-waiters without ever waiting = late-arrival hop evidence.
- P70-BP ENTRY/EXIT realns pairing + dedup by (node, t−held_ms) clusters re-entries into unique tenures.

## The four proven mechanisms (cc@32 rv/uv write-phase rotation)
1. **Batching is healthy**: tenures serve 40-60 EX ops (a node's mv burst ≈ 100 EX ilock cycles for 20 mv = 5 cycles/mv, NOT 3). Ops inside a tenure are client-paced (bash fork ~2-8ms/op); cutting cycles/mv does NOT move wall time. One-shot 15ms fast-yield is correct — leave it.
2. **Two regimes set the phase wall**: fast-client regime → ops ~2-4ms, burst done <150ms, tenure releases at quiet-age → 32×~112ms ≈ 6s phase. Slow-client regime (host CPU load) → ops ~7.5ms+, tenure pins at the 300ms window bound, burst needs 1.5-2 tenures → 10-15s phase.
3. **THE VARIANCE KILLER = burst fragmentation**: with client op-gaps jittering past grace=40ms, the quiet-age gate forfeits the tenure mid-burst; node re-queues behind ~12 waiters × 300ms ≈ 3.5s penalty PER FRAGMENT (P138: el=3538-3831, ffw≈el, ytd=13-16 = plain back-of-queue rotation). Bad runs: per-node rename walls spread 1.5→47s (p50 16s), phases 26-47s. Fragmentation is pure loss (barrier waits for last node; every fragment adds hop+requeue).
4. **Inter-tenure gaps** (good runs): p50 21-35ms (≈ poll backstop — nudge not always landing), p90 ~300ms; ~14 big gaps/phase ≈ 3-4s. Half are PR-interlude demote stagger quantized by the 100ms BAST resend (UDP loss recovery); half are empty (winner arrives late, claims <5ms — client lull/vCPU steal, NOT machinery).

## Counter-lessons (do NOT redo)
- BAST resend 100→25ms flat AND 4×25ms leading burst BOTH regress cc@32 to 84-91s: most waits are <100ms so any burst multiplies cluster hint volume; hints share the recv socket+thread with GRANT nudges → flood drowns the nudges. Keep 100ms.
- inode_mht_ms=600 + grace=80 runtime A/B: rename max 47→32s but rv-verify p50 7→22.6s — net neutral (71s). Window extension spills cost into verify phases.
- 4MB UDP rcvbuf landed in mxfs_pal_udp_open (0.11.31) — keep (defends nudges).

## Environment facts (dominant term!)
- Host swap debt 8G/8G full → multi-second phase stalls; fix `swapoff/swapon` (~60s). VM balloons at 2.5G survive prep reboots now.
- `worldserver` (game server) eats ~1 core permanently on clyde — constant, not the delta.
- Single-run A/Bs are noise-dominated when host loadavg >5; cc@32 wall tracks host health: 56-65s healthy, 70-91s degraded. Preps: 59s healthy, 200-240s degraded (full VM reboot escalation).
- Killed runs: `fuser -k /tmp/mxfs_run.lock` then MUST re-prep before trusting numbers.

## Where the remaining cc@32 seconds live (healthy host)
- Client-fork floors: rv-verify = 1920 ck-forks/node ≈ 9-13s; uv-verify 960 ≈ 6-8s; creates serialized on dir-EX at client cadence. Irreducible at FS layer.
- FS-recoverable: hop gaps (~3-4s), fragmentation tail under jitter (the real lever: burst-aware grace/window adaptation — attempted via knobs, needs an adaptive per-tenure design: extend grace only when tenure_ops≥8 AND op-rate steady; window extension must NOT apply near phase transitions).
- cc cell is PASS (calibration 65s); enforcing <60 needs healthy host + ~4s of the recoverable slack.
