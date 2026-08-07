---
name: ccloop-c7ee71c6-sess38-createint-verdict-and-fairness-tail-root
description: sess38: CREATEINT measured NET LOSS (6 vs 7 rounds knob A/B) -> default 0 in 320; REAL root of dir_reuse margin = 4.7s fairness TAIL in CAW claim (GP…
metadata:
  type: project
---

# sess38 — CREATEINT verdict + the fairness-tail root

## CREATEINT arc closed (0.11.318→320)
- 318's impl had 3 tag-drop leaks (A: consumer_refresh direct ILOCK_SHARED bypassing registry; B: need_iread branch overwrote lock_mode; C: map_recheck rebuilt preserving only PRIREAD). Fixed in **0.11.319** (mxfs_createint_dir_armed() single gate; probes P-CI-A/B/C + P-CI-ARM cached_dlm_mode discriminator).
- Instrumented laps proved mechanism then CORRECT (rc=-35 create-path = 0 on test5/12; P-CI-A 52/52; B/C never fired) **but knob-on = 6 rounds vs knob-off = 7 (same build)**: it moves refresh+evict+FUA-reread INSIDE the serialized dir-EX critical section (~19 vs ~15ms/create), while the EDEADLK self-demote it kills is already drain-free (dir_pr_release_fast=1) and burst batching comes from dir_ex_tenure_floor + 40ms sliding grace either way (P12-DLMTR: release fires 41.3ms after last op = grace expiry, correct).
- **0.11.320 = create_intent_ex default 0** (srcver F6A4AA3C). Mechanism kept for low-contention use. Residual rc=-35 (rank1-only, ~2/round): root-dir mkdir pre-arm walk-PR + rm-rf readdir-PR→unlink-EX. NOT the pace driver.

## The REAL margin root (RULE-4 chain, all measured)
- 320 defaults: 7 rounds/103-112s (floor 8 → FAIL). Round ~15s = waves ~7.5 + wrbar-tail ~3 + presync ~2.5 + dc ~1 + rm(rank1-serial) ~3.
- tests/drc_straggler_report.sh (NEW): per-round per-node phase spans from unconditional DRCph ring stamps. **Wave straggler rotates randomly** (28,14,28,32,30,25…), worst 5-8s vs p50 3-4s; wall = straggler via barrier.
- Uninstrumented straggler anatomy (test28 r=6): file1 fully created in 10ms → **4.70s single wait for shared-dir DLM** (zero local dir activity) → file2 in 10ms. Grant-wait dist: p50<5ms, p90 100-300ms, tail 4700ms.
- P138 anatomy (instr nodes): ffw (grantable→grant claim-side) p50=104 p90=273ms; caw_miss p50=11 max=16; ytd=1 on 4/8. Claim-side machinery + ticket churn = the tail.
- CONFOUND WARNING: P44-MODGRANT (instr-gated, ino<=256) does a SYNC SLOT READ per dir modify → instr nodes self-straggle (P135-HELD-MISS storm ×679 was the probe's own reads). Never attribute pace from instr-node windows alone.
- presync ~2.5s p50 cluster-wide (sync#2 with nothing new dirty) — UNEXPLAINED, open thread.
- wave p50 grows round-over-round (1.7→4.1s) — UNEXPLAINED accumulation, open thread.

## GPT fairness design (RULE 5, full consult in transcript)
Slot already has: holder bitmaps hex/hpr, waiter bitmap w, gm, yt ticket. Missing discipline:
1. PERSISTENT pending: node's w bit stays until served/cancel/GC (never consumed by churn).
2. Persistent 5-bit RR cursor; grant = next pending clockwise from cursor; only the selected node CASes (kills CAS storm); cursor := claimant on grant; never reset on free.
3. NO BARGING: free-lock claim forbidden while eligible pending exists (must enroll + wait turn).
4. Closed PR phases: batch = snapshot of pending PRs at phase open; late PRs behind pending EX. EX never jumps older PRs.
5. Keep 40ms sliding grace (burst batching) + ABSOLUTE tenure cap (~120ms) once w≠0.
6. Dead-node GC via existing lease/incarnation; K=31 bound → wait ≤ residual + 31×fair-tenure ≈ 0.5-0.75s worst → kills the 4.7s tail; barrier max-wait math: median of 32-max ≈ per-node p97.9.
Implementation target: dlm/dlm_caw.c claim loop + release; knob for A/B; then dir_reuse ×3 (≥9 rounds) + full board.
