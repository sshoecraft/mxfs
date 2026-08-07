---
name: ccloop-c7ee71c6-sess158-p248-c1c4c6-PASS-c5-vacuity-ROOTED-fix-plan
description: sess158: 0.11.456 verify: c1/c4/c6 PASS (P271 live, no P269/P270). c5 VACUOUS+ROOTED (needs K6 wait-expire knob). Prep-gate beacon race ROOTED. Edit…
metadata:
  type: project
---

# sess158 — p248_inject on 0.11.456: c1/c4/c6 PASS; c5 vacuity + prep-gate beacon race both ROOT-CAUSED; exact edit plan for 0.11.457

## Verification run (step 1 of sess157 plan) on 0.11.456 (sv 4CA76BE55B7B45177024681, both nodes)
- **c1 PASS**: P271-OWED-DISCHARGE ×5, P267 retired=1, NO P269/P270/P248/P259/P263-missing. New non-vacuity asserts hold.
- **c4 PASS**: p271=5, K5 consumed, p269=0 p270=0. **c6 PASS**: P266 gen=27/26 refusal + P248 entries=1 as designed (frozen=false via gen mismatch → moots as before).
- **c5 FAIL VACUOUS**: K5 never consumed in 3×45s churn rounds (both nodes' windows fully clean otherwise). **c3/c2 NEVER RAN** — the re-prep before c3 aborted.

## ROOT CAUSE 1 — prep abort = run.sh convergence-gate beacon race (HARNESS, not MXFS)
test2's `MXFS-MEMBERSHIP local=3648936738 active_count=2` printed at 278389.231894, **4ms BEFORE** its own `DLM initialized` line (278389.235914): discovery heard test1's announce DURING test2's mount init. run.sh's gate awk (`/DLM initialized/{m=""} /MXFS-MEMBERSHIP/{m=$0}`, lines ~750 + ~772) resets capture at the init line → beacon invisible → "(no beacon this incarnation)" forever → gate false-FAILs a genuinely converged cluster (test1 beacon ac=2; test2 `membership settled at mount: … lease sees 2 node(s)` at .247503, 12ms POST-init). Race window: joining node's discovery listener is live before the init print; hits when mounts are staggered. NOT ledgerable as MXFS defect — cluster truly converged; gate observation blind.

## ROOT CAUSE 2 — c5 vacuity is STRUCTURAL at 2 nodes (code-proven)
Mid-run owed obligations arise ONLY from: (a) divergence strips (caw_slot_clearing diverg-lo/hi arms ~7133/7297/9734 — need a provably-stale holder bit, rare); (b) give-up cleanups → caw_drop_own_waiter at timeout ~6269 / scan give-up ~8018 / upgrade give-up ~9855. The UNLOCK deliberately publishes NO obligation (sess124 comment ~8250: failed release leaves lock HELD, collector = next unlock). Healthy churn: no give-ups (wait timeout 120s ≫ 45s round; BASTQ submitted=dispatched=1724 clean). sess154 already flagged natural in-line clear failure "scarcer at 2 nodes" — it is effectively ZERO. K5 injection point (dlm_caw.c ~3993) is only reached with do_w/do_wx/do_h set.

## THE DETERMINISTIC c5 CHAIN (verified by code read, sess158)
Timeout give-up calls drop_own_waiter(collector=false) → publishes MAXIMAL intent (waiters+waiters_ex+holder_mask, ~3760-3805, BEFORE CAS) → K5 -EIO → `rc != -EAGAIN` hard-error break (~4017) → P245-RECONCILE-EXHAUST, **obligation STANDS** (retract-on-proof only) → always-running owed worker (sess125) collects mid-run via collector pass → real CAS discharges → caw_owed_release completes with ops_closed=false → fix-A gate false → NO retire. Race where a grant lands for the abandoned acquire is benign: P6H-ABORT-RECONCILE arm still CASes → K5 still consumed.

## EDIT PLAN for 0.11.457 (next session — do in this order)
1. **K6 knob** `caw_inject_wait_expire` (dlm_caw.c, module_param_named after K4 ~line 408, MODULE_PARM_DESC "TEST ONLY: treat the next N contended CAW acquire waits (own waiter bit registered) as expired"): in acquire poll loop top (~5528, right after `wait_el` computed, BEFORE real timeout check):
   `if (mxfs_caw_inject_wait_expire && slot_seen && ((cur_slot->waiters | cur_slot->waiters_ex) & ctx->node_bit) && caw_inject_take(&mxfs_caw_inject_wait_expire)) { pr_warn("mxfs: P272-INJECT-WAIT-EXPIRE type=%u ino=%llu mode=%u el_ms=%llu\n", …); break; }`
   Break exits through the natural timeout cleanup (same state as hardcap break; cur_slot from prev iteration valid since slot_seen gate). User-mode #else stub already pattern-established (caw_inject_take(k)=false).
2. **Beacon guarantee (module side)**: emit canonical `mxfs: MXFS-MEMBERSHIP local=%u active_count=%d` UNCONDITIONALLY right after the `DLM initialized` print in the mount path, BOTH transports (v5_mount.c — CAW init print ~:1255, TCP ~:1078; the settle prints at 3617/3942 are inside conditional foreign>0 branches, NOT a guarantee). CAW count via mxfs_lease_get_active_nodes (like v5_membership_beacon_caw ~630); TCP via the dlm engine's active count. Contract: ≥1 beacon post-init per incarnation → run.sh gate awk needs NO change.
3. **c5 rewrite** (tests/p248_inject.sh run_c5): churn as today; at t+10 arm **K5=1 FIRST, then K6=1** on test1; poll knob readbacks (both 0) within round; assert **P272≥1 AND P245≥1 in test1 c5 window** (positive anchors) + existing asserts (p263run=0 p266run=0 ent=0 agg=0 p259=0 p260=0 p257lost=0, clean umounts both). parse() must learn p272/p245 counts (p245 may already be parsed — VERIFY). knobs_zero must cover K6 (update knobs_zero + KNOBS list). Keep ≤3-round fallback.
4. VERSION → 0.11.457, `make modules`, deploy both nodes (run.sh prep or scp+insmod path), **rerun FULL suite** — c3/c2 have NEVER run on any 0.11.456+ build; expect 6/6.
5. Then sess157 steps 2-3 unchanged: injected-departure disk proof (expect TOMB + P271 + P267; slot idx from P109, offset 40960+idx*512 in 1MB-scan file, dd bs=1M skip=64 count=34 iflag=direct from test2), then 32-node census (P248==0, P254/P259/P269/P270 silent, P263/P267/P271 sane). Ledger: D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK → FIXED AND VERIFIED needs all of 1-3; D-RELEASEALL-LREQ-RETIRE-MISSING (#27) closure per sess153 ruling needs deterministic 6/6 + 3× fleet census.

## Rig state at handoff
Both nodes MOUNTED 0.11.456, converged (test1 ac=2 beacon; test2 settle-line lease-sees-2 — the failed gate was observational only). FS is FRESH (the aborted prep ran mkfs; no workload since). All knobs should be zero (run_c5 zeroes test1; VERIFY both nodes before next run). RULE-5 note: K6 follows the sess153/154 GPT-approved consumable-knob family exercising an existing path (timeout give-up) with zero production-logic change — if any production-semantics doubt arises during implementation, consult first.

## Deferred (unchanged): lifecycle-phase enum hardening; docs/.md for dlm module; memory compaction (197 unfolded, DUE).
