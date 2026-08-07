---
name: ccloop-c7ee71c6-sess159-0.11.457-SUITE-6of6-PASS-disk-proof-script-ready
description: sess159: 0.11.457 (sv E44F37271ED23D708AFD84C) LANDED+DEPLOYED; p248 suite 6/6 PASS (c5+c3+c2 first-ever). tests/p248_disk_proof.sh WRITTEN, unrun.
metadata:
  type: project
---

# sess159 — 0.11.457 landed; p248_inject 6/6 PASS; disk-proof script authored

## Landed as 0.11.457 (srcversion E44F37271ED23D708AFD84C, deployed both nodes)
1. **K6 knob** `caw_inject_wait_expire` (dlm_caw.c decl after K4 ~407; injection at acquire poll loop top ~5535, gated slot_seen + own waiter bit, exits via the natural timeout break → drop_own_waiter). Knob referenced ONLY via caw_inject_take (user-mode macro drops arg — a leading direct `mxfs_caw_inject_wait_expire &&` would break user-mode builds; removed).
2. **Beacon guarantee**: unconditional post-init MXFS-MEMBERSHIP beacon in v5_mount.c — CAW branch calls v5_membership_beacon_caw(ctx) after the init print (~3891); TCP branch emits the canonical line from mxfs_lease_get_active_nodes (helper no-ops when ctx->dlm set). Root: discovery live before init print → pre-init beacon invisible to run.sh gate awk.
3. **c5 rewrite** (tests/p248_inject.sh): arm K5 FIRST then K6 at t+10 round 1; consume check = BOTH knobs 0; positive anchors P272≥1 + P245≥1 on test1. parse() learned p272/p245/p259v/p259g; knobs_zero covers K6; dump_probes extended to P245/P269-P272.

## Suite results on 0.11.457 — ALL SIX PASS (first complete run ever)
- c1/c4/c6: same as sess158 (P271×5, K5 consumed in c4, c6 refusal + entries=1).
- **c5 PASS round-1 deterministic**: P272 type=1 ino=2097280 mode=3 el_ms=28 → P245 349µs later (rc=-5, w=1 wx=1 h=1, obligation stands) → p263run=0 (sess117 guard HELD) → teardown ent=0 agg=0. K6 chain exactly as designed.
- **c3 PASS after TEST-assert fix**: one unclean departure emits TWO deliberate P259 lines — CAW verdict (dlm_caw.c:12560, `node=` + quiesced=/owed_left= detail) + v5 GOODBYE-suppression (v5_mount.c:4155, sess131). Assert was written pre-first-run expecting 1. Fixed: parse discriminates p259v (verdict, /node=/) + p259g (/suppressing the GOODBYE/), p259 stays TOTAL for the zero-asserts; c3 asserts p259v==1 AND p259g==1. NOT an MXFS defect — module behavior is the correct fail-closed design. Also learned: c3's 4×P271 = proof-of-ABSENCE discharges (no CAS → K5 can't block); only the really-set mode needs the CAS; P245 count in c3 is timing-dependent (2 then 0 across runs, budget=1ms) and correctly unasserted.
- c2 PASS: K2 ENOENT → retire by proof (P263=1 P267=1), no leak, clean departure.
- Beacon fix verified 4× in the field: preps converged in 9s/24s/205s/204s, zero gate false-fails (sess158's blocker gone).

## Next session — exact continuation
1. **Run `tests/p248_disk_proof.sh`** (WRITTEN sess159, syntax-checked, NEVER RUN): needs both nodes mounted on tree sv (run `./tests/p248_inject.sh prep` first — after c2 test1 is unmounted). Script: injected departure (K1=2) on test1 NO remount → asserts P271≥1 P259==0 → 1MB-scan dd from test2 → decodes owed slot (P109 cas_rc!=0) + ≤3 in-line control slots (cas_rc=0): controls must be TOMB/cleared else run INVALID (stale-scan guard); proof slot must be TOMB or all 5 holder masks clear of test1's node_slot bit. Leaves test1 unmounted. Debug watch: first live run may hit decode/awk field quirks (od spacing) — verify decode output sanity (magic 4d584357/4d58444c) before trusting a FAIL verdict.
2. **32/caw census** (sess157 step 3): P248==0, P254/P259/P269/P270 silent, P263/P267/P271 sane. Ledger needs 3× census for D-RELEASEALL-LREQ-RETIRE-MISSING (#27, sess153 ruling: deterministic 6/6 — HAVE IT — + 3× fleet census).
3. **Ledger dispositions after 1+2**: D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK next-steps 1-3 now DONE except step-3's disk scan (=item 1 here); step 4 = census. Then FIXED AND VERIFIED. #27 closure per sess153.
4. Deferred: lifecycle-phase enum hardening; docs/.md for dlm module (Stop hook may nag: dlm_caw.c + v5_mount.c touched sess159); memory compaction DUE (198 unfolded).

## Rig state at handoff
test1 UNMOUNTED (c2 departure, clean), test2 mounted, both 0.11.457. Knobs zeroed by c2's knobs_zero (test1) — VERIFY test2 knobs before census. FS has c1..c5 workload litter (p248churn, p248_c*_ dirs) — fresh prep before census recommended anyway.
