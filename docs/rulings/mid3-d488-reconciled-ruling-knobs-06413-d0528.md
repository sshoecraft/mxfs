<!-- sess470 15:30Z: D-488 record reconciled with the sess270-283 campaign + GPT disposition (stays OPEN: exits never executed); unlock-exit knobs + harne… -->
# sess470 MID3 (2026-09-02 ~15:30Z) — ledger 74 open (D-0526, D-0527, D-0528 filed this session)

## Rig queue (gated): 103 board (running since 15:15Z, 2900 s bound) → 109 s470a (0.64.12 dirshard verify) → 110 s470b (D-0527 handle probe) → 111 s470c (D-488 exit arms, needs PROD_SV of frozen 0.64.13 — LAUNCH IT when the build lands: `PROD_SV=<sv> setsid nohup bash tests/sess470_chain111_d488_unlock_exits.sh s470c`) → 104 s468c (GATE=chain110 log; must be RE-GATED to chain 111's log if 111 is launched: tests/evidence/sess470_chain111_d488_exits_s470c.log — or accept 104 and 111 racing; DO re-gate) → 100 → 101 → 102 → 107 → 108 → 105 → 106.

## D-488 (D-AGLOCK-ORPHAN-EX-TRACKING-LOSS-LIVELOCK-488) — what this session established
- The record was an UMBRELLA never updated after sess242; faces 1-4/6 closed as -497/-500 etc.; face 5 (own-bit orphan) proven on test28 + fixed 0.11.496-498 (tri-state unlock, watchdog) + verified by the injected ag_strand_repair criterion on every board. Full chain: docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md.
- GPT disposition ruling (sess470): NOT F&V — the sess240 all-25-AG specimen's birth never captured; the criterion injects the postcondition, not the exits; hypothesis (c) untested. Minimal measurement = force each formerly-silent exit on the real body + own-affine strand w/o contention + the two-phase adoption test. Filed D-0528 for (c).
- Built: dlm/dlm_caw.c knobs caw_inject_unlk_{noslot,findslot_eio,cas_eio} (P470-UNLK-INJECT), tests/d488_unlock_exit_arms.sh, tests/sess470_chain111_d488_unlock_exits.sh; docs/dlm-protocol.md '0.64.13'; awareness dlm.md 'sess470'.

## Expected marker chains (worker tail xfs_mxfs_dlm.c ~49160-49350)
findslot_eio / cas_eio1: P274-UNLK-* → P275-AGUNLK-REVERIFY (held=1) → P275-AGUNLK-REARM. cas_eio2: REVERIFY (held=0) → RELEASED. noslot: P274-AGUNLK-NOSLOT → RELEASED with bit set → later P5N-AG-ORPHAN-NAK disk_held=1 / P294-READOPT-MINT. Forbidden: P275-AGUNLK-QUARANTINE, -REARM-FAIL.
