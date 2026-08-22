---
name: ccloop-c7ee71c6-sess310-511-deployed-both-boards-green
description: sess310: 0.11.511 DEPLOYED 32/caw; knob=1 FULL board green + knob=0 regression board green; 5 natural defer_oblig all recovered, cas_noproof_v2=0 x32
metadata:
  type: project
---

# sess310 — 0.11.511 deployment + both verification boards GREEN

## What ran
- Deployed 0.11.511 sv EB44E6A843CF082A799AF9D to all 32 nodes (caw), prep 143s.
- FULL board, knob release_proof_enforce=1 (default): 24 PASS, 0 FAIL, 1 POLICY
  (open_defects), 3 FLAKY-pass.
- Re-prepped with MXFS_EXTRA_MODARGS='release_proof_enforce=0'; FULL regression
  board: 24 PASS, 0 FAIL — equals 0.11.510 behavior.

## Enforcement evidence (knob=1 board)
Fleet sweep via `echo 1 > /sys/module/mxfs/parameters/release_cert_dump`:
- cas_noproof_v2=0 on ALL 32 nodes (the step-9/10 gating invariant).
- wedges=0, tripwires=0, proof_failed=0, deferred_proof_failed=0 fleet-wide.
- defer_oblig fired NATURALLY 5 times (test7=1 test20=2 test26=1 test27=1) and
  every episode resolved via the retry worker — no wedge, admission reopened,
  subsequent tests all passed. The defer machinery works under real load.
- Per-release P280-RELEASE-CERT lines are gated by mxfs_release_cert_log
  (default 0) — for fault-inject runs set it to 1 to see cas_attempted=0 certs.

## Anomalies (both attributed to the LEDGERED post-load pace family, not .511)
- crash_consistency FAILED 90s/90s twice, both times launched back-to-back
  after the coherency chunk at hostload 17-20 (NO_TERMINAL_RECORD=32, phases
  reached verify-done at T+110s; md5write phase stretched 43s). Zero
  deferrals/wedges in kernlogs both times. PASSED isolated both boards:
  20s/90s and 19s/90s with 204/204 checks. Symmetric across knob=1/knob=0.
- ag_strand_repair 240s/240s (PASS) right after dirent_durability churn at
  knob=0; isolated re-run 79s/240s. knob=1 board run was 80s.

## Fault-inject prep (next session)
- Engine: mxfs.relgate_fault_stage (write stage number; 0=disarm), _res
  (0=any), _delay_ms (default 100), _oneshot (default 1). Hits logged as
  P282-RELGATE-FAULT + counted in fault_hits. Static-key gated.
- Stage sites in ICLUS release path (xfs_mxfs_dlm.c): 7=OBLIG_ZERO@47980,
  9=FLUSH_DONE@48010+48017, 10=PROOF@48062, also 1=DEMOTING@47521,
  11=PRE_CAS@47597, 13=POST_HANDOFF@47600, 3=LOGFORCED@47899.
- The fault injects DELAY only — defer requires concurrent dirtying during
  the delay so the settle/proof recheck fails. Run under write churn
  (dir_reuse/rsync workload) with delay 1000-5000ms, cert_log=1, and assert:
  P282 fired, cert cas_attempted=0 + defer_kind set, defer counter up,
  release eventually completes (episode reset), cas_noproof_v2 stays 0.
- NO existing tests/ driver for relgate_fault (grep confirms only the ledger
  mentions it) — a persistent tests/ script must be written (RULE 3).
- Wedge-path test still needs a HELD failure: oneshot=0 + repeated stage-10
  delay, or a dedicated fault mode; design open.
