---
name: ccloop-c7ee71c6-sess239-23-interleave-proven-epoch-wait-verified
description: sess239 #23: interleave RULE-4 PROVEN on .486 (arm=29008 relflush-admit, 5 laps burn 30µs in one tail, defers=0) and epoch-wait fix VERIFIED on .487…
metadata:
  type: project
---

# sess239 — #23 D-OPEN-PROTECT-DEMOTE-RACE-SPURIOUS-EIO: proof + fix verify

## Build-1 measurement (0.11.486 sv CB0259EAEC01E2FD12BF8A6) — RULE-4 PROOF
tests/openprotect_race_ab.sh 60 (both knobs on test1: ride
openprotect_race_delay_ms=1000 polls 1ms for {NL,RELFLUSH} BEFORE the
ilock ride; park openprotect_park_ms=500 parks bast_process right after
the terminal NL store):
- inject_landed_window=60/60, parks=3 (one 500ms park covers many rides)
- ALL 310 P95-OPEN-PROTECT-RESTART/-FAIL stamps arm=29008 = the sess47
  relflush-admit PR arm (xfs_mxfs_dlm.c ~29008, holder++ NO mode check).
  Stamp mechanism: i_mxfs_openprot_pid set before ride, mxfs_dlmtr_rec
  (~1287) records __LINE__ of last MXFS_DLMTR_H by that task.
- Restart insufficiency: try=1→5 burn in ~30µs (nl_age_us 217135→217164)
  inside ONE tail; -EIO. 60/60 cats failed.
- Gate insufficiency: admit_defers=0 — release already past terminal
  store when gate arms. Confirms every clause of the sess238 ruling.

## Build-2 fix (0.11.487 sv C360BB786E9F99E7C7BBF69) — VERIFIED
open_protect !ok path: removed bounded-restart -EIO exhaustion (and
MXFS_OPEN_PROTECT_GATED_RESTARTS); each lost race does EPOCH-AWARE
COMPLETION WAIT: snapshot i_dlm_epoch+state under i_dlm_lock; wait
i_dlm_wait for state!=DEMOTING || epoch!=snap || shutdown (30s slices,
capped P95-OPEN-PROTECT-STUCK). -EIO only at shutdown fence. Gate
arming after 2 plain laps kept. Completion signal = pipeline tail
DEMOTING→NONE (~18916) + wake (~18926), post wire-unlock (ruling:
RELFLUSH-clear too early).
Re-run same injection: 60/60 landed_window, 60 restarts ALL try=1
(each waited out park+tail ~530ms), protect_fail=0, ufails=0, BWR=0 →
script PASS.

## Remaining for closure
- Ruling test 2 (gate-defer): P95-OPEN-ADMIT-DEFER ≥1 deterministic
  exercise — sess239 adding test-only knob arming the gate at open
  entry (openprotect_arm_gate), since with the fix opens converge on
  try=1 and never arm the gate naturally.
- Ledger update + board baseline on .487.

## Traps
- Both injection knobs go on the OPENER node (holds grant, runs demote).
- P95-OPEN-PROTECT-FAIL print is ratelimited: 60 EIOs → only 10 prints;
  count userspace fails, not the probe, for totals.
