---
name: ccloop-c7ee71c6-sess73-preempt-abort-VERIFIED-on-rig-and-prover-vs-replayer-split
description: sess73: PREEMPT AND ABORT VERIFIED on the rig (proves_excl=1, 1 winner/30 losers) — and the replayer is a LOSER. Plus 2 harness traps that fabricated…
metadata:
  type: reference
tags: [scsipr, fencing, rig-evidence, verified, 0.11.414, harness-trap]
---

# sess73 — PREEMPT AND ABORT verified on the rig; prover ≠ replayer

Build 0.11.414 (`DEA067313AD0A51C8558066`), fleet-deployed, 32/32 mounted.
Ran `tests/pr_fence_evidence.sh 17 90` — hard `virsh destroy test17`.

## THE VERIFICATION (D-PR-FENCE-PREEMPT-WITHOUT-ABORT, ledger step 2)

**test9, 2026-08-04T00:51:46.749318Z** — the only preempt-and-abort on its boot:

```
P-PR-FENCE preempt-and-aborted dead node 599795286 (key 0x23c02656) on 'mxfs'
  — task set aborted, registration removed, WE-RO reservation held,
  gen=308: EXCLUSION PROVED
P236-FENCEKIND node=599795286 kind=PREEMPT_ABORT_DONE(16) proves_excl=1 gen=308 rc=0
```

A real fence of a LIVE REGISTERED victim returned **success** — not ILLEGAL
REQUEST, not RESERVATION CONFLICT-swallowed-as-success — and the post-state
verify confirmed victim absent / own key present. **That is the ledger's
verification target for the sess71 PREEMPT AND ABORT change, met.**

Distribution: **1 winner (test9) / 30 losers** (`KEY_ABSENT_UNPROVEN(6)
proves_excl=0`), exactly as designed.

## THE DEFECT IT EXPOSES — prover ≠ replayer

Kill at 00:50:44. test9 preempts ~00:51:44 (the 64→62 table transition).
**test1 (slot 0)** — a LOSER — at 00:51:46.679:

```
P236-FENCEKIND ... kind=KEY_ABSENT_UNPROVEN(6) proves_excl=0
P163-RECOVERY-PENDING slot=25 ...
elected (slot 0) to replay dead node 599795286's log slice 25
+22ms: XFS (dm-1): MXFS: foreign replay of dead slot 25 (slice 1/4)
```

**Foreign replay dispatched 22 ms after the replayer's own `proves_excl=0`.**
The node that PROVES exclusion (fence winner) and the node that REPLAYS
(`lowest_live_slot`) are structurally different, and the prover's evidence is
never published. That is `D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION`, live, in
shipped code, now precisely characterized. Confirms sess72's warning: gating
the dispatch sites BEFORE the evidence channel exists would stall recovery.

## TWO HARNESS TRAPS THAT FABRICATED A WRONG ROOT CAUSE

1. **`tests/pr_fence_evidence.sh` polled only `SURVIVORS="1 2 3 4 5 6 7 8"`.**
   With exactly ONE winner in 32, a partial poll is *guaranteed* to usually miss
   it. It reported "30 losers, no winner" and I concluded the TARGET had reaped
   the registration on I_T-nexus loss. **Wrong.** Fixed: polls the whole fleet,
   prints the outcome distribution, asserts exactly 1 prover, and names the
   replayer. **Never sample a 1-of-N race.**

2. **`tools/mxfs_secrets.sh` killed any script that SOURCED it with args.** It
   ended in a bare `case "${1:-passfile}"`; a sourced script sees the CALLER's
   `$1`, so `pr_fence_evidence.sh 17 90` hit the usage branch and `exit 2` —
   which in a sourced context terminates the CALLER. With stderr redirected it
   died silently before its first echo (cost sess72 a whole rig run). Fixed:
   dispatch only under `[ "${BASH_SOURCE[0]}" = "$0" ]`; sourcing is now
   functions-only. Verified both modes.

## SCST GROUND TRUTH (checked in source, /src/scst, v3.11.0-pre)

`scst_pr_unregister()` is called ONLY from PR OUT command handlers
(`scst_pres.c` 1394/1649/1651/1710/1712). **There is no session/nexus-teardown
path that removes PR registrations.** So on this rig a registration disappears
only because some initiator preempted it — which is why test9's preempt, not a
target reap, explains the 64→62. Do not re-derive this.

## GPT RULE-5 RULING (still binding for the OTHER order)

Asked whether `victim absent + WE-RO held + own key present + count>=live` proves
exclusion. **REFUTED**: that is a *write-admission* observation, not a
*task-drain* proof. Two separable obligations: (1) drain old work, (2) prevent
new work. Key absence addresses only part of (2).
- `count >= live_members` is NOT a safety check on a per-nexus rig (expected
  count isn't one per member); needs an exact authorized-writer inventory via
  READ FULL STATUS.
- Required gate is **disjunctive**:
  `drain_proven = P&A_success OR authoritative_nexus_drain_cert OR LU_reset OR target_session_drain`
  plus valid recovery ownership, reservation validity, writer inventory, and
  closed victim readmission.
- **Do not make correctness depend on winning the race** with target cleanup —
  support both orders. (On SCST the target never reaps, so MXFS always wins;
  other arrays differ.)
- **Q5:** the returning node's barrier must be BEFORE PR REGISTRATION, not just
  before mount I/O — under WE-RO, registering restores write eligibility
  immediately. Check `mxfs_scsipr_register` (v5_mount.c:2456, :2696) ordering
  against `mxfs_dlm_mount_recovery_barrier` (xfs_mxfs_dlm.c:42329).

## NEXT

Build the evidence channel: winner durably publishes the fence certificate
(victim identity+incarnation+old key, LUN, owner term, method
`PA_COMPLETED`, PR generation, state FENCING→FENCED→REPLAYING→RECOVERED);
replayer consumes it and refuses to replay without it. Only THEN gate the two
dispatch sites. Fail closed when no certificate exists.
