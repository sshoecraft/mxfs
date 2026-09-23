---
name: trap-a-gate-fail-closed-against-a-different-report-is-open-to-no-report-and-a-zero-is-a-report
description: TRAP (sess593, D-0960): the settle gate stayed closed only against a peer beaconing a DIFFERENT view; a peer beaconing view 0 ("none installed") was…
metadata:
  type: feedback
tags: [trap, dlm, settle-gate, D-0960, membership]
---

# A gate that is fail-closed against "reports a different X" is open to "reports no X"

**Measured (s592e B-mastered, s593a A-mastered; tests/evidence/20260912T072549Z_jointk_s592e, 20260912T074638Z_jointk_s593a):** the joiner's settle gate (0.83.4) refuses after the 20 s window only if a live member's beacon reports a different view. The incumbent mid-prepare beacons view `{0,0}` — a real statement, "I have installed no multi-node view", i.e. "you are not admitted" — and two filters dropped it as "no report" (`lease.c` forwarded only a non-zero hash; `mxfs_dlm_report_peer_view` returned on hash 0). The gate opened unconfirmed at 18-20 s (`P-D7-SETTLEGATE waited=18000ms confirmed=0`), and every acquire the joiner then made was DEFERred by the incumbent's page-handoff handler (view mismatch, no progress relayed) until its budget or the 30 s watchdog refused the mount.

**The pattern:** a sentinel value (0, empty, "unknown") that the SENDER emits deliberately is data. When a receiver filters it out "because zero means unset", every predicate downstream that asks "did anyone say otherwise?" answers no. Check every filter between the sender and the predicate for a sentinel drop before trusting a "nobody objected" gate.

**Also confirmed here:** the FREEZE_REQ DEFER is a plain park on the requester (no progress in it), so a requester that reaches the DEFER window spends its retry budget at the 100 ms park cadence (nine 60-retry budgets in s592e) — the DEFER path is a safety net, not a wait.

Related: `trap-a-guard-written-for-the-self-direction-leaves-the-symmetric-peer-direction-open`, `trap-a-silent-instrument-and-a-clean-system-are-the-same-observation`.
