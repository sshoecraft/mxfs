---
name: feedback-scope-is-two-node-tcp-only
description: USER (2026-09-05, twice, mid-session): the ONLY objective is two-node TCP working 100%. No CAW laps, no 32-node or 4-node legs, no extra VMs running.…
metadata:
  type: feedback
---

# Two-node TCP only (user directive, 2026-09-05, sess518)

The user interrupted twice:
1. "Wait, why are there 4 VMs running? Your directive is to get 2 node TCP working in production. Why would there be four nodes running? And why are you talking about CAW or 32 node or anything?"
2. "You are to only get two node TCP working 100% Two node TCP only."

What went wrong: the session had inherited test3/test4 running from a prior session's 4-node laps, delegated a chain that re-prepped the rig on CAW for a CAW verification leg of a new defect, and was planning a 32-node TCP campaign because a dozen open ledger records name 32/tcp or CAW legs as their closure condition.

Rules from this:
- Rig = test1 + test2 on the QNAP LUN, TCP transport. Shut down any other VM found running (`virsh destroy testN`).
- Never prep CAW, never run a CAW leg, never plan 32-node or 4-node work under this run's criteria, even when a ledger record's own closure condition names one. Note the owed leg in the record as out of scope for this directive and move on.
- The open_defects board cell counts every open record (incl. 32-node/CAW-only ones); say so plainly instead of chasing them.
- Prioritize records whose mechanism is reachable on the 2-node TCP shape.
