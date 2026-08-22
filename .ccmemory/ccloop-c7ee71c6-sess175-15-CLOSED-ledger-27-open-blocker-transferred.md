---
name: ccloop-c7ee71c6-sess175-15-CLOSED-ledger-27-open-blocker-transferred
description: sess175: #15 D-EX-GRANT-EPOCH ledger closure EXECUTED (FIXED AND VERIFIED 0.11.462); residual transferred to #1 as historical-record-lifetime blocker…
metadata:
  type: project
---

# sess175 — #15 closure transaction executed

The sess174-ratified atomic ledger transaction is DONE in tests/criteria/OPEN_DEFECTS.json:

- #15 D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID: status FIXED AND VERIFIED (closure build 0.11.462
  srcversion F185ED4495CCC5DCEED0914). `disposition` carries: cause, 5-part fix (caw_next_grant_epoch
  zero-skip mint @dlm_caw.c:1102, tombstone preserve ~1273, single mint point at 5 grant sites,
  edge-triggered mint 0.11.461, test-only caw_inject_gep_wrap), verification (sess172 selftest
  basic/wrap/kill + sess174 board 27/27 @32/caw), consumer tuple audit (xfs_log_recover.c:2370-2456),
  and the full wrap policy (zero-skip != post-exhaustion uniqueness; lifetime-bound acceptance
  584,542yr @1M/s; 2^64 wrap not empirically verified; inject knob never a production path).
  why_still_open removed; residual_note marked TRANSFERRED (original text preserved).
- #1 D-FOREIGN-REPLAY-UNGATED-IMAGES: new field `blocker_historical_record_lifetime` (verbatim #15
  residual, scope broadened to ALL persistent consumers — delayed live-path messages, queued work,
  cached capabilities, not just replay records; evaluator may NOT become authoritative until held;
  options: drain-before-rebind / independent lineage discriminator / gate-design inclusion).
  `next` appended: (b) SATISFIED by 0.11.462; new (d) = the lineage blocker. `related` now includes
  D-EX-GRANT-EPOCH. Cross-links intact both ways.
- Open count 28 -> 27 (17 -> 16 critical). ./defects.sh renders both entries correctly.

Note: defects.sh open-queue ordering shifted because #1's `updated` changed — the severity-order
list is unaffected in substance.

## Next
#1 D-FOREIGN-REPLAY: design phase — RULE-5 consult on (c) enforcement (sess163 hazard list:
transaction-atomic rejection, tenure-release invariant, descriptor/DONE crash-resumability) and
(d) the lineage blocker, before writing code. Rig is BOARD-READY on 462, do not re-prep.
