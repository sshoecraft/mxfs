---
name: ccloop-c7ee71c6-sess320-refused-replay-32node-suicide-ledgered-90
description: sess320: sess319 test1 shutdown SOLVED = fence victim's replay refused (blanket skip, 3/3 tokens WOULD_APPLY) -> frozen grants -> all-32 suicide; led…
metadata:
  type: project
---

# sess320 — refused foreign replay → 32-node cascade (D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513, ledger #90)

## Mechanism (PROVEN, test1 dmesg; evidence file tests/evidence/incident_sess320_refused_replay_cascade.txt)
- 0.11.513 knob-on 32/caw, fence_during_write ~09:04Z 2026-08-15. Victim slot=3 node=2891031514 killed mid-write holding EX on shared test dir ino=858369.
- test1 (slot0) elected replayer; certified lease OK; replay hit ONE committed txn lsn=0x1000021af items=5, 3 buf items ALL v3-tokened st=1 lineage=5797620444607153166.
- Blanket ATOMIC-SKIP (xfs_log_recover.c:2856-2863 — ANY buf item = taint; token gate is SHADOW-ONLY) + no snlocal marker → skip → l_mxfs_untagged_skips=1 → mxfs_xlog_recover_foreign_slice returns -117 → sess233 TORN latch (xfs_mxfs_dlm.c:46131-46151): set_bit m_mxfs_foreign_torn_slots, grants frozen, NOT auto-retried, "needs repair or token-authorized redo" — NO such path exists.
- All 32 survivors' acquires on ino=858369 blocked → P34-ACQ-SLOW dur_ms≈360582 attempts=4 rc=-110 → fail-fast at xfs_mxfs_dlm.c:30666-30686 (mxfs_dlm_ilock_begin; "Corruption of in-memory data (0x8)" = SHUTDOWN_CORRUPT_INCORE, NOT a scribble) → shutdown+withdraw t=1735-1755. TOTAL fleet loss ~6min after one node death.
- P273-SHADOW-EVAL on the txn: WOULD_APPLY=3 ENFORCEABLE_WOULD_APPLY=3 all_apply=1 untagged=0 malformed=0 → the #1 enforcement gate would have applied it and recovery would have SUCCEEDED. Natural enforcement sample #4.

## Status pins
- MXFS_PROTO_GEN still 3 (include/mxfs/mxfs_super.h:90); #14 B2-B4 open → sess175 ruling forbids enforcement until cluster-admitted gen>=4. foreign_replay_token_enforce knob NOT BUILT.
- P71-UNDERFLOW ino=2980 storm at t=1009 (dlm_scaling) = separate, batch PASSed; not the cause.
- crash_consistency NO_TERMINAL_RECORD×32 = collateral (cluster dying during it).
- #6's refusal path got its FIRST NATURAL FIRE (logged refusal, stayed unpublished) — feeds #6 verification.
- Fleet left all-32 DOWN; needs full re-prep (make tools if clean build happened).
