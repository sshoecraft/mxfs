---
name: ccloop-c7ee71c6-sess38-END-322-allgreen-board-new-AGI-defect
description: sess38 END: 322 FIRST ALL-GREEN functional board 27/27 @32/caw; dir_reuse 2/3 (still OPEN); NEW D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (9 OPEN);…
metadata:
  type: project
---

# sess38 END — boundary state

## Deployed/verified
- Cluster: 32/caw on **0.11.322 (A5D3929F)**, freshly re-prepped after test1's withdrawal (recovered clean, 120s prep).
- **FIRST ALL-GREEN FUNCTIONAL BOARD**: 27/27 tests PASS on 322 defaults (open_defects gate red by design). fio seqW=7721MiB/s seqR=6487 randW=194k randR=314k.
- dir_reuse_coherency: PASS 111s (in-board), PASS 106s, FAIL 6-rounds/104s → 2/3. D-DIR-REUSE-COHERENCY-32-FLAKY stays OPEN (bimodal pace, zero margin at 8-round floor).

## Session arc (all RULE-4 evidenced, changelog 319-322 + 2 addenda)
1. CREATEINT: 3 tag-leaks fixed (319) → measured net loss → default 0 (320).
2. P139 census (321) → PR-batch admission storm root → batch-claim + guard relax (322) → storms gone.
3. Turn economy quantified: p50 58ms/turn (drain-dominated), discovery 2ms, grace 40ms idle tail.
4. grace=10 A/B: cc 41→25s, crash 79→21s BUT dirent_durability mkdir_err=4 then SHUTDOWN → **NEW DEFECT D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN** (ledger #9, evidence tests/logs/sess38_shutdown_g10/): runtime xfs_iunlink_reload_next (xfs_inode.c:4906) recovers a PEER's in-flight unlinked inode mid-churn; xfs_droplink rc=-117 (dir nlink already 0) in vfs_rmdir → dirty trans cancel → corruption(0x8) shutdown + withdrawal. grace default STAYS 40 (masks the race; race is the defect).

## NEXT SESSION (in order)
1. **AGI defect RULE-4 loop**: instrument xfs_iunlink_reload_next + iunlink add/remove: log (agno, bucket, agino, owner-slot-of-inode, our slot, AG-DLM tenure gen) at each op; repro = grace=10 + dirent_durability (reproduced 2/2 at g10). Hypothesis: in-core bucket linkage (i_prev_unlinked/i_next_unlinked, cached inode list views) survives AG-DLM handoffs → stale stitching after peer reshapes bucket. Candidate fix shapes: (a) invalidate in-core unlinked-list views on AG-DLM re-acquire when agi gen advanced; (b) gate runtime reload on owner-dead (lease) else re-read bucket from fresh AGI; consult GPT before implementing (authority family).
2. dir_reuse margin: remaining levers = release-drain cost (log_force_seq REVERTED v0.3.38 — don't retry), presync 2.5s = 32-way flush congestion, rm 3s rank1-serial. Consider drain-pipelining (publish-before-notify family) — big design, GPT first.
3. Authority family (D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, D-FOREIGN-REPLAY-UNGATED-IMAGES, D-RELEASE-BARRIER-OPEN) — the AGI defect is likely SAME family; attack together.
4. D-DIRVIEW-NONCONVERGE-SESS25, D-MATRIX-UNMEASURED, D-READDIR-PEER-CACHED-DIR-PACE.

## State
9 OPEN defects. Tree: 0.11.322 + P139/PRCLAIMBATCH; CHANGELOG through 322+addenda; awareness dlm.md/xfs.md updated sess38; ledger has the new entry. Criteria NO.
