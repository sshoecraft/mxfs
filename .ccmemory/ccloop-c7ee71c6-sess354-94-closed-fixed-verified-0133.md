---
name: ccloop-c7ee71c6-sess354-94-closed-fixed-verified-0133
description: sess354: #94 idle-slice quarantine FIXED AND VERIFIED on 0.13.3 (sbclean_fence_idle 2/2 PASS); #95 SB lost-update ledgered; open=42 of 95
metadata:
  type: project
---

# sess354 — #94 closed, #95 ledgered

## #94 D-IDLE-SLICE-WSKIP-REFUSAL-AG-QUARANTINE-0130 → FIXED AND VERIFIED
- prep_cluster deployed 0.13.3 sv F7E9E19DF7CC718EBFC32EA to 32/caw (118s).
- tests/sbclean_fence_idle.sh PASS 2/2 consecutive (2026-08-15 17:31-17:40Z):
  P227-FR-SBCOUNTER-CLEANSKIP x2, replay complete sbclean_skips=2, zero
  TORN-UNPUBLISHED/ATOMIC-SKIP/P241, victim slot ZEROED (published), zero
  shutdown/withdraw on 31 live nodes, victim rejoined active_count=32.
  Fence+replay window 71s both runs.
- Two FALSE test fails fixed en route (kernel was correct both times):
  1. GUARD (flags=3) legitimately persists ~10s AFTER the "foreign replay
     of slot N complete" print — recovery_complete (dlm/v5_mount.c:3406)
     runs the CAW authority purge + flush BEFORE purge_node zeroes the hb
     sector. Test now polls <=45s.
  2. caw_slotdump OMITS all-zero hb records (tools/caw_slotdump.c:260) —
     an absent row after replay = sector zeroed = recovery PUBLISHED,
     the strongest PASS. Test treats absent row as not-frozen.

## #95 D-SB-PERNODE-DIVERGENT-WHOLE-LOG-LOST-UPDATE-0133 ledgered (critical)
GPT-identified (sess353 ruling item 4): per-node divergent in-core m_sb +
whole-SB logging (xfs_log_sb serializes logger's m_sb over whole sector)
means any peer SB txn overwrites another node's persistent non-counter SB
changes. 0.13.3 closed only the ATTRBIT arm. Containment = forbid ALL
runtime non-counter SB mutations in cluster mode (reject before mutating
m_sb): xfs_add_attr, quota flag adds, LARP log_incompat, growfs, label/
UUID, NEEDSREPAIR. Next = enumerate producers, land gate, verify growfs +
label ioctl rejection.

## State
open=42 of 95 (30 critical). Cluster clean 32/caw on 0.13.3, ac=32.
Next: #92 races 6/7 (tests/clean_depart_lineage_race.sh 1 + 2, PREP_A
fresh umount+remount A first per sess349 ruling), then full board.
