---
name: ccloop-c7ee71c6-sess178-lineage-LANDED-463-board-PASS-sample4
description: sess178: lineage v3 token path BUILT (0.11.463 sv 9904024B), FULL BOARD 27/27 PASS 32/caw, SAMPLE 4: 11/11 v3 lineage-bearing, ENFORCEABLE==legacy=11…
metadata:
  type: project
---

# sess178 — lineage discriminator landed, measured; #1 item 1 DONE

## Build
- 0.11.463, srcversion 9904024B55916A83189FB6A. sess176+177 edits compiled
  CLEAN first try (make clean && make modules; make tools needed after clean
  — mkfs_mxfs missing caused PREP FAIL, same as sess174).
- Wrapper-caller audit: only xfs_log_recover.c calls
  mxfs_v5_dlm_victim_{ag,inode}_manifest_read. Confirmed post-build.

## Full board 32/caw on 0.11.463 — 27/27 applicable PASS, all in budget
Run ids 20260810T052842Z..054334Z, 6 foreground chunks. Highlights:
crash_consistency 204/204 79s/90s; dir_reuse 79/79 107s/120s;
dirent_durability 30 rounds durable_loss=0 64s/240s; cache_coherency
654/654; zero_silent_loss 644/644; ag_strand_repair strands=1 repaired=2.
Only open_defects red (policy).

## SAMPLE 4 (tests/foreign_replay_ab.sh 32 5, apply=0)
- Live replay on test1 t+112s of slot 9 (victim test5), "complete".
- 11/11 buf tokens v=3, ALL lineage-bearing: AG-9 (class=1 res=9) tokens
  lineage=12027592859354346802; inode (class=3 res=19412559)
  lineage=16127683793989890892 — per-resource lineage distinct as designed.
- P227-TOKENSUM v3=4/4/3 v1=v2=0 malformed=0 untagged=0.
- P273-SHADOW-EVAL capable=1 buf=11 csum=11 wlineage=0 nolineage=0
  WOULD_APPLY=11 ENFORCEABLE_WOULD_APPLY=11 txn=3 all_apply=3 — enforceable
  verdict tracks legacy EXACTLY; nolineage already 0 (fresh prep minted all
  grants under 463, no draining needed).
- Visibility 40/40 dirs, 40/40 files, 40/40 sizes.

## Ledger
- #1 D-FOREIGN-REPLAY-UNGATED-IMAGES next-field refreshed: ITEM 1 LANDED,
  plan-of-record + prior samples preserved. Remaining: 2) tenure-release
  invariant proof, 3) enforcement machinery behind knob, 4) 108-capture
  campaign. Enforcement OFF until proto-gen>=4 (#14).

## Next queue
1. #14 D-MIXED-VERSION-UNGATED-REPLAY blockers B1-B4 before bumping
   MXFS_PROTO_GEN 3->4.
2. Then #1 item 2 (tenure-release invariant proof).
3. Compaction overdue (172 unfolded).
