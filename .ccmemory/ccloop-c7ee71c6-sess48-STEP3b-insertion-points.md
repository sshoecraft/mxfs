---
name: ccloop-c7ee71c6-sess48-STEP3b-insertion-points
description: sess48 step-3b insertion points: xfs_log_recover.c ~2049 ATOMIC-SKIP taint scan + ~2128 per-item P223 skip — parse token from ri_buf[0], report-only…
metadata:
  type: project
---

# Step 3b — exact insertion points (xfs_log_recover.c, read this session)

## The two gates (both in the pass2 item-recover function, ~2030-2145)
1. **ATOMIC-SKIP taint scan (~2049)**: under `xlog_is_mxfs_untrusted_replay(log) && !mxfs_foreign_replay_untagged_apply`, a pre-pass marks the WHOLE transaction tainted if ANY item is BUF/DQUOT/QUOTAOFF/ICREATE → P227-FR-ATOMIC-SKIP returns 0 (sess41: per-item skip manufactured torn states — transaction is the atomicity unit; KNOWN LIMITS in comment: multi-transaction ops still tear, landed home writes not rolled back).
2. **Per-item P223 skip (~2128)**: same condition per item (only reached when the atomic scan didn't trip, i.e. apply-knob=1), plus P226 intent skip above it.

## 3b plan (report-only first)
- Helper `mxfs_blf_parse_authority(item)` → const struct mxfs_blf_authority* or NULL: item type XFS_LI_BUF; blfp = ri_buf[0].i_addr; `blfp->blf_flags & XFS_BLF_MXFS_AUTHORITY`; base = offsetof(blf_data_map)+blf_map_size*4; need ri_buf[0].i_len ≥ base+24; version be16==1. (ri_buf[0] layout identical in both gates.)
- In the taint scan: for each BUF item, parse + xfs_notice P227-TOKEN (class/resource/epoch/owner_slot, count-capped) — DECODE ONLY this build; taint decision unchanged.
- Verification: tests/foreign_replay_ab.sh — victims' foreign-replayed transactions should show P227-TOKEN with class=AG, sane agno, nonzero epoch on the survivor. Then step 4 (descriptor+DONE+victim-slot freeze) before step 5 changes any skip decision: gate rule = class AG + exact {agno, epoch-vs-fenced-slot ex_grant_epoch} match → item NOT tainted; transaction applies iff ALL its images authorized (keep the sess41 transaction-atomic principle); class NONE/SB-unmatched/mismatch → tainted as today. DQUOT/QUOTAOFF/ICREATE remain untokenized → tainted (noquota moots dquot; icreate needs its own class later).
- Note: `mxfs_foreign_replay_untagged_apply` knob semantics preserved; the eventual gate adds a THIRD state effectively (tagged-and-matching applies) — keep knob=0 default.

## Criteria: NO — 11 OPEN of 39 (4 critical). Fleet 0.11.397 32/caw healthy, 15 clean fossil-arm cycles.
