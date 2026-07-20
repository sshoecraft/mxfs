---
name: sess16run-ROOT-valid-epoch-lags-use-master-authoritative-epoch
description: sess16(ccloop) ROOT of why tenure-epoch acquire-side fix fails: i_dlm_dir_valid_epoch LAGS real handoffs — it's set only at the END of the reload (xf…
metadata:
  type: project
---

## sess16 (ccloop) ROOT — i_dlm_dir_valid_epoch lags; must use the master's authoritative epoch

### Measured (build 4509825F, mht=50, P65-EPOCH-ADOPT always-on)
On clobbering nodes test2/test4: i_dlm_dir_valid_epoch climbs 0→66 / 0→58, but the master grant_epoch reaches 70/67. So valid_epoch LAGS the real handoff count by several.

### Why it lags (precise)
i_dlm_dir_valid_epoch is SET only at xfs_mxfs_dlm.c:~9389 (`if (dir_grant_epoch > valid_epoch) valid_epoch = dir_grant_epoch`), which is near the END of the reload — AFTER the P43/P43B/P62 keep-stale guards. Those guards frequently `return` early (keep our base, skip adopt) → line 9389 is NOT reached → valid_epoch does NOT advance even though a handoff occurred. So the "reliable level-triggered epoch" is in practice GATED by the same keep-guards it was meant to bypass.

### Consequence for the tenure-epoch fix (this session's whole approach)
My stamps (create+modify) and checks (pre-read + evict override) compare b_mxfs_dir_epoch vs i_dlm_dir_valid_epoch. Because valid_epoch lags, a stale block0 stamped at epoch 66 (its last modify) is compared against valid_epoch=66 (also stuck) → 66 < 66 false → NOT flagged → stale read proceeds → clobber. That's why P16 fired only ~28× and the loss persisted across all builds (EA41172C, 7FC04802, 4509825F).

### THE FIX (next session — small, decisive)
Use the MASTER's AUTHORITATIVE per-inode epoch `mxfs_v5_dlm_inode_dir_epoch(mp->m_mxfs_dlm, dp->i_ino)` (the DLM grant epoch, bumped on EVERY cross-node handoff, NOT gated by XFS keep-guards) as BOTH the stamp value (at create/modify) AND the compare value (at the pre-read check / evict override) — replacing i_dlm_dir_valid_epoch everywhere in the sess16 tenure-epoch code. Then a block stamped at master-epoch 66, after a handoff to master-epoch 70, is read → 66 < 70 → flagged → re-read fresh. Cost: one mxfs_v5_dlm_inode_dir_epoch() call (hash lookup) per dir create/modify/read on the multinode path — measure vs RULE 0 (cache the value per-op if hot). ALTERNATIVELY: advance i_dlm_dir_valid_epoch EARLY (at handoff DETECTION, xfs_mxfs_dlm.c:8033/8047, before the keep-guards) instead of at 9389 — but verify it doesn't break the genuine_handoff adopt trigger (which tests dir_grant_epoch > valid_epoch). The master-epoch approach is cleaner/lower-risk.

### Stamp/check sites already in tree (build 4509825F, all gated dir_evict_prior_tenure=0 → INERT, safe baseline == 48C6A95E):
- create: xfs_dir3_data_init (xfs_dir2_data.c), xfs_dir3_leaf_init (xfs_dir2_leaf.c)
- modify: xfs_dir2_data_log_entry, xfs_dir2_data_log_header (xfs_dir2_data.c), xfs_dir3_leaf_log_header (xfs_dir2_leaf.c)
- check: PRE-read in xfs_da_read_buf (xfs_da_btree.c, P16-PREREAD-EPOCHSTALE) + evict override in mxfs_dir_evict_data_blocks (P16-PRIORTENURE-EVICT)
Next session: swap i_dlm_dir_valid_epoch → master epoch at all these, enable param, validate mht=50 dirwr=0 ×5+.

### If master-epoch ALSO fails → the staleness is not handoff-detectable at the acquirer at all → GPT release-side REVOKING fence (the releasing node needs no detection) [[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]]. Criterion NOT met. Reconfirmed: double-grant RULED OUT [[sess16run-DECISIVE-double-grant-RULED-OUT-bug-is-buffer-layer]]; no mht reliable [[sess16run-CORRECTION-dirreuse-fails-at-mht300-too-no-reliable-mht]].</body>
