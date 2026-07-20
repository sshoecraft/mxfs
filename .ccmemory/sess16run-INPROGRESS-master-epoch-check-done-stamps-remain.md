---
name: sess16run-INPROGRESS-master-epoch-check-done-stamps-remain
description: sess16(ccloop) IN-PROGRESS at relay boundary: master-epoch swap PARTIALLY done. The pre-read CHECK in xfs_da_btree.c now uses mxfs_v5_dlm_inode_dir_e…
metadata:
  type: project
---

## sess16 (ccloop) — in-progress master-epoch swap (relay boundary)

Per [[sess16run-ROOT-valid-epoch-lags-use-master-authoritative-epoch]]: i_dlm_dir_valid_epoch lags real handoffs (set only at reload end, after keep-guards). Switching the tenure-epoch fix to the master's authoritative epoch `mxfs_v5_dlm_inode_dir_epoch(mp->m_mxfs_dlm, ino)`.

### DONE (build E3CDB9F1, COMPILES, all gated dir_evict_prior_tenure=0 → INERT at default = safe baseline)
- xfs_da_btree.c pre-read epoch_stale CHECK: now computes `cur_ep = mxfs_v5_dlm_inode_dir_epoch(...)` and flags `cbp->b_mxfs_dir_epoch < cur_ep`. P16-PREREAD-EPOCHSTALE log updated to master_epoch.

### REMAINING (next session — finish then test)
1. Swap the STAMP sites from `i_dlm_dir_valid_epoch` to the master epoch (so a current-tenure block carries the master epoch, matching the check; otherwise stamp (≤valid≤master) < master always → over-fires/invalidates every block, slow but would still be a correctness test):
   - xfs_da_btree.c: the dir_stamp_fresh stamp (`bp->b_mxfs_dir_epoch = dp->i_dlm_dir_valid_epoch`) + the postread-reread stamp + the create-init stamps it added.
   - xfs_dir2_data.c: xfs_dir3_data_init, xfs_dir2_data_log_entry, xfs_dir2_data_log_header.
   - xfs_dir2_leaf.c: xfs_dir3_leaf_init, xfs_dir3_leaf_log_header.
   Each: `bp->b_mxfs_dir_epoch = (mp->m_mxfs_dlm ? mxfs_v5_dlm_inode_dir_epoch(mp->m_mxfs_dlm, dp->i_ino) : 0)` — add `extern uint32_t mxfs_v5_dlm_inode_dir_epoch(struct mxfs_v5_dlm *, uint64_t);` in each file. Watch RULE-0 cost (1 hash lookup per dir create/modify/read; cache per-op if hot).
   - ALSO update the evict-override (mxfs_dir_evict_data_blocks, P16-PRIORTENURE) to use master epoch (currently i_dlm_dir_valid_epoch).
2. Enable dir_evict_prior_tenure=1; mht=50 dirwr=0 (instr/dirwr MASK the race — never validate with them). Check P16-PREREAD/PRIORTENURE fire MANY×, P-DIRWR daddr=120 count MONOTONIC, dir_reuse 8/tcp PASS ×5+ clean reboots. Then mht=50 tcp_dlm ≤60s, full 17/17, 1/2/4. Canaries unlink/rename_visibility/crash_consistency PASS.
3. If master-epoch ALSO fails → acquirer cannot detect staleness → GPT release-side REVOKING fence [[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]].

### Build E3CDB9F1 default-config == 48C6A95E baseline (param off). Criterion NOT met — marker not written. Session's KEEP: MX-DOUBLEGRANT auditor (dlm.c).</body>
