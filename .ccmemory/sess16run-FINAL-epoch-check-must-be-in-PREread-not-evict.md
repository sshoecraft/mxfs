---
name: sess16run-FINAL-epoch-check-must-be-in-PREread-not-evict
description: sess16(ccloop) FINAL: complete tenure-epoch fix (create+modify stamp, dropped guard, build 7FC04802) STILL fails — P16 override fires only 28x vs 360…
metadata:
  type: project
---

## sess16 (ccloop) FINAL — the epoch CHECK belongs in xfs_da_read_buf PRE-read, not the evict

### Result (build 7FC04802: create-stamp + modify-stamp + dropped epoch!=0 guard + dir_evict_prior_tenure=1)
dir_reuse 8/tcp mht=50 dirwr=0: STILL FAILS 0/8 (node1_f1/node5_f40). P16-PRIORTENURE fired 28× (test2)/10× (test4) vs 3603/3703 undurable=1 kept blocks. So only ~28 kept-stale blocks have epoch < valid_epoch; the other ~3600 carry epoch == valid_epoch.

### Why (the precise mechanism, fully resolved)
The override at the modify-evict (mxfs_dir_evict_data_blocks) correctly evicts blocks where a HANDOFF occurred since we last touched them (epoch lags). But the durable CLOBBER is: a modify READS a stale block0 (cache-hit, pre-peer-image), adds its entry, and the MODIFY-STAMP then sets epoch = current → the clobbered block looks like legitimate current-tenure work (epoch==valid), so the override (and any later evict) never flags it. The staleness lived in the READ that happened BEFORE the modify — and the modify-evict runs at op start but the clobbering read can be on a path that doesn't re-evaluate (fast-path / the block was kept by the in_ail-undestaged guard from a prior op then read without a fresh evict).

### THE CORRECT PLACEMENT (next session)
Move the epoch staleness CHECK to the ALWAYS-ON pre-read invalidation block in xfs_da_read_buf (xfs/libxfs/xfs_da_btree.c ~3176-3352, the `xfs_buf_incore`+clear-DONE path that runs for EVERY dir DATA-fork read, NOT gated on postread_reread). Add: if the cached buffer's b_mxfs_dir_epoch < dp->i_dlm_dir_valid_epoch (valid!=0), clear XBF_DONE (force FUA re-read) BEFORE the read returns — overriding the in_ail-undestaged keep-guard (safe: epoch-lag ⇒ handoff since ⇒ our work drained). This catches the stale base at READ time on EVERY path (fast or slow), before the modify reads+stamps it. The stamps (create in xfs_dir3_data_init/leaf_init; modify in xfs_dir2_data_log_entry/header + xfs_dir3_leaf_log_header) are already in the tree (build 7FC04802) to keep current-tenure blocks at epoch==valid so they're not falsely invalidated.

CAUTION: the pre-read block uses XBF_TRYLOCK and runs under ILOCK on the modify path — verify the epoch-invalidate there doesn't deadlock (the existing dir_gen invalidate there is the template; just add the epoch term to its condition and drop the undestaged keep for epoch-lag). Validate mht=50 dirwr=0 ×5+, then mht=50 tcp_dlm ≤60s, 17/17, 1/2/4. Canaries unlink/rename_visibility/crash_consistency PASS.

### If STILL fails → release-side REVOKING fence (GPT parts 1+2) [[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]] remains the fallback. The acquire-side has now been thoroughly explored.

### Build 7FC04802 = safe baseline: dir_evict_prior_tenure default 0, all stamps inert unless enabled, MX-DOUBLEGRANT auditor KEEP. Default == 48C6A95E. Criterion NOT met — marker not written. Reconfirmed facts: double-grant RULED OUT; no mht reliably passes; loss survives force_coherent/postread/release_invalidate/release_fua/leaf-refresh/prior-tenure-evict.</body>
