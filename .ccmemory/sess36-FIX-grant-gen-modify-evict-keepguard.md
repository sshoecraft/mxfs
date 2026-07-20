---
name: sess36-FIX-grant-gen-modify-evict-keepguard
description: sess36 FIX (build 64544CAD): wire grant_gen into modify-evict keep-guard (mxfs_dir_grant_evict=1). Root=cache-hit re-stamps stale block fresh; evict…
metadata:
  type: project
---

## sess36 (ccloop 4cb2d0a2) — dir_reuse 8/tcp readdir<800 loss. Build 64544CAD (keeper 4703FA18 + grant-gen evict). CRITERIA NOT YET MET (testing).

### REFUTED this session (RULE 4, A/B clean reboots):
- **conv-bump** (`dir_conv_genbump`, bump i_dlm_dir_gen in xfs_dir2_block_to_leaf): did NOT fix loss (batch iter1 FAIL readdir=796 round5); run1 also hit a 184s ino=131 DLM acquire-timeout shutdown (flaky). DEFAULTED 0. sess35's conversion-gen theory was a mechanism-A variant, refuted.
- **dir_drain_merge=1**: CATASTROPHIC — round1 readdir=471/800, lookup_fail=194 (duplicate names node2_f1×2) + SHUTDOWN. The DATA-graft over-grafts/corrupts. REFUTED (confirms sess34 leaf-desync wall).
- baseline (all fix params off) = FAIL readdir=799 round8, no shutdown (the known steady loss).

### THE PROVEN ROOT (reconciled across sess33/35/67 + GPT-5.5 sess23 design):
1. The loss-write is the **EX-release-drain's xfs_bwrite** of a stale-base block (sess33: disk_extra=1, in-core lacks a peer's prior-tenure add).
2. The bmap is NOT stale (sess35 P37 fires 0×) — the evict walks the right daddrs.
3. The stale base survives because a **cache-HIT read RE-STAMPS the stale block fresh**: at RMW-read time bufgen==dir_gen AND b_mxfs_grant_gen==cached_grant_gen AND b_epoch==valid_epoch — ALL three "freshness" signals read current over stale content (GPT-5.5's "stamped fresh over stale content"). That is why the read-path P67 backstop (`mxfs_dir_postread_reread`) "fired 0× on clobber" and is default-off.
4. BUT at the **modify-EVICT** (mxfs_dir_evict_data_blocks, runs BEFORE the stale read re-stamps), the prior-tenure block STILL carries its OLD b_mxfs_grant_gen != current i_dlm_cached_grant_gen. The evict keep-guard wrongly keeps it via the in-AIL `mxfs_dir_buf_is_undestaged` FLAG — GPT-5.5's EXACT identified bug ("AIL bookkeeping is NOT a durability/ownership oracle").

### THE FIX (build 64544CAD, default ON, `dir_grant_evict=1`):
In mxfs_dir_evict_data_blocks keep-guard (xfs/xfs_mxfs_dlm.c ~3829), force-evict a clean in-AIL DONE block whose `b_mxfs_grant_gen != ip->i_dlm_cached_grant_gen` (both nonzero): grant_gen advances ONLY via slow-path re-grant = we RELEASED EX = Inv 1 drained our work => the undestaged "keep" is a false positive, disk is a superset, cold-read peer image. Added grant_stale_base to the undurable computation AND to the P34-NEWTENURE-RETIRE BLI-retire (so the evicted block's lingering BLI is retired, avoiding the sess26/33 zombie-reflush → readdir=0 trap). Stamped-nonzero gate avoids resurrection on never-stamped blocks. New probe P36-GRANTEVICT (gated dirwr/instr).

### WHY this beats the refuted epoch/dir_gen levers (sess30/32 REFUTED dir_tenure_evict+dir_evict_prior_tenure → 798/worse): grant_gen is the acked-TCP authoritative "lock changed hands" token (dlm.c dlm_next_gen); epoch/dir_gen under-fire on TCP. And it acts at EVICT (under our EX = SAFE per GPT §8), not the read path (which shut down).

### NEXT: batch_ge.log = 6 clean runs (drc 8/tcp). If pass-rate high, run full 1/2/4/8 tcp criteria. If still loses, instrument P36-GRANTEVICT + P68-EVDECIDE under dirwr=1 to confirm the loss-block's b_grant_gen vs cached at evict (is it actually != ? or does cached_grant_gen also fail to advance on the silent handoff?). Repro: drc_repro_loop.sh / scratchpad batch.sh "<MA>" N 24. See [[sess33-HEAD-handoff]] [[sess23-gpt5.5-grant-generation-coherency-design]] [[sess61-THE-FIX-implement-sess10-grant-gen-faststale-check]].
