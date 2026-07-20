---
name: sess62-FIXDESIGN-master-exposes-prior-EX-owner-then-3way-merge
description: sess62 FIX DESIGN (definitive, implementable): the reliable "peer held EX since my last grant" signal the merge needs ALREADY EXISTS in the master's…
metadata:
  type: project
---

## sess62 FIX DESIGN — the missing reliable handoff signal exists in dg_shadow

### The multi-session dilemma (now fully mapped)
On a cached-EX dir hold, a node's in-core shortform can be stale (a peer modified while our cached EX outlived its real grant). Two wrong options:
- BLIND ADOPT disk (mxfs_sf_fastpath_adopt, default 0): RESURRECTS our own async-destaged-then-removed dirents (sess50/53 P-SFM-READD) on continuous hold.
- SKIP (current default): keeps our STALE base -> sf->block conversion freezes it -> node1_f1 durably lost (sess62 root).
The SAFE option is the 3-WAY MERGE (base/ours/theirs: mxfs_dir_sf_3way_merge @ xfs_mxfs_dlm.c:8948, merge_into @8765, base capture @8723): keeps names WE changed, adopts peer's untouched (node1_f1). But it must run ONLY on a GENUINE cross-node handoff (else it merges against a stale/own base and resurrects — sess53). grant_gen is NOT that signal (sess61 REFUTED: bumps on every same-node re-grant, over-fires, regressed 2/24->16/24). The code itself asks for the right signal (xfs_mxfs_dlm.c ~9809): "needs the master to expose the prior owner, not just a monotonic gen".

### THE SIGNAL ALREADY EXISTS — dg_shadow (dlm.c)
dlm.c maintains dg_shadow[]: per INODE resource it records the current EX {owner, gen} (dg_grant_ex @2344 sets it, dg_release @2403 clears it, P-DOUBLEGRANT detector uses it). So AT THE MASTER, at the moment of granting EX to node N, the PRIOR EX owner is known (dg_shadow entry before this grant). prior_owner != N  ==>  a peer held EX since N last held it  ==>  GENUINE HANDOFF  ==>  N must 3-way-merge. prior_owner == N (or none) ==> no peer modified ==> no merge (no resurrection).

### IMPLEMENTATION (multi-file, next session)
1. dlm.c: in the EX grant path (local-master dg_grant_ex sites @1223/1606/1963 and remote-grant @2551/2591/2739), BEFORE overwriting dg_shadow, capture prior_owner; pass it into the grant response (struct mxfs_dlm_lock_resp — add a `prior_ex_owner` field, or a 1-bit `handoff` flag = prior_owner valid && != grantee). For the local path, surface it via *granted_mode side-channel or a new out-param up through mxfs_dlm_lock to the ilock layer.
2. xfs ilock layer (mxfs_dlm_ilock_begin slow + fast paths, xfs_mxfs_dlm.c ~9842/10221): on EX grant where handoff==true for a dir, set a per-inode MXFS_IF_DIR_HANDOFF_MERGE flag (and capture i_dlm_dir_sf_base from the coherent disk image so the merge has a base).
3. At the dir-modify pre-lock / pre-convert (mxfs_dlm_dir_modify_reload_prelock and/or top of sf_addname path), if MXFS_IF_DIR_HANDOFF_MERGE set and dir is shortform, run mxfs_dir_sf_3way_merge against a FUA disk image BEFORE xfs_dir2_sf_to_block. Clear the flag. This adopts node1_f1 (peer add, we didn't touch) while keeping our own dirents, with NO resurrection (handoff means our prior tenure was drained; base is the disk-at-handoff).
4. Block-format dirs: the same handoff signal should drive the data-block evict/refresh so a node adopts the peer's block0 instead of growing its own (the logical-block0 split). Likely the existing mxfs_dir_drain_evict_data_blocks already covers block format on slow-path; the gap is the shortform conversion window + the fast-path cached-EX stale hold.

### VERIFY
P-SFMERGE (or a new P62-HANDOFF-MERGE) fires > 0; node1_f1 survives; dir_reuse_coherency 4/tcp PASS x3; FULL ./run.sh 4 tcp = all-pass (esp. delete-heavy dlm_fairness/tcp_dlm_scaling — NO resurrection regression, which is exactly what the handoff-scoping prevents); THEN 8/tcp (never run). Build on disk: F3342B5D (baseline-equivalent, probes only). See [[sess62-SURGICAL-leadP-SFMERGE-dead-no-same-incarnation-shortform-union]] [[sess62-PROVEN-ROOT-4way-logical-block0-split-divergent-extent-map]] [[sess61-grant-gen-fix-REFUTED-overfires-need-peer-owner-signal]] (sess61 already concluded "need peer-owner signal" — sess62 found it's in dg_shadow).</body>
