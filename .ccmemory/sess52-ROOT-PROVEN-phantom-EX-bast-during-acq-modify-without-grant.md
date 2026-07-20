---
name: sess52-ROOT-PROVEN-phantom-EX-bast-during-acq-modify-without-grant
description: sess52(ccloop) ROOT PROVEN (2 configs): dir_reuse loss = phantom-EX dir modify (dlm_mode=EX but held=0) — modifying without holding the DLM grant. he…
metadata:
  type: project
---

## sess52 — ROOT PROVEN (clock-independent, confirmed across 2 configs)

### Probe (build 7E462481, gated dirwr=1): P51-MOD at xfs_dir2_data.c:xfs_dir2_data_log_entry logs every storm-dir DATA modify with dlm_mode, master_self, mxfs_v5_dlm_inode_held, grant_gen, i_dlm_bast_pending, i_dlm_bast_during_acq (bastacq), i_dlm_demoter (demoting), realns, comm.

### PROOF — the loss IS a phantom-EX modify (dlm_mode=EX but the DLM does NOT hold the grant):
- **Default MHT run** (lost = node6_f43.md5): EXACTLY 1 modify with `master=0 held=0` in 4736 → `name=[node6_f43.md5] dlm_mode=5 held=0 bastacq=1`. 1 phantom = 1 lost dirent. **1:1.**
- **mht=0 run** (inode_mht_ms=0, lost = 9 entries round 10): **13** phantom (held=0 master=0) modifies, and they match the lost names (node2_f17, node2_f31.md5, …). More handoffs → more phantoms → more loss. demoting=1 count exploded 27→1103.
- ⇒ The count-preserving single-dirent loss == a dir-block modify performed WITHOUT a held exclusive DLM grant. A peer (real EX holder) clobbers the phantom's write. This is sess50's "serialization hole / phantom-EX" — PROVEN, with a name-level 1:1 correlation.

### Why ALL prior fixes failed (50+ sessions): base IS coherent (P28-PLATTER MATCH; sess50 relepoch==epoch). The loss is NOT stale read/write — it is a modify under a phantom EX. Cache-coherency levers cannot fix a missing-mutual-exclusion bug.

### REFUTED this session: dir_ex_revalidate=1 (forces slow-path re-acquire — slow path STILL yields phantom); dir_write_merge=1 (wedge); dir_postread_reread+leaf_only=0 (blocks coherent); inode_mht_ms=0 (WORSENS — 13 phantoms; disabling acq-BAST batching is not the fix, the phantom is broader than the batch window).

### ORIGIN (where held=0 comes from) — next session, precise target:
The create transaction acquires EX (ilock_begin, rc=0 from mxfs_v5_dlm_inode_lock @14932, ex_holders++ @14201 under i_dlm_lock), modifies, ilock_end (ex_holders--). The MHT dwork (10520) checks ex/pr/pin==0 before releasing → respects holders. BUT the phantom modifies carry bastacq=1 and/or run with demoting=1 (i_dlm_demoter set, 1103 cases) — i.e. the modify races mxfs_dlm_bast_process draining+releasing the grant. Hypotheses to test:
1. bast_process (immediate, queued when ex_holders==0 per @9330; or INLINE in ilock_end) releases the grant while a SECOND create op on the node is between its state-check and ex_holders++ (or via the i_dlm_demoter belt-and-suspenders @14070 that serves EX even in BAST/DEMOTING state — a create wrongly served as if it were the demoter thread).
2. The slow-path acquire (ilock_begin @14932) publishes i_dlm_mode=EX after rc=0 but a concurrent BAST/master-revoke (i_dlm_bast_during_acq) means the master already moved EX to a peer → node holds i_dlm_mode=EX with held=0 from the moment of publish.
Instrument: at the phantom modify, also dump_stack once + log i_dlm_state + whether current==i_dlm_demoter. That pinpoints which path (belt-and-suspenders serve vs slow-path-publish-without-grant vs concurrent-release).

### FIX direction: guarantee the DLM EX grant is HELD continuously from the first dir-block read through transaction commit; NO bast_process/dwork/demoter path may release the dir grant while a create modify is in flight (ex_holders>0 OR ILOCK_EXCL held). Likely: make bast_process/demote take ILOCK_EXCL (serialize vs the create txn) OR make the dir fast-path/slow-path serve verify mxfs_v5_dlm_inode_held()==1 and bump a release-blocking ref that the demote path waits on (GPT#2 "wait active users before demote"). Validate with P51-MOD held=0 count == 0.

Build 7E462481 = baseline + gated P51-MOD probe (dirwr off = baseline-equiv). Marker NOT written. See [[sess52-FINAL-serialization-hole-block0-contention-grant-ordering]] [[sess50-FINAL-all-coherency-refuted-prime-suspect-dlm-serialization-hole]].
