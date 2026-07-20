---
name: sess31-IMPL-stale-block-reconcile-fix-needs-validation
description: sess31: IMPLEMENTED gated per-block stale-block reconcile fix (dir_stale_reconcile, default 0). Build 8E4B6D08. Passed 7/7 at 8-rounds but P31 was in…
metadata:
  type: project
---

## sess31 — implemented the per-block stale-block reconcile fix (NEEDS VALIDATION)

### What was built (build 8E4B6D08 = keeper 37A37B10 + this fix + gated P-MERGEGATE probe)
A new gated lever **`mxfs.dir_stale_reconcile` (default 0)** — keeper behavior UNCHANGED at default. Implements the targeted fix from [[sess31-ROOT-merge-gate-skips-99pct-targeted-fix-design]]:
- **New fn `mxfs_dir_reconcile_stale_data_blocks(tp, dp)`** (xfs/xfs_mxfs_dlm.c, after mxfs_dir_merge_peer_into_tp): folded into the create transaction, FUA-reads ONLY cached dir DATA/BLOCK blocks whose `b_mxfs_dir_gen != dp->i_dlm_dir_gen` (prior-tenure stale base) and re-adds (xfs_dir_createname → updates leaf/free) any peer dirent the in-core lacks. Cheap (only stale-gen blocks). Idempotent (lookup-guarded). Prints P31-RECONCILE when added||stale_blk>0 (under dirwr/instr).
- **Flag MXFS_IF_DIR_DATA_STALE (1U<<22)** (xfs/xfs_inode.h): set in the drain_evict SKIP branch (xfs_mxfs_dlm.c ~6360) for any DONE DATA/BLOCK block kept stale; test_and_clear'd by the reconcile.
- **Call site**: xfs/xfs_inode.c:1726, right after mxfs_dir_merge_peer_into_tp.
- Header decls in xfs/xfs_mxfs_dlm.h.

### Validation status — INCONCLUSIVE, the fix is UNVERIFIED
- v1 (is_stale = in_ail&&undestaged): passed dir_reuse 8/tcp **7/7 at DRC_ROUNDS=8**, BUT **P31 fired 0×** = the reconcile was INERT (the loss-block is NOT in_ail at evict/reconcile time — it's a CLEAN stale prior-tenure base). So the 7/7 was NOT the fix working — it's that **DRC_ROUNDS=8 has too low a loss rate** to distinguish (reconcile=0 ALSO passed 5/5 at 8 rounds). The reliable repro needs DRC_ROUNDS=24 + DRC_STREAM (or heavy probes like dir_writeprobe=1, which seem to INDUCE the loss by slowing destage).
- v2 (is_stale = `b_mxfs_dir_gen != dir_gen`, build 8E4B6D08): the correct discriminator (loss-block had bgen=0<dir_gen) but **NOT YET TESTED**.

### NEXT SESSION — validate v2 (RULE 4)
1. Reboot, run with `dir_stale_reconcile=1 dir_writeprobe=1` DRC_ROUNDS=24 DRC_STREAM=1 — confirm **P31-RECONCILE fires with re-added>=1** (the fix is actually doing work) AND no loss/shutdown/DLM-timeout. Check wall (must stay <2× native, RULE 0 — the FUA reads add cost).
2. A/B: same conditions with `dir_stale_reconcile=0` MUST still lose (else inconclusive). Use 24 rounds — 8 rounds is too few. The loss reproduced reliably at ROUND 1 in foreground runs WITH dir_writeprobe=1/dir_relverify=1 (those probes induce it); use that as the trigger.
3. If v2 fixes it cleanly: make `dir_stale_reconcile=1` the DEFAULT, re-run full 8/tcp ×3 consecutive (must be 17/17) + re-verify 1/2/4 tcp (no regression). Then criteria MET.
4. If P31 still inert: the flag isn't being set for the loss-block's evict path — add the flag-set to mxfs_dir_evict_data_blocks (~3055, the modify-refresh evict) keep branch too, not just drain_evict.

### State: build 8E4B6D08 deployed (cluster last rebooted default = reconcile OFF = keeper-equivalent). Cluster up. CRITERIA NOT MET. [[sess31-HEAD-handoff]]
</body>
