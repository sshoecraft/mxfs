---
name: sess27-refuted-persistent-idirty-mask-and-next-steps
description: sess27 REFUTED: persistent b_mxfs_idirty_mask in partial-inode-write (inode revert persisted + readdir regressed). Tree clean at 2C3150CB. Precise ne…
metadata:
  type: project
---

## sess27 (ccloop 8ddb16a2) — fix attempts this session + clean tree state

### Tree state (HANDOFF): build 2C3150CB, CLEAN, original behavior + diagnostics
Carries (all SAFE, behavior == prior C99F988B for default args):
- Diagnostic detectors un-capped to `pr_warn_ratelimited` (were atomic-capped ≤200, exhausted mid-run = invisible): P26-LKERR, P26-DSCAN, P22-DATASCAN-HIT, P26-DSCAN-MISS (xfs_dir2_leaf.c), P26-IGET-FAIL (xfs_inode.c). KEEP — essential for seeing the real failure.
- `partial_iwrite` module param (xfs_mxfs_dlm.c, default 1 = ON = original). Set 0 to force whole-buffer inode writes (diagnostic). `dir_reuse_coherency` with **partial_iwrite=0** → inode revert (P26-IGET-FAIL) DISAPPEARS but a dir LEAF-hash hole (P26-LKERR/DSCAN) appears = two manifestations of one durable-lost-update class. Do NOT ship partial_iwrite=0 (sess115 false-sharing regression risk for cross_write_read).
- `b_mxfs_idirty_mask` field on struct xfs_buf (xfs/xfs_buf.h) + its clear in xfs_buf_stale — UNUSED now (the accumulation logic was reverted). Harmless; reuse or delete next session.
- drc_probe2.sh now checks lookup_fail (not just readdir count).

### REFUTED this session (do NOT repeat):
1. **sess26 FUA/BLI plan** — DEAD: target is LIO, rejects FUA reads ([[sess27-target-is-LIO-rejects-FUA-reads-handoff-plan-dead]]).
2. **Persistent b_mxfs_idirty_mask accumulated IN mxfs_submit_partial_inode_write** (write the UNION of all sectors this node ever logged): REFUTED — P26-IGET-FAIL=20 PERSISTED + readdir regressed 200→193. Reason: accumulating only at partial-write time is INCOMPLETE — an inode's log item must be on b_li_list at some partial-write to be captured; inodes whole-written via the di_next_unlinked path (line 1567 dirty-buf-item → whole write) are never added. To do this correctly the home-dirty bit must be set at LOG time (xfs_trans_log_buf / iflush), not at write time. Build D7D2E861 (reverted).

### Best current understanding of the TWO durable lost-updates (RULE 4, both nodes agree, persist drop_caches):
- BUG1 inode-alloc REVERT (dirent→freed inode): node's OWN contiguous inode chunk partially free on disk (f1..f9 durable, f10+ free). partial_iwrite=0 fixes it → it IS the partial-inode-write skipping the node's own freshly-allocated-but-checkpointed inodes. The dir RELEASE fence (sess97, xfs_bwrite synchronous, mxfs_dir_data_durable walks WHOLE data fork incl leaf) is SOUND for the DIR — but FILE inode clusters are flushed by the creating node's OWN sync/xfsaild via the buggy partial-write, NOT via any DLM release. So the fix is in the inode-cluster WRITE path or a LOG-time home-dirty mask.
- BUG2 dir LEAF-hash hole: exposed under whole-writes; leaf stays in-AIL at re-acquire (P21S-EVICTSKIP-LEAF in_ail=1 pin=1) so acquire-refresh skips it → stale RMW reverts peer dirents.

### NEXT STEPS (per GPT design [[sess27-gpt-design-release-drain-is-foundation-unified-root]], RULE 4 — one fix, instr=0, measure):
1. **Pin the exact reverting WRITE** with a daddr-targeted probe: pick the failing inode's cluster daddr (compute from inum via XFS_INO_TO_*), log every write to that daddr (comm, partial/whole, di_mode bitmap, b_li_list). Run drc_probe2.sh to fresh divergence. This settles whether BUG1 is node2's partial-write skip vs node1's rm-rf whole-write-of-stale-cache vs xfsaild.
2. Implement the correct fix for whichever it is: either (a) LOG-time home-dirty mask feeding the partial-write (set bit in xfs_trans_log_buf/iflush for inode bufs, clear on I/O completion), or (b) add a physical inode-cluster handling: whole-write the cluster but skip only sectors a PEER currently holds (needs cheap peer-ownership check), or (c) add an inode-cluster xfsaild-skip submit guard analogous to mxfs_buf_xfsaild_skip_dir_write (skip stale prior-tenure inode write).
3. Then BUG2: ensure the dir leaf is fully destaged before the dir EX is handed off so it's not in-AIL at the peer's re-acquire (extend/verify the sess97 fence covers the leaf extent's actual writeback completion, not just submit).
Run order: fix BUG1 first (default args), confirm P26-IGET-FAIL=0, then attack the exposed BUG2 leaf-hole, then full `./run.sh 2 tcp` ×3 for 100%.
</body>
