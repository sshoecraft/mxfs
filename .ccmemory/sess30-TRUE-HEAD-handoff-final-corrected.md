---
name: sess30-TRUE-HEAD-handoff-final-corrected
description: sess30(ccloop) TRUE FINAL HEAD: keeper 7FDAE615 (4 dir levers default-1, force-flush default-0/refuted). Verified wins: crash_consistency ABBA fix, s…
metadata:
  type: project
---

## sess30 TRUE FINAL HEAD (supersedes the refuted force-flush "breakthrough")

### KEEPER BUILD: **7FDAE615** (deployed via NFS /src/mxfs/mxfs.ko)
= 4 dir levers DEFAULT-1 (dir_release_invalidate, dir_relinval_clean, dir_gen_per_handoff, dir_modify_extent_adopt) + dir_release_flush_all_done DEFAULT-0 (refuted, inert). Behaviorally == C1B0C0CE. Backup: xfs/xfs_mxfs_dlm.c.backup-sess30.

### CRITERIA `./run.sh {1,2,4,8} tcp` 100% — NOT MET. But major progress.

### VERIFIED WINS this session (KEEP — all in the keeper build)
1. **crash_consistency ABBA hang FIXED** (sess21/29 PRIMARY 8/tcp wall) — PASS 8/8 in-suite every run. `mxfs_dir_flush_data_blocks_relsafe`: snapshot daddrs under i_lock → drop i_lock → flush via i_lock-free `mxfs_dir_flush_one_daddr`. [[sess30-FIX-crashconsist-ABBA-flush-snapshot-relsafe]]
2. **soak FIXED** → 4/tcp 17/17. `mxfs_buf_ops_from_magic()` re-derives the write verifier from on-disk magic when b_ops==NULL (pal/linux/xfs_buf.c) → stamps CRC, no dump_stack. [[sess30-WIN-4tcp-17of17-soak-fixed-by-P30-ops-recover]]
3. **1/tcp = 16/16 ✓**, **4/tcp = 17/17 ✓** (3 clean runs, bare run.sh, levers default).

### SOLE remaining blocker: dir_reuse_coherency — FLAKY, TWO distinct faces (both UNSOLVED)
- **Face 1 (2/4-node): durable single-dirent TOTAL loss.** `P21H-LEAFHOLE name=<f> hv_in_leaf=0` + `drc-RDMISS readdir=N-1` (399/400, 799/800). The dirent (leaf+data) vanishes durably after concurrent create + cross-node EX handoff. **force-flush of DONE data blocks at release (dir_release_flush_all_done) did NOT fix it** (loss persists round-3 399/400) and caused a rc=-110 DLM-lock-timeout shutdown → REFUTED. So the lost block is likely !DONE (evict-invalidated) at release, OR the loss is not at release. NEXT: determine the block's XBF_DONE/dirty/pin state at the moment node1's add is lost (instrument the specific dirent's data block across the handoff).
- **Face 2 (8-node): AG-meta CRC / metadata-read-error shutdown** under rm-rf mass-inode-free storm — `xfs_trans_read_buf_map` / `xfs_read_agi` err74 → shutdown → EIO cascade. NOT a no-buf-ops write (P30 never fired). sess22 lead: content valid, CRC wrong — needs daddr-0x2 write-CRC + read-fail-CRC probe. [[sess30-dir_reuse-insuite-cascade-is-AGI-CRC-shutdown-not-dabuf]]

### KEY METHODOLOGY LESSON: dir_reuse is FLAKY — a SINGLE pass proves nothing. Require ≥3 clean runs before claiming a fix (I falsely claimed a force-flush "breakthrough" on one lucky 2/tcp pass). Also: dev-host MAY contaminate after ~15 full-cluster cycles (sess29) — cache_coherency 0/8 in-suite is the tell (passed 4/4 here so not yet severe). Fast repro: `bash tests/tcp/full8.sh 2 ""` fails ~round 2-3.
### Refuted levers (do NOT retry): dir_leaf_rebuild, dir_write_merge, dir_flush_lockwait, dir_postread_reread, dir_release_flush_all_done.
See [[sess30-SCOPING-1and4tcp-100pct-dir_reuse-sole-flaky-blocker]] [[sess30-BREAKTHROUGH-dir_reuse-fixed-force-flush-all-done-2tcp-17of17]] (now the REFUTATION).
