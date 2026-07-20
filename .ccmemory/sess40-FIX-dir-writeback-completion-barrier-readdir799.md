---
name: sess40-FIX-dir-writeback-completion-barrier-readdir799
description: sess40 FIX (build E12A35EE, default-on dir_wr_barrier): dir_reuse readdir=799 = prior-tenure dir-block write bio lands AFTER EX handoff. Fix=wait inf…
metadata:
  type: project
---

## sess40 (ccloop 4cb2d0a2) — build `E12A35EEF48BE52E863808C`. Architectural fix for the dir_reuse readdir=799 residual. UNDER VALIDATION (8/tcp drc_loop8).

### Context
Builds on the sess39 membership split-brain fix (keeper `8CC09D97`/`DC9BB97F`). With membership fixed, 8/tcp dir_reuse still loses ONE dirent ~25-50% of runs (readdir=799 → cascades to DABUF_MAP_HOLE shutdown). sess39's v2 EX-gated subset-DROP (`dir_refresh_inplace=1`) was CATASTROPHIC (leaf_removename corruption + bnobt double-free) → reverted to default 0 this session.

### PROVEN diagnosis (RULE 4, full instrumentation; drc_cap8.sh + drc_loop8.sh probes dataclobber=1 + dir_relverify=1)
- Single committed dirent (e.g. `node3_f46`) durably lost: ALL nodes agree (same dirino=131), `LOOKUP_ENOENT REREAD_MISS` = durable on-disk, not cache staleness.
- Creator added it: `P13-NADD ino=131 daddr=14652640 ... name=[node3_f46]`. Verify: `P26-DSCAN-MISS ... not in any data block`. `P33-DSCAN-ONDISK`: in-core extent map == disk EXACTLY (nx/size/gen) → NOT bmbt/extent staleness.
- **DECISIVE NEGATIVES: `P-DATACLOBBER-SKIP` SILENT + `P25-RELVERIFY-MISMATCH` SILENT.** The write-chokepoint disk-superset detector and the release-time disk==incore probe BOTH never fire on this loss. Acquire-evict working (all blocks done=0). Membership stable (no churn). So it's NOT the pre-membership-fix xfsaild stale-reflush (which the detector DID catch). Fixing split-brain changed the surviving mode to one the detectors are structurally blind to.

### ROOT (GPT-5.5 consult, confirmed by evidence)
A dir DATA/leaf write bio submitted in a PRIOR EX tenure COMPLETES AFTER the node released the dir EX and a peer cold-read + RMW'd + rewrote that block → the late bio lands an older image, durably reverting the peer's committed dirent. Detector blind because at the stale write's SUBMIT disk lacked the entry (harmless then); it clobbers only at COMPLETION. The release fence proves "disk==incore at sample instant" but NOT "no already-submitted bio can still land". AIL-empty is NOT a sufficient proxy for "no in-flight bio" (esp. with rm-rf+recreate daddr REUSE: a freed-block bio from a prior tenure/round lands on the reallocated daddr).

### THE FIX (canonical clustered-FS invariant: GFS2 glock / OCFS2 lock = EX tenure owns the writeback LIFETIME), default-on, kill-switch `mxfs.dir_wr_barrier=0`:
1. `xfs_mount.m_mxfs_dir_wr_inflight` (atomic) — count of dir-metadata write bios submitted-not-completed.
2. `xfs_buf.b_mxfs_dir_wr_counted` (bool) — per-buffer "counted once" flag.
3. `xfs_buf_submit_bio` (pal/linux/xfs_buf.c, after partial-inode check): inc the counter for any multi-node dir data/block/leaf1/leafn/free/da3_node WRITE; set b_mxfs_dir_wr_counted.
4. `__xfs_buf_ioend` (top): if counted, dec + clear (underflow-guarded).
5. Dir EX release fence (xfs_mxfs_dlm.c ~8799, after data_durable+relverify+release_stale, before break): wait (bounded 10s, shutdown/unmount bail) until `m_mxfs_dir_wr_inflight==0` before releasing the DLM lock. Probe `P40-WRBARRIER`. NO write is dropped/suppressed (that's what corrupted before) — only the handoff is DELAYED until I/O quiesce. No deadlock: ioend decrements independently of the bast worker.

### Validation harness
`tests/drc_loop8.sh <iters> [modargs]` (reboot-clean 8-node loop). `tests/drc_cap8.sh <iters> [modargs]` (NEW this session — breaks on first FAIL, pulls drc_fail_r*.dmesg RDMISS/CLASS classifier + clobber/relverify/bmbt traces before reboot wipes them). Capture key probes: mxfs.dataclobber=1 mxfs.dir_relverify=1.

### NEXT (if validates): also confirm 1/2/4 tcp no regression, then criterion. If still loses: the barrier is mount-wide (waits for ALL dir writes) — could need per-inode scoping; or the stale write is on a path that bypasses xfs_buf_submit_bio. See [[sess39-ROOTFIX-membership-splitbrain-formation-and-flap]].
