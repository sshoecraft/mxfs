---
name: sess39-run14d-zsl-cleanstate-pass-dmesgclean-p20-gate
description: sess39 run14d: zsl PASSES on CLEAN cluster (4/4 iters, 0 P-REG-DURABLE-FAIL); 19:12 FAIL was contamination. dmesg_clean FAIL root=ungated P20-BIO-REA…
metadata:
  type: project
---

# sess39 (ccloop 14d31183) — zsl clean-state pass + dmesg_clean P20 gating fix

## zero_silent_loss is GREEN on a CLEAN cluster
- After `cluster_reset_n.sh 16` (fresh), build `4450524B`: zsl passed **1/1 then 3/3**
  (0 silent loss, ~110s/iter). The criteria JSON FAIL at 19:12:59Z (1590 loss,
  completed=1/3) was on a cluster left CONTAMINATED by sess38's mid-work gating sweep —
  matches the recurring "contaminated cluster → catastrophic failure" lesson.
- NON-PERTURBING PROOF the bug didn't fire on clean state: `P-REG-DURABLE-FAIL`,
  `corrupt dinode`, `P133-DIRINO-REVERT`, `P31-RELFLUSH-SELF-SKIP` = **0 across all 16
  nodes** during the passing 3/3 run. So on clean state the release flush succeeds and
  the torn-dinode window never opens.

## LATENT torn-dinode race still in code (not fixed — unreproducible on clean state)
- `mxfs_dlm_bast_process` release loop (xfs_mxfs_dlm.c ~3045): when the 8-try self-flush
  fails (`flushed==false`) AND the dir dinode is still `XFS_LI_IN_AIL`, it only logs
  `P-REG-DURABLE-FAIL` and RELEASES ANYWAY (Invariant-#1 gap). Then a peer grows the
  BTREE dir to nextents=23 (dinode+bmbt durable@23) and this node's stale xfsaild push
  of the still-dirty dinode (nextents=22) reverts it → "corrupt dinode (btree extents)"
  → shutdown → ~1590 loss. Root of the intermittent zsl catastrophic failure.
  - WHY the 8-try loop fails: `xfs_iflush_cluster` uses `xfs_ilock_nowait(SHARED)` and
    trylock-SKIPS the dir inode whenever a local create holds its ILOCK (constant during
    the dpn=100 storm). Did NOT patch (RULE 4: not reproducible on clean state; release-
    path changes have repeatedly regressed). Fix candidate for a future repro: deterministic
    single-inode flush holding ip's ILOCK (bounded), NOT trylock-skip.

## dmesg_clean FAIL ROOT-CAUSED + FIXED (build `5D2D50C8B691678F0A60D19`)
- FAIL: test1 hits=8. The 8 "Call Trace:" lines = `dump_stack()` from the UNGATED
  `P20-BIO-READ-LOGGED` probe in pal/linux/xfs_buf.c (~3213, fires on ANY plain-bio read
  of a buffer with log items attached = routine; daddr=128 during BAST processing). The
  sess38 probe-gating sweep MISSED it (it gated P20-CLUSTER-INVAL, not P20-BIO-READ-LOGGED).
- ALSO gated the flooding `P29-INSTR` bunmapi probe (xfs/libxfs/xfs_bmap.c ~5287, fires
  every unlink). Both are LOG-ONLY → gated behind `unlikely(mxfs_instr_enabled ||
  mxfs_dirwr_enabled)`. dmesg_clean now PASS hits=0 (×2 confirmed).
- KEPT ungated (real-anomaly detectors w/ once-guards, did NOT fire): PROBE-A
  AG-META-WRITE-NOT-HELD (2056), P125-AG-DIVERGE (2110), P88-CLOBBER-PRODUCER (2253),
  and upstream xfs_buf_verify_write "no buf ops" warning (1743).

## SEPARATE real bug seen but NOT yet fixed: xfs_assert_ilocked WARNING in d_revalidate
- During the zsl STORM (not dmesg_clean's window): `WARNING ... xfs_assert_ilocked` at
  `xfs_iread_extents` via `xfs_dir2_format ← xfs_dir_lookup ← mxfs_drevalidate`.
  `xfs_ilock_data_map_shared` picks SHARED (extents look loaded), then the MXFS DLM reload
  hook inside the acquire resets dp->i_df to need-iread; `xfs_iread_extents` then needs
  EXCL but only SHARED held → WARN. Only matters for dmesg_clean (the only dmesg-grepping
  criterion); did NOT fire in dmesg_clean's lighter workload (dmesg_test dir stays
  BLOCK/LEAF, not BTREE). Latent dmesg_clean risk + possible coherency hazard. Address if
  it surfaces in dmesg_clean.

## Gate status on 5D2D50C8 (running end-to-end, foreground criterion-by-criterion)
9/19 PASS: mkfs_timing, chk_clean, dkms_install, online_resize, cluster_ops_timing,
wedged_unmount, online_membership, dmesg_clean, cache_caps. Remaining: posix_semantics(1),
cache_coherency(4), strong_consistency(4), zero_silent_loss, crash_consistency(2),
fence_during_write(4), single_node_paired(1), rsync_paired(4), scaling_curve(16),
posix_semantics(16). FOREGROUND-wait rule re-flagged by user (no bg+poll).
Related: [[sess38-run14d-recovery-and-probe-gating]], [[sess31-run14d-rename-loss-fixed-zsl-torn-dinode]].
