---
name: sess58-dir2-corruption-was-stale-dmesg-artifact
description: sess58: dir2 di_size corruption (sess57 "dominant root") was a STALE-DMESG ARTIFACT. P58 probe at the exact line-287 site fired 0× in 3 full 16-node…
metadata:
  type: project
---

# sess58 — dir2 di_size "corruption" was a stale-dmesg artifact; real blocker is the durable dirent lost-update

## What sess57 claimed (NOW REFUTED)
sess57 named the DOMINANT clean-gate shutdown root as `dp->i_disk_size != geo->blksize`
at xfs/libxfs/xfs_dir2.c:287 (xfs_dir2_format ← xfs_create), supposedly from the MODIFY
path reaching format-detection with a stale di_size vs a fresh extent map. See
[[sess57-dir2format-disize-corruption-modify-gap]].

## What sess58 measured (REFUTES it)
Added an ALWAYS-ON probe **inside** the exact `if (XFS_IS_CORRUPT(mp, dp->i_disk_size !=
geo->blksize))` block at xfs_dir2.c:287 (`mxfs: P58-FMT-DISIZE-CORRUPT ...`, build
E78F3B4A). Ran the full `zero_silent_loss` 16-node × 100dpn × 3-iter storm THREE times.
**P58-FMT-DISIZE-CORRUPT fired ZERO times. No node showed any `Internal error ... line
287` / `Shutting down` / `Corruption of in-memory` on the new build** (scanned all 16
nodes' live dmesg, srcversion confirmed E78F3B4A).

The line-287 `i_disk_size != geo` errors sess57 saw were OLD-BUILD entries (function
`xfs_dir2_format+0x1f2/0x240`; the new build is `+.../0x340`) left in dmesg because
`tests/reset4.sh 16` only virsh-reboots WEDGED nodes — the other ~10 nodes keep their
prior-session dmesg. **Lesson: always `dmesg -C` on ALL nodes (or full destroy+start all
16) before trusting a shutdown signature; reset4 does NOT clear non-wedged nodes.**

## The REAL current zero_silent_loss failure (build E78F3B4A, clean run)
Pure **durable dirent lost-update**, NO FS shutdown:
- iter1: expected=1600 silent=11. Forensics: `MISSING node14_dir1 creator=test14`,
  `CREATOR_MISSING creator_errs=[none]` — test14 mkdir'd node14_dir1..dir11 with no
  error, but they are durably absent from the shared parent `/mnt/shared/wa_iter1`
  (even the creator can't see them). A peer's concurrent mkdir RMW'd the shared parent
  dir block from a STALE cached base and wrote it back, erasing test14's committed
  dirents. This is the long-standing durable lost-update family (sess79–92, sess100,
  sess122).
- iter2/iter3 "VERIFY FAILED node0 find non-numeric" / "mount_cluster failed" were
  INFRA contamination from running storms back-to-back without a full clean reset, not
  FS corruption (no shutdown signatures present).

## Next (sess58, in progress)
Build D82E4FB9 adds ALWAYS-ON, rate-limited `P58-STALE-BASE-ADD` in
xfs_dir_createname_args (xfs_dir2.c, after xfs_dir2_format): fires when a multi-node
block/leaf parent dir is about to be RMW'd with `i_dlm_dir_gen > i_dlm_dir_loaded_gen`
(stale base) — logs self_created/evicted_gen/reload_flag to tell the benign 0→1
self-arming artifact from a real peer-modified stale base. Use the FAST repro
`tests/repro_dirent_loss.sh 16 10` (seconds/round, not the 5-min storm) to catch it.
Hypothesis: the EX-acquire stale-refresh (P101-FASTEX-EVICT, xfs_mxfs_dlm.c:5429) is
SKIPPED by the `!ip->i_mxfs_self_created` gate (sess24) for the freshly-created shared
parent, so the creator RMWs a stale base; OR evict leaves left>0 (stale block uncovered).

Related: [[sess57-clean-rerun-true-state-ino128-deadlock]], [[sess69-ondisk-proof-durable-lostupdate]].
Other open criteria: fence_during_write lost=400, rsync_paired 148%, posix_semantics_multi16 >600s (slowness/EX-contention, ino=128 P138-WAIT).
</body>
