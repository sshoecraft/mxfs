---
name: sess18-candidate-fixes-ranked-force-block-format
description: sess18 ranked fix candidates for 2/tcp sf→block transition loss. RECOMMENDED #1: force multinode dirs to BLOCK format at mkdir (eliminate the sf→bloc…
metadata:
  type: project
---

## sess18 (ccloop 8ddb16a2) — ranked candidate fixes for the PROVEN sf→block transition durable lost-update [[sess18-ROOT-NARROWED-shortform-to-block-transition]] [[sess18-FIX-LOCUS-reload-selfskip-sf-block-format-upgrade]].

## ROOT (decisive): pre-grown-to-block dirs lose 0/30; sf-start dirs lose ~1/8. The bug is two nodes racing the shortform→block format CONVERSION on a fresh dir; one node keeps a stale SHORTFORM in-core base and durably writes shortform over the peer's BLOCK conversion. Steady-state block-format is SAFE. Read-side ruled out (FUA no help); release path does not escape; per-create merge is perf-doomed.

## CANDIDATE #1 (RECOMMENDED — cleanest, avoids regression-prone code): FORCE MULTINODE DIRS TO BLOCK FORMAT, eliminating the transition race entirely. A directory that never lives in shortform on a multinode mount has no sf→block transition to race on (this is a standard clustered-FS approach). Implementation options:
  - At mkdir (xfs_create is_dir path / xfs_dir_create_child / xfs_dir_init), when mp->m_mxfs_dlm && multinode, immediately convert the new dir shortform→block (xfs_dir2_sf_to_block) within the mkdir transaction (reserve the extra block). The dir is then block-format on disk from birth; no node ever holds a shortform base to clobber with.
  - Cost (RULE 0): one extra data block per multinode dir + the conversion at mkdir (ONCE per dir, NOT per-create — so NOT the hot-path merge cost). Acceptable; block format is needed anyway for any concurrently-accessed dir. Verify solo-rsync perf unaffected (mkdir is comparatively rare).
  - Risk: low — it uses the standard XFS sf_to_block path; no change to the heavily-layered reload self-skip. Validate cc_blockdir_probe (sf-start) clean >25 iters + ./run.sh 2 tcp 16/16 x>=5.

## CANDIDATE #2 (fallback — riskier): format-upgrade-forces-adopt in mxfs_dlm_reload_inode self-skip (~5659). Make mxfs_dir_disk_superset also true when incore if_format==LOCAL && disk di_format>=EXTENTS (block never reverts to sf in create-only → definitive peer-convert proof, independent of the laggy i_dlm_dir_gen). MUST handle the in-flight-work tension (replay our pending dirent onto the adopted block image, a bounded transition-only merge) or risk losing our own entry / sess33 CORRUPT_INCORE. Regression-prone (self-skip protects unlink/rename in-flight work).

## METHOD (user guidance): develop against a 4/8-node DETERMINISTIC repro (tests/reset4.sh [N]; VMs test1..test17 defined; sf-start cc_blockdir_probe fires harder with more creators), then VALIDATE on 2-node (the criterion). Watch canaries: cache_coherency, zero_silent_loss, rename_visibility, unlink_visibility.

## STATE: cluster HEALTHY 2-node baseline (build AA741B4E, dir_merge=0, fua_disable=1, both mounted RW_OK). In-tree merge code (mxfs_dir_merge_peer_blocks, mxfs_dir_merge_peer_into_tp, xfs_inode.c fold wiring) is DORMANT (dir_merge default 0) — harmless; can be removed or left. Repro scripts: tests/cc_blockdir_probe.sh (sf-start, reproduces), tests/cc_pregrown_probe.sh (block-start, clean — the discriminator). Marker NOT written (criterion genuinely unmet: durable loss live).
