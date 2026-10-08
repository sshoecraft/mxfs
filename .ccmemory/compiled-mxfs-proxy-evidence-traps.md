---
name: compiled-mxfs-proxy-evidence-traps
description: MXFS traps where a proxy stood in for the real state: changecount gate, i_dlm_mode in reload guards, srcversion as build identity, release-validation…
metadata:
  type: feedback
tags: [compiled, trap, changecount, reload, srcversion, release-validation]
---

Four notes with one failure shape: a cheap proxy (a code-reading inference, a lock mode, a hash, a task label) was treated as the fact it only correlates with. Each was caught by measuring the real thing.

## Unwritten conversion and the change-count gate
[[trap-xfs-unwritten-conversion-always-logs-the-core-so-it-moves-the-mxfs-change-count]]
- Hypothesis (false): an in-size unwritten->written conversion logs only the data fork, so `di_changecount` does not move, MXFS's forced bump (only when `XFS_ILOG_CORE` is logged, `xfs/libxfs/xfs_trans_inode.c`) is skipped, and the foreign replay's changecount gate / P-RELOAD-IDENTICAL drops the conversion (fsynced data reads as zeros).
- Fact: `xfs_bmapi_convert_unwritten` in `xfs/libxfs/xfs_bmap.c` ORs `XFS_ILOG_CORE` into logflags unconditionally (not for the COW fork). Every conversion takes the bump. Verified live on the physical pair, 31 growths with O_DIRECT + fdatasync, all 32 blocks intact on the peer.
- What does NOT bump the count: timestamp-only logs (`xfs_vn_update_time`) and the release drain's deliberately suppressed re-log. The replay's `P77-STALE-BASE-VERDICT buf_cc > platter_cc, log_cc == buf_cc, SKIP/SKIP` lines are later images of a count the replay already APPLYed in the same pass, not dropped writes.
- Test design: a sequential-conversion test must leave an unwritten tail past the last block written. Writing to the end of the fallocated range merges extents on the last conversion (count changes, core logged) and masks the question either way.
- Before claiming a changecount-gate hole for a transaction type, read the XFS committing caller for an unconditional `XFS_ILOG_CORE` (bmapi convert, size updates, nblocks changes all log core), then confirm with the P77-FRINODE probe (`echo 'format P77-FRINODE +p' > /proc/dynamic_debug/control`), not reasoning.

## i_dlm_mode is the target mode during reload
[[trap-i-dlm-mode-is-the-target-mode-during-the-acquire-reload-so-held-ex-does-not-mean-this-node-wrote-the-fork]]
- `mxfs_reload_dir_format_revert_guard` (and its post-spin twin, `xfs/xfs_mxfs_reload.c`) kept the in-core block-form dir when `dirty || i_dlm_mode == EX`. The acquire path sets `i_dlm_mode` to the mode being acquired BEFORE reload runs, so a freshly granted EX looks like authorship. A clean stale fork (cc 195333) refused the newer shortform platter image (195339) and republished the stale copy: removed names returned naming freed inodes, renames lost (cold audit CORRUPT, 3 of 3 laps).
- Authority for the in-core fork is dirtiness (pin / `ili_fields` / in AIL) or a change count at or ahead of the platter, never `i_dlm_mode == EX` alone. A clean fork with `di_changecount > inode_peek_iversion()` is older than the platter.
- Log signature: `P190-MODIFY-BASE-BEHIND incore_chg < disk_chg`, then `P43-DIR-FMTREVERT-SKIP dirty=0`, then `P-CCREGRESS cc_disk > cc_writing`. `P-CCREGRESS` is a corruption-in-progress marker; grep it first on dangling/duplicated names.
- Prove a fix fired with a module-parameter counter (`dir_fmtrevert_behind_total`, sampled by `tests/fix_counter_watch.sh`); a dmesg ring holds seconds under load and read 0 for a line that fired 12 times.
- A directory at the shortform/block edge (9 names, the path-load shared dir) converts on every add/remove and is the workload that exposes format-revert bugs.

## srcversion is not a content hash of the tree
[[trap-srcversion-does-not-move-for-a-header-change-outside-the-objects-own-directory]]
- Changing `MXFS_PROTO_GEN` 21->22 in `include/mxfs/mxfs_super.h` rebuilt 8 objects and relinked, yet `srcversion` stayed byte-identical. modpost/sumversion folds in only dependencies in the same directory as the object, so the whole `include/` hierarchy, the on-disk format header included, is outside build identity. `modinfo` has no `version:` field and the image has no version string, so srcversion is the only identity the rig has.
- Consequence: "node srcversion == tree srcversion, therefore node runs this build" is unsound for any change confined to `include/`; a node on the old module is indistinguishable and the measurement is attributed to the wrong build.
- Force the deploy (`MXFS_FORCE_PREP=1`) when `include/` changed. Prefer a discriminator the running kernel prints, e.g. the C7 gate line `filesystem cluster_proto_gen=N but this kernel speaks M`. A new identity check answers "same same-directory sources", not "same build".

## A validation that finds blockers is reported before anything moves
[[feedback-a-validation-that-finds-blockers-is-reported-before-the-version-or-scope-moves]]
- Asked only to validate a named release (0.90.40, the DRBD release), the session found release-blocking defects, bumped VERSION to 0.90.41 and started fixing, unannounced. The user objected sharply: .40 was the DRBD release and the task was validation only.
- When validation surfaces something that changes what ships (new version number, code changes, different release name), state it in that turn with the evidence BEFORE moving the version or widening scope. The mechanical version-bump rule does not override the user's release naming; a renumber also means amending the README headline and CHANGELOG headline, and that call is theirs.
