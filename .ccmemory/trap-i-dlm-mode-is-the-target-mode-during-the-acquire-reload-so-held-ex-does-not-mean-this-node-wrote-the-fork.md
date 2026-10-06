---
name: trap-i-dlm-mode-is-the-target-mode-during-the-acquire-reload-so-held-ex-does-not-mean-this-node-wrote-the-fork
description: TRAP (0.90.51): a reload guard gated on i_dlm_mode==EX kept a clean stale block-form dir over a newer platter; mode is the TARGET at reload. Compare…
metadata:
  type: feedback
tags: [reload, directory, dlm, corruption]
---

**What bit us (0.90.51, 4/ and 8/net/mesh/mpath, cold audit CORRUPT 3 laps of 3):**
`mxfs_reload_dir_format_revert_guard` (and its post-spin twin in `xfs/xfs_mxfs_reload.c`) kept the
in-core block-form directory whenever `dirty || i_dlm_mode == EX`. The acquire path sets
`i_dlm_mode` to the mode being acquired BEFORE the reload runs, so a node that has only just been
granted EX reads as "the exclusive holder" even though its fork was loaded under PR tenures ago.
A node with a CLEAN block-form fork (change count 195333) refused the shortform platter image
(195339) and published its stale copy: a removed name came back naming a freed inode, renames lost.

**Why:** "holds EX" was used as a proxy for "this node authored the in-core state". It is not —
only dirtiness (pin / ili_fields / in AIL) or a change count at or ahead of the platter says that.

**How to apply:**
- In any reload/adopt guard, never treat `i_dlm_mode == EX` alone as authority for the in-core
  fork. A clean fork with `di_changecount > inode_peek_iversion()` is older than the platter.
- The log already named it: `P190-MODIFY-BASE-BEHIND incore_chg < disk_chg` followed by
  `P43-DIR-FMTREVERT-SKIP dirty=0` and `P-CCREGRESS cc_disk > cc_writing`. A `P-CCREGRESS` line
  (publishing a lower change count than the platter holds) is a corruption-in-progress marker;
  grep for it first when a cold audit shows dangling or duplicated names.
- To prove such a fix fired, read a module-parameter counter (`dir_fmtrevert_behind_total`,
  sampled by `tests/fix_counter_watch.sh`); a node's dmesg ring holds seconds under load and
  counted 0 for a line that had fired 12 times.
- A directory sitting at the shortform/block edge (9 names in the path-load shared dir) converts
  on every add and remove; that workload is what exposes format-revert bugs.
