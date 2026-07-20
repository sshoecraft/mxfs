---
name: sess105_lessons
description: sess105 — MAJOR REFRAME: rename_visibility loss is a CREATE-phase bug, not rename. Loser's before-files never reach the live shared dir inode; its mv…
metadata:
  type: project
---

# sess105 (2026-06-06, ccloop run 29df431e) — build `3911B884` (probes only, KEEP for now)

Continues sess104 (build 736ECD00, criterion 3/4). Goal: residual #1 rename_visibility flaky loss.

## MAJOR REFRAME (RULE-4 PROVEN): it is a CREATE-phase bug, NOT a rename lost-update
Reliable reproducer: fresh `virsh destroy+start` all 4 + `reset4.sh 4`, clear dmesg PER pair,
loop `run_tests --test test_cross_visibility` then `test_rename_visibility`. Fails clean
(no shutdown) within 1-2 pairs: ONE node (this run: node1=test1) loses ALL 20 of its renames,
40 failures/240, identical on ALL nodes (durable).

DECISIVE evidence (P-DIRWR per-dir-block write trace, merged across nodes by realns):
- rename dir = single block (P105 proves nextents=1, size=4096 — **Gemini's multi-block-overflow
  theory REFUTED**: no dir ever reached nextents>=2).
- The live shared dir block (owner=23068801 daddr=25047912) is built to active=62 (count=63) by
  node2/3/4's 60 before-files + ./.. — **node1 NEVER writes this block during create or rename**
  (only at teardown `rm`). node1's 20 before-files are absent cluster-wide.
- node1.log: `mv: cannot stat 'node1_before_1': No such file or directory` → node1's before-files
  were never created/visible. So the loss is in the concurrent **CREATE** phase, not rename.
- node1's FIRST acquire of ino=23068801 (P105-ACQ realns) is at the RENAME/teardown window, NOT
  the create window → during create, node1's path `.mxfs_test/rename_visibility` resolved to a
  DIFFERENT directory inode than node2/3/4's 23068801.

## ROOT HYPOTHESIS (instrumented, awaiting confirm next session)
Concurrent-mkdir / stale-dentry **directory-inode divergence**: harness `run_tests.sh:258` has
ONE node (`ssh_node 1`) `rm -rf .mxfs_test/<test>; mkdir`, then ALL nodes `mkdir -p $TESTDIR`
(test line 14) concurrently + create files. Under broken cross-node dir-entry/inode coherency,
the loser creates its 20 files into an ORPHANED dir inode (its own mkdir result / stale cached
dentry pointing at the old removed incarnation), while the `.mxfs_test` parent dirent for the
name ends up pointing at a peer's inode (23068801). Loser's files are durable but on an
unreachable inode → invisible everywhere, and its later `mv` ENOENTs. Related: sess38 claimed
"concurrent-mkdir coherency FIXED"; d_revalidate is DISABLED (CLAUDE.md) so stale dentries aren't
rechecked after a peer's rmdir+mkdir of the same name.

## PROBES ADDED THIS SESSION (build 3911B884, all always-on ratelimited)
- `P105-REL-DIRINODE` (xfs_mxfs_dlm.c bast_process, before unlock) + `P105-ACQ-DIRINODE`
  (slow-path after reload_inode): log dir i_disk_size + i_df.if_nextents. (Refuted multi-block.)
- `P105-CREATE-PARENT` (xfs_inode.c xfs_create, after dir_modify_refresh): logs `dp=<parent ino>
  name="<child>"`. **NEXT SESSION: build+deploy, reproduce one clean fail, then on each node
  `dmesg|grep P105-CREATE-PARENT|grep <loser>_before_` and compare the dp= parent ino across
  nodes.** If loser's dp != peers' dp for the same name → divergence PROVEN → fix = directory
  dentry/inode coherency on the create/lookup path (re-enable a targeted d_revalidate or invalidate
  the cached dentry+inode for a dir whose parent a peer modified).

## METHODOLOGY confirmed
- Verify reproduction is a CLEAN loss not a shutdown cascade: `grep -c "not mounted" rv.out` must
  be 0; once a node shuts down, all later runs falsely "fail" on not-mounted.
- reload_inode (xfs_mxfs_dlm.c:2282) DOES rebuild i_df + i_disk_size via xfs_idestroy_fork +
  xfs_inode_from_disk, BUT reads the on-disk home block (stale if peer's change only logged).
- Slow-path EX acquire evicts ALL data-fork dir blocks (data+leaf+free, dirty+in_ail, skip pinned);
  publish-before-notify flushes all dir blocks EX-held pre-release. Both proven sound — so per-block
  coherency is NOT the rename hole; the divergence is at the directory-entry/inode-identity level.
Marker NOT written (criterion 3/4).
