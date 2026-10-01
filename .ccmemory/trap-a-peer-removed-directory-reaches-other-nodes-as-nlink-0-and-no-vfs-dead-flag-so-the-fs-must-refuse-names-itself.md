---
name: trap-a-peer-removed-directory-reaches-other-nodes-as-nlink-0-and-no-vfs-dead-flag-so-the-fs-must-refuse-names-itself
description: TRAP (0.90.37): IS_DEADDIR is set only on the node that ran rmdir; peers see nlink 0 via reload and XFS never checked, so mkdir committed into a remo…
metadata:
  type: feedback
tags: [directory, rmdir, mkdir, coherency, integrity]
---

**What bit us (0.90.37, 8/net/mesh/direct).** One node ran `rm -rf` on a directory while the other nodes ran `mkdir` inside it. A mkdir on a node that did not run the rmdir committed its entry into the directory after the rmdir had taken it to nlink 0. The directory was then freed along with that entry, which left the child with no name and a `..` naming a free inode.

**Why nothing stopped it.** Locally, the VFS refuses creates in a removed directory through `IS_DEADDIR`. `vfs_rmdir` sets `S_DEAD` only on the inode of the node that ran it. Every other node learns about the removal only through the cluster grant it acquires, which reloads the inode with nlink 0 and sets no dead flag. Upstream XFS never checks the parent's nlink in `xfs_create`, because the VFS guaranteed it. Grepping `IS_DEADDIR` over the MXFS tree returned 0 hits.

**The rule of thumb.** Any VFS guarantee enforced by an in-core flag on the node that performed an operation, such as `S_DEAD`, `I_WILL_FREE` or dentry state, does not exist on peer nodes. The filesystem has to re-check the equivalent fact from the reloaded inode once its grant is held.

The fix: `xfs_create` refuses with `-ENOENT` when `VFS_I(dp)->i_nlink == 0` after the grant, before `xfs_dialloc`, while the transaction is still clean. A dirty cancel after dialloc shuts the filesystem down.

Still open on the same gap: link, symlink and rename into a directory (defect `D-LINK-SYMLINK-RENAME-INSERT-NAMES-INTO-A-PEER-REMOVED-DIRECTORY`).

**How it was caught.** The board's `ag_strand_repair` only collides when a node lags by several rounds, so it reproduced in about 1 of 4 parallel waves. `tests/stress_rmdir_mkdir_race.sh` forces the overlap every 200 ms, and reproduced it in a single 300 s lap on an idle host. When a race hides behind the load, build the forced-overlap shape rather than waiting on waves.

**Probe trap.** A post-commit probe that checks "parent nlink == 0" can never see a mkdir. The mkdir itself bumps the parent's nlink for the child's `..`, so a check after the commit reads 1.
