---
name: trap-a-release-by-eviction-frees-the-inodes-relmark-so-the-reinstall-refusal-needs-a-peer-driven-release
description: TRAP (0.90.102): drop_caches releases lost to a dead master adopted 9 records, never refused: eviction frees i_mxfs_relmark_*. Peer-driven (BAST) rel…
metadata:
  type: feedback
---

P-RELMARK-REINSTALL-REFUSED compares the grant offered at install against the inode's
IN-MEMORY clean-release mark (ip->i_mxfs_relmark_res/epoch, set in
mxfs_inode_relmark_before_unlock, xfs/xfs_mxfs_authority.c). A release driven by eviction
(drop_caches, reclaim) publishes the durable marker but then frees the inode, so a later
iget starts with no mark and the refusal can never fire — even though the DLM side
(P-TAUTH-ADOPT-LOCAL of the imported record under the released id) happens just the same.

Measured on nested pair A, 0.90.102 unfixed: tests/pve_released_grant_ghost.sh with
RELEASE_BY=evict adopted 9 records and came back clean after the outage; RELEASE_BY=peer
(participant 1 lists the directories while participant 0 writes, so the BAST-driven
release keeps the inode cached, then participant 1 is frozen) reproduced
REINSTALL-REFUSED, a classless image, and P-BOOT-REFUSED after the total outage on the
first lap.

Lesson: to exercise any check keyed on per-inode in-memory state, the release that sets
the state must leave the inode cached — use a peer's request (listing/stat from the other
host), not cache drops.
