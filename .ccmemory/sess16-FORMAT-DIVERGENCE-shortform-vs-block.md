---
name: sess16-FORMAT-DIVERGENCE-shortform-vs-block
description: sess16 KEY: crash_consistency clobber = FORMAT DIVERGENCE under inode reuse — releasing node sees dir as SHORTFORM (fmt=1, low dir_gen) while peer ha…
metadata:
  type: project
---

## sess16 P16-RELEASE instrument result (build 03A6D084, isolated per-iter probe, ino=131 reused across iters 12-14, failing iter 14 lost 4 data entries durably).

## DECISIVE NEW FINDING (RULE 4): the two nodes DISAGREE on the shared dir's on-disk FORMAT.
- test1 P16-RELEASE-DUMP ino=131 **fmt=1** (XFS_DINODE_FMT_LOCAL = SHORTFORM) dir_gen=2,3 inode_in_ail=0. A shortform dir has NO data-fork extents → release fence data-block drain lands NOTHING (dirents are INLINE in the dinode).
- test2 P16-RELEASE-DUMP ino=131 **fmt=2** (EXTENTS = block/leaf) dir_gen=225,241; its data block daddr=2093304 undest=0 (destaged fine).
=> test1 holds/releases ino=131 as SHORTFORM while test2 has the SAME inode as BLOCK format. dir_gen wildly asymmetric (test1=2/3 fresh, test2=241 recycled) = inode-number REUSE where one node's in-core inode is RECYCLED (i_dlm_dir_gen persists high) and the other's is fresh (gen resets low).

## MECHANISM (hypothesis, strong): test2 converted the dir sf→block (allocated data block, moved dirents there, dinode now points to data block). test1's in-core dinode is STALE shortform (never re-read test2's conversion). test1 adds an entry → RMW on stale inline-shortform dinode → writes a SHORTFORM dinode to the LUN, OVERWRITING test2's block-format dinode (which pointed to the data block holding all entries) → entries durably lost. This is INODE/dinode coherency on EX acquire, NOT the dir-DATA-block drain (which the sess97 fence + GPT demote-drain handle). The earlier [[sess16-ROOT-xfsaild-stale-flush-reused-daddr]] xfsaild-stale-flush trace was a PRIOR-iter rm drain (coincidental name match), not THIS clobber.

## This is the SHORTFORM-dir + inode-REUSE stale-cache family: [[sess125-shortform-parent-dir-lost-update-is-the-root]] [[sess128-root-fix-phantom-ex-rearm-unpublished]] [[sess84_lessons]] [[sess94 i_dlm_dir_loaded_gen]]. Existing machinery: i_dlm_dir_loaded_gen (xfs_inode.h:136, sess94) is meant to detect a STALE in-core shortform fork when a cached EX-acquire fast-paths (i_dlm_dir_gen advanced past i_dlm_dir_loaded_gen → shortform fork stale → must reload). It is evidently NOT firing/working for this reuse case (test1 keeps stale shortform across test2's conversion). Also i_dlm_dir_evicted_incarn (sess104) keys evict on VFS i_generation across reuse — but buf_incarn==cur_gen here (di_gen doesn't differ).

## NEXT (RULE 4): PROVE the dinode clobber. (1) Instrument the inode-cluster WRITE (xfs_inode_buf / dinode flush) to dump di_format + dir_gen + whether the inode is shortform-with-N-inline-dirents vs block — see test1 writing a SHORTFORM dinode over test2's block dinode at the same inode location. (2) Check the dir EX ACQUIRE path: does test1 RE-READ/reload the dinode (detect format change sf→block) when a peer modified (i_dlm_dir_gen advanced / i_dlm_dir_loaded_gen stale)? Likely fix: on dir EX acquire after peer-modify, FORCE re-read of the dinode (invalidate the in-core inode fork) when format/gen indicates a peer conversion — analogous to GPT's "invalidate + reread on acquire" but for the INODE, and treat a stale shortform-after-peer-block as a reload trigger. CAUTION: prior sessions' inode-reload-on-acquire fixes regressed (deadlocks, di_size clobber sess39); test in full suite. Build/repro: tests/cc_blockdir_probe.sh (isolated per-iter, ino reused, <15 iter). Fallback 17DCD050 (15/16). [[sess16-gpt-architecture-demote-drain-by-lock-ownership]]
