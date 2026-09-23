---
name: trap-a-synthetic-dirent-harness-misses-the-two-preconditions-the-real-criterion-produces
description: TRAP (sess604/605, D-0963): the synthetic shortform-resurrection harness ran 0/20 because the adopt path is skipped on the dir's creator and the dele…
metadata:
  type: feedback
tags: [D-0963, harness, shortform, reproduction]
---

# The synthetic shape missed two preconditions the real criterion produces

Context: D-0963 (a shortform directory's deleted entry re-added by the 3-way merge
and published as a dangling dirent). Session 604 wrote
`tests/d0963_sf_dirent_resurrect.sh` from the record's chain and it ran 0/20.
Session 605 read why from the code and the capture's numbers:

1. **The pre-mutation platter adopt (P174-STALEGEN-ADOPT) is skipped on the node
   that CREATED the directory** (`sf_disk_check` requires `!i_mxfs_self_created`,
   xfs_mxfs_dlm.c cached-EX fast path). The harness had node A mkdir the directory,
   so A's removals printed P-SFDIR-STALE-RMW ten times per lap and never adopted.
   In the board capture the creator was the OTHER node.
2. **The deleter's fork must stay stale-gen for its whole removal loop**, which
   needs its re-acquire after the peer's tenure to SKIP the rebuild
   (P34F-RELOAD-SELFAHEAD-SKIP: the capture showed pin=1 ili=0x1 — the inode was
   pinned by its own not-yet-logged removals, 73 skips, loaded_gen frozen at 11
   while dir_gen was 12). The harness's handoffs forced the log at each release,
   so the deleter rebuilt (selfahead=0) and loaded_gen caught up.

The real `cache_coherency` unlink_visibility phase produced both (the peer's verify
loop overlaps the deleter's removals), at 1 lap in 5. Lesson: when a board
criterion reproduces a defect at a usable rate, drive THAT criterion in a lap loop
with the diagnostics armed (`tests/d0963_cc_laps.sh`) before inventing a shape,
and when a synthetic shape reads 0/N, check the gate conditions of every probe in
the chain against which NODE plays which role — self-created, pinned, post_release
— rather than assuming the chain is wrong.
