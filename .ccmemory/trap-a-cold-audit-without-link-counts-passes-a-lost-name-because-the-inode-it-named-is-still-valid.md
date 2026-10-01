---
name: trap-a-cold-audit-without-link-counts-passes-a-lost-name-because-the-inode-it-named-is-still-valid
description: TRAP (0.90.37): chk_mxfs checked only what entries name; a lost name leaves a valid inode nothing names. A link lap losing 86 names read dangling=0.
metadata:
  type: feedback
tags: [chk_mxfs, audit, directory, integrity, measurement]
---

**What bit us (0.90.37, 8/net/mesh/direct).** Until 0.90.37, the `chk_mxfs` directory pass checked each entry's target: is it allocated, is it a valid dinode, does the ftype match, is `..` a directory. A name *lost* from a directory leaves nothing bad behind. The inode it named is still allocated and valid, and its di_nlink still counts the lost name. So lost directory updates were invisible, and only dangling entries showed.

**Measured.**
- A `link` control lap of `tests/stress_rmdir_mkdir_race.sh` had hard links committed into a directory a peer had removed, and those links were freed with it. The re-audit found `nlink_mismatch=86` (regular files, nlink 2, one name) with `dangling=0`. The old audit would have said CLEAN.
- The pre-fix mkdir-race image had been graded as having only `dangling=1`. The link-count pass shows 47 mismatches, including 27 subdirectories whose `..` names an allocated directory that does not list them.

**Attribution trap inside the trap.** Those 27 look like lost updates on a live parent, but the parents in that stress are freed and their inode numbers reused within seconds. A child created in a dead parent then points `..` at the reused incarnation, which is "live" and never listed it. Compare crtimes, or rerun on the fixed build, before blaming a live-parent lost update.

**The pass (tools/chk_mxfs.c `check_dirents`).** It counts every entry naming each allocated inode, including `.` and `..` (shortform adds an implicit `.`), and compares the count to di_nlink. It reports `nlink_mismatch=` and `disconnected=`. It skips the sb metadata inodes, dirshard-flagged inodes, and unnamed nlink-0 inodes. It compares nothing if any directory was skipped or had a bad block. Calibrated clean on idle g2/g4 images: 31,530 inodes, 0 mismatches.

**How to apply.** Any CLEAN cold audit from before this pass does not cover lost-name damage. Re-audit a kept image before trusting it. When a corruption class leaves the damaged object looking valid, the audit has to check a cross-object invariant (a count or a reachability), never only the object itself.
