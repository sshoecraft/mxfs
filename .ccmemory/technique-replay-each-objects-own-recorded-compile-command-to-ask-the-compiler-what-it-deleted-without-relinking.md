---
name: technique-replay-each-objects-own-recorded-compile-command-to-ask-the-compiler-what-it-deleted-without-relinking
description: TECHNIQUE (s138): KCFLAGS=-Wextra rebuilds and RELINKS every object, which is unusable while a rig queue deploys the module; replaying each .o.cmd wi…
metadata:
  type: feedback
tags: [build, compiler, technique, rig-safety]
---

# Ask the compiler what it deleted without relinking the module

Four defects in one week were branches or hooks gcc could prove unreachable —
invisible to any amount of source reading, and each one a whole mechanism
missing from the shipped module. The compiler names them, but only at a warning
level the normal build does not use.

## Why `make modules KCFLAGS="-Wextra"` is not the answer

`KCFLAGS` changes every recorded compile command, so kbuild rebuilds all 131
objects **and relinks `mxfs.ko`**. Every lap re-preps the fleet and deploys that
file, so a relink mid-queue splits the sweep across two srcversions. A campaign
usually has a queue running, which makes the obvious instrument unusable exactly
when it is wanted.

## What works instead

`tools/warn_sweep.sh` replays each object's OWN recorded command out of its
`.cmd` file:

    savedcmd_/src/mxfs/xfs/xfs_inode.o := gcc-13 -Wp,-MMD,... <flags> -o <obj> <src>

with three edits and nothing else touched:

- **truncate at the first `;`** — the recorded command is a COMPOUND (`gcc …;
  objtool …`), and objtool exits 129 against `/dev/null`, which makes every
  object look like a failed replay;
- drop `-Wp,-MMD,<path>` so no dependency file is rewritten;
- rewrite `-o <obj>` to `-o /dev/null`.

Run it from `/lib/modules/$(uname -r)/build` — the recorded command's include
paths are relative to the kernel build directory, not the module tree.

131 objects in ~85 s at `-j6`. Nothing in the tree moves: no `.o`, no `.d`, no
`mxfs.ko`. It is safe to run against a live rig, and it doubles as a whole-tree
compile check for an edit you cannot yet build.

## Reading the output

- `comparison is always true/false` (`-Wtype-limits`) is the class that deleted
  two shipped branches. In this tree all 20 remaining sites are benign — a
  `uint8_t namelen` against `MAXNAMELEN` (255), where the type already enforces
  the bound and the real invalid value (`0`) is checked beside it. That sweep is
  complete; do not re-derive it.
- `defined but not used` is the compiler naming a whole function it dropped.
  This is the higher-yield class: it found the iomap revalidation hook and the
  lazytime completion hook, both of which existed, were correct, and were wired
  only into an ops struct a newer kernel has.
- **A name with initialisers can still be "not used".** `xfs_vn_sync_lazytime`
  had FOUR `.sync_lazytime = …` lines and was still reported — every one of them
  sat inside `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`. Grep counting
  references does not answer this question; the compiler does.

## The fix is verified by the warning disappearing

After a fix, re-run the sweep: the warning that named the defect must be gone.
That is what says the code is in the object rather than only in the source. It
is the first instrument, never the last — a referenced function is still not a
called one, so a live probe is owed separately.
