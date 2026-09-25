---
name: technique-prove-a-source-transform-changes-no-code-by-same-path-rebuild-and-non-debug-section-compare
description: TECHNIQUE (0.89.89): prove a comment/whitespace/move refactor changed no code: build before+after at ONE path, force a full rebuild, cmp non-debug se…
metadata:
  type: feedback
tags: [build, verification, refactor, technique]
---

Used for the comment cleanup and the dlm/ reindent in 0.89.89. Every step below was learned by getting it wrong once in the same session.

1. **Build both trees at the SAME path.** An external-module build embeds its directory (`__FILE__` in ASSERT/xfs_do_force_shutdown, DWARF comp_dir), so objects from two different scratch dirs differ everywhere — 161/161 objects "differed" before any edit mattered.
2. **Force the second build.** `rsync -a` keeps the sources' old mtimes, so `make` in the reused tree compiles NOTHING and the compare is vacuous (the first attempt reported 161/161 identical with 0 `CC [M]` lines). `make clean` first, and check the `CC [M]` count equals the object count.
3. **Save the baseline objects to their own dir** (`find -name '*.o' ! -name '*.mod.o' -exec cp --parents`) and name it explicitly — `ls -dt tmp.*` picked the build tree itself and compared it with itself.
4. **Compare non-debug sections**, not whole files: `objdump -h` minus `.debug*`/`.rela.debug*`, then `objdump -s -j <sec>` per section. DWARF legitimately changes (declaration COLUMNS move when a comment on the line shrinks).
5. **Expected non-debug difference for whitespace changes:** Ubuntu's kernel has UBSAN bounds checking; its `struct source_location {file*, u32 line, u32 column}` records live in `.data`. Re-indenting moves columns, so `.data` differs ONLY in the column word (offset 12..15 of each 16-byte record) — verify that with `objcopy -O binary --only-section=.data` byte compare (0.89.89: 3,640 differing bytes, all in column words).

Keep line counts identical in any such transform (edit within lines only) so line numbers — and therefore code using __LINE__, WARN tables, dyndbg descriptors — stay identical.
