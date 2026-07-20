---
name: sess22-freeslot-guard-0x-loss-is-postadd-stale-destage
description: sess22(ccloop) DECISIVE: Layer-3 free-slot guard (P22-FREESLOT-STALE, build 8948C889) fired 0× on all 8 nodes yet dir_reuse still loses entries — so…
metadata:
  type: project
---

## sess22 (ccloop) — free-slot double-alloc RULED OUT; loss is post-add stale-block destage

### Implemented GPT's Layer-3 structural guard (build 8948C889 = EFBB9861 + guard, KEEP — harmless):
In xfs_dir2_node_addname_int (xfs/libxfs/xfs_dir2_node.c ~1966), replaced the bare `ASSERT(bf[0].length >= length)` with a runtime guard: if the freshly-read data block's actual bestfree[0].length < the needed dirent length, freescan to rebuild bestfree, and if still short, repair freehdr.bests[findex] from the data block + `goto restart` (cap 32). Logs P22-FREESLOT-STALE. (freehdr.bests is a pointer INTO the fbp buffer, so the repair persists and the restart re-decodes the corrected summary → converges. Mirrors existing line 2013-2014.)

### RESULT (8/tcp dir_reuse, build 8948C889): **P22-FREESLOT-STALE fired 0× on ALL 8 nodes**, still FAILED (readdir loss), no shutdown. → `bf[0].length >= length` was ALWAYS true at addname. The chosen data block ALWAYS had genuine room. So GPT's stale-freeindex-summary mechanism is NOT the cause — addname writes the new dirent into a genuinely-free region (no overwrite at add time).

### THEREFORE the loss is a POST-ADD stale-block DESTAGE (sess11 "dirent logged rval=0 then VANISHES from the block"):
- node X adds its dirent to data block B at a real free slot (correct, durable-able).
- Later, a STALE cached copy of block B (from before X's add, or a peer's older view) is DESTAGED over the durable block B → X's dirent erased. Content-divergent, ~count-preserving.
- NOT the coordinated release-drain bwrite (my earlier P22 release count-probe was 0× during create).
- NOT caught by ex_write_guard / P-DATACLOBBER-SKIP (0×): EX-gated + count-based.
- Most likely path: **xfsaild async writeback** flushing a lingering dirty/in-AIL stale copy of block B (the sess16 "xfsaild flushes a BACKLOG of stale shrink" / sess40 "dir-block ABA writeback skip" / sess55 M3 family) at a moment the count check / EX-gate misses.

### NEXT SESSION — instrument the POST-ADD destage of a block carrying a just-added dirent:
At the SINGLE bio write chokepoint for dir DATA blocks (pal/linux/xfs_buf.c, where ex_write_guard/P-DATACLOBBER-SKIP lives), for EVERY dir DATA-block write (xfsaild AND release), coherent plain-bio read the on-disk block and log if the IN-CORE block being written is MISSING any inumber that is present on disk (a CONTENT non-superset, same-incarnation gated) — NOT a count compare. That catches the count-preserving content clobber the existing count-based guard misses. Identify comm (xfsaild vs releaser) + whether the node holds EX at that write. Then the fix is likely: suppress/serialize the xfsaild dir-DATA-block writeback the same way P126 suppresses AG-meta and P60 suppresses bmbt — a dir DATA/LEAF block may only be destaged by the current dir-EX holder; an xfsaild flush of a dir-data buffer while we don't hold EX (or of a prior-epoch buffer) must be stale'd, not written. mxfs_dirskip (NL-arm, default 0, "enforce refuted sess17") and mxfs_dir_ex_write_guard (count-based) are the prior incomplete attempts — the missing piece is a CONTENT-superset (not count) check at the chokepoint, same-incarnation gated to dodge the rm-rf ghost. See [[sess22-GPT-fix-design-freeslot-doublealloc-readdir799]] [[sess22-readdir799-is-content-divergent-clobber-count-guards-blind]].
