---
name: trap-an-unload-slab-leak-report-is-not-evidence-about-the-load-that-printed-it
description: TRAP (D-0924): kmem_cache_destroy cannot free a cache holding objects, so it leaves a refcount-0 ZOMBIE the next insmod merges with — every later loa…
metadata:
  type: feedback
tags: [slab, module-unload, evidence-integrity, measurement]
---

# A module-unload leak report can belong to a PREVIOUS load

When `kmem_cache_destroy` finds objects still allocated it **cannot free the
cache**. It leaves it on the slab list with **refcount 0** — and a refcount-0
cache is still *mergeable*. The next `insmod`'s same-shape `kmem_cache_create`
therefore **adopts the zombie**, inherits its stranded objects, and reports them
again at its own unload. That load leaves a zombie too, so the report repeats
for the rest of the boot, unchanged, whatever the module does.

## How this cost ~10 sessions

D-0924 was opened as "six `xfs_buf` objects leak at EVERY unload — an unbounded
leak for the life of the module on every tree-shrinking mount cycle", severity
critical. Its evidence was three unloads of three *different builds* on one node
reporting **the same six hashed addresses at the same slab offsets**, one of them
on an **idle mount that ran no workload at all**.

That is not six leaks per cycle. It is ONE stranded object echoed. The identical
addresses across different builds were the tell, and were read as corroboration.

Two traps rode along:

- The build that appeared to "fix" it had merely **grown `struct xfs_buf` by 16
  bytes** (a debug registry). A different size no longer merges with the zombie,
  so the symptom vanished for a reason unrelated to the bug — and 14+ "clean"
  laps then accumulated against that confound. Adding a field to the struct you
  are measuring can *be* the fix, in the wrong sense.
- `/sys/kernel/slab/<name>` being an **alias symlink** (e.g. `:a-0001216`) is
  what a merged cache looks like; a real directory means the cache is its own.
  That was visible on the nodes the whole time.

## What to do

- Create every cache with **`SLAB_NO_MERGE`** in any module whose unload reports
  you intend to treat as evidence. MXFS routes all of them through
  `mxfs_cache_create` (pal/linux/xfs_super.c); `slab_merge=1` restores the old
  shape and exists only to be a control arm.
- Prove the property with a **positive control** rather than by reasoning: a knob
  that strands exactly N objects at free and prints each address
  (`dbg_leak_bufs`), run in both arms. `tests/d0924_zombie_cache_ab.sh` is the
  harness; the mergeable arm re-reports the seeded address at the two following
  loads, the unmergeable arm reports only each load's own.
- Before trusting ANY "objects remaining" report, ask which load's cache it was.
  A clean unload is only meaningful once merging is off.
