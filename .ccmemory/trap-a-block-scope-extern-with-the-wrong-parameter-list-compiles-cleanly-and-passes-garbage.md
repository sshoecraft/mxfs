---
name: trap-a-block-scope-extern-with-the-wrong-parameter-list-compiles-cleanly-and-passes-garbage
description: TRAP (0.89.88): MXFS callers declare cross-file functions with local `extern`s; one had 2 params vs a 3-param definition that wrote through the 3rd.
metadata:
  type: feedback
tags: [build, warnings, abi, extern]
---

**What bit us:** `xfs/xfs_icache.c` P99-IGET probes declared `extern uint64_t mxfs_inode_disk_di_size(struct xfs_inode *, uint16_t *);` inside a block. The definition in `xfs_mxfs_dlm.c` takes `(ip, modep, genp)` and does `if (genp) *genp = ...`. C checks a call only against the declaration in scope, so the build was silent and the callee wrote through whatever was in the third argument register (only with `mxfs.instr=1`).

**Why it was invisible:** the tree's habit is a local `extern` at each call site instead of a header prototype, so `-Wmissing-prototypes` on the definition was the only symptom — and that warning was one of 236 nobody read.

**What to do:**
- Declare a cross-file function once in a header the defining file includes (`xfs/xfs_mxfs_dlm.h` has a block for this since 0.89.88); a caller that includes it gets a hard "conflicting types" error on a wrong local extern.
- Run `scripts/extern_decl_audit.py` (exit 1 on any extern/definition disagreement, typedef- and width-aware) after adding any local extern.
- Keep the 6.8 build warning-free so a new `-Wmissing-prototypes` is noticed; measure from a CLEAN build (incremental builds hide warnings from unrebuilt files — the first count here missed 3 files).
- Assembler warnings print as capital `Warning:`; grep case-insensitively or they are missed.

Related, same pass: `xfs/xfs_stubs.c` stubs had wrong signatures (the zone stub treated `struct xfs_open_zone **` as a bio); compile stubs against their real headers.
