---
name: Make clean before rebuild for multi-file changes
description: Incremental builds produce stale mxfs.ko when changes span multiple files (.c + .h)
type: feedback
originSessionId: 780a6a21-f9b9-4c3d-823e-7bb94407a7ee
---
When changes span multiple files in /src/mxfs (especially `.c` + `.h` changes
across xfs_mxfs_dlm.{c,h}, xfs_icache.c, xfs_inode.c, etc.), the incremental
`make -C ... modules` can produce a `mxfs.ko` that does NOT reflect the latest
source. This burned an hour in the v0.2.6 session: code that worked on the first
test stopped working after a header change, and adding/removing diagnostic
logging produced inconsistent test results.

**Why:** The kernel build's dependency tracking misses some cross-file changes,
particularly when a static function becomes non-static (header decl added) or
struct fields are added.

**How to apply:** Before testing a build that involves changes to ANY header in
xfs/ or any change to xfs_mxfs_dlm.h, run:
```
make -C /usr/src/linux-headers-6.8.0-101-generic M=/src/mxfs clean
make -C /usr/src/linux-headers-6.8.0-101-generic M=/src/mxfs modules
```
The `make clean` is fast (~1 second). The cost is small compared to chasing
phantom test failures from stale objects.

If a test result is suspicious (e.g., a fix that PASSED suddenly fails again
after small unrelated edits), the FIRST diagnostic step is to clean rebuild,
not to debug the change.
