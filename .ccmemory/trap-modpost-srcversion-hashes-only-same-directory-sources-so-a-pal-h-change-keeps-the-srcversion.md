---
name: trap-modpost-srcversion-hashes-only-same-directory-sources-so-a-pal-h-change-keeps-the-srcversion
description: TRAP (0.90.29): adding a prototype to pal/pal.h rebuilt mxfs.ko with the SAME srcversion; modpost hashes only deps in the object's own directory.
metadata:
  type: feedback
tags: [build, srcversion, modpost, deploy]
---

# srcversion does not change for a header outside the object's directory

**What happened (0.90.29):** a prototype was added to `pal/pal.h` and the
module rebuilt (file size and mtime changed); `modinfo -F srcversion` printed
the same value as before (278D9891F308D0AFC19540B twice).  modpost's
sumversion hashes each object's source and only those dependencies that live
in the SAME directory as the object.  MXFS objects live in `xfs/`, `dlm/`,
`pal/linux/`; `pal/pal.h` and `include/mxfs/*.h` are in none of them.

**What to do:**
- Never take "same srcversion" as "same module" after a header-only change in
  `pal/`, `include/` or `compat/`.  Compare `sha256sum mxfs.ko` (the prep
  leaves the loaded file on each node as `/root/mxfs.ko.prep`) or the
  `version` field.
- A harness that checks the fleet against the tree by srcversion will accept
  a stale fleet after such a change: force the prep.
