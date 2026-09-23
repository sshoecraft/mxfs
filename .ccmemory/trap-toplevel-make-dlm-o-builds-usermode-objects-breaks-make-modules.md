---
name: trap-toplevel-make-dlm-o-builds-usermode-objects-breaks-make-modules
description: TRAP (sess440): `make dlm/foo.o` at /src/mxfs top level builds USER-MODE objects into dlm/ — next `make modules` links them (modpost READ_ONCE undefi…
metadata:
  type: feedback
tags: [trap, build, kbuild, usermode]
---

# Per-object compile check: use the kernel build, never the top-level Makefile

sess440: `make -s dlm/scsipr.o dlm/v5_mount.o dlm/prledger.o dlm/bootstrap.o` at the
repo root compiled them as USER-MODE objects (warnings: implicit READ_ONCE,
WRITE_ONCE, pr_warn_ratelimited, snprintf). They landed at `dlm/*.o` with no
`.o.cmd`, and the next `make modules` (chain 23 s440a) linked them:

    ERROR: modpost: "READ_ONCE" [/src/mxfs/mxfs.ko] undefined!
    ERROR: modpost: "WRITE_ONCE" [/src/mxfs/mxfs.ko] undefined!
    ERROR: modpost: "pr_warn_ratelimited" [/src/mxfs/mxfs.ko] undefined!

BUILD_RC=2 with `grep -c 'error:'` = 0 (modpost prints `ERROR:` not `error:`).

Correct per-object check (what sess439 used):

    make -C /lib/modules/$(uname -r)/build M=/src/mxfs dlm/scsipr.o

Recovery: `rm -f` the affected `dlm/*.o` and `dlm/.*.o.cmd` (full names, no glob),
then rebuild. Chain launchers should also grep `ERROR:` in build.txt.
