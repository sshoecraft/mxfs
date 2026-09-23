---
name: trap-a-source-sweep-over-counts-call-sites-by-every-file-the-kbuild-object-list-leaves-out
description: TRAP (s137): 107 of 236 .c files under xfs/ dlm/ pal/ mxfs_clayer/ are not compiled into mxfs.ko, so a grep-the-source audit names sites that cannot…
metadata:
  type: feedback
tags: [measurement-integrity, build, kbuild, audit, dead-code]
---

# A sweep of the source names sites that are not in the module

Measured s137. Under `xfs/ dlm/ pal/ mxfs_clayer/` there are **236 `.c` files and
the Kbuild object list compiles 129 of them** — 107 are not built at all. Most
are expected for this fork (`xfs/scrub/*` is 60 files on its own, plus quota,
realtime, zones, `xfs_ioctl.c`, `xfs_acl.c`), but the list is NOT confined to
upstream leftovers: `dlm/mount.c`, `dlm/net2_*.c`, `mxfs_clayer/invalidate.c`,
`pal/linux/xfs_hooks.c`, `pal/linux/xfs_drain.c` and `xfs/xfs_mxfs_dentry.c` are
MXFS's own code and none of them is compiled.

## What it cost

The blocking-waits audit behind
`D-A-REVOKED-MOUNTS-BLOCKED-DLM-WAITERS-ARE-NOT-ABORTED` swept 309 raw
sleep/wait matches and resolved 44 hard blocking-API sites to a function and an
exit condition. One of the sites it names as an unbounded wait needing a
disposition is `dlm/mount.c:1225`, `bast_worker_fn`'s untimed
`mxfs_pal_cond_wait`. It cannot hang anything:

```
grep -n "mount.o" Kbuild        # xfs_mount.o and v5_mount.o only
ls dlm/mount.o                  # No such file or directory
nm mxfs.ko | grep -c bast_worker_fn   # 0
```

`xfs/xfs_mxfs_dentry.c` is the same story from the other direction: it defines a
`mxfs_drevalidate` and a `.d_revalidate` hook that look live, and the one the
module actually uses is a differently-shaped function of the same name in
`pal/linux/xfs_super.c`.

## The rule

**Check the Kbuild object list before a source sweep becomes a work list.** The
cheap form, from the tree root:

```sh
nm mxfs.ko | grep -c '<symbol>'          # is the function in the module at all
ls <dir>/<file>.o                        # was the translation unit compiled
grep -n '<file>.o' Kbuild                # is it in the object list
```

A symbol absent from `nm mxfs.ko` cannot execute, so it cannot be the cause of
anything observed on the rig, and it owes no disposition. Conversely, presence
in `nm` is not enough either — a function can be compiled with one of its
branches deleted; see
`technique-ask-the-built-module-which-probes-exist-before-trusting-any-harness-that-counts-one`.

The general form: **the tree is a superset of the product.** Any audit that
enumerates from `grep -r` and then hands the result to a future session as work
has over-counted by whatever the build leaves out, and nothing in the list says
which entries those are.
