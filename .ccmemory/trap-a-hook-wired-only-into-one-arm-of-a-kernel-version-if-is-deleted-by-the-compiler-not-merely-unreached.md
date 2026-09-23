---
name: trap-a-hook-wired-only-into-one-arm-of-a-kernel-version-if-is-deleted-by-the-compiler-not-merely-unreached
description: TRAP (s137): the authority gate's 'data' arm sat in xfs_writeback_submit, referenced only by the 6.17+ iomap ops; on the 6.8 build it was dropped ent…
metadata:
  type: feedback
tags: [authority-gate, kernel-version, measurement-integrity, xfs_aops, build]
---

# A hook behind one arm of a version `#if` is deleted, not just unreached

Measured s137, tree 0.89.58, kernel `6.8.0-101-generic` (`modinfo mxfs.ko`
vermagic), 2/tcp.

`mxfs_mount_write_admitted()` — the authority gate every mutating submission
passes before reaching the shared LUN — has five call sites, one per class:
`log`, `dio`, `dio-zoned`, `meta`, `data`. The `data` site was inside
`xfs_writeback_submit()` in `pal/linux/xfs_aops.c`, which is referenced **only**
by the `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,17,0)` arm of
`xfs_writeback_ops`. This module builds for 6.8, which takes the other arm
(`map_blocks` / `prepare_ioend` / `discard_folio`).

Nothing referenced the function, so gcc dropped it. The arm was not "present but
unreached" — it was not in the binary:

```
strings -a mxfs.ko | grep -c P290-AUTH-REFUSED-DATA   -> 0
strings -a mxfs.ko | grep -c P290-AUTH-REFUSED-LOG    -> 1
strings -a mxfs.ko | grep -c P290-AUTH-REFUSED-DIO    -> 1
strings -a mxfs.ko | grep -c P290-AUTH-REFUSED-META   -> 1
nm pal/linux/xfs_aops.o        # no mxfs_mount_write_admitted reference at all
```

## Why reading the source did not catch it for weeks

The call site is right there in `xfs_aops.c`, with a correct comment explaining
why writeback must consult the authority held *now*. Every read of that file
concluded the arm existed. The `#if` is 60 lines further down, around a *struct
initialiser*, not around the function — so the function looks live and the ops
table looks like boilerplate.

## The instrument that settles it in one call

**For any probe that is supposed to exist, ask the BUILT MODULE, not the tree.**
`strings -a mxfs.ko | grep -c <PROBE>` and `nm <obj> | grep <callee>` are free,
local, and decisive. A probe string with count 0 means that code path is not in
the thing the nodes loaded, whatever the source says. Several harnesses in
`tests/` already open with a `strings -a mxfs.ko | grep -c` build precondition
loop for exactly the probes they read — that loop is the pattern; it just never
listed this one.

## The other half of the lesson: a VACUOUS lap can be the module answering

Lap `s132f` armed the post-admission park for class `data`, ran a whole unmount,
saw `P291-AUTH-TAIL tail_admit=1` for site `log` and **no** `data` submission at
the gate, and exited VACUOUS. That was filed as a harness that failed to produce
its subject. It was the module reporting accurately that the subject does not
exist on this build. When a lap reports "class X never reached the gate", check
whether class X's gate arm is in the binary before assuming the workload was
wrong.

## Sibling trap in the same investigation

`tests/admitted_write_parked_across_fence.sh` chose its *writer program* from
`ORACLE` (where `dio` and `data` collapse to `block`, because both read back from
the same probe block), so `SITE=data` ran the **O_DIRECT** writer and entered the
gate as `dio`. Where a write is read back from and which class submits it are two
different choices; a site→oracle map must not be reused as a site→workload map.
