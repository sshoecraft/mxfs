---
name: technique-a-control-build-made-with-kcflags-keeps-the-srcversion-so-name-it-by-sha256-and-a-line-it-prints
description: TECHNIQUE (0.90.30): make modules KCFLAGS=-DSWITCH gives a control arm with the SAME srcversion; tell builds apart by sha256 + a printed line.
metadata:
  type: feedback
tags: [build, control-arm, srcversion, harness, module-unload]
---

## What

A fix that adds a safety (the module exit stopping unjoined threads) needs a
control arm: the same test on a module WITHOUT the safety, to show the test
makes the state that crashed. Compile the safety out behind an `#ifdef`
and build with `make modules KCFLAGS=-DMXFS_TEST_NO_THREAD_REAP`
(`scripts/queue_build_module.sh` takes it as `MXFS_KCFLAGS=`). Command-line
variables reach the kernel build through the tree's `$(MAKE) -C $(KDIR)`.

## The trap inside it

modpost's srcversion hashes source text, not compiler flags. The control
build and the fix build of 0.90.30 both read `7B9190EE705E969E04D0F5C`. The
rig's prep, every harness and the cluster marker identify a build by
srcversion, so they cannot tell the two apart.

**How to apply:**
- Have the control build print a line only it can print (here
  `P-THREAD-REAP-DISABLED` at every unload, `pr_err` so it reaches the panic
  channel).
- Record the file's sha256 next to the flags (the build step's RESULT line
  does), and keep each built module under `tests/evidence/modules/` — the
  next build overwrites the tree's file, the next prep overwrites the node's
  copy, and a panic's return addresses can only be read against the file that
  ran.
- A change of KCFLAGS rebuilds every object (28 s here), so the build after
  the control build is a whole one too.
- Order the queue: control build, prep, test, rig up, fix build, prep, test.
  Never leave the control build as the tree's `mxfs.ko` when the queue ends.

## What it bought

Unload with two unjoined threads on the control build: 4 of 4 nodes down,
8 faults, all `mxfs-worker`, every address ending in the low 12 bits of the
wrapper's sleep return in that build (objdump of the kept file).
