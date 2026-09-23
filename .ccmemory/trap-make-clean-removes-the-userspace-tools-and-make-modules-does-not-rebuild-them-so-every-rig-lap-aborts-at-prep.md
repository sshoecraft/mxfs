---
name: trap-make-clean-removes-the-userspace-tools-and-make-modules-does-not-rebuild-them-so-every-rig-lap-aborts-at-prep
description: TRAP (s85): `make clean` deletes tools/mkfs_mxfs and tools/chk_mxfs; `make modules` rebuilds only the module, so prep_cluster aborts and every queued…
metadata:
  type: feedback
---

# A clean build of the module leaves the rig unable to prep

`make clean` removes the userspace binaries in `tools/` along with the module
objects. `make modules` rebuilds **only** `mxfs.ko`. The tools have their own
target:

```sh
make clean && make modules && make tools     # all three, in that order
```

## How it presents

Not as a build error — the build is `BUILD_RC=0` and `mxfs.ko` is correct.
It presents one step later, as a prep failure:

```
FS_PREP_FAIL: mkfs tool not found/executable at /src/mxfs/tools/mkfs_mxfs
ABORT: cluster prep failed
```

and then as a cascade: a driver that chains `prep → lap → lap → lap` loses
**every** lap, each ABORTing at its own prep or fleet-check stage, ~40 s for
the whole chain. Measured s85: three queued verification laps, all ABORT, zero
measurements, and the only honest reading of that run is "the instrument never
started".

## Why it is easy to miss

A header change forces `make clean` (an incremental build produces a stale
`mxfs.ko` when a change spans `.c` + `.h`), so the clean is correct and
necessary — it is the omitted `make tools` that costs the run. `recov_forge`
hides the problem further: `tests/fence_kind_matrix.sh` builds it itself, so
the matrix arms look like they have their tools while `mkfs_mxfs` and
`chk_mxfs` are missing.

## The check that costs nothing

Before queuing rig work after any clean build:

```sh
ls -l tools/mkfs_mxfs tools/chk_mxfs tools/recov_forge
```

`caw_verify` may legitimately be older than the rest — it is not rebuilt by
`make tools` unless its source moved.
