---
name: trap-srcversion-does-not-move-for-a-header-change-outside-the-objects-own-directory
description: TRAP (s90): MXFS_PROTO_GEN 21→22 in include/mxfs/mxfs_super.h rebuilt 8 objects and left srcversion byte-identical — modpost hashes only same-dir dep…
metadata:
  type: feedback
tags: [build, measurement-integrity, deploy, srcversion]
---

# srcversion is not a content hash of the tree

Measured 0.89.23 (session 90). `MXFS_PROTO_GEN` was changed 21 → 22 in
`include/mxfs/mxfs_super.h`. `make modules` rebuilt eight objects
(`dlm/disklock.o`, `dlm/prledger.o`, `dlm/bootstrap.o`, `dlm/v5_mount.o`,
`xfs/xfs_log.o`, `xfs/xfs_mxfs_dirshard.o`, `pal/linux/xfs_super.o`, `mxfs.o`
— all newer than the header, and `dlm/.disklock.o.cmd` does list the header in
its deps). The module was relinked. And:

```
srcversion:     A2ABA0E3B98727EFE11B6B9     # 0.89.22
srcversion:     A2ABA0E3B98727EFE11B6B9     # 0.89.23, after the gen bump
```

Byte-identical across a change to the on-disk protocol generation.

## Why

The kernel's `modpost`/`sumversion` builds the module source hash from each
object's `.<obj>.o.cmd` dependency list, but it only folds in dependencies
**that live in the same directory as the object file**. `dlm/disklock.o` hashes
`dlm/*.h`; it does not hash `include/mxfs/mxfs_super.h`. So the MXFS tree's
entire `include/` hierarchy — the on-disk format header among it — is outside
the build identity.

`modinfo mxfs.ko` also carries **no `version:` field**, and the module image
contains no `0.89.x` string, so srcversion is the only build identity the rig
has.

## What this breaks

Every deployment check of the shape "the node's
`/sys/module/mxfs/srcversion` equals the tree's, therefore the node is running
this build" is **unsound for any change confined to `include/`**. A node left
on the previous module is indistinguishable from one carrying the new one, and
the measurement that follows is attributed to the wrong build.

## What to do instead

- Force the deploy (`MXFS_FORCE_PREP=1`) rather than letting an identity
  comparison decide, whenever the change touched `include/`.
- Prefer a discriminator the running kernel prints. For a generation change the
  C7 gate line names both sides — `filesystem cluster_proto_gen=N but this
  kernel speaks M` — which identifies the loaded module's generation directly
  and is therefore better evidence than srcversion ever was.
- When adding a new build-identity check, remember it answers "same
  same-directory sources", not "same build".
