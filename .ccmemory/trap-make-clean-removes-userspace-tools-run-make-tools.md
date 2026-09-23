---
name: trap-make-clean-removes-userspace-tools-run-make-tools
description: TRAP (sess396): `make clean` also cleans tools/ (mkfs_mxfs, chk_mxfs, ...) -> next prep fails 'FS_PREP_FAIL: mkfs tool not found'. Always `make tools…
metadata:
  type: feedback
tags: [build, trap, make-clean, tools]
---

# make clean removes the userspace tools

The top-level Makefile's `clean` target runs `$(MAKE) -C tools clean`, so after a
clean module rebuild `tools/mkfs_mxfs`, `tools/chk_mxfs`, `tools/resize_mxfs`,
`tools/fua_verify` are GONE. `run.sh ... prep_cluster` then fails with
`PREP FAIL (mkfs): FS_PREP_FAIL: mkfs tool not found/executable at /src/mxfs/tools/mkfs_mxfs`
after rmmod-ing the fleet (sess396, 0.23.5, cost one rig-agent round + a fleet rmmod).

Rule: any build chain that does `make clean && make modules` MUST end with
`make tools` (measured 2 s) before the deploy/prep step. `make modules` alone
does not rebuild tools.
