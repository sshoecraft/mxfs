---
name: trap-a-lap-chain-compares-the-fleet-module-to-the-trees-mxfs-ko-so-nothing-is-built-or-edited-in-the-tree-while-it-runs
description: TRAP: quiesce_remount laps check fleet srcversion against the tree's mxfs.ko and re-read the harness each lap; a rebuild or script edit mid-chain bre…
metadata:
  type: feedback
tags: [harness, chain, build, rig, release-gate]
---

# A running lap chain depends on the tree staying still

`tests/quiesce_remount_chain.sh` starts `tests/quiesce_remount_access.sh` as a
new process for every lap, and each lap begins by comparing every node's
loaded srcversion with `modinfo mxfs.ko` of the TREE.

So while a chain runs:
- **Do not run `make modules` in the tree.**  A changed source rebuilds
  `mxfs.ko` with another srcversion and every later lap ends
  `INFRA ... the fleet does not run this tree's module`.  Compile-check in a
  scratch copy (`rsync` to a `mktemp -d`, as `tests/full_verify.sh` does), and
  not while pace-graded laps run: the build loads the host.
- **Do not edit the lap harness.**  Later laps would run the edited script (a
  chain whose laps are not the same test), and bash reads a running script by
  offset, so the lap in flight can break too.
- Source edits without a build are invisible to the chain, but
  `tests/release_gate_chain.sh` starts the release verification by itself when
  the laps pass, and that makes a clean build of whatever the tree holds then.
  Decide the final source BEFORE launching the gate, or stop the wrapper
  (its pid by `comm` from `/proc/*/comm`; the lap chain is its child and runs
  on) and start `tests/release_verify_chain.sh` by hand afterwards.

Also measured (chain `v23a`): a lap that leaves a node unmounted turns every
later lap into `INFRA: precondition not met`, rc=2, 1 s each.  They measure
nothing; read the first non-zero lap and ignore the rest.
