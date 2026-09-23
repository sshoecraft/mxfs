---
name: trap-a-make-in-the-tree-during-a-delegated-lap-chain-moves-the-srcversion-and-aborts-every-later-lap
description: TRAP (sess606): a compile check (make modules) run while a delegated lap chain was on the rig changed the tree's mxfs.ko srcversion; both harnesses a…
metadata:
  type: feedback
tags: [rig, harness, srcversion, build, D-0958]
---

# A make in the tree during a lap chain aborts every later lap

## What happened (sess606, D-0958 xattr boundaries)
- Deployed 0.84.19 (sv A089BB5F) and handed a rig-runner a chain: deploy, 2 fault laps, 2 control laps.
- While lap 1 ran I staged the NEXT site's kernel code and ran `make modules -j8` "just to compile-check it" — reasoning that the nodes run the installed module, so the tree's .ko is irrelevant to the laps.
- `tests/tcp_lockreq_blackhole.sh` and `tests/live_holder_wait.sh` both begin with `ABORT: <node> srcversion != tree '<modinfo mxfs.ko>'` — they compare the FLEET against the TREE's current build, on purpose (a lap on a stale fleet is void). Laps 2, 3 and 4 aborted in 1 s each. Lap 1 survived only because its check had already passed.

## The rule
- Never run `make` (or anything that rewrites mxfs.ko) while a lap is running or a chain is queued. Compile-check BEFORE the deploy, or after the chain reports.
- If a compile check is needed mid-chain, it is not needed: the staged code cannot be measured until the running chain is done anyway.
- Corollary: when a chain reports `ABORT ... srcversion != tree`, the first suspect is the parent session having rebuilt, not the fleet.

## Cost
Three laps (~25 min of rig time), one extra deploy, and the version had to move on to re-measure the first site on the next build.
