---
name: trap-never-rebuild-mxfs-ko-while-rig-run-in-flight
description: TRAP (sess403): the rig preps insmod the TREE's /src/mxfs/mxfs.ko over NFS — rebuilding while a harness/agent run is in flight splits the run's srcve…
metadata:
  type: feedback
tags: [trap, build, rig, srcversion, sess403]
---

# Never rebuild mxfs.ko while a rig run is in flight

sess403: dispatched a rig-runner (kill5c then kill4c, each prepping the cluster from the tree's
mxfs.ko 0.24.0 sv BD61C31672EDB3B63D3FDF8), then — while it was running — made a one-line fix and
`make modules` again (sv 26BEDA0E1ACD42A921DA08E). Every prep (`run.sh N caw prep_cluster`) insmods
/src/mxfs/mxfs.ko from the NFS-shared tree, so the second run (or a node mid-insmod) picks up the
new file: the A/B's two arms can end up on different srcversions, or a node can read a truncated
.ko during the relink.

Rule: once a rig run/agent is dispatched, the tree's mxfs.ko (and tools/) are FROZEN until the run
reports. Queue source edits; build after. If a build is unavoidable, build into a scratch copy
(`make -C` of a worktree) — never the tree the nodes mount. Always read the per-run srcversion the
harness/agent reports (test1 /sys/module/mxfs/srcversion) and cite it, not the tree's modinfo.
