---
name: trap-run-sh-reaps-a-live-drbd-rig-sh-as-orphans-of-a-dead-run
description: TRAP (0.90.41): run.sh started beside a live drbd_rig.sh saw its rig-lock holders as "orphans of a dead run.sh" and killed them; never overlap them.
metadata:
  type: feedback
tags: [rig, drbd, run.sh, trap]
---

Observed 2026-10-02: `scripts/drbd_rig.sh up` (test1/test2) was running; a harness on g2b (test15/test16) started `./run.sh 2/net/mesh/direct prep_cluster`. run.sh printed `WARN: /tmp/mxfs_run.lock held only by orphans of a dead run.sh — reaping: <pids>` and killed drbd_rig.sh's ssh/LUN-login children; drbd_rig exited 143 mid-LUN-allocation (test2's login half done).

drbd_rig.sh takes /tmp/mxfs_run.lock SHARED itself (tests/lib/runlock.sh), but run.sh's orphan check only recognises run.sh process trees, so any other legitimate holder is "an orphan".

Rule of thumb until run.sh is fixed: never start run.sh (including a harness's prep_cluster) while drbd_rig.sh is running, even on a different rig group. Sequence them.
