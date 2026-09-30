---
name: trap-a-lap-that-aborts-after-starting-its-load-leaves-the-load-loops-running-into-the-next-lap
description: TRAP (0.90.36): multi_victim_containment ABORT at 'load never appeared' exits without touching the stop file; old loops rm -rf the next lap's dirs.
metadata:
  type: feedback
tags: [harness, multi_victim, rig, trap]
---

**What happened.** tests/multi_victim_containment.sh starts a nohup load loop per node (bounded by `end=SECONDS+LOAD_S+VICTIM_GAP*NV+30`, ~480 s, or /tmp/mvc_load.stop), then checks the load appeared; on failure it does `say ABORT...; exit 2` (line ~334) WITHOUT touching /tmp/mvc_load.stop. The next lap in the queue re-prepped and remounted within ~2 min, and its new loop ran beside the survivor of the aborted one on the same `/mnt/shared/.mvc_load/nodeN`, the same /tmp/mvc_load.err, .cycles and .done. Result (queue x36b lap 2): rsync mkstemp ENOENT and rm rc=1 on three survivors, `cycles=17407` in .done (the old loop's count), a 185 s "stall", 4 survivors that could not unmount, lap FAIL -- all harness, no FS fault.

**How to recognise it.** Two cycle numberings in one node's FAILED lines (cycle=16897 next to cycle=1); a .done cycle count far above the ~300-350 a healthy lap makes.

**What to do.** Any exit after the load launch must touch /tmp/mvc_load.stop on every node first (and wait for .done); a lap after an ABORT is suspect until its load files show one numbering. Never edit the harness while a queued lap runs -- bash reads the script lazily and each lap re-reads it.
