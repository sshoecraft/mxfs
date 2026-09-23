---
name: trap-never-rebuild-mxfs-ko-while-a-rig-harness-run-is-in-flight
description: TRAP (sess566): `make modules` during a live harness run changes the tree srcversion mid-flight; the next lap's precondition check fails INFRA agains…
metadata:
  type: feedback
tags: [trap, rig, build, sess566, harness]
---

# Never rebuild mxfs.ko while a rig harness is in flight

sess566. A loop harness was running 8 laps on the rig. Mid-run I built a new module in the
tree. Every MXFS harness derives its precondition from the TREE:

    SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
    ... compare against each node's /sys/module/mxfs/srcversion

and `run.sh` does the same for its marker match. So lap 8 died with:

    ERROR: cluster is prepped for 2/tcp (srcver=BE2A6EAF1FEE5DFCEAFC597),
           you requested 2/tcp (srcver=3DDEBC17BCDC11CC065F9DC).

recorded as `NO_TERMINAL_RECORD(rc=1)` / `infra=1`. The nodes were perfectly healthy; the
reference point moved underneath them. One lap of a 16-lap campaign lost.

**The rule:** while any rig run is live, source edits are fine — `make modules` is not.
Stage the edits, wait for the completion notification, then build. If a build is genuinely
urgent, the run has to be stopped first, deliberately, not raced.

**The good news, worth keeping:** the harness caught it and refused to record a verdict,
rather than measuring a stale module and reporting a PASS. That precondition check is
load-bearing — a harness that compared nothing would have produced a clean-looking result
for the wrong build. Every harness in `tests/` should keep the srcversion+mounted
precondition for exactly this reason.

Related: the "stale build read as current" family that motivated `marker_live_ok()` in
run.sh, and the sess565 lesson that a probe's field presence cannot tell you which build
emitted a dmesg line.
