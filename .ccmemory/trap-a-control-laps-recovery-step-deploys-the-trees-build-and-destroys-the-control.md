---
name: trap-a-control-laps-recovery-step-deploys-the-trees-build-and-destroys-the-control
description: TRAP (sess590, D-0960): the death-arm lap re-formed the fleet with module_swap_deploy, which installs the TREE's mxfs.ko — the fix — so no second con…
metadata:
  type: feedback
tags: [trap, harness, control, deploy, locality, D-0960]
---

# A control lap whose recovery step deploys the tree's build destroys the control

Session 590 (D-0960, the joiner that dies inside the bootstrap's takeover pass).

## What happened
1. The fix was built into the tree BEFORE the control lap ran on the old fleet build.
2. The control lap (`tests/join_during_takeover.sh EXPECT=death`) ends with a re-form
   via `scripts/module_swap_deploy.sh`, which installs `/src/mxfs/mxfs.ko` — the tree's
   build, i.e. the fix.  One lap later the old build was gone from the fleet and there
   was no old `.ko` to put back (no git use, no saved copy).
3. The single control iteration did not reproduce the death anyway: which node masters
   the root inode's page is a hash of per-incarnation node ids, and that lap landed the
   B-mastered shape, which the old build already survived (FREEZE_REQ takeover-request).
   The recorded defect is the A-mastered shape.  The harness had no notion of the shape
   and no repeat loop.

## Rules that follow
- Run the control BEFORE building the fix, or copy the old `.ko` aside
  (`mxfs.ko.backup` is the only permitted name) before `make modules`.  A harness whose
  recovery step deploys the tree is a one-shot control.
- A two-node lap on any per-resource path must NAME the locality it measured
  (`LOCALITY=A|B|none`) and repeat until it gets the recorded shape (`WANT=`,
  `ITER_MAX=`) — the existing trap `trap-which-node-masters-a-resource-is-a-hash-so-a-two-node-lap-must-establish-locality`
  applies to a mount-time root acquire too.
- When the control cannot be re-run, prove the harness's detectors against the recorded
  evidence directories (the s588c `dmesg_B_reform.txt` carried every death pattern) and
  say so in the changelog, rather than claiming a control that did not happen.
