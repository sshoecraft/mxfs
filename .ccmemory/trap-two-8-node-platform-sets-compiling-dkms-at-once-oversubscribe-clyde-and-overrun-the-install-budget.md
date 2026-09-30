---
name: trap-two-8-node-platform-sets-compiling-dkms-at-once-oversubscribe-clyde-and-overrun-the-install-budget
description: TRAP (0.90.36): PLATFORM_GROUPS="pve9,debian13 rhel9,ubuntu2404" at 8 nodes = 64 vCPUs of DKMS compile on 56 cores; 6/8 rhel9 installs overran 660 s.
metadata:
  type: feedback
tags: [release, platforms, dkms, rig, trap]
---

**What happened.** The 8-node release chain (tests/full_verify.sh, POWER=1) ran two platform sets per group, as its header then advised. The packaged round's install step is a DKMS compile of the whole module on every node, budgeted per guest (45 core-minutes on a 4-vCPU guest -> 660 s, tests/packaged_round.sh). rhel9 and ubuntu2404 compiled together: 16 guests x 4 vCPUs = 64 vCPUs on clyde's 56 cores. Six of eight alma9 nodes were still in the %post DKMS build at 660 s (rc 124, install_*.log ends at "Running scriptlet"); the round failed. At 4 nodes the same pairing is 32 vCPUs and installed in 426-527 s.

**What to do.** Run 8-node platform verification one set per group: `PLATFORM_GROUPS="pve9 debian13 rhel9 ubuntu2404"` (full_verify header now says so). Never widen INSTALL_S for this -- the budget is right per guest; the schedule oversubscribed the host. Before choosing groups at a new node count, compute concurrent compile vCPUs (sets x nodes x 4) against `nproc` on clyde.
