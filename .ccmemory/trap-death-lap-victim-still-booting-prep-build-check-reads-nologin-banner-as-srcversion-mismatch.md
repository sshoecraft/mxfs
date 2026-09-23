---
name: trap-death-lap-victim-still-booting-prep-build-check-reads-nologin-banner-as-srcversion-mismatch
description: TRAP (sess528): a prep started <60 s after a death lap restarted the victim FAILS 'bad nodes: test2(build="System is booting up...")' — pam_nologin b…
metadata:
  type: feedback
---

# Prep right after a death lap fails on the victim's boot banner (sess528)

tests/tcp_2node_death_chain.sh s528m lap 1 and tests/concurrent_create_race_2node.sh s528n (with prep) both failed their prep 40-44 s after the s528l death lap had restarted the victim test2:

PREP FAIL: bad nodes: test2(build="Systemisbootingup.Unprivilegedusersarenotpermittedtologinyet..." != CDD0B14B...)

The victim VM was back on the network but still in early boot; sshd answered, pam_nologin printed the banner, and the prep's build check read the banner as the srcversion. NOT an MXFS defect and NOT a rig fault — a chain-timing trap.

Rule: before any prep that follows a death/restart lap, wait (bounded, ~120 s) until `test ! -e /run/nologin` on every node (or `systemctl is-system-running` is not 'starting'). tests/tcp_2node_death_chain.sh now does this at the top of each lap (sess528 edit). A NOPREP lap ~60 s later (s528o) found both nodes mounted: the restarted victim had rejoined on its own, so the failed preps did not leave the rig unusable.
