---
name: trap-32-idle-vms-running-exhausts-clyde-ram-harness-kills-background-tasks-shut-idle-vms
description: TRAP (sess515): 32 test VMs left running (~1.3 GB RSS each) put clyde at 0 free / 20 of 23 GB swap; Claude Code killed the session's background Bash…
metadata:
  type: feedback
---

# TRAP: idle VMs exhaust clyde's RAM and the harness kills background tasks (sess515, 2026-09-05)

**What happened.** A background Bash carrying an 80-minute rig chain (build + plain lap + sess507 chain steps 1-10) was killed by Claude Code at 08:24Z with "stopped because the system is running low on memory". `free -g`: 94 G total, 49 used, 0 free, 44 buff/cache, **swap 20 of 23 G used**. 32 test VMs were running (4 GB each configured, ~1.2-1.4 GB RSS each per `virsh dommemstat`), most of them idle leftovers from earlier 32-node boards. The chain script itself survived as an orphan (its later prep failed on a survivor whose umount took 5-10 s — a separate, real finding) and then died at step 6.

**Fix that worked.** `virsh shutdown test5..test32` (ACPI: none of the 28 had completed after 60 s), then `virsh destroy` for all 28 → free 20 G, swap 5 G, available 64 G. Delegated to a rig-runner (one Agent call replaces 30 Bash calls).

**Rules.**
- Before a long background rig job on the 2-node QNAP rig, check `free -g`; if swap is in use, shut the VMs the job does not need (test1-test4 stay for the 2-node + 3-node arms).
- The 32-node leg needs the VMs back: start them in batches of ~8 (`virsh start`), then `sudo -E bash scripts/mpath_up.sh up 32` as the readiness gate (mpatha was already assembled on all 31 reachable nodes before the shutdown; node records are node.startup=automatic so they re-login on boot).
- A killed background wrapper does NOT kill the chain it launched: check `tools/mxfs_pgrep.sh <script>` before assuming the rig is idle, and attach a Monitor to the orphan's log instead of relaunching on top of it.
