---
name: feedback-lab-vms-are-disposable-reset-them-without-asking
description: USER 2026-09-23 (angry): every lab VM (testN, pve9-*, vstest*, alma-97) may be reset/restarted/reconfigured without asking; waiting for permission wa…
metadata:
  type: feedback
---

After I stopped a vSphere test to ask permission to reset vstest1 (a wedged test VM), the user: "I don't care if you reset ... It's literally named test one ... reset whatever you want. I can't believe you sat here waiting for me to answer that."

**How to apply:**
- Lab VMs are disposable test infrastructure: test1..test32, pve9-1/pve9-2 (libvirt on the rig host), vstest1/vstest2/alma-97 (vSphere, via govc with the osimager vsphere/lab credentials). Reset, power-cycle, resize or reconfigure them whenever a test needs it, and say what was done afterwards — never stop to ask.
- This does NOT extend to the rig host (clyde) itself, the ESXi hosts, vCenter, or the QNAP (its iSCSI service is never restarted).
- Still check that nothing is mounted from a shared LUN before a reset when the evidence matters; a reset is not a reason to pause for approval.
