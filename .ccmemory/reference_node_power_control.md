---
name: reference-node-power-control
description: How to power-control/recover wedged test1-4 cluster VMs (virsh qemu:///system)
metadata: 
  node_type: memory
  type: reference
  originSessionId: 6a6e3b82-43fe-4c7a-8920-ceee3d0b0c4e
---

The test1-4 cluster VMs run on THIS dev host (clyde, .120.1/br0) but under
the **system** libvirt instance, NOT the default session one.

- `virsh list` (default `qemu:///session`) shows the VMs as "shut off" — WRONG/misleading; that's a different unused set.
- `virsh -c qemu:///system list --all` (or `export LIBVIRT_DEFAULT_URI=qemu:///system`) shows the REAL cluster: test1,test2,test3,test4 = running.

Recover a wedged node (D-state kernel threads after a stuck `reboot`; node pings DOWN but virsh shows "running"):
```
export LIBVIRT_DEFAULT_URI=qemu:///system
virsh destroy testN ; sleep 2 ; virsh start testN
```
Boot takes ~60-90s. A guest `reboot` over ssh often does NOT complete on a
CAW-starvation-wedged node (sshd dies but kernel hangs in shutdown, no
watchdog) — use virsh destroy+start instead.

Node IPs: test1=.114 test2=.143 test3=.140 test4=.174 (192.168.120.0/24, br0).
Only test1-4 of the 16-name set are actually provisioned/running.
See [[project_test_cluster_scst]].
