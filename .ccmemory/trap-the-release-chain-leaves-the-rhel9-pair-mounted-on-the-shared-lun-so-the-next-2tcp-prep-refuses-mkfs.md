---
name: trap-the-release-chain-leaves-the-rhel9-pair-mounted-on-the-shared-lun-so-the-next-2tcp-prep-refuses-mkfs
description: TRAP (0.89.88): tcp_peer_freeze_death ends remounted + sVirt runs on it, so alma9-1/2 keep the LUN mounted; next run.sh 2 tcp prep → FS_PREP_FAIL.
metadata:
  type: feedback
tags: [rig, release, lun]
---

The release verification chain ends with `PREP=rhel9 tests/tcp_peer_freeze_death.sh` (whose last step remounts the victim) and `tests/selinux_svirt_mxfs.sh` (which uses that mount). Nothing unmounts afterwards, so alma9-1/alma9-2 keep heartbeating into the shared LUN.

The next `./run.sh 2 tcp` then aborts before any test: `FS_PREP_FAIL: a node is still heartbeating into <lun> — refusing to mkfs under a live writer: slot 0 node <id> ts_ms a->b`. That refusal is correct behaviour, not a rig fault.

Fix before a suite: find the holder (`grep " mxfs " /proc/mounts` on every lab node via `tools/mxfs_lab.sh addr <host>` + `tools/mxfs_sshpass.sh`), then `timeout 60 umount` it (lab VMs are disposable). The 0.89.88 chain appends that unmount as its last step; keep doing so.
