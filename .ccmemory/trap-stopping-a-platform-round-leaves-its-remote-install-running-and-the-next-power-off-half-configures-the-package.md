---
name: trap-stopping-a-platform-round-leaves-its-remote-install-running-and-the-next-power-off-half-configures-the-package
description: TRAP (0.90.39): killing full_verify mid-install left apt-get/DKMS running on all 8 nodes; the rerun hit the dpkg lock, power-off left mxfs half-confi…
metadata:
  type: feedback
---

Killing a full_verify / packaged_round process group on clyde kills the local ssh clients only. The remote command each ssh started (apt-get install of the mxfs .deb, whose postinst runs a DKMS build) keeps running on every node.

Seen 0.90.39 on debian13:
- The relaunched run's install failed in 10 s on all 8 nodes: "Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 8xx (apt-get)".
- full_verify then powered the set off (POWER=1) mid-DKMS, and dpkg --audit read mxfs "install ok half-configured" on all 8.
- Every later step failed: the install, and "not mounted after prep_cluster" on the hung-node tests.

After stopping a platform run, before rerunning:
1. Power the set up.
2. On every node, check `dpkg --audit` (or `rpm -qa` / `dnf history` on RHEL), check for apt/dpkg processes, and run `dkms status mxfs`.
3. Purge a half-configured mxfs (`apt-get -y purge mxfs`), then confirm audit is empty and no package or DKMS entry remains.

Also: never edit a script that a running full_verify may execute (packaged_round.sh, tcp_peer_freeze_death.sh, lun_pool.sh). Each step is a fresh bash that reads its script from disk as it goes. That is why this run was stopped in the first place.
