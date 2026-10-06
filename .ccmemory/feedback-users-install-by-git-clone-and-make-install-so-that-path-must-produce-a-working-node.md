---
name: feedback-users-install-by-git-clone-and-make-install-so-that-path-must-produce-a-working-node
description: USER (stunned, 0.90.55): people clone and run `make && make install`; it installed only mxfs.ko. That path must install what the packages do, and be…
metadata:
  type: feedback
tags: [install, packaging, drbd, release]
---

The user installed 0.90.42 on two physical PVE 9 hosts from a GitHub clone with `make && make install && modprobe mxfs`. `make install` was `modules_install` + `depmod` only: no current `mkfs.mxfs` (an old 0.11.39 package's binary was on PATH and formatted the volume), no DRBD witness or fence-peer handler, no `/etc/modprobe.d/mxfs.conf` (module ran target_cache_protected=0 fua_disable=1), no man pages or udev rule. The DRBD pair then ran unfenced and pve2 died.

User: "you do know that people are just gonna git clone this and type make make install, right?"

**Why:** the rig deploys a built mxfs.ko plus its own tool copies, and release rounds install .deb/.rpm, so nothing ever exercised the path a real user takes first.

**How to apply:**
- The node-side file list lives in ONE place, `mxfs_stage_node_files` in `packaging/common.sh`; `make install` (via `packaging/install_source.sh`) and `mkdeb.sh` both call it. Add a new node file there, never in one installer only. mkrpm.sh's spec still has its own copy; keep it in step.
- `make install` refuses on a host with an MXFS .deb/.rpm/DKMS already present (two versions under the same names).
- A release claim should include a clean-clone `make && make install` → mkfs → mount on a fresh node, not only the package rounds.
- Instructions a user needs to make a configuration safe (e.g. DRBD fencing) must be reachable from the README's install path, and a setup missing them must be refused by the module, not merely documented.

Evidence: tests/evidence/pve_phys_drbd_20261005/.
