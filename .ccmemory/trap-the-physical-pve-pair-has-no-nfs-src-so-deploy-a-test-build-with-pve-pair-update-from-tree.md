---
name: trap-the-physical-pve-pair-has-no-nfs-src-so-deploy-a-test-build-with-pve-pair-update-from-tree
description: TRAP: neither PVE pair (pve1/pve2 nor nested pve9-1/pve9-2) mounts clyde's /src; pve_dkms_rebuild.sh exits 127. Deploy: pve_pair_update.sh FROM_TREE=…
metadata:
  type: feedback
tags: [trap, pve, deploy, physical-pair, nested-pair]
---

`scripts/pve_dkms_rebuild.sh` reads the tree from /src/mxfs over NFS. Neither Proxmox pair mounts it:
- the physical pair (pve1 192.168.1.80, pve2 192.168.1.81);
- the nested pair (pve9-1 192.168.120.192, pve9-2 192.168.120.137).

On both, measured 0.90.109, the call fails with `bash: /src/mxfs/scripts/pve_dkms_rebuild.sh: No such file or directory`, RC=127.

To put the working tree on a pair, run `PVE_PAIR="<addr> <addr>" FROM_TREE=1 scripts/pve_pair_update.sh`. It:
- packs the tree (about 9 s);
- copies it to /root/mxfs-tree on each host and runs `make install OVERWRITE=1` there (about 7 min on the physical hosts);
- stops both units, swaps the module and starts both units.

The host's /root/mxfs clone is left alone. Confirm `/sys/module/mxfs/srcversion` on each host afterwards. The tree is packed at the start, so an edit made after the "packed the working tree" line is not in that build.

pve_pair_update stops BOTH hosts together, so it is not a single-departure measurement.
