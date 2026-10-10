---
name: trap-pve-hosts-do-not-mount-clyde-src-so-dkms-rebuild-fails-use-pair-update-from-tree
description: TRAP: physical pve1/pve2 and nested pve9-3/4 have no /src/mxfs, so pve_dkms_rebuild.sh exits 127; deploy a test build with pve_pair_update.sh FROM_TR…
metadata:
  type: feedback
---

The compiled PVE note says test builds go to the physical pair via `scripts/pve_dkms_rebuild.sh` (reads clyde's NFS /src) then `scripts/pve_pair_update.sh SKIP_INSTALL=1`. On 2026-10-09 neither the physical pair (192.168.1.80/.81) nor nested pair B (192.168.120.211/.212) had `/src/mxfs`: the remote `bash /src/mxfs/scripts/pve_dkms_rebuild.sh` returned "No such file or directory" (exit 127), and the following `SKIP_INSTALL=1` update silently reloaded the OLD installed build (0.90.114) and reported success.

**How to apply:** deploy a working-tree build with `FROM_TREE=1 scripts/pve_pair_update.sh` (packs the tree to /root/mxfs-tree on each host, `make install OVERWRITE=1`, swaps the module; ~8 min on the physical pair, add `CHECK=1` for a cold chk_mxfs). Always read back `/sys/module/mxfs/version` on both hosts afterwards: `SKIP_INSTALL=1` succeeding proves nothing about which build is loaded. The host-built srcversion differs from clyde's (different kernel), so compare the version string and the update log's `installed=` srcversion, not clyde's `modinfo mxfs.ko`.
