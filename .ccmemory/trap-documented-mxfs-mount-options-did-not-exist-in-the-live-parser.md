---
name: trap-documented-mxfs-mount-options-did-not-exist-in-the-live-parser
description: TRAP (s163): docs/discovery.md and mxfs(5) listed ~11 MXFS mount options (dlm_transport=, port=, broadcast...) the live xfs_super.c parser never had.
metadata:
  type: feedback
tags: [docs, mount-options, trap]
---

# Check the fs_parameter table before documenting or using a mount option

The live mount option parser is `xfs_fs_parameters[]` in pal/linux/xfs_super.c.
Until 0.89.74 it held only stock XFS options; `broadcast`, `multicast=`,
`discovery_port=`, `port=`, `dlm_transport=`, `block_cache=`, `inode_cache=`,
`dir_cache=`, `node_slot=`, `journal_offset=`, `disklock_offset=` existed only in
the retired `dlm/mount.c` (`struct mxfs_mount_opts`, NOT in Kbuild) — yet
docs/discovery.md and docs/man/man5/mxfs.5 documented them, with examples. A
user following them gets "unknown mount option".

Real knobs: module parameters (`modinfo mxfs.ko`): `force_transport` (0 auto,
1 TCP), `cache_mem_pct`, `inode_cache_max`, `block_cache_max`,
`dead_timeout_ms`, `dirshard_mkdir_enable`. Real MXFS mount options since
0.89.74: `peers=A/B/...` (slash-separated: the option string is split on
commas) and `cluster=NAME`.

The live discovery/lease code hardcodes multicast 239.66.83.1 and the port
defaults (dlm/v5_mount.c `mxfs_discovery_create` / `mxfs_lease_create` calls).
