---
name: technique-a-verifier-that-gains-exclusion-must-give-its-constants-their-own-mode-or-every-live-node-caller-parses-nothing
description: TECHNIQUE (0.89.7): chk_mxfs -v on a mounted node is refused (O_EXCL since 0.89.6); geometry callers (agcount/agblocks/inopblog/xfs_data_offset) use…
metadata:
  type: feedback
tags: [chk_mxfs, geometry, harness, O_EXCL]
---

# A verifier that gains exclusion must give its constants their own mode

**What happened (0.89.6 → 0.89.7):** the checker's main descriptor became `O_EXCL` + `BLKFLSBUF` so a node whose own module holds the device is refused (its page cache is not the platter). An inventory of the 59 `chk_mxfs` execution sites in tests/ then found four harnesses that ran `chk_mxfs -v` on a MOUNTED node only to grep `agcount=`, `agblocks=`, `agblklog=`, `inopblog=`, `xfs_data_offset=`, `disklock_offset=` — with the refusal they got rc 4 and an empty parse, silently (their stderr went to /dev/null).

**The distinction:** geometry and envelope offsets are mkfs-time constants (resize_mxfs is the only other writer and runs offline under its own exclusive open). The first buffered image IS the current value, so the stale-cache hazard does not apply to them. Live state (ledger records, heartbeat slots, icount/ifree, btree contents) is the hazard and stays refused on a mounted node.

**The mode:** `tools/chk_mxfs --geometry <dev>` — plain `O_RDONLY` open, prints the envelope offsets and the XFS superblock geometry through the same two checks the full run starts with, exits 0/4, no verdict. Its header line says the counts it lists are the platter's at the last unmount. Callers: tests/tcp_death_replay.sh, tests/closure_reuse_directed.sh, tests/closure_footprint_shapes.sh, tests/typeflip_dead_incarn_repro.sh.

**Unaffected sub-modes** (they open their own descriptor before the exclusive one): `--pr-keys` (PERSISTENT RESERVE IN passthrough), `--show-quarantine` (records read O_DIRECT since s433), `--ino-offset` (envelope + sb constants).

**The general lesson:** before making a tool refuse a class of caller, inventory the callers (grep the tree for the binary, classify each site MOUNTED/UNMOUNTED by the umount above it) and split off the callers whose need is legitimate under the new contract. A refusal whose stderr is discarded is an empty capture, which is the fabricated-verdict class again.
