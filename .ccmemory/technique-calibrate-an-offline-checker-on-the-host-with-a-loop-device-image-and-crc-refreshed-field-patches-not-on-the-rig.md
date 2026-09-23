---
name: technique-calibrate-an-offline-checker-on-the-host-with-a-loop-device-image-and-crc-refreshed-field-patches-not-on-the-rig
description: TECHNIQUE (s70i, 0.89.7): tests/chk_oracle_calibration.sh proves chk_mxfs FAILS corrupted images without the rig: /var/tmp image + sudo losetup + too…
metadata:
  type: feedback
tags: [chk_mxfs, calibration, loop-device, oracle]
---

# Calibrate an offline checker on the host with a loop-device image and CRC-refreshed field patches

**Why:** a gate's CLEAN is an assumption until the oracle has been shown to FAIL what it claims to catch (ledger D-THE-CLUSTERED-STRUCTURAL-AUDIT-GATE-DOES-NOT-ESTABLISH-THAT item 2). The rig is the wrong place for it: a rig lap costs minutes and a VM restart, and the fixtures are byte patches on a disposable image.

**How (tests/chk_oracle_calibration.sh, tools/xfs_block_patch.py):**
- mkfs_mxfs formats block devices only (`not a block device`, min 200 MiB) → `truncate -s 512M /var/tmp/...img; sudo -n losetup -f --show`. The session runs as uid 1000; `sudo -n` is passwordless on clyde. The checker's BLKFLSBUF needs CAP_SYS_ADMIN, so the check runs under sudo too.
- Patch ONE big-endian field and refresh the block's XFS CRC (crc32c table 0x82F63B78, seed ~0, complemented, stored little-endian at the block's crc offset: sb 0xE0 over the sector, AGI 0x138 over the sector, short btree block 0x34 over the fs block). Otherwise the checker reports a CRC failure, which proves only that CRCs are verified. The patcher: `xfs_block_patch.py IMG BLOCK_OFF BLOCK_LEN CRC_OFF FIELD_OFF WIDTH VALUE` (`+n`/`-n` relative).
- Read the geometry from the clean control's `chk_mxfs -v` listing (xfs_data_offset, blocksize, sectsize, inopblock, `AG 0 AGI: ino_root= ... fino_root=`, `AG 0 AGF: bno_root=`, `AG 0 inobt rec 0: startino= count=`), never assume it. AGI: count 0x10, freecount 0x1C. finobt leaf rec: startino(4) holemask(2) count(1) freecount(1) free(8) at 56. bnobt leaf rec: startblock(4) blockcount(4) at 56 — patch BOTH fields before the check or the extent overflows the AG and the walk refuses it before the cross-tree audit runs.
- Execution fixtures: missing path (rc 4), sector 0 zeroed (rc 4), image truncated (rc 4, no clean summary), `timeout 0.01` (rc 124), SIGSEGV. The kill must be issued INSIDE the root shell that spawned the checker (`sudo -n sh -c '"$1" -v "$2" & p=$!; kill -SEGV $p; wait $p; echo CRASH_RC=$?'`): a 50 ms `timeout -s SEGV` outlived a 512 MiB check (the check takes 10-50 ms), and an unprivileged `kill` of the root-owned process is refused silently.
- Cleanup with a literal path (`rm -f /var/tmp/mxfs_chk_calib.img`), never a variable.

**Gaps it exposed:** the checker has no "dinode home aliasing a directory data block" detector at all, and a two-level inobt (the shape of the 0.89.7 walker defect) has no offline constructor yet — both recorded in the ledger as not credited.
