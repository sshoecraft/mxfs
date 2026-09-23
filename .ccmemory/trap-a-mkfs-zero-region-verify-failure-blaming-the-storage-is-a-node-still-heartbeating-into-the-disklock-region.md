---
name: trap-a-mkfs-zero-region-verify-failure-blaming-the-storage-is-a-node-still-heartbeating-into-the-disklock-region
description: TRAP (s62e→s65): mkfs_mxfs "zero_region verify FAIL @67118080 byte 1024 = 0x4b (storage silently dropped writes)" was the MXLK slot magic of a node s…
metadata:
  type: feedback
tags: [prep, mkfs, disklock, harness, rig]
---

# The storage did not drop the write; a node wrote over it

## What bit
`tests/evidence/20260919T040458Z_d0932_s62e-.../prep.log`: `mkfs.mxfs: zero_region verify FAIL @67118080 byte 1024 = 0x4b (storage silently dropped writes — try 'blkdiscard --zeroout' first or use a different backend)`, PREP FAIL, the d0932 lap never ran. The disklock heartbeat table is at 67117056 (`disklock heartbeat table @67117056` in every hb dump); 67118080 is slot 1's record and 0x4b is the 'K' of the `MXLK` slot magic. A node from the previous lap was still mounted and heartbeating while mkfs zeroed and re-read the region.

Because that prep failed, the LUN kept the previous incarnations' ACTIVE records; the next lap (sole_survivor_gate_probe) started on them, and its FAILs were read at first as a fencing defect. They were the residue.

## The lesson
- mkfs's message names the wrong suspect. A non-zero readback at a slot-record offset with a magic byte is a live writer, not a target that drops writes. Check `tools/disklock_hb_dump.py <dev>` for ACTIVE records with a fresh ts_ms before believing the storage.
- prep_cluster must not format under a heartbeat writer: every node must be unmounted and the module unloaded (or the VM down) before mkfs, and the prep should refuse if the hb dump shows a record whose ts_ms advanced between two reads.
- A lap that failed at prep leaves the LUN as the previous lap left it. The next lap's "ghosts" are not the kernel's doing; read the prep log of the lap before.
- Recorded on D-A-HARNESS-CAN-MEASURE-THE-WRONG-DEVICE's next step (s65) as a prep-ordering hole to close.
