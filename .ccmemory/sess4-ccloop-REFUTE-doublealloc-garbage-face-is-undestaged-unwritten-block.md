---
name: sess4-ccloop-REFUTE-doublealloc-garbage-face-is-undestaged-unwritten-block
description: sess4(ccloop run6614) REFUTES own double-alloc theory for the GARBAGE face: P-DBLALLOC-BIRTH FUA read-back at dir block0 alloc found 0 foreign blocks…
metadata:
  type: project
---

## sess4 (run 6614aa96) — birth-probe REFUTES double-alloc for the garbage face

### TEST (RULE 4, build 6C7545D5): P-DBLALLOC-BIRTH
Added a FUA read-back at `xfs_dir3_data_init` block0 (xfs_dir2_data.c): before init, SCSI-READ(16)-FUA the block's current disk content; if it holds a valid dir3 magic with owner != this dir, log foreign=1. Ran `./run.sh 2 tcp cache_coherency` @default (FAIL 0/2).
- **P-DBLALLOC-BIRTH foreign hits = 0** on both nodes. The allocator did NOT hand out a block live in another dir.
- The failing read: `P-BLKRV-CRC daddr=120 blkno=0xFFFFFFFFFFFFFFFF owner=<huge>` = **all-0xFF UNWRITTEN** block content.

### CONCLUSION — TWO DISTINCT FACES (do not conflate)
1. **GARBAGE / 0xFF face (daddr 112/120)**: NOT a double-alloc (birth=0). The dir's block0 physical block is UNWRITTEN on disk, yet a read goes to disk and gets 0xFF → CRC fail → shutdown. = cold-read of an UNDESTAGED dir block0 (write still in-core, never reached disk) OR a corrupt extent map pointing at an unwritten block. **This REFUTES the [[sess4-ccloop-REFINE-owner-mismatch-is-disk-level-bnobt-not-dirgen]] owner-side-AG-drain theory for THIS face.** NOT bnobt.
2. **VALID-FOREIGN face (daddr 4186568, owner=4194437 with real entries)**: a different run/daddr; birth probe did not test it. Could still be double-alloc OR stale extent map pointing at another live dir's block. UNSETTLED.

### NEXT SESSION — for the garbage face (dominant, daddr 120)
Determine why a dir holds an extent for block0 that was NEVER durably written: (a) is the reading inode's DISK dinode extent map == in-core (points at 120)? then the block0 write was lost/undestaged before a cold read — instrument the block0 WRITE (does it reach disk? xfsaild flush skipped? b_ops NULL like sess30 P30?); (b) or is the in-core extent map divergent (points at 120 but disk dinode maps elsewhere)? = corrupt/phantom map. Note: disabling dir_release_invalidate/relinval_clean did NOT fix (so eviction isn't those levers); cache_coherency doesn't drop_caches, so the cold read is mxfs-internal (reload/FUA path reading block0 from disk instead of using in-core). Relevant: [[sess11run-SMOKINGGUN-datalog-entry-bytes-logged-then-vanish-no-evict-no-reload]] [[sess40-FIX-dirblock-ABA-writeback-skip-build-B9F9326E]].
### Probe in build 6C7545D5: P-DBLALLOC-BIRTH (xfs_dir2_data.c, FUA read-back, capped 400×).
See [[sess4-ccloop-HANDOFF-full-column-status-and-next-step]] [[sess4-ccloop-UNIFIED-bug-corrupt-dir-extent-map-both-tests-same-root]]
