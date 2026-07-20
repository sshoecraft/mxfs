---
name: caw-CORRECTION-mkfs-DOES-zero-caw-slots-dlm_scaling-epoch-is-intrarun
description: CORRECTION: mkfs_mxfs DOES zero the CAW lock slot table (it's inside the zeroed disklock region). dlm_scaling valid_epoch>0 is NOT cross-mkfs stale t…
metadata:
  type: project
---

## CORRECTION — mkfs DOES zero the CAW slot table (code-proven, ccloop 0d6e174d sess2, 2026-07-07)

Corrects the prev-session claim in [[caw-16node-SESSION-SUMMARY-dlm_scaling-fixed-next-caw-epoch-and-coherency-variance]]
("mkfs_mxfs.c has NO CAW slot-table init → stale tombstones survive mkfs → dlm_scaling valid_epoch>0").
That claim is **WRONG**.

### PROOF (read the code, no cluster needed):
- Envelope layout: `[MXFS super 4KB] [journal] [disklock region] [XFS data]`.
- The **disklock region** = `MXFS_DISKLOCK_HB_SIZE` (64 HB slots × 512) + **65536 lock slots × 512** (~32MB).
- mkfs_mxfs.c:1636 `zero_region(fd, disklock_offset, disklock_size)` zeros the ENTIRE disklock region
  (BLKZEROOUT + read-back verify — mkfs_mxfs.c:330 zero_region).
- dlm_caw.c:4017 `ctx->lock_region_offset = disklock_offset + MXFS_DISKLOCK_HB_SIZE`; slot_offset()
  (dlm_caw.c:295) = lock_region_offset + slot_index*SLOT_SIZE. ⇒ the CAW lock slot table lives at
  `disklock_offset + HB_SIZE` .. `disklock_offset + disklock_size` — **entirely INSIDE the region mkfs
  zeros.** So every CAW slot (incl. dir_epoch / last_ex_slot tombstone fields) is 0 after mkfs.

### IMPLICATION: dlm_scaling@32 valid_epoch>0 is INTRA-RUN, not cross-mkfs.
On a fresh FS all epochs start 0. valid_epoch advances via caw_advance_epoch on a REAL cross-node EX→EX
handoff. dlm_scaling gives each node its OWN private subdir (no peer touches it) → its subdir epoch
should stay 0. Observed valid_epoch=8,5,32 at 32 nodes ⇒ candidate real causes (next session, instrument
WHICH inode gets epoch>0 and its handoff history):
1. **Intra-run inode REUSE**: dlm_scaling create+unlinks 2000 FILES/node in the subdir; freed inodes get
   reused, possibly by a DIFFERENT node's file in shared AGs → the reused inode carries the prior owner's
   CAW-slot epoch (real handoff via reuse). If valid_epoch is being read for the FILE inodes (not the
   subdir), this is it.
2. **Parent-dir epoch bleed**: the SHARED parent dir (all 32 nodes create their subdir in it) gets real
   handoffs → high epoch; check whether children inherit/read the parent's epoch.
3. The dir_priv_ex_skip gate reads `i_dlm_dir_valid_epoch` for the dir being modified — confirm it's the
   private subdir, and trace where its epoch became >0.
Fix direction: NOT a mkfs change. Likely either scope the epoch check to the actual dir, or make
caw_advance_epoch not treat intra-run inode-reuse as a coherency-relevant handoff for a provably-private
subdir. Delicate — instrument first (RULE 4).

### Also: the whole "15/16 dlm_scaling epoch" fix the prev session deferred is moot — dlm_scaling PASSES
16/16 ALONE on a clean cluster (was contamination). The epoch issue only bites at 32 (pervasive).
