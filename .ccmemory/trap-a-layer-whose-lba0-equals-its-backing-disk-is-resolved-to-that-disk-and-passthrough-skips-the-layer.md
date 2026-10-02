---
name: trap-a-layer-whose-lba0-equals-its-backing-disk-is-resolved-to-that-disk-and-passthrough-skips-the-layer
description: TRAP (0.90.40): mxfs_bdev_to_sdev matched /dev/drbd0's LBA 0 to its backing iSCSI LUN; every SCSI passthrough would have written one replica. Content…
metadata:
  type: feedback
tags: [drbd, pal, scsi, passthrough, integrity]
---

pal/linux/kern.c mxfs_bdev_to_sdev resolved any non-SCSI, non-partition device to "the SCSI disk whose LBA 0 matches" (built for dm-multipath). DRBD with internal metadata, and md RAID1 with end-of-device metadata, have the SAME LBA 0 as their backing disk, so the resolver picked the disk under the layer. MEASURED on test1: `P-MPATH-RESOLVE stacked bdev 147:0 -> SCSI backing path 3:0:0:0` (sda, the LUN DRBD replicates), during a refused mount on the 0.90.39 module.

Consequence had the mount been admitted: mxfs_pal_scsi_write_fua_bdev (xfs_ialloc.c, xfs_mxfs_dir_data.c, xfs_buf.c), every FUA read, and COMPARE AND WRITE would have gone straight to the local replica — writes never replicated, reads bypassing resync state. It was invisible only because PR admission refused the device first.

Fixed 0.90.40: content resolution only for disks named dm-*. Any new attachment that stacks a layer over SCSI (DRBD, md, a future one): check for P-MPATH-RESOLVE on its major before trusting a passthrough path. Defect D-STACKED-DEVICE-RESOLVED-TO-ITS-BACKING-DISK-BY-CONTENT-BYPASSES-REPLICATION carries the verification step.
