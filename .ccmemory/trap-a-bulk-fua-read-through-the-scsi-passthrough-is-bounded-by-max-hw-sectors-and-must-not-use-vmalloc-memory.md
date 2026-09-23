---
name: trap-a-bulk-fua-read-through-the-scsi-passthrough-is-bounded-by-max-hw-sectors-and-must-not-use-vmalloc-memory
description: TRAP (D-0531, s61): mxfs_pal_bdev_read_prio is a READ(16) passthrough; >max_hw_sectors_kb (512 on the 2/tcp LUN) is -EINVAL and a vzalloc buffer maps…
metadata:
  type: feedback
tags: [pal, fua, scsi, bulk-io, slice-lifecycle]
---

# A bulk FUA read is not a bulk bio read

While implementing the claim-time slice zero (0.88.0, `dlm/bootstrap.c`
`mxfs_slife_claim_init`) the first cut zeroed and read back a 64 MiB payload
in 1 MiB chunks allocated with `mxfs_pal_alloc`.  Two things would have made
that fail (or worse) on the rig, caught by reading the PAL before deploying:

1. **`mxfs_pal_bdev_read_prio` is a SCSI READ(16) passthrough**
   (`mxfs_pal_scsi_read_fua_bdev` → `scsi_execute_cmd`), not a bio.  The block
   layer's `blk_rq_map_kern` refuses a transfer larger than the queue's
   `max_hw_sectors`; the 2-node rig's LUN (`/sys/block/sda/queue/max_hw_sectors_kb`
   on test1) reports **512**.  A 1 MiB read returns -EINVAL and the fallback only
   fires on -EOPNOTSUPP, so the claim would have been refused and every mount
   with it.
2. **`mxfs_pal_alloc` is `vzalloc` above 16 KiB.**  On this 6.8 kernel
   `bio_map_kern` maps a kernel buffer by `virt_to_page` on its virtual
   address; a vmalloc address yields the wrong pages silently.  The bio path
   (`bdev_sync_io`, used by `mxfs_pal_bdev_write_fua`) handles vmalloc through
   `kaddr_to_page`, the passthrough does not.

Rule: a buffer that goes through the FUA read path is `mxfs_pal_alloc_io`
(kzalloc) memory of at most the LUN's hardware transfer limit — 64 KiB is an
order-4 allocation that is reliable at mount time and well inside any target's
limit.  The FUA write path may use any chunk size (the block layer splits bios).
Check `max_hw_sectors_kb` on the node before choosing a passthrough size for a
new rig.
