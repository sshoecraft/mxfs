---
name: trap-pal-bdev-write-must-be-sector-aligned-subsector-bio-hangs-dm
description: TRAP (sess405, 0.26.0): mxfs_pal_bdev_write/read of a NON-sector-multiple length (96 B) HANGS in submit_bio_wait on /dev/mapper/mpatha (D-state, unki…
metadata:
  type: feedback
---

# Sub-sector bio hangs on the dm-multipath LUN (sess405)

**Observed** (0.26.0 sv 246B191F, tests/evidence/sess405_v0260/diag1): the first
prover manifest write issued `mxfs_pal_bdev_write(dev, off, ents, 96)` (3 × 32 B
entries).  On 6 of 30 nodes the calling thread sat in D-state forever:

    submit_bio_wait / bdev_sync_io / mxfs_pal_bdev_write /
    mxfs_disklock_recovery_manifest_write / v5_pr_fence_prove_locked /
    v5_handle_node_death / v5_disklock_expire_cb / disklock_hb_fn

— i.e. ON THE HEARTBEAT THREAD, so the prover's own heartbeat stalled
(P-HB-MONSLOW monitor_ms=64055) until peers fenced IT; the bio then returned
-52 (EBADE = reservation conflict) after 63998 ms (`P-RMAN-WRITE-FAIL ...
bytes=96 rc=-52`).  Cascade: each new prover hung the same way; test1 fenced;
both kill runs timed out; the rig needed virsh destroy/start of 7 VMs.

**Rule**: every bio through the PAL (`mxfs_pal_bdev_write/_fua/read`) must be a
whole multiple of the logical block size — in MXFS always round to 4 KiB
(`MXFS_RMAN_IO_ALIGN`).  The SCSI paths (`read_prio` = READ(16) FUA,
`write_fua`) reject sub-sector lengths with -EINVAL; the plain bio path does
NOT fail fast on dm — it hangs.  Fixed in 0.26.1: entry-area I/O is
round_up(byte_len, 4096) with a zero-padded buffer; the crc covers byte_len.

**Second lesson**: anything slow or hang-prone in `v5_pr_fence_prove` runs on
the disklock heartbeat thread (expire_cb path) — a stall > lease there turns
the prover into the next victim.  Keep the fence/snapshot path bounded.
