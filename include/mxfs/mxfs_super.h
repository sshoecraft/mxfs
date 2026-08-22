/*
 * MXFS — Multinode XFS
 * On-disk MXFS superblock definition
 *
 * Written by mkfs.mxfs at the first 4KB of the block device.
 * Read by the mount path to auto-detect journal, disklock, and XFS data offsets.
 *
 * Shared between:
 *   - tools/mkfs_mxfs.c (userspace format tool)
 *   - libmxfs/mount.c   (kernel/userspace auto-detect on mount)
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_SUPER_H
#define MXFS_SUPER_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/* On-disk MXFS format magic — reads "MXFS" in hexdump (LE).
 * Distinct from the VFS MXFS_SUPER_MAGIC (0x4D584653)
 * used for statfs f_type. */
#define MXFS_FORMAT_MAGIC       0x5346584D
#define MXFS_FORMAT_VERSION     1
#define MXFS_SUPER_SIZE         4096

/*
 * sess42 C7 version gate (GPT-designed, ledger D-CROSSNODE-OPEN-UNLINK /
 * D-AGI-UNLINKED "C7").  The cluster protocol generation is the single
 * monotonically-bumped number for INCOMPATIBLE coordination-protocol
 * changes; every member must run code with an EQUAL generation.
 * Generation 1 = the open-tracking era (open_holders bitmap in lock
 * slots, publish-on-release-CAS, B6 defer, survivor sweep, fence purge).
 *
 * Enforcement layers (defense in depth, all required):
 *  1. XFS sb_features_incompat bit (xfs_format.h
 *     XFS_SB_FEAT_INCOMPAT_MXFS_PROTOGATE): every pre-gate mxfs kernel
 *     inherits upstream's strict unknown-incompat refusal, so old code
 *     cannot mount a gated filesystem AT ALL.  This is the preventative
 *     gate; the layers below are live defense among gate-aware kernels.
 *  2. Envelope: MXFS_FORMAT_F_PROTOGATE flag + cluster_proto_gen field
 *     below.  Gate-aware kernels refuse unknown envelope flag bits and
 *     require cluster_proto_gen == MXFS_PROTO_GEN.
 *  3. Disklock heartbeat feature block (disklock.h): every member
 *     publishes {proto_gen} in its HB record; joiners quarantine until
 *     all live peers validate; the monitor fences any live record that
 *     lacks a valid block or carries a different generation.
 */
#define MXFS_FORMAT_F_PROTOGATE 0x00000001u
#define MXFS_FORMAT_F_KNOWN     (MXFS_FORMAT_F_PROTOGATE)
/*
 * sess75: 1 -> 2 for the recovery-descriptor v2 fence certificate.
 *
 * This bump is a HARD PREREQUISITE of MXFS_RECOV_DESC_VERSION 2, not
 * bookkeeping.  The sess74 RULE-5 ruling REFUTED the claim that a per-slot
 * version mismatch is fail-closed on its own: a v1 replayer REPLAYS THE
 * FOREIGN SLICE FIRST and only consults the descriptor at completion, so it
 * would replay a v2-fenced slice on the old ungated path and only afterwards
 * notice the descriptor it cannot read.  Per-slot fail-closed is no
 * substitute for cluster-wide protocol compatibility, so v1 recovery code is
 * excluded from the cluster outright by layers 1-3 above.
 *
 * Bumping this REQUIRES a re-mkfs or `chk_mxfs --upgrade-protogate` (offline,
 * all nodes unmounted) — a v1-formatted volume will refuse to mount.
 *
 * sess86: 2 -> 3 for the NONZERO MOUNT INCARNATION
 * (D-MOUNT-INCARNATION-CONSTANT-ZERO).
 *
 * Until now every heartbeat record carried epoch = 0, measured on the live LUN
 * across all 31 members (sess83).  Nodes now draw a random nonzero 64-bit
 * incarnation, and this bump is a HARD PREREQUISITE of that — not bookkeeping.
 *
 * The mixed-version hazard runs OLD-watching-NEW, which no per-record check on
 * the new side can prevent.  Under gen 2 both peers wrote 0, so the monitor's
 * epoch-change arm could never fire; a gen-2 node watching a gen-3 node reboot
 * sees a genuine incarnation change and fires its death path — the pre-sess86
 * one, which rebases node_track onto the SUCCESSOR before declaring the
 * predecessor dead and whose first act is a per-NODE SCSI-PR fence.  The
 * victim of that fence is the healthy node that just rejoined.
 *
 * Per-record fail-closed is no defence here (the sess74 ruling, again): the
 * gen-2 code does not know there is anything to fail closed about.  Only
 * cluster-wide exclusion works, so gen-2 code is kept out by layers 1-3 above.
 *
 * sess346: 3 -> 4 for the CLEAN-DEPARTURE PROVENANCE carve (#92
 * D-CLEAN-RELEASE-TREATED-AS-DEATH-PHANTOM-RECOVERY-526).  The heartbeat
 * record layout changed (evict ring 25→23 entries; a 32-byte
 * mxfs_hb_provenance block now sits at offset 424) and the monitor's
 * clean-departure arms consume it.  A gen-3 node reading a gen-4 record
 * would misparse ring entries 23/24 as live hints and see garbage where
 * it expects zeros; a gen-3 node's records carry no provenance, so gen-4
 * monitors would conservatively fire death on its clean releases —
 * exactly the defect this carve fixes.  Mixed generations are excluded
 * cluster-wide, as above.
 *
 * sess381: 4 -> 5 for the SCSI-PR RESERVATION TYPE change
 * (D-PR-RESERVATION-SINGLE-HOLDER-UNMOUNT-DISARMS-FENCING-381).
 *
 * MXFS reserved the shared LUN with type 0x05 WRITE EXCLUSIVE - REGISTRANTS
 * ONLY, a SINGLE-HOLDER type.  SPC releases it when the holder's registration
 * is removed, and MXFS retires its own registration unconditionally at
 * put_super, so the holder's routine clean unmount released the reservation
 * and disarmed fencing for the WHOLE cluster.  MEASURED at 32 nodes: one
 * 0.49-second umount took the LU from a held reservation to none with 31 nodes
 * still mounted; nothing re-reserved; the next peer death fenced with
 * kind=NO_RESERVATION(8) and the filesystem became permanently unmountable.
 * Gen 5 reserves type 0x07 WRITE EXCLUSIVE - ALL REGISTRANTS instead, under
 * which every registrant is a holder and the reservation survives until the
 * last registration goes.
 *
 * This bump is a HARD PREREQUISITE, not bookkeeping, and the hazard is
 * OLD-watching-NEW as usual.  A gen-4 binary hard-requires resv.type == 0x05
 * in three places — the fence path, the admission gate and the certificate
 * re-check — so against a live WR_EX_AR reservation it would classify a
 * perfectly armed LU as "no reservation held": it would refuse its own
 * admission, and any fence it attempted would publish an UNPROVEN result that
 * blocks the slice.  Its kernel PAL is worse than that: it decides `held` from
 * the reservation KEY, which SPC reports as ZERO for an all-registrants type
 * (MEASURED), so it cannot see the reservation at all.  Per-record
 * fail-closed is no defence — gen-4 code does not know there is anything to
 * fail closed about — so gen-4 code is kept out cluster-wide by layers 1-3.
 */
#define MXFS_PROTO_GEN          5u

/*
 * On-disk MXFS superblock — first 4KB of the block device.
 *
 * Layout on device:
 *   [this 4KB super] [journal region] [disklock region] [XFS data to end]
 *
 * All offsets are absolute byte offsets from the start of the device.
 * All multi-byte fields are native byte order (x86 = little-endian).
 */
struct mxfs_ondisk_super {
    uint32_t    magic;              /* MXFS_FORMAT_MAGIC (0x5346584D) */
    uint32_t    version;            /* MXFS_FORMAT_VERSION */
    uint32_t    flags;              /* reserved, must be 0 */
    uint32_t    crc;                /* CRC32C of this 4KB (with crc=0) */
    uint8_t     fs_uuid[16];        /* copy of XFS sb_uuid */
    uint64_t    device_size;        /* total device size in bytes */
    uint64_t    xfs_data_size;      /* XFS data area in bytes */
    uint64_t    journal_offset;     /* byte offset of journal region */
    uint64_t    journal_size;       /* journal region size in bytes */
    uint64_t    disklock_offset;    /* byte offset of disklock region */
    uint64_t    disklock_size;      /* disklock region size in bytes */
    uint32_t    max_nodes;          /* max node count at format time */
    uint32_t    journal_slot_sectors; /* sectors per journal slot */
    uint64_t    xfs_data_offset;    /* byte offset where XFS data starts */
    uint32_t    xfs_log_node_count; /* per-node XFS log slices (0=legacy) */
    uint32_t    xfs_log_slice_bblks;/* basic blocks (512B) per log slice */
    uint32_t    cluster_proto_gen;  /* sess42 C7: valid iff flags has
                                     * MXFS_FORMAT_F_PROTOGATE; members
                                     * must run code with an EQUAL
                                     * MXFS_PROTO_GEN */
    uint8_t     reserved[3988];     /* pad to 4096 bytes */
};

/* Compile-time size check */
#ifdef __KERNEL__
#define MXFS_BUILD_CHECK_SUPER() \
    BUILD_BUG_ON(sizeof(struct mxfs_ondisk_super) != MXFS_SUPER_SIZE)
#elif !defined(__cplusplus)
_Static_assert(sizeof(struct mxfs_ondisk_super) == MXFS_SUPER_SIZE,
               "mxfs_ondisk_super must be exactly 4096 bytes");
#endif

#endif /* MXFS_SUPER_H */
