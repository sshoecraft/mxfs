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
 * C7 version gate (review-designed, ledger D-CROSSNODE-OPEN-UNLINK /
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
/*
 * (docs/recovery-manifest.md): the RECOVERY MANIFEST region exists —
 * rman_offset / rman_size below are valid.  One slot per disklock heartbeat
 * slot; the fence prover writes the victim's fence-time write-authority
 * manifest there (sealed) before the FENCED descriptor points at it, and the
 * foreign-replay authority gate consumes the manifest, never the live CAW
 * table.  Layout: [super][journal][disklock][rman][XFS data].
 */
#define MXFS_FORMAT_F_RMAN      0x00000002u
/*
 * (docs/tcp-authority-ledger.md step 2): the TCP DURABLE AUTHORITY
 * LEDGER region exists — tauth_offset / tauth_size below are valid.  One
 * 128-byte authority record per CAW resource-hash slot (65536), in 4 KiB
 * pages with TWO shadow copies each (crash-atomic without compare-and-write;
 * the layout lives in mxfs_tauth.h).  The TCP transport's lock masters
 * make every grant/release durable here before it is delivered, so a dead
 * master's authority can be imported by its successor and the fence-time
 * replay gate has authority evidence for a TCP victim's images.
 * Layout: [super][journal][disklock][rman][tauth][XFS data].
 */
#define MXFS_FORMAT_F_TAUTH     0x00000004u
/*
 * (docs/whole-cluster-restart.md item 2): 64-BIT PER-BOOT PR KEYS and
 * the PR REGISTRANT LEDGER region exist — prkey_offset / prkey_size below are
 * valid.  The SCSI PR key is no longer the 32-bit node_id: it is a 64-bit key
 * derived once per {host boot, LUN} (from the host/boot/fs uuids —
 * the ledger is written AFTER the verified REGISTER, because under the
 * cluster's all-registrants reservation an unregistered initiator cannot
 * write it; the derived key gives a retried mount its own registration back
 * without on-LUN state) and published in every heartbeat record's identity
 * block; fencers take the victim key from that record.  INCOMPAT:
 * a 32-bit-key node would fence the wrong key, so it is excluded by this
 * flag (envelope refusal) and by MXFS_PROTO_GEN 12, never tolerated.
 * Layout: [super][journal][disklock][rman][tauth][prkey][XFS data].
 */
#define MXFS_FORMAT_F_PRKEY64   0x00000008u
/*
 * (docs/whole-cluster-restart.md §5): the WHOLE-CLUSTER BOOTSTRAP
 * RECORD region exists — bootstrap_offset / bootstrap_size below are valid.
 * One CAW-written 512-byte record (dlm/bootstrap.h) that (a) lends the first
 * node up after a total outage a durable PROVISIONAL identity that may own
 * fence intents and recovery descriptors before it holds any heartbeat
 * slot, (b) seals the recovery set for that outage (dead-slot bitmap +
 * registrant-ledger generation) and (c) forbids ACTIVE publication and
 * xfs_mountfs until every sealed slice and registrant is durably complete.
 * mkfs writes it IDLE; an unformatted (zero) sector fails closed.
 * Layout: [super][journal][disklock][rman][tauth][prkey][bootstrap][XFS data].
 */
#define MXFS_FORMAT_F_BOOTSTRAP 0x00000010u
/*
 * /466 (docs/dir-sharding.md): symmetric directory sharding.  The
 * value is owned by include/mxfs/mxfs_dirshard.h (MXFS_FORMAT_F_DIRSHARD
 * 0x20); it is one of the three gates (sb incompat bit 29, this flag, and
 * MXFS_PROTO_GEN 18) that must all agree before a PARENT/CONTAINER inode
 * flag is legal.  No new region: the manifest lives in a holder inode's
 * block inside the XFS data area.
 */
#define MXFS_FORMAT_F_DIRSHARD_VALUE 0x00000020u
/*
 * 0.88.0 (D-SLICE-CLAIM-TIME-INIT-UNTRUSTED-ZERO-531, design ruling
 * docs/rulings/twin-hole-fix-zeroing-strictness.md item (a)): the SLICE
 * LIFECYCLE region exists — slife_offset / slife_size below are valid.  One
 * 512-byte record per XFS log slice (struct mxfs_slife_record).  mkfs writes
 * every record INIT_REQUIRED for the filesystem's uuid; the node that claims
 * heartbeat slot k — the exclusive lease on slice k — persists ZEROING (FUA),
 * zeroes the whole slice payload through the kernel FUA path, flushes,
 * persists READY (FUA), and only then mounts its log.  READY is sticky for
 * the fs incarnation.  A slice found INIT_REQUIRED or ZEROING by a foreign
 * recovery holds no record of this incarnation (nothing is journaled before
 * READY is durable) and is skipped, its state left for the next claimant to
 * restart the full zero.  Why: mkfs's zero of the log region is a userspace
 * write whose durability the target stack does not promise; a slice that
 * still carries a previous incarnation's CRC-valid records mis-steers the
 * cycle-number head search and the committed tail becomes unrecoverable
 * (measured s60j, 0 of 40 files back).  A volume without this flag keeps
 * the old behaviour, loudly: nothing ever synthesises INIT_REQUIRED for a
 * slice that may have been used.
 * Layout: [super][journal][disklock][rman][tauth][prkey][bootstrap][slife][XFS data].
 */
#define MXFS_FORMAT_F_SLIFE     0x00000040u
/*
 * The filesystem belongs to a named cluster: cluster_name below is valid,
 * and a mount must pass the same name (mount option cluster=) or it is
 * refused before any heartbeat, network traffic or write.  The point is the
 * node that would otherwise hear no peers and run alone against the shared
 * disk because it was configured for a different cluster.  Set by
 * mkfs.mxfs -c or mxfs_admin -c, cleared by mxfs_admin -c "".  An incompat
 * flag on purpose: a kernel that does not check the name must not mount a
 * volume that has one.  A name is an agreement check, not a secret.
 */
#define MXFS_FORMAT_F_CLUSTER_NAME 0x00000080u
#define MXFS_FORMAT_F_KNOWN     (MXFS_FORMAT_F_PROTOGATE | MXFS_FORMAT_F_RMAN | \
								 MXFS_FORMAT_F_TAUTH | MXFS_FORMAT_F_PRKEY64 | \
								 MXFS_FORMAT_F_BOOTSTRAP | MXFS_FORMAT_F_DIRSHARD_VALUE | \
								 MXFS_FORMAT_F_SLIFE | MXFS_FORMAT_F_CLUSTER_NAME)

/* A cluster name: 1..63 of [A-Za-z0-9._-], NUL-terminated in 64 bytes.
 * The character set keeps it safe in a mount option string (no ',' or '=')
 * and in a log line. */
#define MXFS_CLUSTER_NAME_LEN   64

static inline int mxfs_cluster_name_valid(const char *s)
{
	int i;

	for (i = 0; s[i]; i++) {
		char c = s[i];

		if (i >= MXFS_CLUSTER_NAME_LEN - 1)
			return 0;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
			return 0;
	}
	return i > 0;
}

#define MXFS_SLIFE_MAGIC        0x45464C53u  /* "SLFE" */
#define MXFS_SLIFE_VERSION      1u
#define MXFS_SLIFE_RECORD_SIZE  512u
/* The region: one record per heartbeat slot (64), 32 KiB, laid out by mkfs
 * before the slice count is settled (the native XFS format decides it, and
 * it is at most 32); records beyond xfs_log_node_count stay zero and are
 * never consulted, because no slot >= the slice count is ever admitted. */
#define MXFS_SLIFE_BYTES        32768u
#define MXFS_SLIFE_INIT_REQUIRED 1u  /* mkfs wrote it; the payload is untrusted */
#define MXFS_SLIFE_ZEROING      2u  /* a claimant is zeroing; a crash here restarts the full zero */
#define MXFS_SLIFE_READY        3u  /* the payload was zeroed through the kernel FUA path */
struct mxfs_slife_record {
	uint32_t    magic;              /* MXFS_SLIFE_MAGIC */
	uint32_t    version;            /* MXFS_SLIFE_VERSION */
	uint32_t    crc;                /* CRC32C of this 512 B with crc=0 */
	uint32_t    state;              /* MXFS_SLIFE_* */
	uint32_t    slice;              /* slice index this record describes */
	uint32_t    generation;         /* bumped at every INIT_REQUIRED -> READY */
	uint8_t     fs_uuid[16];        /* the incarnation the state belongs to */
	uint64_t    owner_node;         /* claimant that wrote ZEROING / READY (0 at mkfs) */
	uint64_t    owner_epoch;        /* its incarnation epoch (0 at mkfs) */
	uint64_t    when_ms;            /* writer's clock, informational */
	uint8_t     pad[MXFS_SLIFE_RECORD_SIZE - 64];
};

/* Bootstrap record geometry: one sector, in a 4 KiB region. */
#define MXFS_BOOTSTRAP_REC_BYTES    512u
/* (docs/whole-cluster-restart.md §6.8): 64 sectors — 0 the record;
 * 1-15 manifest bank A, 16-30 bank B (term parity: a takeover's T+1 manifest
 * never overwrites T's); 31 the TAKEOVER journal; 32-39 completion
 * tombstones (64 x 64 B); 40-47 lineage (8 x one sector); 48-63 reserved.
 * A gen-17 kernel refuses a smaller region (the super carries the size). */
#define MXFS_BOOTSTRAP_BYTES        32768u

/* PR registrant ledger geometry.  One 512-byte CAW-written entry
 * per registrant; a registrant is a {host boot, LUN} key, so the ledger must
 * hold every live member plus the crashed boots whose keys are not yet fenced
 * and the clean departures not yet reused.  256 entries = 128 KiB. */
#define MXFS_PRLEDGER_ENTRY_BYTES   512u
#define MXFS_PRLEDGER_ENTRIES       256u
#define MXFS_PRLEDGER_BYTES         ((uint64_t)MXFS_PRLEDGER_ENTRIES * \
									 MXFS_PRLEDGER_ENTRY_BYTES)

/* Recovery-manifest region geometry.  Capacity proof: the protocol
 * maximum held set is every CAW lock slot (MXFS_CAW_MAX_SLOTS = 65536) x one
 * 32-byte entry = 2 MiB, plus a 4 KiB header -> 2 MiB + 64 KiB per slot.
 * max_held is a tracking cap ("granted but NOT tracked" past it), not a grant
 * cap, so the region must hold the maximum, not the typical population. */
#define MXFS_RMAN_SLOTS         64u
#define MXFS_RMAN_ENTRY_BYTES   32u
#define MXFS_RMAN_HDR_BYTES     4096u
#define MXFS_RMAN_SLOT_BYTES    ((uint64_t)65536u * MXFS_RMAN_ENTRY_BYTES + \
								 65536u)          /* 2 MiB + 64 KiB */
#define MXFS_RMAN_REGION_BYTES  ((uint64_t)MXFS_RMAN_SLOTS * MXFS_RMAN_SLOT_BYTES)
/*
 * 1 -> 2 for the recovery-descriptor v2 fence certificate.
 *
 * This bump is a HARD PREREQUISITE of MXFS_RECOV_DESC_VERSION 2, not
 * bookkeeping.  The design-consult ruling REFUTED the claim that a per-slot
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
 * 2 -> 3 for the NONZERO MOUNT INCARNATION
 * (D-MOUNT-INCARNATION-CONSTANT-ZERO).
 *
 * Until now every heartbeat record carried epoch = 0, measured on the live LUN
 * across all 31 members.  Nodes now draw a random nonzero 64-bit
 * incarnation, and this bump is a HARD PREREQUISITE of that — not bookkeeping.
 *
 * The mixed-version hazard runs OLD-watching-NEW, which no per-record check on
 * the new side can prevent.  Under gen 2 both peers wrote 0, so the monitor's
 * epoch-change arm could never fire; a gen-2 node watching a gen-3 node reboot
 * sees a genuine incarnation change and fires its death path — the earlier
 * one, which rebases node_track onto the SUCCESSOR before declaring the
 * predecessor dead and whose first act is a per-NODE SCSI-PR fence.  The
 * victim of that fence is the healthy node that just rejoined.
 *
 * Per-record fail-closed is no defence here (the ruling, again): the
 * gen-2 code does not know there is anything to fail closed about.  Only
 * cluster-wide exclusion works, so gen-2 code is kept out by layers 1-3 above.
 *
 * 3 -> 4 for the CLEAN-DEPARTURE PROVENANCE carve (#92
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
 * 4 -> 5 for the SCSI-PR RESERVATION TYPE change
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
/*
 * Gen 6: the journal carries XFS_LI_MXFS_RELMARK clean-release
 * markers.  A gen-5 replayer fails pass 1 of a gen-6 node's slice with
 * -EFSCORRUPTED (unknown item type), so mixed generations are refused.
 *
 * Gen 7: the RECOVERY MANIFEST region (MXFS_FORMAT_F_RMAN) and the
 * SNAPSHOTTING recovery stage (docs/recovery-manifest.md).  A gen-6 node
 * would fence a victim without writing its manifest, replay from the live CAW
 * table, and never honour the writer guard on a protected victim's slots; a
 * gen-7 replayer presented with a gen-6 certificate has no manifest to consume.
 * Per-record fail-closed is no defence (ruling, again): mixed
 * generations are excluded cluster-wide by layers 1-3.  Bumping requires a
 * re-mkfs (the region must exist) — `chk_mxfs --upgrade-protogate` cannot
 * create it.
 *
 * Gen 8: the TCP DURABLE AUTHORITY LEDGER region
 * (MXFS_FORMAT_F_TAUTH, docs/tcp-authority-ledger.md).  A gen-7 node on the
 * TCP transport keeps grant authority only in memory and purges the whole
 * lock table on every membership change; a gen-8 master makes each grant
 * durable in the ledger before delivering it and imports a dead master's
 * pages instead of answering FREE.  Mixed generations would let a gen-7
 * survivor grant a resource whose gen-8 record is still ACTIVE, so they are
 * excluded cluster-wide by layers 1-3.  Bumping requires a re-mkfs (the
 * region must exist) — `chk_mxfs --upgrade-protogate` cannot create it.
 *
 * Gen 9 (D-0348 step 2): the ledger region is FORMAT v2 — the page
 * count is an mkfs-time parameter in the region header and every resource
 * routes to home_page = seeded_hash % npages.  A gen-8 node routes by the
 * fixed 2115-page, unseeded geometry: on the same region it would master a
 * resource on a DIFFERENT page than a gen-9 node (two writers for one
 * record), and its store refuses a v2 header anyway.  Mixed generations are
 * excluded cluster-wide by layers 1-3.  Bumping requires a re-mkfs.
 *
 * Gen 11 (D-0354 candidate A): a LONE node's grants are REAL on-disk
 * CAW grants with real epochs, its journal images carry v3 authority tokens,
 * and its BAST poll thread runs unconditionally.  A gen-10 node grants
 * memory-only while alone (no slot bit, epoch 0, untagged images) and does
 * not poll for revokes until its discovery callback fires: a gen-10 lone
 * incumbent met by a gen-11 joiner would hold authority the joiner cannot
 * see in the table and could not revoke, and a gen-11 lone incumbent's
 * retained grants would be surrendered/re-minted by a gen-10 joiner's
 * transition (the D-0354 staleep hazard in reverse).  Per-record fail-closed
 * is no defence — the gen-10 side has nothing on disk to fail closed about —
 * so mixed generations are excluded cluster-wide by layers 1-3.  No new
 * on-disk region: `chk_mxfs --upgrade-protogate` suffices (prep re-mkfs's).
 */
/*
 * Gen 12 (docs/whole-cluster-restart.md item 2): the heartbeat
 * record carries a 64-byte host/boot/PR-key identity block at offset 360
 * (evict ring 23 → 19 entries) and the PR key is a 64-bit per-boot key from
 * the registrant ledger region (MXFS_FORMAT_F_PRKEY64), no longer node_id.
 * A gen-11 fencer would PREEMPT the victim's node_id, which is not the key
 * a gen-12 victim registered, so it would certify a fence that excluded
 * nothing; excluded cluster-wide.  New region ⇒ re-mkfs (prep does).
 */
/*
 * Gen 13 (docs/whole-cluster-restart.md §5): the WHOLE-CLUSTER
 * BOOTSTRAP RECORD region (MXFS_FORMAT_F_BOOTSTRAP).  A gen-12 node never
 * consults it, so it would publish ACTIVE and run xfs_mountfs in the middle
 * of a sealed bootstrap recovery, and would judge a provisional bootstrap
 * owner (which heartbeats only in that record) abandoned; excluded
 * cluster-wide.  New region ⇒ re-mkfs (prep does).
 */
/*
 * Gen 18 (docs/dir-sharding.md): SYMMETRIC DIRECTORY SHARDING
 * (MXFS_FORMAT_F_DIRSHARD + sb incompat bit 29).  A gen-17 node does not
 * understand the manifest lifecycle (PARENT/CONTAINER inode flags, the
 * manifest block type in replay, the shard-aware inactivation of an
 * unlinked PARENT), so it must be excluded cluster-wide; the sb bit alone
 * refuses its mount, the gen keeps a mixed fleet from ever forming.
 * No new region.  The two on-disk gates are optional on a gen-18+ format:
 * mkfs sets them only under -D, and a format without them has sharding off.
 */
/*
 * Gen 19 (0.75.0, D-JOINER-TRANSPORT-NOT-CONFORMED-...-0904): the heartbeat
 * feature word gains MXFS_HB_FEAT_TCP, and a CLEAR bit now means "this
 * incarnation runs the CAW transport".  A gen-18 TCP node's records carry a
 * clear bit, so a gen-19 joiner reading them would adopt CAW next to a live
 * TCP node — the exact split-DLM shape the bit exists to prevent.  Excluded
 * cluster-wide; no new region, no re-mkfs needed beyond the gate itself.
 */
/*
 * Gen 20 (0.88.0, D-SLICE-CLAIM-TIME-INIT-UNTRUSTED-ZERO-531): the SLICE
 * LIFECYCLE region (MXFS_FORMAT_F_SLIFE).  A gen-19 node never consults it:
 * it would mount its slice without the claim-time zero and journal into a
 * payload the lifecycle still says is untrusted, and a gen-20 foreign
 * recovery of that slice would then skip records that do exist.  Excluded
 * cluster-wide.  New region ⇒ re-mkfs (prep does).
 */
/*
 * 0.89.0 (gen 21): the TCP open-unlink registry (D-0977).  The authority
 * ledger record's byte 104 is the open-holder mask (a gen-20 region keeps a
 * wall clock there — reading it as marks would defer every free forever or,
 * zeroed, free open files; MXFS_TAUTH_VERSION 4 refuses the old region), the
 * LOCK_RELEASE carries the releaser's mark change and the LOCK_GRANT reply
 * carries the mask, so a gen-20 master would drop every mark a gen-21
 * releaser publishes.  Excluded cluster-wide.  New region ⇒ re-mkfs.
 */
/*
 * 0.89.23 (gen 22): THE FENCE-CLASS REVOCATION CUTOVER.
 *
 * 0.89.16 retired MXFS_FENCE_KIND_PREEMPT_ABORT_DONE (16) and 0.89.18 revoked
 * MXFS_FENCE_KIND_SINGLE_NODE_EXCLUSIVE (17); a corrected reader refuses both
 * wherever a certificate authorises replay, and only the versioned
 * MXFS_FENCE_KIND_PREEMPT_ABORT_PROVEN_V1 (23) carries a declared retirement
 * basis.  Those releases changed what a DURABLE recovery descriptor MEANS
 * without moving the generation, and that is the one thing the descriptor's
 * own coexistence argument (dlm/disklock.h, at MXFS_RECOV_DESC_VERSION) says
 * must never happen: a reader that predates the change replays first and
 * classifies afterwards.
 *
 * The direction that corrupts is not an old node reading a new record — kind
 * 23 is a code point it has never heard of, so its kind==16||kind==19 test
 * refuses it.  It is an old node JOINING beside a corrected one and MINTING
 * kind 16 from a basis that was retired: the corrected build refuses that
 * certificate, the old build honours its own and replays a peer's slice on a
 * retirement claim nobody proved.  Refusing the class at the corrected reader
 * does not repair the node that still mints it, so the old, write-capable
 * implementation has to be kept off the LUN entirely.
 *
 * That is what this bump does, and it is the enforceable all-reader cutover
 * rather than an assertion that every node was upgraded: the exact-match
 * generation gate refuses the MOUNT of a pre-cutover module against a
 * post-cutover filesystem (-EPROTONOSUPPORT, pal/linux/xfs_super.c), and the
 * generation carried in the heartbeat feature block fences a mismatched
 * incarnation that is already live.  No new on-disk region; re-mkfs (prep
 * does) or `chk_mxfs --upgrade-protogate` stamps the generation.
 */
#define MXFS_PROTO_GEN          22u  /* 0.89.23 (gen 22): fence-class revocation cutover.
									 * 0.89.0 (gen 21): open-holder marks on the ledger.
									 * 0.88.0 (gen 20): slice lifecycle region.
									 * 0.75.0 (gen 19): transport bit in the feature word.
									 * (gen 18): directory sharding gates.
									 * (gen 17): bootstrap record v5, 32 KB region (manifest banks,
									 * completion tombstones, lineage, takeover journal — §6.8).
									 * bootstrap record v4 (escrow manifest pointer); v3 (adopted-
									 * slice escrow) + HB_FEAT_BOOTSTRAP_PENDING.
									 * 8 KB bootstrap region with the
									  * sealed manifest; descriptor owner kind */

/*
 * On-disk MXFS superblock — first 4KB of the block device.
 *
 * Layout on device:
 *   [this 4KB super] [journal region] [disklock region] [recovery manifest
 *   region,, iff MXFS_FORMAT_F_RMAN] [TCP authority ledger region,
 * , iff MXFS_FORMAT_F_TAUTH] [XFS data to end]
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
	uint32_t    cluster_proto_gen;  /* C7: valid iff flags has
									 * MXFS_FORMAT_F_PROTOGATE; members
									 * must run code with an EQUAL
									 * MXFS_PROTO_GEN */
	uint32_t    pad0;               /* keep the u64s below naturally aligned */
	uint64_t    rman_offset;        /* byte offset of the recovery
									 * manifest region; valid iff flags has
									 * MXFS_FORMAT_F_RMAN */
	uint64_t    rman_size;          /* its size in bytes */
	uint64_t    tauth_offset;       /* byte offset of the TCP
									 * authority ledger region; valid iff
									 * flags has MXFS_FORMAT_F_TAUTH */
	uint64_t    tauth_size;         /* its size in bytes */
	uint64_t    prkey_offset;       /* byte offset of the PR
									 * registrant ledger region; valid iff
									 * flags has MXFS_FORMAT_F_PRKEY64 */
	uint64_t    prkey_size;         /* its size in bytes */
	uint64_t    bootstrap_offset;   /* byte offset of the bootstrap
									 * record region; valid iff flags has
									 * MXFS_FORMAT_F_BOOTSTRAP */
	uint64_t    bootstrap_size;     /* its size in bytes */
	uint64_t    slife_offset;       /* 0.88.0: byte offset of the slice
									 * lifecycle region; valid iff flags has
									 * MXFS_FORMAT_F_SLIFE */
	uint64_t    slife_size;         /* 0.88.0: its size in bytes
									 * (MXFS_SLIFE_BYTES; the first
									 * xfs_log_node_count records are live) */
	char        cluster_name[MXFS_CLUSTER_NAME_LEN]; /* valid iff flags has
									 * MXFS_FORMAT_F_CLUSTER_NAME; else zero */
	uint8_t     reserved[3840];     /* pad to 4096 bytes */
};

#ifdef __KERNEL__
#define MXFS_BUILD_CHECK_SLIFE() \
	BUILD_BUG_ON(sizeof(struct mxfs_slife_record) != MXFS_SLIFE_RECORD_SIZE)
#elif !defined(__cplusplus)
_Static_assert(sizeof(struct mxfs_slife_record) == MXFS_SLIFE_RECORD_SIZE,
	       "mxfs_slife_record must be exactly 512 bytes");
#endif

/* Compile-time size check */
#ifdef __KERNEL__
#define MXFS_BUILD_CHECK_SUPER() \
	BUILD_BUG_ON(sizeof(struct mxfs_ondisk_super) != MXFS_SUPER_SIZE)
#elif !defined(__cplusplus)
_Static_assert(sizeof(struct mxfs_ondisk_super) == MXFS_SUPER_SIZE,
	       "mxfs_ondisk_super must be exactly 4096 bytes");
#endif

#endif /* MXFS_SUPER_H */
