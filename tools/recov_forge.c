/*
 * recov_forge — read, decode, forge and restore the RECOVERY GUARD state of an
 * MXFS disklock heartbeat sector.
 *
 * WHY THIS EXISTS
 * ---------------
 * The D-513 containment machinery (terminal recovery-outcome record + survivor
 * import + quarantine map) has three consumers of an on-disk outcome record
 * that each apply a DIFFERENT level of scrutiny:
 *
 *   1. the disklock monitor          (dlm/disklock.c, heartbeat thread)
 *   2. the registration-time scan    (mxfs_v5_dlm_recovery_scan_outcomes)
 *   3. the shared terminal classifier(mxfs_freplay_classify_terminal ->
 *                                     mxfs_freplay_import_verdict)
 *
 * The sess333 RULE-5 review demanded pre-disposition checks that a MALFORMED
 * or MISPLACED record makes every one of them fail CLOSED, and that the
 * refusing path never rewrites the sector it refused.  Nothing in the tree can
 * produce those inputs: the kernel only ever writes well-formed records.  This
 * tool produces them, on the real LUN, with the real CRC binding, so the checks
 * exercise the real code path instead of a reimplementation of it.
 *
 * It is a DIAGNOSTIC/TEST tool.  It writes to the shared device.  Every forge
 * mode saves nothing implicitly — use `save` first and `restore` after.
 *
 * Usage:
 *   recov_forge <dev> dump [slot]
 *   recov_forge <dev> save    <slot> <file>
 *   recov_forge <dev> restore <slot> <file>
 *   recov_forge <dev> copy    <src_slot> <dst_slot>
 *   recov_forge <dev> mkguard <slot> [options]
 *
 * mkguard options (defaults in brackets):
 *   --fsgen G          heartbeat fs_gen [auto: first ACTIVE slot's fs_gen]
 *   --node N           heartbeat node_id / desc victim_node [4242]
 *   --epoch E          heartbeat epoch  / desc victim_epoch [7]
 *   --victim-slot S    desc.victim_slot [= slot]
 *   --stage S          desc.stage [2 = FENCED]
 *   --live             omit MXFS_RECOV_F_QUARANTINED (live descriptor)
 *   --break-desc-crc   store a deliberately wrong descriptor crc
 *   --oc SHAPE         outcome region shape [none]
 *       none          all-zero outcome region (legacy intent quarantine)
 *       valid         TERMINAL_REFUSED / POLICY / AG_MASK(--oc-agmask), crc ok
 *       fswide        TERMINAL_REFUSED / POLICY / FSWIDE, crc ok
 *       badkind       crc-VALID record whose outcome kind is unknown (99)
 *       badreason     crc-VALID record whose refusal reason is unknown (99)
 *       agmask0       crc-VALID AG_MASK record with an empty mask
 *       fswidemask    crc-VALID FSWIDE record carrying a nonzero AG mask
 *                     (noncanonical: FSWIDE defines no AG set)
 *       slotmismatch  crc-VALID record whose victim_slot names another slot
 *       badcrc        well-formed fields, deliberately wrong crc
 *   --oc-agmask M      AG mask for AG_MASK shapes [0x1]
 *
 * All device I/O is SCSI READ(16)/WRITE(16) with FUA, exactly like the kernel's
 * disklock reader — a buffered or plain O_DIRECT access on this target stack
 * can be served from a stale image (see tools/caw_slotdump.c).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>

#include <mxfs/mxfs_super.h>

#define SECTOR_SIZE     512
#define TIMEOUT_MS      30000
#define HB_SLOTS        64
#define HB_RECORD_SIZE  512

#define DL_MAGIC            0x4D584C4Bu   /* "MXLK" */
#define DL_FLAG_EMPTY       0u
#define DL_FLAG_ACTIVE      1u
#define DL_FLAG_WITHDRAWN   2u
#define DL_FLAG_GUARD       3u

#define RECOV_DESC_MAGIC    0x5643524Du   /* "MRCV" LE */
#define RECOV_DESC_VERSION  2
#define RECOV_F_QUARANTINED 0x00000001u

#define OC_MAGIC            0x4F435652u   /* "RVCO" LE */
#define OC_VERSION          1
#define OC_TERMINAL_REFUSED 1u
#define REFUSAL_POLICY      1u
#define REFUSAL_TORN        2u
#define REFUSAL_LEGACY      3u
#define DOMAIN_FSWIDE       1u
#define DOMAIN_AG_MASK      2u

/* Mirrors struct mxfs_recov_desc (dlm/disklock.h) — layout asserted below. */
struct recov_desc {
	uint32_t magic;
	uint16_t version;
	uint16_t stage;
	uint64_t victim_epoch;
	uint64_t owner_epoch;
	uint64_t recovery_gen;
	uint64_t owner_stamp_ms;
	uint32_t victim_node;
	uint32_t owner_node;
	uint32_t victim_fs_gen;
	uint32_t flags;
	uint16_t victim_slot;
	uint16_t owner_slot;
	uint16_t slice_idx;
	uint16_t slice_count;
	uint64_t stage_seq;
	uint32_t owner_term;
	uint16_t fence_kind;
	uint16_t fence_resv_type;
	uint64_t fence_victim_key;
	uint64_t fence_prover_epoch;
	uint64_t fence_stamp_ms;
	uint32_t fence_prover_node;
	uint32_t fence_pr_gen;
	uint32_t fence_term;
	uint32_t crc32c;
};

/* Mirrors struct mxfs_recov_outcome (dlm/disklock.h). */
struct recov_outcome {
	uint32_t magic;
	uint16_t version;
	uint16_t outcome;
	uint16_t reason;
	uint16_t domain_kind;
	uint16_t victim_slot;
	uint16_t owner_slot;
	uint64_t victim_epoch;
	uint64_t owner_epoch;
	uint64_t recovery_gen;
	uint64_t ag_mask;
	uint64_t slice_digest;
	uint64_t publish_seq;
	uint32_t victim_node;
	uint32_t victim_fs_gen;
	uint32_t owner_node;
	uint32_t owner_term;
	uint32_t refused_items;
	uint32_t malformed_items;
	uint32_t flags;
	uint32_t crc32c;
};

/* Mirrors struct mxfs_disklock_heartbeat's head + the recov arm of its union. */
struct hb_rec {
	uint32_t magic;
	uint32_t flags;
	uint32_t node_id;
	uint32_t fs_gen;
	uint64_t timestamp_ms;
	uint64_t epoch;
	uint64_t lock_count;
	struct recov_desc    desc;      /* union base + 0 */
	struct recov_outcome outcome;   /* union base + 120 */
	uint8_t  pad[168];
	uint8_t  tail[88];              /* prov(32) + mepoch(44) + feat(12) */
};

_Static_assert(sizeof(struct recov_desc) == 120, "recov_desc is 120 bytes");
_Static_assert(sizeof(struct recov_outcome) == 96, "recov_outcome is 96 bytes");
_Static_assert(sizeof(struct hb_rec) == 512, "hb record is one sector");
_Static_assert(__builtin_offsetof(struct hb_rec, desc) == 40, "union at 40");
_Static_assert(__builtin_offsetof(struct hb_rec, outcome) == 160, "outcome at 160");
_Static_assert(__builtin_offsetof(struct hb_rec, tail) == 424, "prov at 424");

/* ── crc32c, byte-for-byte the same function as mxfs_pal_crc32c ───────────── */
static uint32_t crc_tab[256];
static int crc_ready;

static void crc_init(void)
{
	uint32_t i, j, c;

	for (i = 0; i < 256; i++) {
		c = i;
		for (j = 0; j < 8; j++)
			c = (c & 1) ? (c >> 1) ^ 0x82F63B78u : c >> 1;
		crc_tab[i] = c;
	}
	crc_ready = 1;
}

static uint32_t crc32c(uint32_t crc, const void *data, size_t len)
{
	const uint8_t *p = data;

	if (!crc_ready)
		crc_init();
	while (len--)
		crc = (crc >> 8) ^ crc_tab[(crc & 0xFF) ^ *p++];
	return crc;
}

struct ident {
	uint32_t fs_gen;
	uint32_t node_id;
	uint64_t epoch;
} __attribute__((packed));

static uint32_t desc_crc(const struct hb_rec *hb, const struct recov_desc *d)
{
	struct ident id = { hb->fs_gen, hb->node_id, hb->epoch };
	uint32_t crc = crc32c(~0U, d, __builtin_offsetof(struct recov_desc, crc32c));

	return crc32c(crc, &id, sizeof(id));
}

static uint32_t oc_crc(const struct hb_rec *hb, const struct recov_outcome *oc)
{
	struct ident id = { hb->fs_gen, hb->node_id, hb->epoch };
	uint32_t crc = crc32c(~0U, oc,
			      __builtin_offsetof(struct recov_outcome, crc32c));

	return crc32c(crc, &id, sizeof(id));
}

/* ── device I/O: READ(16)/WRITE(16) with FUA ──────────────────────────────── */
static int sg_rw(int fd, int write, uint64_t lba, void *buf, uint32_t blocks)
{
	unsigned char cdb[16] = {0};
	unsigned char sense[64];
	sg_io_hdr_t hdr;

	cdb[0]  = write ? 0x8A : 0x88;          /* WRITE(16) / READ(16) */
	cdb[1]  = 0x08;                         /* FUA */
	cdb[2]  = (uint8_t)(lba >> 56);
	cdb[3]  = (uint8_t)(lba >> 48);
	cdb[4]  = (uint8_t)(lba >> 40);
	cdb[5]  = (uint8_t)(lba >> 32);
	cdb[6]  = (uint8_t)(lba >> 24);
	cdb[7]  = (uint8_t)(lba >> 16);
	cdb[8]  = (uint8_t)(lba >> 8);
	cdb[9]  = (uint8_t)(lba);
	cdb[10] = (uint8_t)(blocks >> 24);
	cdb[11] = (uint8_t)(blocks >> 16);
	cdb[12] = (uint8_t)(blocks >> 8);
	cdb[13] = (uint8_t)(blocks);

	memset(&hdr, 0, sizeof(hdr));
	memset(sense, 0, sizeof(sense));
	hdr.interface_id = 'S';
	hdr.cmd_len = sizeof(cdb);
	hdr.cmdp = cdb;
	hdr.dxferp = buf;
	hdr.dxfer_len = blocks * SECTOR_SIZE;
	hdr.dxfer_direction = write ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
	hdr.sbp = sense;
	hdr.mx_sb_len = sizeof(sense);
	hdr.timeout = TIMEOUT_MS;

	if (ioctl(fd, SG_IO, &hdr) < 0) {
		fprintf(stderr, "SG_IO %s: %s\n", write ? "write" : "read",
			strerror(errno));
		return -1;
	}
	if (hdr.status || hdr.host_status || hdr.driver_status) {
		fprintf(stderr, "SG_IO %s failed: status=%u host=%u driver=%u "
			"sense=%02x/%02x/%02x\n", write ? "write" : "read",
			hdr.status, hdr.host_status, hdr.driver_status,
			sense[2] & 0x0F, sense[12], sense[13]);
		return -1;
	}
	return 0;
}

static uint64_t hb_base;        /* byte offset of slot 0 */

static int slot_read(int fd, int slot, struct hb_rec *hb)
{
	return sg_rw(fd, 0, (hb_base + (uint64_t)slot * HB_RECORD_SIZE) /
			 SECTOR_SIZE, hb, 1);
}

static int slot_write(int fd, int slot, const struct hb_rec *hb)
{
	return sg_rw(fd, 1, (hb_base + (uint64_t)slot * HB_RECORD_SIZE) /
			 SECTOR_SIZE, (void *)hb, 1);
}

/* ── decode ───────────────────────────────────────────────────────────────── */
static const char *flag_name(uint32_t f)
{
	switch (f) {
	case DL_FLAG_EMPTY:     return "EMPTY";
	case DL_FLAG_ACTIVE:    return "ACTIVE";
	case DL_FLAG_WITHDRAWN: return "WITHDRAWN";
	case DL_FLAG_GUARD:     return "GUARD";
	default:                return "?";
	}
}

static bool desc_present(const struct hb_rec *hb)
{
	return hb->magic == DL_MAGIC && hb->flags == DL_FLAG_GUARD &&
	       hb->desc.magic == RECOV_DESC_MAGIC;
}

static bool oc_present(const struct hb_rec *hb)
{
	const uint8_t *p = (const uint8_t *)&hb->outcome;
	size_t i;

	for (i = 0; i < sizeof(hb->outcome); i++)
		if (p[i])
			return true;
	return false;
}

static void dump_slot(int slot, const struct hb_rec *hb)
{
	bool dpres = desc_present(hb);
	bool dvalid = dpres && hb->desc.version == RECOV_DESC_VERSION &&
		      hb->desc.crc32c == desc_crc(hb, &hb->desc);
	bool ovalid = dpres && hb->outcome.magic == OC_MAGIC &&
		      hb->outcome.version == OC_VERSION &&
		      hb->outcome.crc32c == oc_crc(hb, &hb->outcome);

	printf("slot=%-2d magic=%s flags=%-9s node=%-6u fs_gen=0x%08x "
	       "epoch=%llu sector_crc32c=0x%08x\n",
	       slot, hb->magic == DL_MAGIC ? "MXLK" : "----",
	       flag_name(hb->flags), hb->node_id, hb->fs_gen,
	       (unsigned long long)hb->epoch,
	       crc32c(~0U, hb, sizeof(*hb)));
	if (!dpres) {
		if (hb->magic == DL_MAGIC && hb->flags == DL_FLAG_GUARD)
			printf("        desc: GUARD record with no descriptor magic\n");
		return;
	}
	printf("        desc: ver=%u stage=%u flags=0x%08x victim=%u/%llu "
	       "victim_slot=%u fs_gen=0x%08x owner=%u term=%u crc=%s\n",
	       hb->desc.version, hb->desc.stage, hb->desc.flags,
	       hb->desc.victim_node,
	       (unsigned long long)hb->desc.victim_epoch,
	       hb->desc.victim_slot, hb->desc.victim_fs_gen,
	       hb->desc.owner_node, hb->desc.owner_term,
	       dvalid ? "OK" : "BAD");
	printf("        desc: QUARANTINED=%d\n",
	       !!(hb->desc.flags & RECOV_F_QUARANTINED));
	if (!oc_present(hb)) {
		printf("        oc:   all-zero (no outcome record)\n");
		return;
	}
	printf("        oc:   magic=%s ver=%u outcome=%u reason=%u domain=%u "
	       "ag_mask=0x%llx victim_slot=%u owner=%u seq=%llu crc=%s\n",
	       hb->outcome.magic == OC_MAGIC ? "RVCO" : "----",
	       hb->outcome.version, hb->outcome.outcome, hb->outcome.reason,
	       hb->outcome.domain_kind,
	       (unsigned long long)hb->outcome.ag_mask,
	       hb->outcome.victim_slot, hb->outcome.owner_node,
	       (unsigned long long)hb->outcome.publish_seq,
	       ovalid ? "OK" : "BAD");
	printf("        read_outcome() would return: %s\n",
	       !desc_present(hb) ? "-ENOENT" :
	       !dvalid ? "-EPROTO" :
	       !(hb->desc.flags & RECOV_F_QUARANTINED) ? "-EAGAIN" :
	       ovalid ? "0 (record)" :
	       oc_present(hb) ? "-EBADMSG" : "-ENODATA");
}

/* ── main ─────────────────────────────────────────────────────────────────── */
static void usage(void)
{
	fprintf(stderr,
		"usage: recov_forge <dev> dump [slot]\n"
		"       recov_forge <dev> save    <slot> <file>\n"
		"       recov_forge <dev> restore <slot> <file>\n"
		"       recov_forge <dev> copy    <src> <dst>\n"
		"       recov_forge <dev> mkguard <slot> [--fsgen G] [--node N]\n"
		"              [--epoch E] [--victim-slot S] [--stage S] [--live]\n"
		"              [--break-desc-crc] [--oc SHAPE] [--oc-agmask M]\n"
		"  SHAPE: none valid fswide badkind badreason agmask0 slotmismatch\n"
		"         fswidemask badcrc\n");
	exit(2);
}

int main(int argc, char **argv)
{
	const char *dev, *cmd;
	uint8_t sbuf[MXFS_SUPER_SIZE];
	struct mxfs_ondisk_super *sb;
	struct hb_rec hb;
	int fd, i;

	if (argc < 3)
		usage();
	dev = argv[1];
	cmd = argv[2];

	fd = open(dev, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", dev, strerror(errno));
		return 1;
	}
	if (sg_rw(fd, 0, 0, sbuf, MXFS_SUPER_SIZE / SECTOR_SIZE) < 0)
		return 1;
	sb = (struct mxfs_ondisk_super *)sbuf;
	if (sb->magic != MXFS_FORMAT_MAGIC) {
		fprintf(stderr, "not an MXFS device (magic 0x%08x)\n", sb->magic);
		return 1;
	}
	hb_base = sb->disklock_offset;

	if (!strcmp(cmd, "dump")) {
		if (argc >= 4) {
			int slot = atoi(argv[3]);

			if (slot_read(fd, slot, &hb) < 0)
				return 1;
			dump_slot(slot, &hb);
			return 0;
		}
		printf("device=%s disklock_offset=%llu\n", dev,
		       (unsigned long long)hb_base);
		for (i = 0; i < HB_SLOTS; i++) {
			if (slot_read(fd, i, &hb) < 0)
				return 1;
			if (hb.magic != DL_MAGIC && !oc_present(&hb))
				continue;
			dump_slot(i, &hb);
		}
		return 0;
	}

	if (!strcmp(cmd, "save") || !strcmp(cmd, "restore")) {
		int slot;
		FILE *f;

		if (argc < 5)
			usage();
		slot = atoi(argv[3]);
		if (!strcmp(cmd, "save")) {
			if (slot_read(fd, slot, &hb) < 0)
				return 1;
			f = fopen(argv[4], "wb");
			if (!f) {
				fprintf(stderr, "open %s: %s\n", argv[4],
					strerror(errno));
				return 1;
			}
			if (fwrite(&hb, sizeof(hb), 1, f) != 1) {
				fprintf(stderr, "short write to %s\n", argv[4]);
				return 1;
			}
			fclose(f);
			printf("saved slot=%d sector_crc32c=0x%08x -> %s\n",
			       slot, crc32c(~0U, &hb, sizeof(hb)), argv[4]);
			return 0;
		}
		f = fopen(argv[4], "rb");
		if (!f) {
			fprintf(stderr, "open %s: %s\n", argv[4],
				strerror(errno));
			return 1;
		}
		if (fread(&hb, sizeof(hb), 1, f) != 1) {
			fprintf(stderr, "short read from %s\n", argv[4]);
			return 1;
		}
		fclose(f);
		if (slot_write(fd, slot, &hb) < 0)
			return 1;
		printf("restored slot=%d sector_crc32c=0x%08x from %s\n",
		       slot, crc32c(~0U, &hb, sizeof(hb)), argv[4]);
		return 0;
	}

	if (!strcmp(cmd, "copy")) {
		int src, dst;

		if (argc < 5)
			usage();
		src = atoi(argv[3]);
		dst = atoi(argv[4]);
		if (slot_read(fd, src, &hb) < 0)
			return 1;
		if (slot_write(fd, dst, &hb) < 0)
			return 1;
		printf("copied slot %d -> %d (byte-for-byte, "
		       "sector_crc32c=0x%08x)\n", src, dst,
		       crc32c(~0U, &hb, sizeof(hb)));
		printf("NOTE: desc.victim_slot=%u now disagrees with the sector "
		       "index %d\n", hb.desc.victim_slot, dst);
		return 0;
	}

	if (!strcmp(cmd, "mkguard")) {
		int slot;
		uint32_t fsgen = 0;
		uint32_t node = 4242;
		uint64_t epoch = 7;
		int victim_slot = -1;
		uint32_t stage = 2;
		bool quarantine = true;
		bool break_desc = false;
		const char *ocshape = "none";
		uint64_t agmask = 0x1;
		bool have_fsgen = false;

		if (argc < 4)
			usage();
		slot = atoi(argv[3]);
		for (i = 4; i < argc; i++) {
			if (!strcmp(argv[i], "--fsgen") && i + 1 < argc) {
				fsgen = (uint32_t)strtoul(argv[++i], NULL, 0);
				have_fsgen = true;
			} else if (!strcmp(argv[i], "--node") && i + 1 < argc) {
				node = (uint32_t)strtoul(argv[++i], NULL, 0);
			} else if (!strcmp(argv[i], "--epoch") && i + 1 < argc) {
				epoch = strtoull(argv[++i], NULL, 0);
			} else if (!strcmp(argv[i], "--victim-slot") &&
				   i + 1 < argc) {
				victim_slot = atoi(argv[++i]);
			} else if (!strcmp(argv[i], "--stage") && i + 1 < argc) {
				stage = (uint32_t)strtoul(argv[++i], NULL, 0);
			} else if (!strcmp(argv[i], "--live")) {
				quarantine = false;
			} else if (!strcmp(argv[i], "--break-desc-crc")) {
				break_desc = true;
			} else if (!strcmp(argv[i], "--oc") && i + 1 < argc) {
				ocshape = argv[++i];
			} else if (!strcmp(argv[i], "--oc-agmask") &&
				   i + 1 < argc) {
				agmask = strtoull(argv[++i], NULL, 0);
			} else {
				usage();
			}
		}
		if (victim_slot < 0)
			victim_slot = slot;

		if (!have_fsgen) {
			/* Adopt the live filesystem's generation: a record whose
			 * fs_gen differs is a pre-mkfs ghost and every sweep
			 * skips it (hb_gen_foreign), so the forge would be
			 * invisible to the code under test. */
			struct hb_rec probe;
			int s;

			for (s = 0; s < HB_SLOTS; s++) {
				if (slot_read(fd, s, &probe) < 0)
					return 1;
				if (probe.magic == DL_MAGIC && probe.fs_gen) {
					fsgen = probe.fs_gen;
					break;
				}
			}
			if (!fsgen) {
				fprintf(stderr, "could not auto-detect fs_gen: "
					"no slot carries one — pass --fsgen\n");
				return 1;
			}
			printf("auto fs_gen=0x%08x (from slot %d)\n", fsgen, s);
		}

		memset(&hb, 0, sizeof(hb));
		hb.magic = DL_MAGIC;
		hb.flags = DL_FLAG_GUARD;
		hb.node_id = node;
		hb.fs_gen = fsgen;
		hb.timestamp_ms = 1000;
		hb.epoch = epoch;

		hb.desc.magic = RECOV_DESC_MAGIC;
		hb.desc.version = RECOV_DESC_VERSION;
		hb.desc.stage = (uint16_t)stage;
		hb.desc.victim_epoch = epoch;
		hb.desc.owner_epoch = 1;
		hb.desc.recovery_gen = 1;
		hb.desc.owner_stamp_ms = 1000;
		hb.desc.victim_node = node;
		hb.desc.owner_node = 1;
		hb.desc.victim_fs_gen = fsgen;
		hb.desc.flags = quarantine ? RECOV_F_QUARANTINED : 0;
		hb.desc.victim_slot = (uint16_t)victim_slot;
		hb.desc.owner_slot = 0;
		hb.desc.slice_idx = 0;
		hb.desc.slice_count = 4;
		hb.desc.stage_seq = 1;
		hb.desc.owner_term = 1;
		hb.desc.crc32c = desc_crc(&hb, &hb.desc);
		if (break_desc)
			hb.desc.crc32c ^= 0xFFFFFFFFu;

		if (strcmp(ocshape, "none")) {
			struct recov_outcome *oc = &hb.outcome;

			oc->magic = OC_MAGIC;
			oc->version = OC_VERSION;
			oc->outcome = OC_TERMINAL_REFUSED;
			oc->reason = REFUSAL_POLICY;
			oc->domain_kind = DOMAIN_AG_MASK;
			oc->victim_slot = (uint16_t)slot;
			oc->owner_slot = 0;
			oc->victim_epoch = epoch;
			oc->owner_epoch = 1;
			oc->recovery_gen = 1;
			oc->ag_mask = agmask;
			oc->slice_digest = 0;
			oc->publish_seq = 1;
			oc->victim_node = node;
			oc->victim_fs_gen = fsgen;
			oc->owner_node = 1;
			oc->owner_term = 1;
			oc->refused_items = 3;
			oc->malformed_items = 0;
			oc->flags = 0;

			if (!strcmp(ocshape, "valid")) {
				/* defaults above */
			} else if (!strcmp(ocshape, "fswide")) {
				oc->domain_kind = DOMAIN_FSWIDE;
				oc->ag_mask = 0;
			} else if (!strcmp(ocshape, "badkind")) {
				oc->outcome = 99;
			} else if (!strcmp(ocshape, "badreason")) {
				oc->reason = 99;
			} else if (!strcmp(ocshape, "agmask0")) {
				oc->ag_mask = 0;
			} else if (!strcmp(ocshape, "fswidemask")) {
				/* noncanonical: FSWIDE domain with a nonzero
				 * mask.  Two consumers can disagree about what
				 * such a record means. */
				oc->domain_kind = DOMAIN_FSWIDE;
				oc->ag_mask = agmask;
			} else if (!strcmp(ocshape, "slotmismatch")) {
				oc->victim_slot = (uint16_t)((slot + 1) % HB_SLOTS);
			} else if (!strcmp(ocshape, "badcrc")) {
				/* fields fine, crc broken below */
			} else {
				usage();
			}
			oc->crc32c = oc_crc(&hb, oc);
			if (!strcmp(ocshape, "badcrc"))
				oc->crc32c ^= 0xFFFFFFFFu;
		}

		if (slot_write(fd, slot, &hb) < 0)
			return 1;
		printf("forged slot=%d oc=%s%s%s\n", slot, ocshape,
		       break_desc ? " +break-desc-crc" : "",
		       quarantine ? " +QUARANTINED" : " (live desc)");
		if (slot_read(fd, slot, &hb) < 0)
			return 1;
		dump_slot(slot, &hb);
		return 0;
	}

	usage();
	return 2;
}
