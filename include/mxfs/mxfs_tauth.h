/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MXFS TCP durable-authority ledger — ON-DISK LAYOUT of the TAUTH envelope
 * region (docs/tcp-authority-ledger.md, build step 2; design-consult ruling
 * docs/rulings/tcp-durable-authority-ledger.md).
 *
 * This header is kernel/user neutral: it is included by the kernel module
 * (dlm/tauth_store.c), by mkfs_mxfs (formats the region), by chk_mxfs
 * (verifies it) and by the usermode torn-write unit test.  It carries the
 * structures, the geometry and the PURE validation helpers only — no I/O.
 *
 * Why this region exists.  The TCP transport's lock masters keep their
 * grant tables in memory; a master crash loses the only record of who holds
 * what, and the fence-time replay gate then has no authority evidence for a
 * victim's images (D-TCP-FOREIGN-REPLAY-ALWAYS-REFUSED-NO-AUTHORITY-SOURCE-
 * 0288) while the membership-change purge issues conflicting grants
 * (D-TCP-MEMBERSHIP-CHANGE-PURGES-HELD-GRANTS-NO-RECONSTRUCTION-0287).  The
 * ledger keeps the CAW authority SCHEMA (one record per resource, on the
 * resource's home page) but its physical protocol is "one authorised writer per
 * page, plain crash-safe writes" — no compare-and-write.
 *
 * Crash atomicity.  In-place read-modify-write of a 4 KiB page with a crc is
 * REJECTED by the ruling: a torn page makes every resource on it UNKNOWN,
 * and routine master crashes would quarantine slices again.  Every page has
 * TWO shadow copies (A and B, in two contiguous copy arrays).  A writer reads
 * both, writes the copy that does NOT hold the highest valid committed seq
 * with seq = highest + 1, flushes, and only then considers the transition
 * durable.  A reader validates both and takes the highest valid seq.  The
 * only valid copy is therefore never overwritten, and a torn write leaves
 * the previous committed image intact in the other copy.  The region
 * header is dual-copy for the same reason.
 *
 * Layout (all offsets relative to tauth_offset in the envelope super):
 *   [region hdr copy A: 4 KiB] [region hdr copy B: 4 KiB]
 *   [page 0..npages-1 copy A]  [page 0..npages-1 copy B]
 * Every page is 4 KiB = 128-byte page header + 31 x 128-byte entries.
 * npages is a FORMAT-TIME parameter (v2) held in the region header.
 *
 * Absence == FREE only with COMPLETE valid coverage: mkfs writes every page
 * as a valid EMPTY page (seq 1) in copy A, so a fresh region has no
 * unreadable page.  Any page with NO valid copy is UNKNOWN to the reader
 * (-EUCLEAN) and the authority code must fail closed on it, never treat it
 * as free.
 */
#ifndef MXFS_TAUTH_H
#define MXFS_TAUTH_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#else
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#endif
#include "mxfs_common.h"     /* mxfs_uuid_to_volume_id */

#define MXFS_TAUTH_REGION_MAGIC     0x48545541u  /* "AUTH" LE */
#define MXFS_TAUTH_PAGE_MAGIC       0x47504154u  /* "TAPG" LE */
#define MXFS_TAUTH_TICKET_MAGIC     0x4b545441u  /* "ATTK" LE: a copy under commit */
#define MXFS_TAUTH_TICKET_BYTES     512u
#define MXFS_TAUTH_VERSION          4u   /* (D-0348 step 2): v2 = mkfs-sized
										  * geometry + seeded hash;
										  * (docs/tauth-view-table.md build step 1):
										  * v3 adds the VIEW RECORD control pages;
										  * 0.89.0: v4 puts the open-holder mask in
										  * the record (entry byte 104, where v3
										  * kept a forensic wall clock); a v3
										  * region's bytes there are timestamps, so
										  * v1..v3 regions are REFUSED and reformatted */
#define MXFS_TAUTH_VIEW_MAGIC       0x56484154u  /* on-media bytes 54 41 48 56 "TAHV" */
#define MXFS_TAUTH_ROOT_MAGIC       0x54524854u  /* on-media bytes 54 48 52 54 "THRT" */
#define MXFS_TAUTH_VIEW_VERSION     1u
#define MXFS_TAUTH_ROOT_VERSION     1u
#define MXFS_TAUTH_CTRL_PAGES       3u   /* view slot A, view slot B, root */
#define MXFS_TAUTH_CTRL_VIEW_A      0u
#define MXFS_TAUTH_CTRL_VIEW_B      1u
#define MXFS_TAUTH_CTRL_ROOT        2u
#define MXFS_TAUTH_VIEW_MEMBERS     64u
#define MXFS_TAUTH_VIEW_REMOVED     32u
#define MXFS_TAUTH_ROOT_BYTES       512u  /* the CAW unit on 512 B logical blocks */
#define MXFS_TAUTH_ROOT_SLOT_NONE   0xffffu
#define MXFS_TAUTH_VIEW_DOMAIN      "MXFS-TAUTH-VIEW1"   /* 16 ASCII bytes, no NUL */
#define MXFS_TAUTH_VIEW_DOMAIN_LEN  16u
#define MXFS_TAUTH_VIEW_DIGEST_OFF  4024u
#define MXFS_TAUTH_VIEW_CRC_OFF     4088u
#define MXFS_TAUTH_ROOT_CRC_OFF     500u

#define MXFS_TAUTH_PAGE_BYTES       4096u
#define MXFS_TAUTH_PAGE_HDR_BYTES   128u
#define MXFS_TAUTH_ENTRY_BYTES      128u
#define MXFS_TAUTH_ENTRIES_PER_PAGE ((MXFS_TAUTH_PAGE_BYTES - MXFS_TAUTH_PAGE_HDR_BYTES) / \
									 MXFS_TAUTH_ENTRY_BYTES)          /* 31 */
/*
 * (D-0348 step 2, design-consult ruling
 * tauth-slot-collision-page-open-addressing): the page count is an MKFS-TIME
 * PARAMETER recorded in the region header, not a compile-time constant.  A
 * resource hashes deterministically to ONE home page
 * (home_page = hash(seed, resource) % npages) and the page's master finds /
 * creates its record among that page's 31 entries by full key.  Capacity is
 * sized from the PEAK number of simultaneously held tenures (mean occupancy
 * must stay well below 31/page): the old fixed 65,565 records was
 * categorically undersized for the small-file workloads (44 refusals at
 * 8,000 live inode locks).  MXFS_TAUTH_NPAGES is the MINIMUM and the
 * usermode-test default; mkfs_mxfs derives the real count from the device
 * (tools/mkfs_mxfs.c tauth_npages_for_device) or takes -t <entries>.
 */
#define MXFS_TAUTH_SLOTS            65536u   /* legacy minimum record count */
#define MXFS_TAUTH_NPAGES           ((MXFS_TAUTH_SLOTS + MXFS_TAUTH_ENTRIES_PER_PAGE - 1) / \
									 MXFS_TAUTH_ENTRIES_PER_PAGE)     /* 2115 = minimum */
#define MXFS_TAUTH_NPAGES_MIN       MXFS_TAUTH_NPAGES
#define MXFS_TAUTH_NPAGES_MAX       (1u << 20)                        /* 8 GiB dual */
#define MXFS_TAUTH_HASH_VERSION     1u   /* fnv1a-32 over the resource id, seeded */
#define MXFS_TAUTH_HDR_COPIES       2u
#define MXFS_TAUTH_PAGE_COPIES      2u
/* Region size for a page count (the header copies + both page copy arrays). */
#define MXFS_TAUTH_REGION_BYTES_FOR(npages) \
									((uint64_t)MXFS_TAUTH_PAGE_BYTES * \
									 (MXFS_TAUTH_HDR_COPIES + MXFS_TAUTH_CTRL_PAGES + \
									  (uint64_t)MXFS_TAUTH_PAGE_COPIES * (uint64_t)(npages)))
/* The MINIMUM region (2115 pages, 16.5 MiB); also the usermode-test geometry. */
#define MXFS_TAUTH_REGION_BYTES     MXFS_TAUTH_REGION_BYTES_FOR(MXFS_TAUTH_NPAGES)

/* entry state */
#define MXFS_TAUTH_ST_EMPTY         0u   /* never used since format */
#define MXFS_TAUTH_ST_ACTIVE        1u   /* a live grant */
#define MXFS_TAUTH_ST_FREE          2u   /* tombstone: last grant superseded */
#define MXFS_TAUTH_ST_UNKNOWN       3u   /* explicit: authority could not be
										  * reconstructed (never treat as FREE) */

/*
 * One authority record (128 bytes) — the CAW authority schema with a
 * single-writer WRITE backend (design-consult ruling 2, option (b), ccmemory
 * docs/rulings/tauth-step3-master-ledger-design.md):
 *
 *  - shared holders are a 64-bit HEARTBEAT-SLOT bitmap (`holders`) under one
 *    `shared_mode`; a slot is unique per live mount incarnation and is only
 *    re-claimable after its previous tenant's recovery has purged these
 *    records, so slot + the {node, incarnation} the message carries (compared
 *    against the CURRENT heartbeat row, never inferred from it) qualifies a
 *    PR release.  PR carries no per-holder grant id (PR writes no images).
 *  - the exclusive holder (EX/PW, the replay-authority case) is explicit:
 *    {ex_node, ex_inc, ex_slot, ex_mode} with grant_id =
 *    {authority_epoch, grant_seq64}; FREE keeps last_grant_seq64.
 *  - the FULL resource identity is recorded; a slot collision between two
 *    resources fails closed (the master must never share one record).
 *  - authority_epoch is the writer generation {membership epoch, page master
 *    node, page master inc} folded by the master; existing records keep the
 *    epoch they were issued under across takeovers.
 */
struct mxfs_tauth_entry {
	uint16_t    state;              /*  0: MXFS_TAUTH_ST_* */
	uint8_t     res_type;           /*  2: mxfs_lock_type of the resource */
	uint8_t     shared_mode;        /*  3: mode of every `holders` bit (PR…) */
	uint32_t    ag_number;          /*  4: resource identity */
	uint64_t    ino;                /*  8: resource identity */
	uint64_t    offset;             /* 16: resource identity */
	uint64_t    holders;            /* 24: shared holders, bit = HB slot */
	uint64_t    resource_lineage;   /* 32: the lineage tag images carry */
	uint32_t    ex_node;            /* 40: exclusive holder (0 = none) */
	uint16_t    ex_slot;            /* 44 */
	uint8_t     ex_mode;            /* 46: EX or PW */
	uint8_t     pad0;               /* 47 */
	uint64_t    ex_inc;             /* 48: exclusive holder incarnation */
	uint64_t    authority_epoch;    /* 56: grant_id half (EX holder) */
	uint64_t    grant_seq64;        /* 64: grant_id half (EX holder) */
	uint64_t    last_grant_seq64;   /* 72: FREE: the superseded EX grant */
	uint64_t    config_epoch;       /* 80: membership epoch of the transition */
	uint64_t    dir_epoch;          /* 88 */
	uint64_t    transition_seq64;   /* 96: per-page transition counter value */
	/*
	 * 104: OPEN-HOLDER MARKS, one bit per heartbeat slot (0.89.0, the TCP
	 * open-unlink registry — D-0977).  A set bit says that slot's node
	 * released its grant on this inode while it still had the file open
	 * or mapped, and the bit is honoured by the destructive inactivation
	 * guard of whichever node next holds EX: the free is deferred until
	 * the bit is cleared by its owner's release (last close rides a
	 * release), zeroed by the genuine free, or stripped by the owner's
	 * fence purge.  A record carrying marks is a LIVE LIFETIME RECORD
	 * whatever its lock state says: a FREE (tombstone) entry with a
	 * non-zero mask is never reclaimed for another resource and pins one
	 * of the page's entries until its last opener clears.  Replaced the
	 * per-record forensic wall clock (the page header keeps one per
	 * transition).
	 */
	uint64_t    open_holders;
	uint32_t    auth_node;          /* 112: the master that minted the EX
									 * grant (authority_epoch is its mount
									 * incarnation; together = the writer
									 * generation, step 3c) */
	uint16_t    auth_slot;          /* 116: that master's heartbeat slot */
	uint8_t     reserved[2];        /* 118 */
	uint64_t    volume;             /* 120: resource identity (volume id) */
};                                  /* 128 */

/* Page header (128 bytes).  crc32c covers the WHOLE 4 KiB page with the crc
 * field zero, seeded ~0 and not inverted (the project's convention).
 * `seq` is the shadow-copy COMMIT sequence (copy selection); `grant_seq_next`
 * / `transition_seq_next` are the per-page ALLOCATORS the master continues
 * from after a takeover (distinct fields, distinct semantics). */
struct mxfs_tauth_page_hdr {
	uint32_t    magic;              /*  0: MXFS_TAUTH_PAGE_MAGIC */
	uint16_t    version;            /*  4 */
	uint16_t    nentries;           /*  6: MXFS_TAUTH_ENTRIES_PER_PAGE */
	uint32_t    page_id;            /*  8 */
	uint32_t    fs_gen;             /* 12 */
	uint64_t    seq;                /* 16: commit sequence, highest valid wins */
	uint64_t    authority_epoch;    /* 24: epoch of the writing authority */
	uint64_t    config_epoch;       /* 32 */
	uint32_t    writer_node;        /* 40 */
	uint32_t    write_nonce;        /* 44: per-write random; the readback must
									 * match the WHOLE image (step 4:
									 * a lost same-seq race is NOT durable) */
	uint64_t    writer_inc;         /* 48 */
	uint64_t    stamp_ms;           /* 56 */
	uint8_t     fs_uuid[16];        /* 64 */
	uint64_t    grant_seq_next;     /* 80: next EX grant_seq64 on this page */
	uint64_t    transition_seq_next;/* 88: next transition_seq64 on this page */
	/*
	 * (step 4, ordered mastership handoff): the page's AUTHORITY is
	 * durable in the page itself.  Only {auth_node, authority_epoch(=auth
	 * inc)} may write entry transitions while auth_state is ACTIVE; a
	 * handoff is TWO durable transitions: the authority writes PREPARED
	 * (entries unchanged, target named) and the named target consumes that
	 * exact record (state, target, seq) with its own ACTIVE.  UNOWNED is
	 * the mkfs state (no authority yet).  `config_epoch` carries the
	 * writer's configuration id (rendezvous cookie, never an authority).
	 */
	uint8_t     auth_state;         /* 96: MXFS_TAUTH_PG_* */
	uint8_t     pad1[3];            /* 97 */
	uint32_t    auth_node;          /* 100: authority node (0 = unowned) */
	uint32_t    target_node;        /* 104: PREPARED: the named successor */
	uint32_t    pad2;               /* 108 */
	uint64_t    target_inc;         /* 112: PREPARED: successor incarnation */
	uint32_t    reserved;           /* 120 */
	uint32_t    crc32c;             /* 124 */
};                                  /* 128 */

/* page authority state (auth_state) */
#define MXFS_TAUTH_PG_UNOWNED       0u   /* formatted; no authority yet */
#define MXFS_TAUTH_PG_ACTIVE        1u   /* {auth_node, authority_epoch} serves */
#define MXFS_TAUTH_PG_PREPARED      2u   /* frozen; handed to {target_node,
										  * target_inc}; entries immutable
										  * until the target activates */

struct mxfs_tauth_page {
	struct mxfs_tauth_page_hdr  hdr;
	struct mxfs_tauth_entry     ent[MXFS_TAUTH_ENTRIES_PER_PAGE];
};                                  /* 4096 */

/*
 * (D-0347, conditional commit): a copy under commit carries a
 * TICKET in its sector 0 instead of a page header.  Its magic makes the
 * 4 KiB image INVALID (readers keep the other copy as the truth); its
 * identity names the writer and the exact committed image (base_seq /
 * base_nonce) the new image was derived from.  Written and consumed with
 * SCSI COMPARE AND WRITE: acquire = CAW(spare sector 0 as read -> ticket),
 * publish = CAW(ticket -> final sector 0).  crc32c over the first 508 B.
 */
struct mxfs_tauth_ticket {
	uint32_t    magic;              /*  0: MXFS_TAUTH_TICKET_MAGIC */
	uint16_t    version;            /*  4 */
	uint16_t    pad0;               /*  6 */
	uint32_t    page_id;            /*  8 */
	uint32_t    fs_gen;             /* 12 */
	uint64_t    proposed_seq;       /* 16: the seq being published */
	uint64_t    base_seq;           /* 24: committed image this derives from */
	uint32_t    base_nonce;         /* 32: ... and its write_nonce */
	uint32_t    ticket_nonce;       /* 36: unique per acquisition */
	uint32_t    writer_node;        /* 40 */
	uint32_t    pad1;               /* 44 */
	uint64_t    writer_inc;         /* 48 */
	uint64_t    stamp_ms;           /* 56 */
	uint8_t     reserved[444];      /* 64 */
	uint32_t    crc32c;             /* 508 */
};                                  /* 512 */

/* Region header (one 4 KiB block, dual copy).  crc over the whole block. */
struct mxfs_tauth_region_hdr {
	uint32_t    magic;              /*  0: MXFS_TAUTH_REGION_MAGIC */
	uint16_t    version;            /*  4 */
	uint16_t    entries_per_page;   /*  6 */
	uint32_t    npages;             /*  8 */
	uint32_t    entry_bytes;        /* 12 */
	uint32_t    page_bytes;         /* 16 */
	uint32_t    fs_gen;             /* 20 */
	uint8_t     fs_uuid[16];        /* 24 */
	uint64_t    seq;                /* 40 */
	uint64_t    format_stamp_ms;    /* 48 */
	uint16_t    hash_version;       /* 56: MXFS_TAUTH_HASH_VERSION (v2) */
	uint8_t     pad0[6];            /* 58 */
	uint64_t    hash_seed;          /* 64: per-format random seed folded into
									 * every resource hash (v2); the routing
									 * hash % npages is only meaningful with
									 * the seed the region was formatted with */
	uint8_t     reserved[4016];     /* 72 */
	uint32_t    crc32c;             /* 4088 */
	uint32_t    pad_end;            /* 4092 */
};                                  /* 4096 */

/*
 * — VIEW RECORD + ROOT (docs/tauth-view-table.md §13, frozen layout,
 * little-endian on media; every reserved/pad byte zero on write and
 * validated zero on read).  The committed member list is the ONLY durable
 * input to page ownership (owner(page) = HRW over the members' heartbeat
 * slots); the ROOT names the committed view record by {slot, gen, digest}
 * and carries the coordinator BALLOT.  Digest = SHA-256(MXFS_TAUTH_VIEW_
 * DOMAIN || bytes[0,4024)); crc32c over [0,4088) (view) / [0,500) (root).
 */
struct mxfs_tauth_member {
	uint32_t    node;
	uint16_t    slot;               /* heartbeat slot: the HRW placement key */
	uint16_t    pad;                /* = 0 */
	uint64_t    inc;                /* mount incarnation: the authority tuple */
};                                  /* 16 */

struct mxfs_tauth_removed {         /* fence-and-recovery certificate essentials */
	uint32_t    node;
	uint16_t    slot;
	uint16_t    stage;              /* recovery-descriptor stage reached */
	uint64_t    inc;
	uint64_t    recovery_gen;
	uint64_t    fence_term;
	uint64_t    manifest_seq;
	uint32_t    manifest_crc32c;
	uint16_t    manifest_count;
	uint16_t    pad;                /* = 0 */
};                                  /* 48 */

struct mxfs_tauth_view {
	uint32_t    magic;              /*    0: MXFS_TAUTH_VIEW_MAGIC */
	uint16_t    version;            /*    4: MXFS_TAUTH_VIEW_VERSION */
	uint16_t    count;              /*    6: members, 1..64 */
	uint64_t    gen;                /*    8: >= 1 */
	uint64_t    prev_gen;           /*   16: 0 for gen 1 */
	uint8_t     prev_digest[32];    /*   24: zero for gen 1 */
	uint32_t    coord_node;         /*   56 */
	uint32_t    pad0;               /*   60 */
	uint64_t    coord_inc;          /*   64 */
	uint64_t    coord_ballot;       /*   72 */
	uint64_t    memb_epoch;         /*   80: membership service sequence */
	uint8_t     memb_digest[32];    /*   88 */
	uint32_t    fs_gen;             /*  120 */
	uint32_t    pad1;               /*  124 */
	uint8_t     fs_uuid[16];        /*  128 */
	uint64_t    stamp_ms;           /*  144 */
	uint64_t    nonce_inc;          /*  152: nonce = {writer_inc, seq} */
	uint64_t    nonce_seq;          /*  160 */
	uint16_t    nremoved;           /*  168: 0..32 */
	uint8_t     pad2[6];            /*  170 */
	struct mxfs_tauth_member  member[MXFS_TAUTH_VIEW_MEMBERS];   /*  176: sorted by node */
	struct mxfs_tauth_removed removed[MXFS_TAUTH_VIEW_REMOVED];  /* 1200: sorted by slot */
	uint8_t     reserved[1288];     /* 2736 */
	uint8_t     digest[32];         /* 4024 */
	uint8_t     reserved2[32];      /* 4056 */
	uint32_t    crc32c;             /* 4088: over [0,4088) */
	uint32_t    pad_end;            /* 4092 */
};                                  /* 4096 */

struct mxfs_tauth_root {
	uint32_t    magic;              /*    0: MXFS_TAUTH_ROOT_MAGIC */
	uint16_t    version;            /*    4: MXFS_TAUTH_ROOT_VERSION */
	uint16_t    slot;               /*    6: 0 = A, 1 = B, 0xffff = none */
	uint64_t    gen;                /*    8: committed view gen, 0 = none */
	uint8_t     digest[32];         /*   16: committed view digest */
	uint32_t    coord_node;         /*   48: ballot owner, 0 = none */
	uint32_t    pad0;               /*   52 */
	uint64_t    coord_inc;          /*   56 */
	uint64_t    coord_ballot;       /*   64: 0 at mkfs, monotonic */
	uint32_t    fs_gen;             /*   72 */
	uint32_t    pad1;               /*   76 */
	uint8_t     fs_uuid[16];        /*   80 */
	uint64_t    stamp_ms;           /*   96 */
	uint64_t    nonce_inc;          /*  104 */
	uint64_t    nonce_seq;          /*  112 */
	uint8_t     reserved[380];      /*  120 */
	uint32_t    crc32c;             /*  500: over [0,500) */
	uint64_t    pad_end;            /*  504 */
};                                  /* 512 */

#if !defined(__KERNEL__) && !defined(__cplusplus)
_Static_assert(sizeof(struct mxfs_tauth_entry) == MXFS_TAUTH_ENTRY_BYTES,
	       "mxfs_tauth_entry must be 128 bytes");
_Static_assert(sizeof(struct mxfs_tauth_page_hdr) == MXFS_TAUTH_PAGE_HDR_BYTES,
	       "mxfs_tauth_page_hdr must be 128 bytes");
_Static_assert(sizeof(struct mxfs_tauth_page) == MXFS_TAUTH_PAGE_BYTES,
	       "mxfs_tauth_page must be 4096 bytes");
_Static_assert(sizeof(struct mxfs_tauth_ticket) == MXFS_TAUTH_TICKET_BYTES,
	       "mxfs_tauth_ticket must be 512 bytes");
_Static_assert(sizeof(struct mxfs_tauth_region_hdr) == MXFS_TAUTH_PAGE_BYTES,
	       "mxfs_tauth_region_hdr must be 4096 bytes");
_Static_assert(sizeof(struct mxfs_tauth_member) == 16, "mxfs_tauth_member must be 16 bytes");
_Static_assert(sizeof(struct mxfs_tauth_removed) == 48, "mxfs_tauth_removed must be 48 bytes");
_Static_assert(sizeof(struct mxfs_tauth_view) == MXFS_TAUTH_PAGE_BYTES,
	       "mxfs_tauth_view must be 4096 bytes");
_Static_assert(sizeof(struct mxfs_tauth_root) == MXFS_TAUTH_ROOT_BYTES,
	       "mxfs_tauth_root must be 512 bytes");
_Static_assert(offsetof(struct mxfs_tauth_view, member) == 176, "view.member @176");
_Static_assert(offsetof(struct mxfs_tauth_view, removed) == 1200, "view.removed @1200");
_Static_assert(offsetof(struct mxfs_tauth_view, digest) == MXFS_TAUTH_VIEW_DIGEST_OFF, "view.digest @4024");
_Static_assert(offsetof(struct mxfs_tauth_view, crc32c) == MXFS_TAUTH_VIEW_CRC_OFF, "view.crc32c @4088");
_Static_assert(offsetof(struct mxfs_tauth_root, crc32c) == MXFS_TAUTH_ROOT_CRC_OFF, "root.crc32c @500");
_Static_assert(offsetof(struct mxfs_tauth_root, nonce_inc) == 104, "root.nonce @104");
#endif

/* The volume identity fold every on-disk MXFS record uses (disklock ctx->fs_gen):
 * fnv1a-64 of the 16-byte uuid, folded to 32 bits, 0 reserved for "unset". */
static inline uint32_t mxfs_tauth_fs_gen(const uint8_t fs_uuid[16])
{
	uint64_t vid = mxfs_uuid_to_volume_id(fs_uuid, 16);
	uint32_t g = (uint32_t)(vid ^ (vid >> 32));

	return g ? g : 1;
}

/* Byte offsets inside the region. */
static inline uint64_t mxfs_tauth_hdr_off(unsigned copy)
{
	return (uint64_t)copy * MXFS_TAUTH_PAGE_BYTES;
}

static inline uint64_t mxfs_tauth_page_off(uint32_t npages, uint32_t page_id,
					   unsigned copy)
{
	return (uint64_t)MXFS_TAUTH_PAGE_BYTES *
	       (MXFS_TAUTH_HDR_COPIES + MXFS_TAUTH_CTRL_PAGES +
		(uint64_t)copy * npages + page_id);
}

/* the control pages (view slots A/B, root) follow the header copies. */
static inline uint64_t mxfs_tauth_ctrl_off(unsigned which)
{
	return (uint64_t)MXFS_TAUTH_PAGE_BYTES * (MXFS_TAUTH_HDR_COPIES + which);
}

/*
 * Resource hash (v2): fnv1a-32 over the resource-id bytes, seeded.  Kept here
 * (kernel/user neutral) so the module, the tools and the tests route a
 * resource to the SAME home page for the same region.
 */
static inline uint32_t mxfs_tauth_res_hash(const void *res, size_t len,
					   uint64_t seed)
{
	const uint8_t *p = (const uint8_t *)res;
	uint32_t h = 2166136261u ^ (uint32_t)seed ^ (uint32_t)(seed >> 32);
	size_t i;

	for (i = 0; i < len; i++) {
		h ^= p[i];
		h *= 16777619u;
	}
	/* final avalanche so % npages and the home index use different bits */
	h ^= h >> 16;
	h *= 0x7feb352dU;
	h ^= h >> 15;
	return h;
}

/* hash -> home page (routing) and preferred home index on that page */
static inline uint32_t mxfs_tauth_home_page(uint32_t hash, uint32_t npages)
{
	return npages ? hash % npages : 0;
}

static inline uint32_t mxfs_tauth_home_index(uint32_t hash, uint32_t npages)
{
	return (npages ? hash / npages : hash) % MXFS_TAUTH_ENTRIES_PER_PAGE;
}

/*
 * Pure validation.  `crc` is the caller's crc32c(seed ~0, data, len) —
 * mxfs_pal_crc32c in the module, the local table in the tools — so this
 * header stays I/O- and platform-free.
 */
typedef uint32_t (*mxfs_tauth_crc_fn)(uint32_t seed, const void *data, size_t len);

static inline uint32_t mxfs_tauth_page_crc(const struct mxfs_tauth_page *pg,
					   mxfs_tauth_crc_fn crc)
{
	struct mxfs_tauth_page_hdr h = pg->hdr;
	uint32_t c;

	h.crc32c = 0;
	c = crc(~0U, &h, sizeof(h));
	c = crc(c, pg->ent, sizeof(pg->ent));
	return c;
}

/* 1 = a committed page of this id for this fs; 0 = not valid (torn, zero,
 * foreign, wrong id, wrong version). */
static inline int mxfs_tauth_page_valid(const struct mxfs_tauth_page *pg,
					uint32_t page_id, uint32_t fs_gen,
					mxfs_tauth_crc_fn crc)
{
	if (pg->hdr.magic != MXFS_TAUTH_PAGE_MAGIC ||
	    pg->hdr.version != MXFS_TAUTH_VERSION ||
	    pg->hdr.nentries != MXFS_TAUTH_ENTRIES_PER_PAGE ||
	    pg->hdr.page_id != page_id ||
	    pg->hdr.fs_gen != fs_gen ||
	    pg->hdr.seq == 0)
		return 0;
	return pg->hdr.crc32c == mxfs_tauth_page_crc(pg, crc);
}

static inline uint32_t mxfs_tauth_ticket_crc(const struct mxfs_tauth_ticket *t,
					     mxfs_tauth_crc_fn crc)
{
	return crc(~0U, t, offsetof(struct mxfs_tauth_ticket, crc32c));
}

/* 1 = a live/abandoned commit ticket of this page for this fs. */
static inline int mxfs_tauth_ticket_valid(const struct mxfs_tauth_ticket *t,
					  uint32_t page_id, uint32_t fs_gen,
					  mxfs_tauth_crc_fn crc)
{
	if (t->magic != MXFS_TAUTH_TICKET_MAGIC || t->version != MXFS_TAUTH_VERSION ||
	    t->page_id != page_id || t->fs_gen != fs_gen)
		return 0;
	return t->crc32c == mxfs_tauth_ticket_crc(t, crc);
}

/* No 4 KiB stack copy (kernel frame limit): crc the bytes before the crc
 * field, four zero bytes in its place, then the bytes after it. */
static inline uint32_t mxfs_tauth_region_crc(const struct mxfs_tauth_region_hdr *rh,
					     mxfs_tauth_crc_fn crc)
{
	const uint32_t zero = 0;
	const size_t before = offsetof(struct mxfs_tauth_region_hdr, crc32c);
	const size_t after = before + sizeof(uint32_t);
	uint32_t c;

	c = crc(~0U, rh, before);
	c = crc(c, &zero, sizeof(zero));
	c = crc(c, (const uint8_t *)rh + after, sizeof(*rh) - after);
	return c;
}

static inline int mxfs_tauth_region_valid(const struct mxfs_tauth_region_hdr *rh,
					  uint32_t fs_gen, mxfs_tauth_crc_fn crc)
{
	if (rh->magic != MXFS_TAUTH_REGION_MAGIC ||
	    rh->version != MXFS_TAUTH_VERSION ||
	    rh->entries_per_page != MXFS_TAUTH_ENTRIES_PER_PAGE ||
	    rh->npages < MXFS_TAUTH_NPAGES_MIN ||
	    rh->npages > MXFS_TAUTH_NPAGES_MAX ||
	    rh->entry_bytes != MXFS_TAUTH_ENTRY_BYTES ||
	    rh->page_bytes != MXFS_TAUTH_PAGE_BYTES ||
	    rh->hash_version != MXFS_TAUTH_HASH_VERSION ||
	    rh->fs_gen != fs_gen ||
	    rh->seq == 0)
		return 0;
	return rh->crc32c == mxfs_tauth_region_crc(rh, crc);
}

/* Fill an EMPTY committed page image (mkfs, and the store's repair path). */
static inline void mxfs_tauth_page_init_empty(struct mxfs_tauth_page *pg,
					      uint32_t page_id, uint32_t fs_gen,
					      const uint8_t fs_uuid[16],
					      uint64_t seq, uint64_t stamp_ms,
					      mxfs_tauth_crc_fn crc)
{
	memset(pg, 0, sizeof(*pg));
	pg->hdr.magic    = MXFS_TAUTH_PAGE_MAGIC;
	pg->hdr.version  = MXFS_TAUTH_VERSION;
	pg->hdr.nentries = MXFS_TAUTH_ENTRIES_PER_PAGE;
	pg->hdr.page_id  = page_id;
	pg->hdr.fs_gen   = fs_gen;
	pg->hdr.seq      = seq;
	pg->hdr.stamp_ms = stamp_ms;
	pg->hdr.grant_seq_next = 1;      /* 0 is never a valid grant_seq64 */
	pg->hdr.transition_seq_next = 1;
	memcpy(pg->hdr.fs_uuid, fs_uuid, 16);
	pg->hdr.crc32c   = mxfs_tauth_page_crc(pg, crc);
}

/* the mkfs ROOT — no committed view, ballot 0, nonce {0, 1}. */
static inline void mxfs_tauth_root_init_empty(struct mxfs_tauth_root *r,
					      uint32_t fs_gen, const uint8_t fs_uuid[16],
					      uint64_t stamp_ms, mxfs_tauth_crc_fn crc)
{
	memset(r, 0, sizeof(*r));
	r->magic     = MXFS_TAUTH_ROOT_MAGIC;
	r->version   = MXFS_TAUTH_ROOT_VERSION;
	r->slot      = MXFS_TAUTH_ROOT_SLOT_NONE;
	r->fs_gen    = fs_gen;
	memcpy(r->fs_uuid, fs_uuid, 16);
	r->stamp_ms  = stamp_ms;
	r->nonce_inc = 0;
	r->nonce_seq = 1;
	r->crc32c    = ~crc(~0u, r, MXFS_TAUTH_ROOT_CRC_OFF);
}

/*
 * — view record / root format helpers (docs/tauth-view-table.md
 * §13; build step 1).  Header-only so the module, mkfs/chk (single TU) and
 * the usermode tests compute the SAME digest/crc/validation.
 */
#include "mxfs_sha256.h"

/* validation verdicts (0 = valid; negative = the FIRST rule that failed) */
#define MXFS_TVIEW_OK               0
#define MXFS_TVIEW_E_MAGIC         -1
#define MXFS_TVIEW_E_VERSION       -2
#define MXFS_TVIEW_E_COUNT         -3
#define MXFS_TVIEW_E_GEN           -4
#define MXFS_TVIEW_E_PREV          -5
#define MXFS_TVIEW_E_IDENTITY      -6   /* fs_gen / fs_uuid */
#define MXFS_TVIEW_E_PAD           -7   /* a reserved/pad byte not zero */
#define MXFS_TVIEW_E_MEMBERS       -8   /* unsorted / duplicate node / dup slot / inc 0 / unused nonzero */
#define MXFS_TVIEW_E_REMOVED       -9   /* nremoved > 32, unsorted, stage range, unused nonzero */
#define MXFS_TVIEW_E_DIGEST       -10
#define MXFS_TVIEW_E_CRC          -11
#define MXFS_TVIEW_E_SLOT         -12   /* root: slot vs gen/digest consistency */
#define MXFS_TVIEW_E_BALLOT       -13   /* root: ballot == UINT64_MAX */
#define MXFS_TVIEW_E_TAIL         -14   /* root: bytes beyond the 512 B payload not zero */

/* recovery-descriptor stage range accepted in removed[].stage (§13.1) */
#define MXFS_TVIEW_STAGE_MIN        6u   /* FENCED */
#define MXFS_TVIEW_STAGE_MAX       15u   /* CONSUMABLE */

static inline int mxfs_tauth_all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i])
			return 0;
	return 1;
}

static inline void mxfs_tauth_view_digest(const struct mxfs_tauth_view *v, uint8_t out[32])
{
	struct mxfs_sha256_ctx c;

	mxfs_sha256_init(&c);
	mxfs_sha256_update(&c, MXFS_TAUTH_VIEW_DOMAIN, MXFS_TAUTH_VIEW_DOMAIN_LEN);
	mxfs_sha256_update(&c, v, MXFS_TAUTH_VIEW_DIGEST_OFF);
	mxfs_sha256_final(&c, out);
}

static inline uint32_t mxfs_tauth_view_crc(const struct mxfs_tauth_view *v, mxfs_tauth_crc_fn crc)
{
	return ~crc(~0u, v, MXFS_TAUTH_VIEW_CRC_OFF);
}

static inline uint32_t mxfs_tauth_root_crc(const struct mxfs_tauth_root *r, mxfs_tauth_crc_fn crc)
{
	return ~crc(~0u, r, MXFS_TAUTH_ROOT_CRC_OFF);
}

static inline void mxfs_tauth_view_seal(struct mxfs_tauth_view *v, mxfs_tauth_crc_fn crc)
{
	mxfs_tauth_view_digest(v, v->digest);
	v->crc32c = mxfs_tauth_view_crc(v, crc);
}

static inline void mxfs_tauth_root_seal(struct mxfs_tauth_root *r, mxfs_tauth_crc_fn crc)
{
	r->crc32c = mxfs_tauth_root_crc(r, crc);
}

static inline int mxfs_tauth_view_validate(const struct mxfs_tauth_view *v, uint32_t fs_gen,
			     const uint8_t fs_uuid[16], mxfs_tauth_crc_fn crc)
{
	uint8_t d[32];
	unsigned i;

	if (v->magic != MXFS_TAUTH_VIEW_MAGIC)
		return MXFS_TVIEW_E_MAGIC;
	if (v->version != MXFS_TAUTH_VIEW_VERSION)
		return MXFS_TVIEW_E_VERSION;
	/* crc first: everything below reads fields the crc protects */
	if (v->crc32c != mxfs_tauth_view_crc(v, crc))
		return MXFS_TVIEW_E_CRC;
	if (v->count < 1 || v->count > MXFS_TAUTH_VIEW_MEMBERS)
		return MXFS_TVIEW_E_COUNT;
	if (v->gen == 0)
		return MXFS_TVIEW_E_GEN;
	if (v->prev_gen != v->gen - 1)
		return MXFS_TVIEW_E_PREV;
	if (v->gen == 1 && !mxfs_tauth_all_zero(v->prev_digest, 32))
		return MXFS_TVIEW_E_PREV;
	if (v->fs_gen != fs_gen || memcmp(v->fs_uuid, fs_uuid, 16) != 0)
		return MXFS_TVIEW_E_IDENTITY;
	if (v->pad0 || v->pad1 || !mxfs_tauth_all_zero(v->pad2, sizeof(v->pad2)) ||
	    !mxfs_tauth_all_zero(v->reserved, sizeof(v->reserved)) ||
	    !mxfs_tauth_all_zero(v->reserved2, sizeof(v->reserved2)) || v->pad_end)
		return MXFS_TVIEW_E_PAD;
	for (i = 0; i < MXFS_TAUTH_VIEW_MEMBERS; i++) {
		const struct mxfs_tauth_member *m = &v->member[i];
		unsigned j;

		if (i >= v->count) {
			if (m->node || m->slot || m->pad || m->inc)
				return MXFS_TVIEW_E_MEMBERS;
			continue;
		}
		if (m->pad || m->inc == 0 || m->node == 0 || m->slot >= 64)
			return MXFS_TVIEW_E_MEMBERS;
		if (i && m->node <= v->member[i - 1].node)
			return MXFS_TVIEW_E_MEMBERS;         /* sorted, unique nodes */
		for (j = 0; j < i; j++)
			if (v->member[j].slot == m->slot)
				return MXFS_TVIEW_E_MEMBERS;     /* unique slots */
	}
	if (v->nremoved > MXFS_TAUTH_VIEW_REMOVED)
		return MXFS_TVIEW_E_REMOVED;
	for (i = 0; i < MXFS_TAUTH_VIEW_REMOVED; i++) {
		const struct mxfs_tauth_removed *r = &v->removed[i];

		if (i >= v->nremoved) {
			if (!mxfs_tauth_all_zero((const uint8_t *)r, sizeof(*r)))
				return MXFS_TVIEW_E_REMOVED;
			continue;
		}
		if (r->pad || r->inc == 0 || r->slot >= 64 ||
		    r->stage < MXFS_TVIEW_STAGE_MIN || r->stage > MXFS_TVIEW_STAGE_MAX)
			return MXFS_TVIEW_E_REMOVED;
		if (i && r->slot <= v->removed[i - 1].slot)
			return MXFS_TVIEW_E_REMOVED;         /* sorted, unique slots */
	}
	mxfs_tauth_view_digest(v, d);
	if (memcmp(d, v->digest, 32) != 0)
		return MXFS_TVIEW_E_DIGEST;
	return MXFS_TVIEW_OK;
}

static inline int mxfs_tauth_root_validate(const void *img, size_t img_len, uint32_t fs_gen,
			     const uint8_t fs_uuid[16], mxfs_tauth_crc_fn crc)
{
	const struct mxfs_tauth_root *r = img;

	if (img_len < MXFS_TAUTH_ROOT_BYTES)
		return MXFS_TVIEW_E_TAIL;
	if (r->magic != MXFS_TAUTH_ROOT_MAGIC)
		return MXFS_TVIEW_E_MAGIC;
	if (r->version != MXFS_TAUTH_ROOT_VERSION)
		return MXFS_TVIEW_E_VERSION;
	if (r->crc32c != mxfs_tauth_root_crc(r, crc))
		return MXFS_TVIEW_E_CRC;
	if (r->fs_gen != fs_gen || memcmp(r->fs_uuid, fs_uuid, 16) != 0)
		return MXFS_TVIEW_E_IDENTITY;
	if (r->pad0 || r->pad1 || !mxfs_tauth_all_zero(r->reserved, sizeof(r->reserved)) ||
	    r->pad_end)
		return MXFS_TVIEW_E_PAD;
	if (img_len > MXFS_TAUTH_ROOT_BYTES &&
	    !mxfs_tauth_all_zero((const uint8_t *)img + MXFS_TAUTH_ROOT_BYTES,
		      img_len - MXFS_TAUTH_ROOT_BYTES))
		return MXFS_TVIEW_E_TAIL;
	if (r->gen == 0) {
		if (r->slot != MXFS_TAUTH_ROOT_SLOT_NONE || !mxfs_tauth_all_zero(r->digest, 32))
			return MXFS_TVIEW_E_SLOT;
	} else {
		if ((r->slot != MXFS_TAUTH_CTRL_VIEW_A && r->slot != MXFS_TAUTH_CTRL_VIEW_B) ||
		    mxfs_tauth_all_zero(r->digest, 32))
			return MXFS_TVIEW_E_SLOT;
	}
	if (r->coord_ballot == ~0ULL)
		return MXFS_TVIEW_E_BALLOT;
	if (r->coord_node == 0 && (r->coord_inc || r->coord_ballot))
		return MXFS_TVIEW_E_BALLOT;
	return MXFS_TVIEW_OK;
}

static inline int mxfs_tauth_ctrl_validate(const struct mxfs_tauth_root *root,
			     const struct mxfs_tauth_view *a,
			     const struct mxfs_tauth_view *b,
			     uint32_t fs_gen, const uint8_t fs_uuid[16],
			     mxfs_tauth_crc_fn crc,
			     const struct mxfs_tauth_view **committed,
			     int *other_kind)
{
	const struct mxfs_tauth_view *c = NULL, *o;
	int rc, va, vb;

	if (committed)
		*committed = NULL;
	if (other_kind)
		*other_kind = 0;
	rc = mxfs_tauth_root_validate(root, MXFS_TAUTH_ROOT_BYTES, fs_gen, fs_uuid, crc);
	if (rc)
		return rc;
	va = mxfs_tauth_view_validate(a, fs_gen, fs_uuid, crc);
	vb = mxfs_tauth_view_validate(b, fs_gen, fs_uuid, crc);
	if (root->gen == 0) {
		/* no committed view: each slot is empty (all-zero page) or a
		 * gen-1 proposal */
		const struct mxfs_tauth_view *s[2] = { a, b };
		int v[2] = { va, vb };
		int i;

		for (i = 0; i < 2; i++) {
			if (mxfs_tauth_all_zero((const uint8_t *)s[i], sizeof(*s[i])))
				continue;
			if (v[i] == MXFS_TVIEW_OK && s[i]->gen == 1) {
				if (other_kind)
					*other_kind = 2;
				continue;
			}
			return MXFS_TVIEW_E_SLOT;
		}
		return MXFS_TVIEW_OK;
	}
	c = (root->slot == MXFS_TAUTH_CTRL_VIEW_A) ? a : b;
	o = (root->slot == MXFS_TAUTH_CTRL_VIEW_A) ? b : a;
	if (((root->slot == MXFS_TAUTH_CTRL_VIEW_A) ? va : vb) != MXFS_TVIEW_OK)
		return MXFS_TVIEW_E_SLOT;
	if (c->gen != root->gen || memcmp(c->digest, root->digest, 32) != 0)
		return MXFS_TVIEW_E_SLOT;
	if (committed)
		*committed = c;
	if (mxfs_tauth_all_zero((const uint8_t *)o, sizeof(*o)))
		return MXFS_TVIEW_OK;
	if (((root->slot == MXFS_TAUTH_CTRL_VIEW_A) ? vb : va) != MXFS_TVIEW_OK)
		return MXFS_TVIEW_E_SLOT;
	if (o->gen < root->gen) {
		if (other_kind)
			*other_kind = 1;
		return MXFS_TVIEW_OK;
	}
	if (o->gen == root->gen + 1 && memcmp(o->prev_digest, root->digest, 32) == 0) {
		if (other_kind)
			*other_kind = 2;
		return MXFS_TVIEW_OK;
	}
	return MXFS_TVIEW_E_SLOT;
}

static inline uint64_t mxfs_tauth_root_next_ballot(const struct mxfs_tauth_root *root)
{
	if (root->coord_ballot >= ~0ULL - 1)
		return 0;
	return root->coord_ballot + 1;
}

static inline uint64_t mxfs_tauth_mix64(uint64_t x)
{
	uint64_t z = x + 0x9E3779B97F4A7C15ULL;

	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

static inline int mxfs_tauth_view_owner_index(const struct mxfs_tauth_view *v, uint32_t page)
{
	int best = -1;
	uint64_t best_score = 0;
	unsigned i;

	for (i = 0; i < v->count && i < MXFS_TAUTH_VIEW_MEMBERS; i++) {
		uint64_t s = mxfs_tauth_mix64(((uint64_t)page << 16) | (uint64_t)v->member[i].slot);

		if (best < 0 || s > best_score ||
		    (s == best_score && v->member[i].slot < v->member[best].slot)) {
			best = (int)i;
			best_score = s;
		}
	}
	return best;
}


/* Format-time geometry: npages in [MIN, MAX]; seed folded into every hash. */
static inline void mxfs_tauth_region_init(struct mxfs_tauth_region_hdr *rh,
					  uint32_t fs_gen, const uint8_t fs_uuid[16],
					  uint32_t npages, uint64_t hash_seed,
					  uint64_t stamp_ms, mxfs_tauth_crc_fn crc)
{
	memset(rh, 0, sizeof(*rh));
	rh->magic            = MXFS_TAUTH_REGION_MAGIC;
	rh->version          = MXFS_TAUTH_VERSION;
	rh->entries_per_page = MXFS_TAUTH_ENTRIES_PER_PAGE;
	rh->npages           = npages;
	rh->hash_version     = MXFS_TAUTH_HASH_VERSION;
	rh->hash_seed        = hash_seed;
	rh->entry_bytes      = MXFS_TAUTH_ENTRY_BYTES;
	rh->page_bytes       = MXFS_TAUTH_PAGE_BYTES;
	rh->fs_gen           = fs_gen;
	memcpy(rh->fs_uuid, fs_uuid, 16);
	rh->seq              = 1;
	rh->format_stamp_ms  = stamp_ms;
	rh->crc32c           = mxfs_tauth_region_crc(rh, crc);
}

#endif /* MXFS_TAUTH_H */
