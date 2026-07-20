/*
 * MXFS — Multinode XFS
 * NET2 transport — outer wire format (v1)
 *
 * NET2 wraps the unchanged 32-byte inner mxfs_dlm_msg_hdr (+ body) as an
 * opaque payload behind a 64-byte outer header.  Everything here is
 * little-endian ON THE WIRE and is packed/unpacked FIELD BY FIELD via the
 * pal.h byteorder helpers — the in-memory struct below is ordered for
 * natural alignment (and is itself exactly 64 bytes, asserted), but it is
 * NOT the wire image: mxfs_net2_hdr_pack()/_unpack() are the format
 * authority.  Never memcpy the struct to/from a socket.
 *
 * Wire layout (offsets in bytes, total MXFS_NET2_HDR_SIZE = 64):
 *
 *   off size field                 off size field
 *    0   4  magic                   24   2  src_slot
 *    4   1  version                 26   2  dst_slot
 *    5   1  frame_class             28   4  src_incarnation
 *    6   1  priority                32   4  dst_incarnation
 *    7   1  flags                   36   8  seq
 *    8   1  ttl                     44   8  ack
 *    9   1  hopcount                52   4  sack_mask
 *   10   2  payload_len             56   4  msg_id
 *   12   4  cluster_uuid_hash       60   4  pad (must be 0)
 *   16   8  membership_epoch
 *
 * Framing per link: read 64 bytes, validate, read payload_len bytes.
 * payload_len <= MXFS_NET2_MAX_MSG_SIZE (8192); no fragmentation — larger
 * frames are rejected.  (8192 matches peer.c's private
 * MXFS_PEER_MAX_MSG_SIZE; the copies merge at §11 step 12.)
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_NET2_WIRE_H
#define MXFS_LIBMXFS_NET2_WIRE_H

#include "../pal/pal.h"

#define MXFS_NET2_MAGIC         0x4E455432u   /* "NET2" */
#define MXFS_NET2_WIRE_VERSION  1

#define MXFS_NET2_HDR_SIZE      64
#define MXFS_NET2_MAX_MSG_SIZE  8192
#define MXFS_NET2_MAX_FRAME     (MXFS_NET2_HDR_SIZE + MXFS_NET2_MAX_MSG_SIZE)

/* frame_class */
enum mxfs_net2_frame_class {
	MXFS_NET2_FC_DATA    = 0,
	MXFS_NET2_FC_ACK     = 1,   /* standalone ACK (unreliable) */
	MXFS_NET2_FC_SYN     = 2,   /* session establish, carries TLV block */
	MXFS_NET2_FC_SYN_ACK = 3,   /* session accept, carries TLV block */
	MXFS_NET2_FC_FIN     = 4,   /* orderly session teardown */
	MXFS_NET2_FC_COUNT
};

/* flags */
#define MXFS_NET2_F_RELIABLE  (1u << 0)  /* in a session's seq space; ACKed */
#define MXFS_NET2_F_ACKREQ    (1u << 1)  /* sender requests immediate ACK */
#define MXFS_NET2_F_RELAYED   (1u << 2)  /* traversed >=1 overlay relay */
#define MXFS_NET2_F_ALL       (MXFS_NET2_F_RELIABLE | MXFS_NET2_F_ACKREQ | \
                               MXFS_NET2_F_RELAYED)

/* Wire-protocol fact (not an implementation choice): 5 priority classes.
 * The scheduler enum in net2.h must match — cross-asserted there. */
#define MXFS_NET2_WIRE_PRI_COUNT  5

/*
 * In-memory header.  Field ORDER here is alignment-driven (u64 -> u32 ->
 * u16 -> u8) so the struct is naturally packed to exactly 64 bytes with
 * no compiler padding; the WIRE order is the offset table above.
 */
struct mxfs_net2_hdr {
	uint64_t membership_epoch;
	uint64_t seq;
	uint64_t ack;
	uint32_t magic;
	uint32_t cluster_uuid_hash;
	uint32_t src_incarnation;
	uint32_t dst_incarnation;
	uint32_t sack_mask;          /* 32 slots past cumulative ack */
	uint32_t msg_id;             /* NET2-allocated per-session counter */
	uint32_t pad;                /* reserved; MUST be zero on the wire */
	uint16_t payload_len;        /* bytes following the 64-byte header */
	uint16_t src_slot;
	uint16_t dst_slot;
	uint8_t  version;
	uint8_t  frame_class;        /* enum mxfs_net2_frame_class */
	uint8_t  priority;           /* enum net2_priority (net2.h) */
	uint8_t  flags;              /* MXFS_NET2_F_* */
	uint8_t  ttl;                /* overlay only; 0 on mesh */
	uint8_t  hopcount;           /* overlay only; incremented per relay */
};

_Static_assert(sizeof(struct mxfs_net2_hdr) == MXFS_NET2_HDR_SIZE,
               "mxfs_net2_hdr must be exactly 64 bytes");
_Static_assert(MXFS_NET2_MAX_FRAME == 8256,
               "net2 max frame is header + max msg");

/* ─── Unaligned little-endian accessors (wire buffer side) ─── */

static inline void mxfs_net2_put_le16(uint8_t *p, uint16_t v)
{
	v = mxfs_cpu_to_le16(v);
	__builtin_memcpy(p, &v, 2);
}
static inline void mxfs_net2_put_le32(uint8_t *p, uint32_t v)
{
	v = mxfs_cpu_to_le32(v);
	__builtin_memcpy(p, &v, 4);
}
static inline void mxfs_net2_put_le64(uint8_t *p, uint64_t v)
{
	v = mxfs_cpu_to_le64(v);
	__builtin_memcpy(p, &v, 8);
}
static inline uint16_t mxfs_net2_get_le16(const uint8_t *p)
{
	uint16_t v;
	__builtin_memcpy(&v, p, 2);
	return mxfs_le16_to_cpu(v);
}
static inline uint32_t mxfs_net2_get_le32(const uint8_t *p)
{
	uint32_t v;
	__builtin_memcpy(&v, p, 4);
	return mxfs_le32_to_cpu(v);
}
static inline uint64_t mxfs_net2_get_le64(const uint8_t *p)
{
	uint64_t v;
	__builtin_memcpy(&v, p, 8);
	return mxfs_le64_to_cpu(v);
}

/* ─── Pack / unpack (the wire-format authority) ─── */

static inline void mxfs_net2_hdr_pack(const struct mxfs_net2_hdr *h,
                                      uint8_t buf[MXFS_NET2_HDR_SIZE])
{
	mxfs_net2_put_le32(buf +  0, h->magic);
	buf[4] = h->version;
	buf[5] = h->frame_class;
	buf[6] = h->priority;
	buf[7] = h->flags;
	buf[8] = h->ttl;
	buf[9] = h->hopcount;
	mxfs_net2_put_le16(buf + 10, h->payload_len);
	mxfs_net2_put_le32(buf + 12, h->cluster_uuid_hash);
	mxfs_net2_put_le64(buf + 16, h->membership_epoch);
	mxfs_net2_put_le16(buf + 24, h->src_slot);
	mxfs_net2_put_le16(buf + 26, h->dst_slot);
	mxfs_net2_put_le32(buf + 28, h->src_incarnation);
	mxfs_net2_put_le32(buf + 32, h->dst_incarnation);
	mxfs_net2_put_le64(buf + 36, h->seq);
	mxfs_net2_put_le64(buf + 44, h->ack);
	mxfs_net2_put_le32(buf + 52, h->sack_mask);
	mxfs_net2_put_le32(buf + 56, h->msg_id);
	mxfs_net2_put_le32(buf + 60, h->pad);
}

static inline void mxfs_net2_hdr_unpack(const uint8_t buf[MXFS_NET2_HDR_SIZE],
                                        struct mxfs_net2_hdr *h)
{
	h->magic             = mxfs_net2_get_le32(buf +  0);
	h->version           = buf[4];
	h->frame_class       = buf[5];
	h->priority          = buf[6];
	h->flags             = buf[7];
	h->ttl               = buf[8];
	h->hopcount          = buf[9];
	h->payload_len       = mxfs_net2_get_le16(buf + 10);
	h->cluster_uuid_hash = mxfs_net2_get_le32(buf + 12);
	h->membership_epoch  = mxfs_net2_get_le64(buf + 16);
	h->src_slot          = mxfs_net2_get_le16(buf + 24);
	h->dst_slot          = mxfs_net2_get_le16(buf + 26);
	h->src_incarnation   = mxfs_net2_get_le32(buf + 28);
	h->dst_incarnation   = mxfs_net2_get_le32(buf + 32);
	h->seq               = mxfs_net2_get_le64(buf + 36);
	h->ack               = mxfs_net2_get_le64(buf + 44);
	h->sack_mask         = mxfs_net2_get_le32(buf + 52);
	h->msg_id            = mxfs_net2_get_le32(buf + 56);
	h->pad               = mxfs_net2_get_le32(buf + 60);
}

/* ─── Structural validation (session/link semantics live above this) ─── */

enum mxfs_net2_hdr_err {
	MXFS_NET2_HDR_OK = 0,
	MXFS_NET2_HDR_EMAGIC,
	MXFS_NET2_HDR_EVERSION,
	MXFS_NET2_HDR_ECLASS,
	MXFS_NET2_HDR_EPRIORITY,
	MXFS_NET2_HDR_ELEN,
	MXFS_NET2_HDR_EFLAGS,
	MXFS_NET2_HDR_EPAD,
};

static inline enum mxfs_net2_hdr_err
mxfs_net2_hdr_validate(const struct mxfs_net2_hdr *h)
{
	if (h->magic != MXFS_NET2_MAGIC)
		return MXFS_NET2_HDR_EMAGIC;
	if (h->version != MXFS_NET2_WIRE_VERSION)
		return MXFS_NET2_HDR_EVERSION;
	if (h->frame_class >= MXFS_NET2_FC_COUNT)
		return MXFS_NET2_HDR_ECLASS;
	if (h->priority >= MXFS_NET2_WIRE_PRI_COUNT)
		return MXFS_NET2_HDR_EPRIORITY;
	if (h->payload_len > MXFS_NET2_MAX_MSG_SIZE)
		return MXFS_NET2_HDR_ELEN;
	if (h->flags & (uint8_t)~MXFS_NET2_F_ALL)
		return MXFS_NET2_HDR_EFLAGS;
	if (h->pad != 0)
		return MXFS_NET2_HDR_EPAD;
	return MXFS_NET2_HDR_OK;
}

/* ─── SYN / SYN_ACK TLV block ───
 *
 * The SYN payload is a sequence of {type u16, len u16, value[len]} records,
 * all little-endian, no alignment padding between records.  Unknown types
 * are skipped (forward compatibility); the REQUIRED set for a valid SYN is
 * UUID + VOLUME_ID + FS_GEN + NONCE + FEATURES + WIRE_VER — session
 * establishment rejects a SYN missing any of them (fail-closed).
 */

#define MXFS_NET2_TLV_HDR_SIZE 4

enum mxfs_net2_tlv_type {
	MXFS_NET2_TLV_UUID      = 1,   /* 16 B full cluster UUID            */
	MXFS_NET2_TLV_VOLUME_ID = 2,   /* u32                               */
	MXFS_NET2_TLV_FS_GEN    = 3,   /* u32                               */
	MXFS_NET2_TLV_NONCE     = 4,   /* u64 per-boot session nonce        */
	MXFS_NET2_TLV_FEATURES  = 5,   /* u32 MXFS_NET2_FEAT_*              */
	MXFS_NET2_TLV_WIRE_VER  = 6,   /* u16 highest supported wire version */
};

#define MXFS_NET2_FEAT_MEMBFENCE  (1u << 0)
#define MXFS_NET2_FEAT_BAST_WAKE  (1u << 1)
#define MXFS_NET2_FEAT_ENVELOPE   (1u << 2)

/* Append one TLV; returns new offset or -1 if it would overflow cap. */
static inline int mxfs_net2_tlv_put(uint8_t *buf, int cap, int off,
                                    uint16_t type, const void *val,
                                    uint16_t len)
{
	if (off < 0 || off + MXFS_NET2_TLV_HDR_SIZE + len > cap)
		return -1;
	mxfs_net2_put_le16(buf + off, type);
	mxfs_net2_put_le16(buf + off + 2, len);
	__builtin_memcpy(buf + off + MXFS_NET2_TLV_HDR_SIZE, val, len);
	return off + MXFS_NET2_TLV_HDR_SIZE + len;
}

/*
 * Iterate: *off advances past the returned record.  Returns 1 and fills
 * type/len/val while records remain, 0 at clean end, -1 on truncation
 * (a record extending past the block = malformed SYN, reject).
 */
static inline int mxfs_net2_tlv_next(const uint8_t *buf, int cap, int *off,
                                     uint16_t *type, uint16_t *len,
                                     const uint8_t **val)
{
	if (*off == cap)
		return 0;
	if (*off < 0 || *off + MXFS_NET2_TLV_HDR_SIZE > cap)
		return -1;
	*type = mxfs_net2_get_le16(buf + *off);
	*len  = mxfs_net2_get_le16(buf + *off + 2);
	if (*off + MXFS_NET2_TLV_HDR_SIZE + *len > cap)
		return -1;
	*val = buf + *off + MXFS_NET2_TLV_HDR_SIZE;
	*off += MXFS_NET2_TLV_HDR_SIZE + *len;
	return 1;
}

#endif /* MXFS_LIBMXFS_NET2_WIRE_H */
