/*
 * MXFS — Multinode XFS
 * NET2 lock plane — message formats (§11 step 4, DLM_PLAN.md §6/§7.B)
 *
 * Lock-plane payloads ride inside NET2 DATA frames as the (otherwise
 * opaque) payload.  They are distinguished from the legacy inner
 * `mxfs_dlm_msg_hdr` (magic "MXFS", 0x4D584653) by their own leading
 * magic "N2LK" — the step-7 seam dispatch reads the first 4 bytes and
 * routes.  Everything is little-endian ON THE WIRE, packed/unpacked
 * field by field with the net2_wire.h helpers — never memcpy'd.
 *
 * Operation identity (§6): every mutating op carries
 * {requester slot+incarnation, request_id u64, resource_id,
 * membership_epoch, shard_term} in the envelope + body.  The midcomms
 * msg_id dedup is a delivery optimization only; EFFECT idempotency
 * lives in the shard's replicated completed-op cache keyed by
 * (requester slot, incarnation, request_id).
 *
 * Envelope wire layout (MXFS_N2MSG_HDR_SIZE = 40):
 *
 *   off size field            off size field
 *    0   4  magic "N2LK"       16   4  shard_term
 *    4   2  type               20   4  shard_id
 *    6   2  flags              24   2  req_slot
 *    8   8  membership_epoch   26   2  pad (0)
 *                              28   4  req_incarnation
 *                              32   8  request_id
 *
 * The resource_id wire image (MXFS_N2MSG_RES_SIZE = 32) mirrors
 * struct mxfs_resource_id field by field:
 *   0 8 volume | 8 8 ino | 16 8 offset | 24 4 ag_number | 28 1 type |
 *   29 3 pad (0)
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_LIBMXFS_NET2_MSG_H
#define MXFS_LIBMXFS_NET2_MSG_H

#include "net2_wire.h"
#include "../include/mxfs/mxfs_common.h"

#define MXFS_N2MSG_MAGIC     0x4E324C4Bu   /* "N2LK" (legacy inner = "MXFS") */
#define MXFS_N2MSG_HDR_SIZE  40
#define MXFS_N2MSG_RES_SIZE  32

/* Message types (envelope.type). */
enum mxfs_n2msg_type {
	N2_ACQUIRE         = 1,   /* client -> leader: acquire/convert       */
	N2_GRANT           = 2,   /* leader -> client: committed grant       */
	N2_DENY            = 3,   /* leader/replica -> client: see reason    */
	N2_RELEASE         = 4,   /* client -> leader: gen-qualified release */
	N2_RELEASE_ACK     = 5,   /* leader -> client: committed (or ESTALE) */
	N2_BAST            = 6,   /* leader -> holder: revoke callback       */
	N2_APPEND          = 7,   /* leader -> replica: log entry            */
	N2_APPEND_ACK      = 8,   /* replica -> leader: ack/nack + last_seq  */
	N2_TERM_VOTE       = 9,   /* candidate <-> voter (VOTE_GRANT flag)   */
	N2_TERM_COMMIT     = 10,  /* reserved (barrier rides N2_APPEND)      */
	N2_SNAPSHOT_REQ    = 11,  /* transferee -> source                    */
	N2_SNAPSHOT_CHUNK  = 12,  /* source -> transferee                    */
	N2_RECOVERY_REPORT = 13,  /* leader -> all members; REPLY flag back  */
	N2_CAUGHT_UP       = 14,  /* reserved (rides the log as N2L entry)   */
	N2_MEPOCH_PROPOSE  = 15,  /* proposer -> voters of E (§7.C)          */
	N2_MEPOCH_ACK      = 16,  /* voter -> proposer: PREPARED + ack/nack  */
	N2_MEPOCH_COMMIT   = 17,  /* proposer -> all members of E ∪ E+1      */
	N2_MSG_TYPE_COUNT
};

/* Envelope flags. */
#define N2F_VOTE_GRANT    (1u << 0)  /* N2_TERM_VOTE: this is the grant     */
#define N2F_REPLY         (1u << 1)  /* N2_RECOVERY_REPORT: member's reply  */
#define N2F_FROM_WAITQ    (1u << 2)  /* N2_GRANT: satisfied a queued waiter */

/* N2_DENY reasons (body.status). */
enum mxfs_n2msg_deny {
	N2D_NOT_LEADER  = 1,   /* leader_hint carries the known leader     */
	N2D_STALE_TERM  = 2,
	N2D_STALE_EPOCH = 3,
	N2D_RETRY       = 4,   /* electing / transferring / frozen — retry */
	N2D_STALE_GEN   = 5,   /* gen-qualified release missed its tenure  */
};

/* Replicated log entry ops (N2_APPEND body.op — §7.B: the lock table,
 * waiter queue and completed-op cache mutate ONLY via committed
 * entries, so fairness order and idempotent results survive failover). */
enum mxfs_n2log_op {
	N2L_TERM       = 1,   /* election/reconfig barrier                  */
	N2L_GRANT      = 2,   /* make requester a holder (gen assigned)     */
	N2L_WAIT       = 3,   /* append requester to the replicated waitq   */
	N2L_RELEASE    = 4,   /* clear requester's holder bit (gen checked) */
	N2L_EX_PENDING = 5,   /* mark pending_revoke_mask + queue EX waiter */
	N2L_CAUGHT_UP  = 6,   /* replica finished state transfer            */
	N2L_REBUILD    = 7,   /* reserved (recovery installs via snapshot)  */
	N2L_OP_COUNT
};

/*
 * In-memory message view.  pack/unpack below are the wire authority;
 * bodies are unions over the type-specific fields.
 */
struct mxfs_n2msg {
	uint16_t type;
	uint16_t flags;
	uint64_t membership_epoch;
	uint32_t shard_term;
	uint32_t shard_id;
	uint16_t req_slot;
	uint32_t req_inc;
	uint64_t request_id;

	struct mxfs_resource_id resource;   /* valid where the body has it */
	uint8_t  mode;
	uint8_t  status;                    /* grant status / deny reason  */
	uint16_t leader_hint;               /* N2_DENY(NOT_LEADER)         */
	uint64_t grant_gen;
	uint64_t dir_epoch;

	/* N2_APPEND / N2_APPEND_ACK */
	uint16_t op;                        /* enum mxfs_n2log_op          */
	uint64_t entry_seq;
	uint64_t commit_watermark;
	uint32_t entry_term;                /* APPEND: entry's ORIGIN term
	                                     * (envelope shard_term is the
	                                     * leader's current term)      */
	uint8_t  ack_ok;                    /* APPEND_ACK: 1 ack, 0 nack   */
	uint64_t last_seq;                  /* APPEND_ACK: replica's last  */

	/* N2_TERM_VOTE */
	uint32_t cand_term;
	uint64_t cand_commit_seq;
	uint64_t cand_last_seq;

	/* N2_SNAPSHOT_REQ/CHUNK + N2_RECOVERY_REPORT reply */
	uint32_t chunk_idx;
	uint32_t chunk_count;
	uint32_t rec_count;                 /* records in chunk/reply      */
	uint32_t log_count;                 /* CHUNK: trailing log records */

	/* N2_MEPOCH_* (§7.C single-decree; ack/nack rides ack_ok+status) */
	uint64_t mep_epoch;                 /* candidate epoch             */
	uint64_t mep_member;
	uint64_t mep_fenced;
	uint64_t mep_fence_ok;              /* slots w/ fence_done proof   */
	uint16_t mep_voters[3];             /* candidate's committing set  */
	uint16_t mep_flags;                 /* MXFS_MEPOCH_F_*             */
	uint32_t mep_incs[MXFS_MAX_NODES];  /* slot -> incarnation table   */
};

/* ─── low-level: resource id ─── */

static inline void mxfs_n2msg_res_pack(const struct mxfs_resource_id *r,
                                       uint8_t buf[MXFS_N2MSG_RES_SIZE])
{
	mxfs_net2_put_le64(buf + 0, r->volume);
	mxfs_net2_put_le64(buf + 8, r->ino);
	mxfs_net2_put_le64(buf + 16, r->offset);
	mxfs_net2_put_le32(buf + 24, r->ag_number);
	buf[28] = r->type;
	buf[29] = 0; buf[30] = 0; buf[31] = 0;
}

static inline void mxfs_n2msg_res_unpack(const uint8_t buf[MXFS_N2MSG_RES_SIZE],
                                         struct mxfs_resource_id *r)
{
	r->volume = mxfs_net2_get_le64(buf + 0);
	r->ino = mxfs_net2_get_le64(buf + 8);
	r->offset = mxfs_net2_get_le64(buf + 16);
	r->ag_number = mxfs_net2_get_le32(buf + 24);
	r->type = buf[28];
	r->pad[0] = 0; r->pad[1] = 0; r->pad[2] = 0;
}

/* ─── envelope ─── */

static inline void mxfs_n2msg_hdr_pack(const struct mxfs_n2msg *m,
                                       uint8_t buf[MXFS_N2MSG_HDR_SIZE])
{
	mxfs_net2_put_le32(buf + 0, MXFS_N2MSG_MAGIC);
	mxfs_net2_put_le16(buf + 4, m->type);
	mxfs_net2_put_le16(buf + 6, m->flags);
	mxfs_net2_put_le64(buf + 8, m->membership_epoch);
	mxfs_net2_put_le32(buf + 16, m->shard_term);
	mxfs_net2_put_le32(buf + 20, m->shard_id);
	mxfs_net2_put_le16(buf + 24, m->req_slot);
	mxfs_net2_put_le16(buf + 26, 0);
	mxfs_net2_put_le32(buf + 28, m->req_inc);
	mxfs_net2_put_le64(buf + 32, m->request_id);
}

/* Returns 0 on success, -EINVAL if this is not an N2LK envelope. */
static inline int mxfs_n2msg_hdr_unpack(const uint8_t *buf, uint32_t len,
                                        struct mxfs_n2msg *m)
{
	if (len < MXFS_N2MSG_HDR_SIZE)
		return -EINVAL;
	if (mxfs_net2_get_le32(buf + 0) != MXFS_N2MSG_MAGIC)
		return -EINVAL;
	memset(m, 0, sizeof(*m));
	m->type = mxfs_net2_get_le16(buf + 4);
	m->flags = mxfs_net2_get_le16(buf + 6);
	m->membership_epoch = mxfs_net2_get_le64(buf + 8);
	m->shard_term = mxfs_net2_get_le32(buf + 16);
	m->shard_id = mxfs_net2_get_le32(buf + 20);
	m->req_slot = mxfs_net2_get_le16(buf + 24);
	m->req_inc = mxfs_net2_get_le32(buf + 28);
	m->request_id = mxfs_net2_get_le64(buf + 32);
	return 0;
}

/* Cheap payload sniff for the recv dispatch (step 7 seam + harness). */
static inline bool mxfs_n2msg_is_lockplane(const void *payload, uint32_t len)
{
	return len >= 4 &&
	       mxfs_net2_get_le32((const uint8_t *)payload) == MXFS_N2MSG_MAGIC;
}

/*
 * ─── bodies ───
 *
 * Body wire layouts by type (offsets AFTER the 40-byte envelope):
 *
 * N2_ACQUIRE:      0 32 resource | 32 1 mode | 33 3 pad          (36)
 * N2_GRANT:        0 32 resource | 32 1 mode | 33 1 status |
 *                  34 2 pad | 36 8 grant_gen | 44 8 dir_epoch    (52)
 * N2_DENY:         0 32 resource | 32 1 mode | 33 1 status(deny) |
 *                  34 2 leader_hint                              (36)
 * N2_RELEASE:      0 32 resource | 32 1 mode | 33 3 pad |
 *                  36 8 grant_gen                                (44)
 * N2_RELEASE_ACK:  0 32 resource | 32 1 status | 33 3 pad |
 *                  36 8 grant_gen                                (44)
 * N2_BAST:         0 32 resource | 32 1 mode(wanted) | 33 3 pad |
 *                  36 8 grant_gen                                (44)
 * N2_APPEND:       0 2 op | 2 2 pad | 4 8 entry_seq |
 *                  12 8 commit_watermark | 20 32 resource |
 *                  52 1 mode | 53 3 pad | 56 8 grant_gen |
 *                  64 8 dir_epoch | 72 4 entry_term              (76)
 *                  (entry requester/request_id ride the envelope;
 *                  envelope shard_term = LEADER's current term,
 *                  entry_term = the entry's ORIGIN term — a
 *                  backfilled prior-term entry keeps its origin
 *                  term while the frame proves current authority)
 * N2_APPEND_ACK:   0 8 entry_seq | 8 1 ack_ok | 9 3 pad |
 *                  12 8 last_seq | 20 8 commit_watermark         (28)
 * N2_TERM_VOTE:    0 4 cand_term | 4 8 cand_commit_seq |
 *                  12 8 cand_last_seq                            (20)
 * N2_SNAPSHOT_REQ: 0 8 from_seq(=entry_seq)                      (8)
 * N2_SNAPSHOT_CHUNK:
 *                  0 8 base(=entry_seq) | 8 8 src_last(=last_seq) |
 *                  16 4 chunk_idx | 20 4 chunk_count |
 *                  24 4 rec_count | 28 4 log_count |
 *                  then rec_count × snapshot records, then
 *                  log_count × log records (both below)          (32+)
 *                  base/src_last ride EVERY chunk: chunk0's pair is
 *                  the source's completeness vote (§7.B max-wins
 *                  collection); log records are the source's
 *                  UNAPPLIED suffix (commit+1..last) — the pulling
 *                  leader inherits it and its barrier re-commits
 *                  (leader completeness survives the transfer).
 * N2_RECOVERY_REPORT reply:
 *                  0 4 chunk_idx | 4 4 chunk_count |
 *                  8 4 rec_count | 12 4 pad | then rec_count ×
 *                  snapshot records (below)                      (16+)
 * N2_RECOVERY_REPORT request: empty body                         (0)
 *
 * Snapshot/report record (MXFS_N2MSG_SNAPREC_SIZE = 64):
 *   0 32 resource | 32 1 kind | 33 1 mode | 34 2 slot |
 *   36 4 inc | 40 8 gen_or_enqseq | 48 8 request_id | 56 8 aux
 * Field use by kind:
 *   N2SR_HOLDERS  one per (resource, mode) with a nonzero holder
 *                 mask: mode set, aux = mask64.
 *   N2SR_WAITER   mode, slot, inc, request_id, gen_or_enqseq =
 *                 enq_seq (FIFO order key).
 *   N2SR_OPCACHE  slot, inc, request_id, mode, gen_or_enqseq = gen,
 *                 aux = result status.
 *   N2SR_RECMETA  per-resource meta: gen_or_enqseq = grant_gen,
 *                 aux = dir_epoch, slot = last_ex_slot (0xFFFF =
 *                 none), mode = handoff flag, request_id =
 *                 pending_revoke_mask.
 *   N2SR_HELD     client-held report entry (recovery barrier):
 *                 mode, gen_or_enqseq = the client's stored gen.
 *
 * N2_MEPOCH_PROPOSE / N2_MEPOCH_COMMIT (§7.C, identical bodies):
 *                  0 8 mep_epoch | 8 8 mep_member |
 *                  16 8 mep_fenced | 24 8 mep_fence_ok |
 *                  32 2×3 mep_voters | 38 2 mep_flags |
 *                  40 4×64 mep_incs (slot→incarnation table)     (296)
 *                  (fence_ok = removal-authorization proof mask —
 *                  §7.D fence_done OR clean-leave; the FENCED bit in
 *                  mep_fenced marks real fences only, so a clean
 *                  leaver never disk-self-fences)
 * N2_MEPOCH_ACK:   0 8 mep_epoch | 8 1 ack_ok |
 *                  9 1 status(net2_mepoch_reason) | 10 2 pad      (12)
 */
#define MXFS_N2MSG_SNAPREC_SIZE 64
enum mxfs_n2snap_kind {
	N2SR_HOLDERS = 1,
	N2SR_WAITER  = 2,
	N2SR_OPCACHE = 3,
	N2SR_RECMETA = 4,
	N2SR_HELD    = 5,
};

struct mxfs_n2snap_rec {
	struct mxfs_resource_id resource;
	uint8_t  kind;
	uint8_t  mode;
	uint16_t slot;
	uint32_t inc;
	uint64_t gen_or_enqseq;
	uint64_t request_id;
	uint64_t aux;
};

static inline void mxfs_n2snap_rec_pack(const struct mxfs_n2snap_rec *r,
                                        uint8_t buf[MXFS_N2MSG_SNAPREC_SIZE])
{
	mxfs_n2msg_res_pack(&r->resource, buf);
	buf[32] = r->kind;
	buf[33] = r->mode;
	mxfs_net2_put_le16(buf + 34, r->slot);
	mxfs_net2_put_le32(buf + 36, r->inc);
	mxfs_net2_put_le64(buf + 40, r->gen_or_enqseq);
	mxfs_net2_put_le64(buf + 48, r->request_id);
	mxfs_net2_put_le64(buf + 56, r->aux);
}

static inline void mxfs_n2snap_rec_unpack(const uint8_t *buf,
                                          struct mxfs_n2snap_rec *r)
{
	mxfs_n2msg_res_unpack(buf, &r->resource);
	r->kind = buf[32];
	r->mode = buf[33];
	r->slot = mxfs_net2_get_le16(buf + 34);
	r->inc = mxfs_net2_get_le32(buf + 36);
	r->gen_or_enqseq = mxfs_net2_get_le64(buf + 40);
	r->request_id = mxfs_net2_get_le64(buf + 48);
	r->aux = mxfs_net2_get_le64(buf + 56);
}

/* Log record (SNAPSHOT_CHUNK trailer, MXFS_N2MSG_LOGREC_SIZE = 96):
 * one un-applied source log entry (seq in commit+1..last), full §6 op
 * identity preserved so the inheriting leader's barrier re-commits it
 * byte-identically:
 *   0 32 resource | 32 8 seq | 40 4 term | 44 2 op | 46 1 mode |
 *   47 1 pad | 48 2 slot | 50 2 pad | 52 4 inc | 56 8 request_id |
 *   64 8 grant_gen | 72 8 dir_epoch | 80 4 msg_flags | 84 12 pad
 */
#define MXFS_N2MSG_LOGREC_SIZE 96

struct mxfs_n2log_rec {
	struct mxfs_resource_id resource;
	uint64_t seq;
	uint32_t term;
	uint16_t op;
	uint8_t  mode;
	uint16_t slot;
	uint32_t inc;
	uint64_t request_id;
	uint64_t grant_gen;
	uint64_t dir_epoch;
	uint32_t msg_flags;
};

static inline void mxfs_n2log_rec_pack(const struct mxfs_n2log_rec *r,
                                       uint8_t buf[MXFS_N2MSG_LOGREC_SIZE])
{
	mxfs_n2msg_res_pack(&r->resource, buf);
	mxfs_net2_put_le64(buf + 32, r->seq);
	mxfs_net2_put_le32(buf + 40, r->term);
	mxfs_net2_put_le16(buf + 44, r->op);
	buf[46] = r->mode;
	buf[47] = 0;
	mxfs_net2_put_le16(buf + 48, r->slot);
	mxfs_net2_put_le16(buf + 50, 0);
	mxfs_net2_put_le32(buf + 52, r->inc);
	mxfs_net2_put_le64(buf + 56, r->request_id);
	mxfs_net2_put_le64(buf + 64, r->grant_gen);
	mxfs_net2_put_le64(buf + 72, r->dir_epoch);
	mxfs_net2_put_le32(buf + 80, r->msg_flags);
	memset(buf + 84, 0, 12);
}

static inline void mxfs_n2log_rec_unpack(const uint8_t *buf,
                                         struct mxfs_n2log_rec *r)
{
	mxfs_n2msg_res_unpack(buf, &r->resource);
	r->seq = mxfs_net2_get_le64(buf + 32);
	r->term = mxfs_net2_get_le32(buf + 40);
	r->op = mxfs_net2_get_le16(buf + 44);
	r->mode = buf[46];
	r->slot = mxfs_net2_get_le16(buf + 48);
	r->inc = mxfs_net2_get_le32(buf + 52);
	r->request_id = mxfs_net2_get_le64(buf + 56);
	r->grant_gen = mxfs_net2_get_le64(buf + 64);
	r->dir_epoch = mxfs_net2_get_le64(buf + 72);
	r->msg_flags = mxfs_net2_get_le32(buf + 80);
}

/* Fixed body size by type (excludes trailing snapshot records). */
static inline int mxfs_n2msg_body_size(uint16_t type)
{
	switch (type) {
	case N2_ACQUIRE:         return 36;
	case N2_GRANT:           return 52;
	case N2_DENY:            return 36;
	case N2_RELEASE:         return 44;
	case N2_RELEASE_ACK:     return 44;
	case N2_BAST:            return 44;
	case N2_APPEND:          return 76;
	case N2_APPEND_ACK:      return 28;
	case N2_TERM_VOTE:       return 20;
	case N2_SNAPSHOT_REQ:    return 8;
	case N2_SNAPSHOT_CHUNK:  return 32;
	case N2_RECOVERY_REPORT: return 16;   /* request uses rec_count=0 */
	case N2_MEPOCH_PROPOSE:  return 296;
	case N2_MEPOCH_COMMIT:   return 296;
	case N2_MEPOCH_ACK:      return 12;
	default:                 return -1;
	}
}

/* Full message pack (envelope + fixed body): returns total bytes
 * written, or -EMSGSIZE / -EINVAL.  Snapshot/report records are
 * appended by the caller after the chunk header. */
static inline int mxfs_n2msg_pack(const struct mxfs_n2msg *m, uint8_t *buf,
                                  uint32_t cap)
{
	int bsz = mxfs_n2msg_body_size(m->type);
	uint8_t *b = buf + MXFS_N2MSG_HDR_SIZE;

	if (bsz < 0)
		return -EINVAL;
	if (cap < (uint32_t)(MXFS_N2MSG_HDR_SIZE + bsz))
		return -EMSGSIZE;
	mxfs_n2msg_hdr_pack(m, buf);
	memset(b, 0, (size_t)bsz);
	switch (m->type) {
	case N2_ACQUIRE:
		mxfs_n2msg_res_pack(&m->resource, b);
		b[32] = m->mode;
		break;
	case N2_GRANT:
		mxfs_n2msg_res_pack(&m->resource, b);
		b[32] = m->mode;
		b[33] = m->status;
		mxfs_net2_put_le64(b + 36, m->grant_gen);
		mxfs_net2_put_le64(b + 44, m->dir_epoch);
		break;
	case N2_DENY:
		mxfs_n2msg_res_pack(&m->resource, b);
		b[32] = m->mode;
		b[33] = m->status;
		mxfs_net2_put_le16(b + 34, m->leader_hint);
		break;
	case N2_RELEASE:
	case N2_BAST:
		mxfs_n2msg_res_pack(&m->resource, b);
		b[32] = m->mode;
		mxfs_net2_put_le64(b + 36, m->grant_gen);
		break;
	case N2_RELEASE_ACK:
		mxfs_n2msg_res_pack(&m->resource, b);
		b[32] = m->status;
		mxfs_net2_put_le64(b + 36, m->grant_gen);
		break;
	case N2_APPEND:
		mxfs_net2_put_le16(b + 0, m->op);
		mxfs_net2_put_le64(b + 4, m->entry_seq);
		mxfs_net2_put_le64(b + 12, m->commit_watermark);
		mxfs_n2msg_res_pack(&m->resource, b + 20);
		b[52] = m->mode;
		mxfs_net2_put_le64(b + 56, m->grant_gen);
		mxfs_net2_put_le64(b + 64, m->dir_epoch);
		mxfs_net2_put_le32(b + 72, m->entry_term);
		break;
	case N2_APPEND_ACK:
		mxfs_net2_put_le64(b + 0, m->entry_seq);
		b[8] = m->ack_ok;
		mxfs_net2_put_le64(b + 12, m->last_seq);
		mxfs_net2_put_le64(b + 20, m->commit_watermark);
		break;
	case N2_TERM_VOTE:
		mxfs_net2_put_le32(b + 0, m->cand_term);
		mxfs_net2_put_le64(b + 4, m->cand_commit_seq);
		mxfs_net2_put_le64(b + 12, m->cand_last_seq);
		break;
	case N2_SNAPSHOT_REQ:
		mxfs_net2_put_le64(b + 0, m->entry_seq);
		break;
	case N2_SNAPSHOT_CHUNK:
		mxfs_net2_put_le64(b + 0, m->entry_seq);
		mxfs_net2_put_le64(b + 8, m->last_seq);
		mxfs_net2_put_le32(b + 16, m->chunk_idx);
		mxfs_net2_put_le32(b + 20, m->chunk_count);
		mxfs_net2_put_le32(b + 24, m->rec_count);
		mxfs_net2_put_le32(b + 28, m->log_count);
		break;
	case N2_RECOVERY_REPORT:
		mxfs_net2_put_le32(b + 0, m->chunk_idx);
		mxfs_net2_put_le32(b + 4, m->chunk_count);
		mxfs_net2_put_le32(b + 8, m->rec_count);
		break;
	case N2_MEPOCH_PROPOSE:
	case N2_MEPOCH_COMMIT: {
		int mi;

		mxfs_net2_put_le64(b + 0, m->mep_epoch);
		mxfs_net2_put_le64(b + 8, m->mep_member);
		mxfs_net2_put_le64(b + 16, m->mep_fenced);
		mxfs_net2_put_le64(b + 24, m->mep_fence_ok);
		mxfs_net2_put_le16(b + 32, m->mep_voters[0]);
		mxfs_net2_put_le16(b + 34, m->mep_voters[1]);
		mxfs_net2_put_le16(b + 36, m->mep_voters[2]);
		mxfs_net2_put_le16(b + 38, m->mep_flags);
		for (mi = 0; mi < MXFS_MAX_NODES; mi++)
			mxfs_net2_put_le32(b + 40 + 4 * mi,
			                   m->mep_incs[mi]);
		break;
	}
	case N2_MEPOCH_ACK:
		mxfs_net2_put_le64(b + 0, m->mep_epoch);
		b[8] = m->ack_ok;
		b[9] = m->status;
		break;
	default:
		return -EINVAL;
	}
	return MXFS_N2MSG_HDR_SIZE + bsz;
}

/* Full unpack of envelope + fixed body.  When the type carries
 * trailing records, *recs_off points at the first one on return.
 * Returns 0 or -EINVAL on malformed/short input. */
static inline int mxfs_n2msg_unpack(const uint8_t *buf, uint32_t len,
                                    struct mxfs_n2msg *m, uint32_t *recs_off)
{
	const uint8_t *b = buf + MXFS_N2MSG_HDR_SIZE;
	int rc, bsz;

	rc = mxfs_n2msg_hdr_unpack(buf, len, m);
	if (rc)
		return rc;
	bsz = mxfs_n2msg_body_size(m->type);
	if (bsz < 0 || len < (uint32_t)(MXFS_N2MSG_HDR_SIZE + bsz))
		return -EINVAL;
	switch (m->type) {
	case N2_ACQUIRE:
		mxfs_n2msg_res_unpack(b, &m->resource);
		m->mode = b[32];
		break;
	case N2_GRANT:
		mxfs_n2msg_res_unpack(b, &m->resource);
		m->mode = b[32];
		m->status = b[33];
		m->grant_gen = mxfs_net2_get_le64(b + 36);
		m->dir_epoch = mxfs_net2_get_le64(b + 44);
		break;
	case N2_DENY:
		mxfs_n2msg_res_unpack(b, &m->resource);
		m->mode = b[32];
		m->status = b[33];
		m->leader_hint = mxfs_net2_get_le16(b + 34);
		break;
	case N2_RELEASE:
	case N2_BAST:
		mxfs_n2msg_res_unpack(b, &m->resource);
		m->mode = b[32];
		m->grant_gen = mxfs_net2_get_le64(b + 36);
		break;
	case N2_RELEASE_ACK:
		mxfs_n2msg_res_unpack(b, &m->resource);
		m->status = b[32];
		m->grant_gen = mxfs_net2_get_le64(b + 36);
		break;
	case N2_APPEND:
		m->op = mxfs_net2_get_le16(b + 0);
		m->entry_seq = mxfs_net2_get_le64(b + 4);
		m->commit_watermark = mxfs_net2_get_le64(b + 12);
		mxfs_n2msg_res_unpack(b + 20, &m->resource);
		m->mode = b[52];
		m->grant_gen = mxfs_net2_get_le64(b + 56);
		m->dir_epoch = mxfs_net2_get_le64(b + 64);
		m->entry_term = mxfs_net2_get_le32(b + 72);
		break;
	case N2_APPEND_ACK:
		m->entry_seq = mxfs_net2_get_le64(b + 0);
		m->ack_ok = b[8];
		m->last_seq = mxfs_net2_get_le64(b + 12);
		m->commit_watermark = mxfs_net2_get_le64(b + 20);
		break;
	case N2_TERM_VOTE:
		m->cand_term = mxfs_net2_get_le32(b + 0);
		m->cand_commit_seq = mxfs_net2_get_le64(b + 4);
		m->cand_last_seq = mxfs_net2_get_le64(b + 12);
		break;
	case N2_SNAPSHOT_REQ:
		m->entry_seq = mxfs_net2_get_le64(b + 0);
		break;
	case N2_SNAPSHOT_CHUNK:
		m->entry_seq = mxfs_net2_get_le64(b + 0);
		m->last_seq = mxfs_net2_get_le64(b + 8);
		m->chunk_idx = mxfs_net2_get_le32(b + 16);
		m->chunk_count = mxfs_net2_get_le32(b + 20);
		m->rec_count = mxfs_net2_get_le32(b + 24);
		m->log_count = mxfs_net2_get_le32(b + 28);
		if (len < (uint32_t)(MXFS_N2MSG_HDR_SIZE + bsz) +
		          (uint64_t)m->rec_count * MXFS_N2MSG_SNAPREC_SIZE +
		          (uint64_t)m->log_count * MXFS_N2MSG_LOGREC_SIZE)
			return -EINVAL;
		break;
	case N2_RECOVERY_REPORT:
		m->chunk_idx = mxfs_net2_get_le32(b + 0);
		m->chunk_count = mxfs_net2_get_le32(b + 4);
		m->rec_count = mxfs_net2_get_le32(b + 8);
		if (len < (uint32_t)(MXFS_N2MSG_HDR_SIZE + bsz) +
		          (uint64_t)m->rec_count * MXFS_N2MSG_SNAPREC_SIZE)
			return -EINVAL;
		break;
	case N2_MEPOCH_PROPOSE:
	case N2_MEPOCH_COMMIT: {
		int mi;

		m->mep_epoch = mxfs_net2_get_le64(b + 0);
		m->mep_member = mxfs_net2_get_le64(b + 8);
		m->mep_fenced = mxfs_net2_get_le64(b + 16);
		m->mep_fence_ok = mxfs_net2_get_le64(b + 24);
		m->mep_voters[0] = mxfs_net2_get_le16(b + 32);
		m->mep_voters[1] = mxfs_net2_get_le16(b + 34);
		m->mep_voters[2] = mxfs_net2_get_le16(b + 36);
		m->mep_flags = mxfs_net2_get_le16(b + 38);
		for (mi = 0; mi < MXFS_MAX_NODES; mi++)
			m->mep_incs[mi] =
				mxfs_net2_get_le32(b + 40 + 4 * mi);
		break;
	}
	case N2_MEPOCH_ACK:
		m->mep_epoch = mxfs_net2_get_le64(b + 0);
		m->ack_ok = b[8];
		m->status = b[9];
		break;
	default:
		return -EINVAL;
	}
	if (recs_off)
		*recs_off = (uint32_t)(MXFS_N2MSG_HDR_SIZE + bsz);
	return 0;
}

#endif /* MXFS_LIBMXFS_NET2_MSG_H */
