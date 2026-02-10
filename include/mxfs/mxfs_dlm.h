/*
 * MXFS — Multinode XFS
 * Distributed Lock Manager protocol definitions
 *
 * The DLM is the single coordination mechanism for MXFS. Node liveness,
 * fencing, journal recovery, and cache coherency all derive from lock state.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_DLM_H
#define MXFS_DLM_H

#include "mxfs_common.h"

/*
 * Lock modes — standard DLM 6-mode compatibility matrix
 *
 *        NL  CR  CW  PR  PW  EX
 *   NL    Y   Y   Y   Y   Y   Y
 *   CR    Y   Y   Y   Y   Y   N
 *   CW    Y   Y   Y   N   N   N
 *   PR    Y   Y   N   Y   N   N
 *   PW    Y   Y   N   N   N   N
 *   EX    Y   N   N   N   N   N
 */
enum mxfs_lock_mode {
	MXFS_LOCK_NL = 0,   /* null — placeholder, no access */
	MXFS_LOCK_CR,        /* concurrent read */
	MXFS_LOCK_CW,        /* concurrent write */
	MXFS_LOCK_PR,        /* protected read — shared read lock */
	MXFS_LOCK_PW,        /* protected write — upgradeable */
	MXFS_LOCK_EX,        /* exclusive */
	MXFS_LOCK_MODE_COUNT,
};

/* Lock resource types */
enum mxfs_lock_type {
	MXFS_LTYPE_INODE = 1,
	MXFS_LTYPE_EXTENT,
	MXFS_LTYPE_AG,
	MXFS_LTYPE_JOURNAL,
	MXFS_LTYPE_SUPER,       /* superblock lock — mount/unmount coordination */
};

/* Lock state machine */
enum mxfs_lock_state {
	MXFS_LSTATE_UNLOCKED = 0,
	MXFS_LSTATE_WAITING,      /* request sent, awaiting grant */
	MXFS_LSTATE_GRANTED,
	MXFS_LSTATE_CONVERTING,   /* mode upgrade/downgrade in flight */
	MXFS_LSTATE_BLOCKED,      /* blocked by incompatible holder */
};

/* Lock flags */
#define MXFS_LKF_NOQUEUE    (1 << 0)  /* don't queue if can't grant immediately */
#define MXFS_LKF_CONVERT    (1 << 1)  /* mode conversion, not new lock request */
#define MXFS_LKF_CANCEL     (1 << 2)  /* cancel a pending request */
#define MXFS_LKF_ORPHAN     (1 << 3)  /* keep lock on process exit */
#define MXFS_LKF_RECOVERY   (1 << 4)  /* lock acquired during recovery phase */
#define MXFS_LKF_TRYLOCK    (1 << 5)  /* non-blocking attempt */

/* ─── Peer-to-peer DLM messages (daemon <-> daemon over TCP) ─── */

enum mxfs_dlm_msg_type {
	MXFS_MSG_LOCK_REQ = 1,
	MXFS_MSG_LOCK_GRANT,
	MXFS_MSG_LOCK_DENY,
	MXFS_MSG_LOCK_RELEASE,
	MXFS_MSG_LOCK_CONVERT,
	MXFS_MSG_LOCK_BAST,        /* blocking AST — request holder to downgrade */
	MXFS_MSG_LEASE_RENEW,
	MXFS_MSG_LEASE_ACK,
	MXFS_MSG_LEASE_EXPIRE,
	MXFS_MSG_NODE_JOIN,
	MXFS_MSG_NODE_LEAVE,
	MXFS_MSG_NODE_ALIVE,       /* heartbeat piggyback on lease renewal */
	MXFS_MSG_JOURNAL_RECOVER,
	MXFS_MSG_JOURNAL_DONE,
	MXFS_MSG_CACHE_INVAL,
};

#define MXFS_DLM_MAGIC      0x4D584653  /* "MXFS" in ASCII */
#define MXFS_DLM_VERSION    1

/* Wire protocol header — all DLM messages start with this */
struct mxfs_dlm_msg_hdr {
	uint32_t        magic;
	uint16_t        version;
	uint16_t        type;       /* mxfs_dlm_msg_type */
	uint32_t        length;     /* total message length including header */
	uint32_t        seq;        /* sender's sequence number */
	mxfs_node_id_t  sender;
	mxfs_node_id_t  target;     /* 0 = broadcast */
	mxfs_epoch_t    epoch;
};

/* Lock request */
struct mxfs_dlm_lock_req {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
	uint8_t                 mode;    /* requested mxfs_lock_mode */
	uint8_t                 pad[3];
	uint32_t                flags;   /* MXFS_LKF_* */
};

/* Lock grant/deny response */
struct mxfs_dlm_lock_resp {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
	uint8_t                 mode;    /* granted mode (may differ from request) */
	uint8_t                 status;  /* mxfs_error */
	uint8_t                 pad[2];
};

/* Lock release */
struct mxfs_dlm_lock_release {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
};

/* Blocking AST — tell a holder to downgrade or release */
struct mxfs_dlm_bast {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
	uint8_t                 requested_mode; /* mode the waiter needs */
	uint8_t                 pad[3];
};

/* Lease renewal */
struct mxfs_dlm_lease_msg {
	struct mxfs_dlm_msg_hdr hdr;
	uint64_t                lease_duration_ms;
	uint32_t                lock_count;  /* locks held — informational */
	uint32_t                pad;
};

/* Cache invalidation */
struct mxfs_dlm_cache_inval {
	struct mxfs_dlm_msg_hdr hdr;
	struct mxfs_resource_id resource;
	uint64_t                range_start;  /* byte offset */
	uint64_t                range_len;    /* 0 = entire resource */
};

/* Journal recovery notification */
struct mxfs_dlm_journal_msg {
	struct mxfs_dlm_msg_hdr hdr;
	mxfs_node_id_t          dead_node;    /* node whose journal to replay */
	uint32_t                journal_slot;
};

/* Node join/leave */
struct mxfs_dlm_node_msg {
	struct mxfs_dlm_msg_hdr hdr;
	char                    name[MXFS_NODE_NAME_MAX];
	uint16_t                port;
	uint8_t                 pad[2];
};

/* ─── Timing parameters ─── */

#define MXFS_LEASE_DURATION_MS     5000
#define MXFS_LEASE_RENEW_MS        2000   /* renew at 2/5 of lease duration */
#define MXFS_NODE_TIMEOUT_MS      15000   /* 3 missed renewals = dead */
#define MXFS_LOCK_WAIT_TIMEOUT_MS 30000
#define MXFS_BAST_TIMEOUT_MS      10000   /* time for holder to respond to BAST */

#endif /* MXFS_DLM_H */
