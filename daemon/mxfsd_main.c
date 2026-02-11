/*
 * MXFS — Multinode XFS
 * Daemon entry point
 *
 * mxfsd is the userspace daemon that runs on each node participating in
 * an MXFS cluster. It manages peer connections, runs the DLM protocol,
 * and communicates with the local mxfs.ko kernel module via generic netlink.
 *
 * Kernel-spawned lifecycle:
 *   Launched by mxfs.ko during mount via call_usermodehelper().
 *   Receives device, mountpoint, and volume UUID as command-line arguments.
 *   Signals readiness to the kernel via MXFS_NL_CMD_DAEMON_READY.
 *   Terminated by SIGTERM on umount.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include <mxfs/mxfs_common.h>
#include <mxfs/mxfs_netlink.h>
#include "mxfsd_config.h"
#include "mxfsd_log.h"
#include "mxfsd_peer.h"
#include "mxfsd_dlm.h"
#include "mxfsd_netlink.h"
#include "mxfsd_lease.h"
#include "mxfsd_journal.h"
#include "mxfsd_volume.h"
#include "mxfsd_scsi_pr.h"
#include "mxfsd_disklock.h"
#include "mxfsd_discovery.h"

#define MXFSD_CTRL_SOCKET "/var/run/mxfsd.sock"
#define MXFSD_DLM_BUCKETS 1024
#define MXFSD_DEFAULT_PORT 7600

/* ─── Node UUID persistence ──────────────────────────────── */

#define MXFS_NODE_UUID_PATH  "/etc/mxfs/node.uuid"
#define MXFS_NODE_UUID_DIR   "/etc/mxfs"

static uint8_t local_node_uuid[16];
static uint8_t local_volume_uuid[16];

static int generate_uuid(uint8_t uuid[16])
{
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) return -errno;
	ssize_t n = read(fd, uuid, 16);
	close(fd);
	if (n != 16) return -EIO;
	/* Set version 4 and variant bits */
	uuid[6] = (uuid[6] & 0x0F) | 0x40;
	uuid[8] = (uuid[8] & 0x3F) | 0x80;
	return 0;
}

static int load_or_generate_uuid(uint8_t uuid[16])
{
	int fd = open(MXFS_NODE_UUID_PATH, O_RDONLY);
	if (fd >= 0) {
		ssize_t n = read(fd, uuid, 16);
		close(fd);
		if (n == 16) return 0;
	}
	/* Generate new UUID */
	int rc = generate_uuid(uuid);
	if (rc < 0) return rc;
	/* Save it */
	mkdir(MXFS_NODE_UUID_DIR, 0755);
	fd = open(MXFS_NODE_UUID_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd >= 0) {
		ssize_t n = write(fd, uuid, 16);
		(void)n;
		close(fd);
	}
	return 0;
}

static mxfs_node_id_t uuid_to_node_id(const uint8_t uuid[16])
{
	uint32_t hash = 2166136261u;
	for (int i = 0; i < 16; i++) {
		hash ^= uuid[i];
		hash *= 16777619u;
	}
	/* Ensure non-zero — node ID 0 is reserved */
	if (hash == 0) hash = 1;
	return hash;
}

static void uuid_to_string(const uint8_t uuid[16], char *out, size_t len)
{
	snprintf(out, len,
	         "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	         uuid[0], uuid[1], uuid[2], uuid[3],
	         uuid[4], uuid[5], uuid[6], uuid[7],
	         uuid[8], uuid[9], uuid[10], uuid[11],
	         uuid[12], uuid[13], uuid[14], uuid[15]);
}

/* ─── XFS superblock UUID reader ──────────────────────────
 *
 * Reads the sb_uuid (16 bytes at offset 32) from an XFS device.
 * Also validates the XFS magic number (0x58465342 "XFSB").
 */

#define XFS_SB_MAGIC  0x58465342
#define XFS_SB_UUID_OFFSET  32

static int read_xfs_sb_uuid(const char *device, uint8_t uuid[16])
{
	int fd = open(device, O_RDONLY);
	if (fd < 0) return -errno;

	uint8_t buf[48];
	ssize_t n = pread(fd, buf, sizeof(buf), 0);
	close(fd);
	if (n < (ssize_t)sizeof(buf)) return -EIO;

	uint32_t magic = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
	                 ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
	if (magic != XFS_SB_MAGIC) return -EINVAL;

	memcpy(uuid, buf + XFS_SB_UUID_OFFSET, 16);
	return 0;
}

/* ─── Global state ───────────────────────────────────────── */

static volatile sig_atomic_t running;

static struct mxfsd_config      config;
static struct mxfsd_peer_ctx    peer_ctx;
static struct mxfsd_dlm_ctx     dlm_ctx;
static struct mxfsd_netlink_ctx nl_ctx;
static struct mxfsd_journal_ctx journal_ctx;
static struct mxfsd_volume_ctx  volume_ctx;
static struct mxfsd_scsi_pr_ctx scsi_pr_ctx;
static struct mxfsd_disklock_ctx disklock_ctx;

/* Discovery subsystem */
static struct mxfsd_discovery_ctx discovery_ctx;

/* Control socket for local test tools */
static int ctrl_fd = -1;
static pthread_t ctrl_thread_id;

/* Track which subsystems initialized for orderly shutdown */
enum subsystem {
	SUB_LOG = 0,
	SUB_CONFIG,
	SUB_VOLUME,
	SUB_SCSI_PR,
	SUB_DISKLOCK,
	SUB_DLM,
	SUB_NETLINK,
	SUB_PEER,
	SUB_JOURNAL,
	SUB_DISCOVERY,
	SUB_COUNT,
};

static bool sub_init[SUB_COUNT];

/* ─── Pending request tracking ─────────────────────────────
 *
 * When this node is not the resource master and forwards a lock
 * request to the master, the requesting thread blocks on a
 * condition variable until the master responds.
 */

#define MAX_PENDING 64

struct pending_req {
	struct mxfs_resource_id resource;
	bool active;
	bool completed;
	int result;              /* 0 = granted, negative = error */
	uint8_t granted_mode;
	pthread_mutex_t mtx;
	pthread_cond_t cv;
};

static struct pending_req pending[MAX_PENDING];
static pthread_mutex_t pending_mtx = PTHREAD_MUTEX_INITIALIZER;

static struct pending_req *pending_alloc(const struct mxfs_resource_id *res)
{
	pthread_mutex_lock(&pending_mtx);
	for (int i = 0; i < MAX_PENDING; i++) {
		if (!pending[i].active) {
			pending[i].active = true;
			pending[i].completed = false;
			pending[i].result = -1;
			pending[i].granted_mode = 0;
			pending[i].resource = *res;
			pthread_mutex_init(&pending[i].mtx, NULL);
			pthread_cond_init(&pending[i].cv, NULL);
			pthread_mutex_unlock(&pending_mtx);
			return &pending[i];
		}
	}
	pthread_mutex_unlock(&pending_mtx);
	return NULL;
}

static void pending_free(struct pending_req *pr)
{
	if (!pr)
		return;
	pthread_mutex_destroy(&pr->mtx);
	pthread_cond_destroy(&pr->cv);
	pr->active = false;
}

static struct pending_req *pending_find(const struct mxfs_resource_id *res)
{
	for (int i = 0; i < MAX_PENDING; i++) {
		if (pending[i].active &&
		    memcmp(&pending[i].resource, res,
		           sizeof(*res)) == 0)
			return &pending[i];
	}
	return NULL;
}

/* ─── Active node list management ─────────────────────────
 *
 * Builds the list of active nodes (self + connected peers) and
 * pushes it into the DLM context. The DLM uses this sorted list
 * to hash-map each resource to a master node. All nodes must
 * agree on the same sorted list for consistent mastering.
 */

static void update_active_node_list(void)
{
	mxfs_node_id_t nodes[MXFS_MAX_NODES];
	int count = 0;

	/* Always include self */
	nodes[count++] = config.node_id;

	/* Add connected peers — scan the peer context directly since
	 * in discovery mode peers are dynamically added rather than
	 * being listed in config.peers[]. */
	for (int i = 0; i < peer_ctx.peer_count; i++) {
		struct mxfsd_peer *p = &peer_ctx.peers[i];
		if (p->state == MXFSD_CONN_ACTIVE)
			nodes[count++] = p->node_id;
	}

	mxfsd_dlm_update_active_nodes(&dlm_ctx, nodes, count);
}

/* ─── Control socket protocol ────────────────────────────
 *
 * Local tools (mxfs_lock) connect to /var/run/mxfsd.sock and
 * send binary lock/unlock requests. The daemon processes them
 * through the DLM as if they came from the kernel.
 */

struct ctrl_req {
	uint8_t cmd;      /* 1 = lock, 2 = unlock */
	uint8_t mode;     /* mxfs_lock_mode */
	uint8_t pad[2];
	uint32_t flags;
	struct mxfs_resource_id resource;
};

struct ctrl_resp {
	uint8_t status;   /* 0 = granted, 1 = denied, 2 = error */
	uint8_t mode;     /* granted mode */
	uint8_t pad[2];
};

/* Forward declarations */
static int handle_lock_request(const struct mxfs_resource_id *resource,
                               enum mxfs_lock_mode mode, uint32_t flags);
static int handle_lock_release(const struct mxfs_resource_id *resource);

/* ─── Peer message send helpers ──────────────────────────── */

static int send_peer_lock_req(mxfs_node_id_t target,
                              const struct mxfs_resource_id *resource,
                              enum mxfs_lock_mode mode, uint32_t flags)
{
	struct mxfs_dlm_lock_req msg;
	memset(&msg, 0, sizeof(msg));
	msg.hdr.magic = MXFS_DLM_MAGIC;
	msg.hdr.version = MXFS_DLM_VERSION;
	msg.hdr.type = MXFS_MSG_LOCK_REQ;
	msg.hdr.length = sizeof(msg);
	msg.hdr.sender = config.node_id;
	msg.hdr.target = target;
	msg.hdr.epoch = mxfsd_dlm_get_epoch(&dlm_ctx);
	msg.resource = *resource;
	msg.mode = (uint8_t)mode;
	msg.flags = flags;

	return mxfsd_peer_send(&peer_ctx, target, &msg.hdr);
}

static int send_peer_lock_grant(mxfs_node_id_t target,
                                const struct mxfs_resource_id *resource,
                                enum mxfs_lock_mode mode)
{
	struct mxfs_dlm_lock_resp msg;
	memset(&msg, 0, sizeof(msg));
	msg.hdr.magic = MXFS_DLM_MAGIC;
	msg.hdr.version = MXFS_DLM_VERSION;
	msg.hdr.type = MXFS_MSG_LOCK_GRANT;
	msg.hdr.length = sizeof(msg);
	msg.hdr.sender = config.node_id;
	msg.hdr.target = target;
	msg.hdr.epoch = mxfsd_dlm_get_epoch(&dlm_ctx);
	msg.resource = *resource;
	msg.mode = (uint8_t)mode;
	msg.status = MXFS_OK;

	return mxfsd_peer_send(&peer_ctx, target, &msg.hdr);
}

static int send_peer_lock_deny(mxfs_node_id_t target,
                               const struct mxfs_resource_id *resource)
{
	struct mxfs_dlm_lock_resp msg;
	memset(&msg, 0, sizeof(msg));
	msg.hdr.magic = MXFS_DLM_MAGIC;
	msg.hdr.version = MXFS_DLM_VERSION;
	msg.hdr.type = MXFS_MSG_LOCK_DENY;
	msg.hdr.length = sizeof(msg);
	msg.hdr.sender = config.node_id;
	msg.hdr.target = target;
	msg.hdr.epoch = mxfsd_dlm_get_epoch(&dlm_ctx);
	msg.resource = *resource;
	msg.status = MXFS_ERR_DEADLOCK;

	return mxfsd_peer_send(&peer_ctx, target, &msg.hdr);
}

static int send_peer_lock_release(mxfs_node_id_t target,
                                  const struct mxfs_resource_id *resource)
{
	struct mxfs_dlm_lock_release msg;
	memset(&msg, 0, sizeof(msg));
	msg.hdr.magic = MXFS_DLM_MAGIC;
	msg.hdr.version = MXFS_DLM_VERSION;
	msg.hdr.type = MXFS_MSG_LOCK_RELEASE;
	msg.hdr.length = sizeof(msg);
	msg.hdr.sender = config.node_id;
	msg.hdr.target = target;
	msg.hdr.epoch = mxfsd_dlm_get_epoch(&dlm_ctx);
	msg.resource = *resource;

	return mxfsd_peer_send(&peer_ctx, target, &msg.hdr);
}

/* ─── DLM grant callback ─────────────────────────────────
 *
 * Fired by the DLM when a queued lock gets promoted to GRANTED
 * (after a conflicting lock is released). Routes the grant
 * notification to the correct destination.
 */

static void on_lock_granted(const struct mxfs_resource_id *resource,
                            mxfs_node_id_t owner,
                            enum mxfs_lock_mode mode,
                            void *user_data)
{
	(void)user_data;

	mxfsd_info("dlm: lock promoted for node %u mode %u "
	           "vol=%lu ino=%lu",
	           owner, mode,
	           (unsigned long)resource->volume,
	           (unsigned long)resource->ino);

	/* Persist the grant to disk before notifying anyone.
	 * Disk write happens before the response so that recovery
	 * can see the grant even if the daemon crashes right after. */
	if (disklock_ctx.fd >= 0) {
		mxfsd_disklock_write_grant(&disklock_ctx, resource, owner,
		                           mode,
		                           mxfsd_dlm_get_epoch(&dlm_ctx));
	}

	if (owner == config.node_id) {
		/* Local request was queued — send grant to kernel */
		mxfsd_netlink_send_lock_grant(&nl_ctx, resource, mode);

		/* Also wake any pending control socket request */
		pthread_mutex_lock(&pending_mtx);
		struct pending_req *pr = pending_find(resource);
		if (pr) {
			pthread_mutex_lock(&pr->mtx);
			pr->result = 0;
			pr->granted_mode = (uint8_t)mode;
			pr->completed = true;
			pthread_cond_signal(&pr->cv);
			pthread_mutex_unlock(&pr->mtx);
		}
		pthread_mutex_unlock(&pending_mtx);
	} else {
		/* Remote peer was queued — send grant over TCP */
		send_peer_lock_grant(owner, resource, mode);
	}
}

/* ─── Peer message handler ───────────────────────────────
 *
 * Called by the peer recv thread when a complete message arrives
 * from another daemon. Routes to the appropriate DLM operation.
 */

static void on_peer_message(mxfs_node_id_t sender,
                            const struct mxfs_dlm_msg_hdr *hdr,
                            const void *payload, uint32_t payload_len,
                            void *user_data)
{
	(void)user_data;
	(void)payload;  /* payload is part of the full message body */

	switch (hdr->type) {
	case MXFS_MSG_LOCK_REQ: {
		/* Reconstruct the lock_req from hdr + payload.
		 * The payload starts right after the header that we
		 * already read separately. */
		struct mxfs_dlm_lock_req req;
		memcpy(&req.hdr, hdr, sizeof(*hdr));
		if (payload_len >= sizeof(req) - sizeof(req.hdr))
			memcpy(&req.resource, payload,
			       sizeof(req) - sizeof(req.hdr));
		else
			break;

		/* Verify we are the resource master for this resource */
		if (!mxfsd_dlm_is_resource_master(&dlm_ctx, &req.resource)) {
			mxfsd_warn("received LOCK_REQ from node %u but "
			           "not master for vol=%lu ino=%lu",
			           sender,
			           (unsigned long)req.resource.volume,
			           (unsigned long)req.resource.ino);
			break;
		}

		mxfsd_info("dlm: lock request from node %u: "
		           "mode %u vol=%lu ino=%lu",
		           sender, req.mode,
		           (unsigned long)req.resource.volume,
		           (unsigned long)req.resource.ino);

		int rc = mxfsd_dlm_lock_request(&dlm_ctx, &req.resource,
		                                 sender,
		                                 (enum mxfs_lock_mode)req.mode,
		                                 req.flags);
		if (rc == 0) {
			/* Immediately granted — persist to disk first */
			if (disklock_ctx.fd >= 0)
				mxfsd_disklock_write_grant(&disklock_ctx,
				                           &req.resource,
				                           sender,
				                           (enum mxfs_lock_mode)req.mode,
				                           mxfsd_dlm_get_epoch(&dlm_ctx));
			mxfsd_info("dlm: granted lock to node %u", sender);
			send_peer_lock_grant(sender, &req.resource,
			                     (enum mxfs_lock_mode)req.mode);
		} else if (rc == -EINPROGRESS) {
			/* Queued — grant callback will fire when ready */
			mxfsd_info("dlm: lock queued for node %u", sender);
		} else {
			/* Error or incompatible with NOQUEUE */
			mxfsd_info("dlm: lock denied for node %u (rc=%d)",
			           sender, rc);
			send_peer_lock_deny(sender, &req.resource);
		}
		break;
	}

	case MXFS_MSG_LOCK_GRANT: {
		/* Master granted our lock request. */
		struct mxfs_dlm_lock_resp resp;
		memcpy(&resp.hdr, hdr, sizeof(*hdr));
		if (payload_len >= sizeof(resp) - sizeof(resp.hdr))
			memcpy(&resp.resource, payload,
			       sizeof(resp) - sizeof(resp.hdr));
		else
			break;

		mxfsd_info("dlm: lock granted by master (node %u): "
		           "mode %u vol=%lu ino=%lu",
		           sender, resp.mode,
		           (unsigned long)resp.resource.volume,
		           (unsigned long)resp.resource.ino);

		/* Send grant to local kernel */
		mxfsd_netlink_send_lock_grant(&nl_ctx, &resp.resource,
		                              (enum mxfs_lock_mode)resp.mode);

		/* Wake any pending control socket request */
		pthread_mutex_lock(&pending_mtx);
		struct pending_req *pr = pending_find(&resp.resource);
		if (pr) {
			pthread_mutex_lock(&pr->mtx);
			pr->result = 0;
			pr->granted_mode = resp.mode;
			pr->completed = true;
			pthread_cond_signal(&pr->cv);
			pthread_mutex_unlock(&pr->mtx);
		}
		pthread_mutex_unlock(&pending_mtx);
		break;
	}

	case MXFS_MSG_LOCK_DENY: {
		/* Master denied our lock request. */
		struct mxfs_dlm_lock_resp resp;
		memcpy(&resp.hdr, hdr, sizeof(*hdr));
		if (payload_len >= sizeof(resp) - sizeof(resp.hdr))
			memcpy(&resp.resource, payload,
			       sizeof(resp) - sizeof(resp.hdr));
		else
			break;

		mxfsd_info("dlm: lock denied by master (node %u): "
		           "vol=%lu ino=%lu",
		           sender,
		           (unsigned long)resp.resource.volume,
		           (unsigned long)resp.resource.ino);

		/* Send deny to local kernel */
		mxfsd_netlink_send_lock_deny(&nl_ctx, &resp.resource,
		                             MXFS_ERR_DEADLOCK);

		/* Wake any pending control socket request */
		pthread_mutex_lock(&pending_mtx);
		struct pending_req *prq = pending_find(&resp.resource);
		if (prq) {
			pthread_mutex_lock(&prq->mtx);
			prq->result = -EAGAIN;
			prq->completed = true;
			pthread_cond_signal(&prq->cv);
			pthread_mutex_unlock(&prq->mtx);
		}
		pthread_mutex_unlock(&pending_mtx);
		break;
	}

	case MXFS_MSG_LOCK_RELEASE: {
		/* A peer is releasing a lock. Process if we are resource master. */
		struct mxfs_dlm_lock_release rel;
		memcpy(&rel.hdr, hdr, sizeof(*hdr));
		if (payload_len >= sizeof(rel) - sizeof(rel.hdr))
			memcpy(&rel.resource, payload,
			       sizeof(rel) - sizeof(rel.hdr));
		else
			break;

		mxfsd_info("dlm: lock release from node %u: "
		           "vol=%lu ino=%lu",
		           sender,
		           (unsigned long)rel.resource.volume,
		           (unsigned long)rel.resource.ino);

		if (mxfsd_dlm_is_resource_master(&dlm_ctx, &rel.resource)) {
			mxfsd_dlm_lock_release(&dlm_ctx, &rel.resource,
			                       sender);
			/* Clear disk lock record */
			if (disklock_ctx.fd >= 0)
				mxfsd_disklock_clear_grant(&disklock_ctx,
				                           &rel.resource,
				                           sender);
			/* Promotions handled by the grant callback */
		} else {
			mxfsd_warn("received LOCK_RELEASE from node %u but "
			           "not master for vol=%lu ino=%lu",
			           sender,
			           (unsigned long)rel.resource.volume,
			           (unsigned long)rel.resource.ino);
		}
		break;
	}

	default:
		mxfsd_dbg("peer: unhandled msg type %u from node %u",
		          hdr->type, sender);
		break;
	}
}

/* ─── Netlink NLA attribute parser ───────────────────────── */

struct parsed_nl_attrs {
	struct mxfs_resource_id *resource;
	int has_resource;
	uint8_t mode;
	int has_mode;
	uint32_t flags;
	int has_flags;
};

static void parse_nl_attrs(void *data, int len, struct parsed_nl_attrs *out)
{
	memset(out, 0, sizeof(*out));
	int offset = 0;

	while (offset + (int)NLA_HDRLEN <= len) {
		struct nlattr *nla = (struct nlattr *)((char *)data + offset);
		int nla_total = NLA_ALIGN(nla->nla_len);
		int nla_data_len = nla->nla_len - NLA_HDRLEN;
		void *nla_data = (char *)nla + NLA_HDRLEN;

		if (nla_total <= 0 || offset + nla_total > len)
			break;

		switch (nla->nla_type) {
		case MXFS_NL_ATTR_RESOURCE:
			if (nla_data_len >= (int)sizeof(struct mxfs_resource_id)) {
				out->resource = (struct mxfs_resource_id *)nla_data;
				out->has_resource = 1;
			}
			break;
		case MXFS_NL_ATTR_LOCK_MODE:
			if (nla_data_len >= 1) {
				out->mode = *(uint8_t *)nla_data;
				out->has_mode = 1;
			}
			break;
		case MXFS_NL_ATTR_LOCK_FLAGS:
			if (nla_data_len >= 4) {
				out->flags = *(uint32_t *)nla_data;
				out->has_flags = 1;
			}
			break;
		default:
			break;
		}

		offset += nla_total;
	}
}

/* ─── Lock request handling ──────────────────────────────
 *
 * Unified handler for lock requests from the kernel, control
 * socket, or (on master) from peer daemons.
 *
 * Returns 0 on immediate grant, -EINPROGRESS if queued,
 * negative errno on error.
 */

static int handle_lock_request(const struct mxfs_resource_id *resource,
                               enum mxfs_lock_mode mode, uint32_t flags)
{
	if (mxfsd_dlm_is_resource_master(&dlm_ctx, resource)) {
		/* We are the resource master — process locally */
		int rc = mxfsd_dlm_lock_request(&dlm_ctx, resource,
		                                 config.node_id, mode, flags);
		if (rc == 0) {
			/* Persist the grant to disk before returning */
			if (disklock_ctx.fd >= 0)
				mxfsd_disklock_write_grant(&disklock_ctx,
				                           resource,
				                           config.node_id,
				                           mode,
				                           mxfsd_dlm_get_epoch(&dlm_ctx));
			mxfsd_info("dlm: local lock granted: mode %u "
			           "vol=%lu ino=%lu",
			           mode,
			           (unsigned long)resource->volume,
			           (unsigned long)resource->ino);
		} else if (rc == -EINPROGRESS) {
			mxfsd_info("dlm: local lock queued: mode %u "
			           "vol=%lu ino=%lu",
			           mode,
			           (unsigned long)resource->volume,
			           (unsigned long)resource->ino);
		} else {
			mxfsd_info("dlm: local lock denied (rc=%d): mode %u "
			           "vol=%lu ino=%lu",
			           rc, mode,
			           (unsigned long)resource->volume,
			           (unsigned long)resource->ino);
		}
		return rc;
	} else {
		/* Forward to the resource master node */
		mxfs_node_id_t master = mxfsd_dlm_resource_master(
			&dlm_ctx, resource);
		mxfsd_info("dlm: forwarding lock request to master "
		           "(node %u): mode %u vol=%lu ino=%lu",
		           master, mode,
		           (unsigned long)resource->volume,
		           (unsigned long)resource->ino);

		return send_peer_lock_req(master, resource, mode, flags);
	}
}

static int handle_lock_release(const struct mxfs_resource_id *resource)
{
	if (mxfsd_dlm_is_resource_master(&dlm_ctx, resource)) {
		mxfsd_dlm_lock_release(&dlm_ctx, resource, config.node_id);
		/* Clear the disk lock record after in-memory release */
		if (disklock_ctx.fd >= 0)
			mxfsd_disklock_clear_grant(&disklock_ctx, resource,
			                           config.node_id);
		/* Promotions handled by the grant callback */
	} else {
		mxfs_node_id_t master = mxfsd_dlm_resource_master(
			&dlm_ctx, resource);
		send_peer_lock_release(master, resource);
	}
	return 0;
}

/* ─── Netlink callback ───────────────────────────────────
 *
 * Called by the netlink recv thread when the kernel module
 * sends a message to the daemon (LOCK_REQ, LOCK_RELEASE, etc.)
 */

static int on_netlink_msg(enum mxfs_nl_cmd cmd, void *attrs,
                          int attrs_len, void *user_data)
{
	(void)user_data;

	struct parsed_nl_attrs parsed;
	parse_nl_attrs(attrs, attrs_len, &parsed);

	switch (cmd) {
	case MXFS_NL_CMD_LOCK_REQ: {
		if (!parsed.has_resource || !parsed.has_mode) {
			mxfsd_warn("netlink: LOCK_REQ missing attributes");
			break;
		}

		int rc = handle_lock_request(parsed.resource,
		                              (enum mxfs_lock_mode)parsed.mode,
		                              parsed.flags);
		if (rc == 0) {
			/* Immediately granted — tell the kernel */
			mxfsd_netlink_send_lock_grant(&nl_ctx,
			                              parsed.resource,
			                              (enum mxfs_lock_mode)parsed.mode);
		} else if (rc == -EINPROGRESS) {
			/* Queued — grant callback will fire later */
		} else if (rc == -EAGAIN || rc == -EWOULDBLOCK) {
			mxfsd_netlink_send_lock_deny(&nl_ctx,
			                             parsed.resource,
			                             MXFS_ERR_DEADLOCK);
		}
		/* If we forwarded to master, the peer response handler
		 * will send the grant/deny to the kernel */
		break;
	}

	case MXFS_NL_CMD_LOCK_RELEASE: {
		if (!parsed.has_resource) {
			mxfsd_warn("netlink: LOCK_RELEASE missing resource");
			break;
		}
		handle_lock_release(parsed.resource);
		break;
	}

	default:
		mxfsd_dbg("netlink: unhandled cmd %u", cmd);
		break;
	}

	return 0;
}

/* ─── Discovery peer callback ────────────────────────────
 *
 * Fired by the discovery module when a new peer is discovered
 * on the same volume. Adds the peer and initiates TCP connection
 * following the lower-ID-initiates convention.
 */

static void on_peer_discovered(const uint8_t *node_uuid,
                                mxfs_node_id_t node_id,
                                const char *host, uint16_t tcp_port,
                                const uint8_t *volume_uuid,
                                mxfs_volume_id_t volume_id,
                                void *user_data)
{
	(void)user_data;
	(void)node_uuid;
	(void)volume_uuid;
	(void)volume_id;

	struct mxfsd_peer *existing = mxfsd_peer_find(&peer_ctx, node_id);
	if (existing) return;

	mxfsd_notice("discovery: found peer node %u at %s:%u",
	             node_id, host, tcp_port);

	int rc = mxfsd_peer_add(&peer_ctx, node_id, host, tcp_port);
	if (rc != 0 && rc != -EEXIST) return;

	/* Lower ID initiates TCP connection */
	if (node_id < config.node_id) {
		mxfsd_peer_connect(&peer_ctx, node_id);
	}

	update_active_node_list();
}

/* ─── Signal handling ───────────────────────────────────── */

static void signal_handler(int sig)
{
	(void)sig;
	running = 0;
}

static void setup_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);

	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	/* Ignore SIGPIPE — peer sockets may close unexpectedly */
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
}

/* ─── Control socket thread ──────────────────────────────
 *
 * Accepts connections from local tools (mxfs_lock) and
 * processes lock/unlock requests through the DLM.
 */

static int read_full(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t rem = len;
	while (rem > 0) {
		ssize_t n = read(fd, p, rem);
		if (n <= 0) return -1;
		p += n;
		rem -= (size_t)n;
	}
	return 0;
}

static int write_full(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t rem = len;
	while (rem > 0) {
		ssize_t n = write(fd, p, rem);
		if (n <= 0) return -1;
		p += n;
		rem -= (size_t)n;
	}
	return 0;
}

static void *ctrl_thread_fn(void *arg)
{
	(void)arg;

	mxfsd_info("ctrl: control socket thread started");

	while (running) {
		struct pollfd pfd = { .fd = ctrl_fd, .events = POLLIN };
		if (poll(&pfd, 1, 500) <= 0)
			continue;

		int client = accept(ctrl_fd, NULL, NULL);
		if (client < 0)
			continue;

		struct ctrl_req req;
		if (read_full(client, &req, sizeof(req)) < 0) {
			close(client);
			continue;
		}

		struct ctrl_resp resp;
		memset(&resp, 0, sizeof(resp));

		if (req.cmd == 1) {
			/* Lock request */
			mxfsd_info("ctrl: lock request mode %u "
			           "vol=%lu ino=%lu",
			           req.mode,
			           (unsigned long)req.resource.volume,
			           (unsigned long)req.resource.ino);

			/* Allocate pending req BEFORE sending, so the
			 * response handler can find it. */
			struct pending_req *pr =
				pending_alloc(&req.resource);

			int rc = handle_lock_request(&req.resource,
			                              (enum mxfs_lock_mode)req.mode,
			                              req.flags);
			if (rc == 0 && mxfsd_dlm_is_resource_master(&dlm_ctx,
				&req.resource)) {
				/* Immediately granted — we are resource master */
				resp.status = 0;
				resp.mode = req.mode;
				if (pr) pending_free(pr);
			} else if (rc == -EAGAIN || rc == -EWOULDBLOCK) {
				/* NOQUEUE/TRYLOCK denied */
				resp.status = 1;
				if (pr) pending_free(pr);
			} else if (pr) {
				/* Either queued (-EINPROGRESS on master) or
				 * forwarded to master (rc >= 0 from send).
				 * Block until the grant/deny callback fires. */
				pthread_mutex_lock(&pr->mtx);
				struct timespec ts;
				clock_gettime(CLOCK_REALTIME, &ts);
				ts.tv_sec += 30;
				while (!pr->completed) {
					int wrc = pthread_cond_timedwait(
						&pr->cv, &pr->mtx, &ts);
					if (wrc == ETIMEDOUT) {
						pr->result = -ETIMEDOUT;
						pr->completed = true;
					}
				}
				pthread_mutex_unlock(&pr->mtx);

				if (pr->result == 0) {
					resp.status = 0;
					resp.mode = pr->granted_mode;
				} else {
					resp.status = 1;
				}
				pending_free(pr);
			} else {
				resp.status = 2; /* no pending slot */
			}
		} else if (req.cmd == 2) {
			/* Unlock request */
			mxfsd_info("ctrl: unlock request "
			           "vol=%lu ino=%lu",
			           (unsigned long)req.resource.volume,
			           (unsigned long)req.resource.ino);
			handle_lock_release(&req.resource);
			resp.status = 0;
		} else {
			resp.status = 2; /* unknown command */
		}

		write_full(client, &resp, sizeof(resp));
		close(client);
	}

	mxfsd_info("ctrl: control socket thread exiting");
	return NULL;
}

static int ctrl_init(void)
{
	unlink(MXFSD_CTRL_SOCKET);

	ctrl_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctrl_fd < 0) {
		mxfsd_err("ctrl: socket() failed: %s", strerror(errno));
		return -errno;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, MXFSD_CTRL_SOCKET,
	        sizeof(addr.sun_path) - 1);

	if (bind(ctrl_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		mxfsd_err("ctrl: bind(%s) failed: %s",
		          MXFSD_CTRL_SOCKET, strerror(errno));
		close(ctrl_fd);
		ctrl_fd = -1;
		return -errno;
	}

	chmod(MXFSD_CTRL_SOCKET, 0660);

	if (listen(ctrl_fd, 8) < 0) {
		mxfsd_err("ctrl: listen() failed: %s", strerror(errno));
		close(ctrl_fd);
		ctrl_fd = -1;
		return -errno;
	}

	int rc = pthread_create(&ctrl_thread_id, NULL, ctrl_thread_fn, NULL);
	if (rc != 0) {
		mxfsd_err("ctrl: thread create failed: %s", strerror(rc));
		close(ctrl_fd);
		ctrl_fd = -1;
		return -rc;
	}

	mxfsd_info("ctrl: listening on %s", MXFSD_CTRL_SOCKET);
	return 0;
}

static void ctrl_shutdown(void)
{
	if (ctrl_fd >= 0) {
		close(ctrl_fd);
		ctrl_fd = -1;
		pthread_join(ctrl_thread_id, NULL);
		unlink(MXFSD_CTRL_SOCKET);
	}
}

/* ─── Peer disconnect callback ──────────────────────────── */

static void on_peer_disconnect(mxfs_node_id_t node, void *user_data)
{
	(void)user_data;

	mxfsd_notice("node %u disconnected — fencing, purging locks, "
		     "and initiating journal recovery", node);

	/* LAYER 1: SCSI PR fencing — preempt the dead node's registration
	 * key so the storage array rejects all further I/O from it.
	 * This MUST happen before we touch any lock state. */
	if (scsi_pr_ctx.fd >= 0) {
		uint64_t victim_key = (uint64_t)node;
		int pr_rc = mxfsd_scsi_pr_preempt(&scsi_pr_ctx, victim_key);
		if (pr_rc == 0)
			mxfsd_notice("scsi_pr: fenced node %u (key 0x%lx)",
			             node, (unsigned long)victim_key);
		else
			mxfsd_err("scsi_pr: FAILED to fence node %u: %s",
			          node, strerror(-pr_rc));
	}

	/* LAYER 2: Clear on-disk lock records for the dead node */
	if (disklock_ctx.fd >= 0)
		mxfsd_disklock_purge_node(&disklock_ctx, node);

	/* Update active node list — this changes resource master mapping.
	 * Some resources previously mastered on the dead node now map to
	 * surviving nodes. */
	update_active_node_list();

	/* LAYER 3: Purge all in-memory DLM locks held by the dead node */
	mxfsd_dlm_purge_node(&dlm_ctx, node);

	/* Mark journal slot for recovery */
	mxfsd_journal_mark_needs_recovery(&journal_ctx, node);

	/* Attempt to begin recovery */
	if (mxfsd_journal_begin_recovery(&journal_ctx, node) == 0) {
		mxfsd_netlink_send_recovery_start(&nl_ctx);
		mxfsd_netlink_send_node_status(&nl_ctx, node, MXFS_NODE_DEAD);
		mxfsd_journal_finish_recovery(&journal_ctx, node);
		mxfsd_netlink_send_recovery_done(&nl_ctx);
	}

	/* Advance epoch to invalidate stale locks */
	mxfsd_dlm_advance_epoch(&dlm_ctx);
}

/* ─── Subsystem init / shutdown ──────────────────────────── */

static void shutdown_subsystems(void)
{
	/* Shutdown in reverse init order */
	ctrl_shutdown();

	if (sub_init[SUB_DISCOVERY]) {
		mxfsd_discovery_stop(&discovery_ctx);
		mxfsd_discovery_shutdown(&discovery_ctx);
		sub_init[SUB_DISCOVERY] = false;
	}
	if (sub_init[SUB_JOURNAL]) {
		mxfsd_journal_shutdown(&journal_ctx);
		sub_init[SUB_JOURNAL] = false;
	}
	if (sub_init[SUB_PEER]) {
		mxfsd_peer_shutdown(&peer_ctx);
		sub_init[SUB_PEER] = false;
	}
	if (sub_init[SUB_NETLINK]) {
		mxfsd_netlink_shutdown(&nl_ctx);
		sub_init[SUB_NETLINK] = false;
	}
	if (sub_init[SUB_DLM]) {
		mxfsd_dlm_shutdown(&dlm_ctx);
		sub_init[SUB_DLM] = false;
	}
	if (sub_init[SUB_DISKLOCK]) {
		mxfsd_disklock_shutdown(&disklock_ctx);
		sub_init[SUB_DISKLOCK] = false;
	}
	if (sub_init[SUB_SCSI_PR]) {
		/* Clean unregister — remove our key from the device */
		mxfsd_scsi_pr_unregister(&scsi_pr_ctx);
		mxfsd_scsi_pr_shutdown(&scsi_pr_ctx);
		sub_init[SUB_SCSI_PR] = false;
	}
	if (sub_init[SUB_VOLUME]) {
		mxfsd_volume_shutdown(&volume_ctx);
		sub_init[SUB_VOLUME] = false;
	}
	/* LOG stays up until the very end so shutdown messages are captured */
}

static int init_subsystems(const char *mountpoint,
                           const char *iface, const char *mcast_or_bcast,
                           bool bcast_mode)
{
	int rc;

	/* Volume tracking */
	rc = mxfsd_volume_init(&volume_ctx, config.node_id);
	if (rc) {
		mxfsd_err("volume init failed: %d", rc);
		return rc;
	}
	sub_init[SUB_VOLUME] = true;

	/* Add configured volumes */
	for (int i = 0; i < config.volume_count; i++) {
		mxfsd_volume_add(&volume_ctx,
				 config.volumes[i].name,
				 config.volumes[i].device);
	}

	/* Set mount point if provided (kernel-spawned mode) */
	if (mountpoint && mountpoint[0] != '\0' &&
	    volume_ctx.volume_count > 0) {
		strncpy(volume_ctx.volumes[0].mount_point, mountpoint,
		        MXFS_PATH_MAX - 1);
		volume_ctx.volumes[0].mount_point[MXFS_PATH_MAX - 1] = '\0';
	}

	/* SCSI-3 Persistent Reservations — hardware I/O fencing.
	 * Register our key and acquire WRITE EXCLUSIVE REGISTRANTS ONLY.
	 * Uses the first configured volume's device for the shared LUN. */
	if (config.volume_count > 0) {
		uint64_t pr_key = (uint64_t)config.node_id;
		rc = mxfsd_scsi_pr_init(&scsi_pr_ctx,
		                         config.volumes[0].device,
		                         pr_key);
		if (rc == 0) {
			sub_init[SUB_SCSI_PR] = true;
			rc = mxfsd_scsi_pr_register(&scsi_pr_ctx);
			if (rc == 0) {
				rc = mxfsd_scsi_pr_reserve(&scsi_pr_ctx);
				if (rc != 0 && rc != -EBUSY) {
					/* -EBUSY means another node already holds
					 * the reservation, which is fine for
					 * REGISTRANTS ONLY type */
					mxfsd_warn("scsi_pr: reserve failed "
					           "(rc=%d), continuing without "
					           "hardware fencing", rc);
				}
			} else {
				mxfsd_warn("scsi_pr: register failed (rc=%d), "
				           "continuing without hardware fencing",
				           rc);
			}
		} else {
			mxfsd_warn("scsi_pr: init failed (rc=%d) — device may "
			           "not support SCSI PR, continuing without "
			           "hardware fencing", rc);
		}
	}

	/* On-disk lock state persistence.
	 * Uses the mountpoint provided by the kernel. */
	if (config.volume_count > 0 &&
	    volume_ctx.volumes[0].mount_point[0] != '\0') {
		rc = mxfsd_disklock_init(&disklock_ctx,
		                          volume_ctx.volumes[0].mount_point,
		                          config.node_id);
		if (rc == 0) {
			sub_init[SUB_DISKLOCK] = true;
			mxfsd_disklock_start_heartbeat(&disklock_ctx);
		} else {
			mxfsd_warn("disklock: init failed (rc=%d), continuing "
			           "without disk lock persistence", rc);
		}
	} else {
		mxfsd_info("disklock: no mounted volume yet, "
		           "disk lock persistence deferred");
	}

	/* DLM engine */
	rc = mxfsd_dlm_init(&dlm_ctx, config.node_id, MXFSD_DLM_BUCKETS);
	if (rc) {
		mxfsd_err("DLM init failed: %d", rc);
		return rc;
	}
	sub_init[SUB_DLM] = true;

	/* Set DLM grant callback */
	mxfsd_dlm_set_grant_cb(&dlm_ctx, on_lock_granted, NULL);

	/* Netlink to kernel module */
	rc = mxfsd_netlink_init(&nl_ctx);
	if (rc) {
		mxfsd_err("netlink init failed: %d", rc);
		return rc;
	}
	sub_init[SUB_NETLINK] = true;

	/* Register netlink callback for kernel messages */
	mxfsd_netlink_set_callback(&nl_ctx, on_netlink_msg, NULL);

	/* Peer connections */
	rc = mxfsd_peer_init(&peer_ctx, config.node_id,
			     config.bind_addr, config.bind_port);
	if (rc) {
		mxfsd_err("peer init failed: %d", rc);
		return rc;
	}
	sub_init[SUB_PEER] = true;

	/* Set disconnect callback — TCP state = liveness */
	mxfsd_peer_set_disconnect_cb(&peer_ctx, on_peer_disconnect, NULL);

	/* Set message callback — route DLM messages */
	mxfsd_peer_set_msg_cb(&peer_ctx, on_peer_message, NULL);

	/* Discovery — always used in kernel-spawned mode */
	{
		/* Build discovery announcement */
		struct mxfsd_discovery_announce announce;
		memset(&announce, 0, sizeof(announce));
		announce.magic = MXFS_DISCOVERY_MAGIC;
		announce.version = MXFS_DISCOVERY_VERSION;
		memcpy(announce.node_uuid, local_node_uuid, 16);
		announce.node_id = config.node_id;
		announce.tcp_port = config.bind_port;
		memcpy(announce.volume_uuid, local_volume_uuid, 16);
		if (volume_ctx.volume_count > 0)
			announce.volume_id = volume_ctx.volumes[0].id;
		gethostname(announce.hostname, sizeof(announce.hostname));
		announce.flags = 0x01;  /* has_volume */

		rc = mxfsd_discovery_init(&discovery_ctx, &announce,
		                           mcast_or_bcast,
		                           0, /* discovery port = default */
		                           iface,
		                           bcast_mode);
		if (rc == 0) {
			sub_init[SUB_DISCOVERY] = true;
			mxfsd_discovery_set_peer_cb(&discovery_ctx,
			                             on_peer_discovered, NULL);
			mxfsd_discovery_start(&discovery_ctx);
			mxfsd_info("discovery: started (%s mode on %s)",
			           bcast_mode ? "broadcast" : "multicast",
			           iface ? iface : "all interfaces");
		} else {
			mxfsd_err("discovery init failed: %d", rc);
		}
	}

	/* Journal coordination */
	rc = mxfsd_journal_init(&journal_ctx, config.node_id, MXFS_MAX_NODES);
	if (rc) {
		mxfsd_err("journal init failed: %d", rc);
		return rc;
	}
	sub_init[SUB_JOURNAL] = true;

	rc = mxfsd_journal_claim_slot(&journal_ctx);
	if (rc) {
		mxfsd_err("journal slot claim failed: %d", rc);
		return rc;
	}

	/* Build initial active node list from self + connected peers */
	update_active_node_list();

	/* Control socket for local tools */
	rc = ctrl_init();
	if (rc)
		mxfsd_warn("control socket init failed (non-fatal): %d", rc);

	mxfsd_info("dlm: distributed mastering active — "
	           "this node masters resources from %d active node(s)",
	           dlm_ctx.active_nodes.count);

	return 0;
}

/* ─── Parse hex UUID string to binary ────────────────────── */

static int parse_hex_uuid(const char *hex, uint8_t uuid[16])
{
	/* Accept 32 hex chars, optionally with dashes */
	int idx = 0;
	for (const char *p = hex; *p && idx < 16; p++) {
		if (*p == '-') continue;

		char hi = *p;
		p++;
		if (!*p) return -EINVAL;
		char lo = *p;

		int h, l;
		if (hi >= '0' && hi <= '9') h = hi - '0';
		else if (hi >= 'a' && hi <= 'f') h = hi - 'a' + 10;
		else if (hi >= 'A' && hi <= 'F') h = hi - 'A' + 10;
		else return -EINVAL;

		if (lo >= '0' && lo <= '9') l = lo - '0';
		else if (lo >= 'a' && lo <= 'f') l = lo - 'a' + 10;
		else if (lo >= 'A' && lo <= 'F') l = lo - 'A' + 10;
		else return -EINVAL;

		uuid[idx++] = (uint8_t)((h << 4) | l);
	}

	if (idx != 16) return -EINVAL;
	return 0;
}

/* ─── Main ──────────────────────────────────────────────── */

int main(int argc, char **argv)
{
	const char *device_path = NULL;
	const char *mountpoint = NULL;
	const char *uuid_hex = NULL;
	char iface[64] = {0};
	char broadcast_addr[64] = {0};
	char multicast_addr[64] = {0};
	uint16_t tcp_port = MXFSD_DEFAULT_PORT;
	int rc;

	static struct option long_opts[] = {
		{ "device",     required_argument, NULL, 'd' },
		{ "mountpoint", required_argument, NULL, 'M' },
		{ "uuid",       required_argument, NULL, 'u' },
		{ "iface",      required_argument, NULL, 'i' },
		{ "broadcast",  required_argument, NULL, 'b' },
		{ "multicast",  required_argument, NULL, 'm' },
		{ "port",       required_argument, NULL, 'p' },
		{ NULL,         0,                 NULL,  0  },
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "d:M:u:i:b:m:p:",
	                          long_opts, NULL)) != -1) {
		switch (opt) {
		case 'd':
			device_path = optarg;
			break;
		case 'M':
			mountpoint = optarg;
			break;
		case 'u':
			uuid_hex = optarg;
			break;
		case 'i':
			strncpy(iface, optarg, sizeof(iface) - 1);
			break;
		case 'b':
			strncpy(broadcast_addr, optarg,
			        sizeof(broadcast_addr) - 1);
			break;
		case 'm':
			strncpy(multicast_addr, optarg,
			        sizeof(multicast_addr) - 1);
			break;
		case 'p':
			{
				long pv = strtol(optarg, NULL, 10);
				if (pv <= 0 || pv > 65535) {
					fprintf(stderr, "mxfsd: invalid port '%s'\n",
					        optarg);
					return 1;
				}
				tcp_port = (uint16_t)pv;
			}
			break;
		default:
			fprintf(stderr, "mxfsd: unknown option\n");
			return 1;
		}
	}

	/* Validate required arguments */
	if (!device_path) {
		fprintf(stderr, "mxfsd: --device is required\n");
		return 1;
	}
	if (!mountpoint) {
		fprintf(stderr, "mxfsd: --mountpoint is required\n");
		return 1;
	}

	/* Parse volume UUID — either from kernel-provided hex string
	 * or by reading the XFS superblock directly */
	if (uuid_hex) {
		rc = parse_hex_uuid(uuid_hex, local_volume_uuid);
		if (rc < 0) {
			fprintf(stderr, "mxfsd: invalid UUID '%s'\n", uuid_hex);
			return 1;
		}
	} else {
		rc = read_xfs_sb_uuid(device_path, local_volume_uuid);
		if (rc < 0) {
			fprintf(stderr, "mxfsd: failed to read XFS superblock "
			        "from '%s': %s\n", device_path,
			        rc == -EINVAL ? "not an XFS filesystem"
			                      : strerror(-rc));
			return 1;
		}
	}

	/* Load/generate persistent node UUID */
	rc = load_or_generate_uuid(local_node_uuid);
	if (rc < 0) {
		fprintf(stderr, "mxfsd: failed to load/generate "
		        "node UUID: %s\n", strerror(-rc));
		return 1;
	}

	char uuid_str[48];
	uuid_to_string(local_node_uuid, uuid_str, sizeof(uuid_str));

	char vol_uuid_str[48];
	uuid_to_string(local_volume_uuid, vol_uuid_str, sizeof(vol_uuid_str));

	/* Build config from command-line args */
	mxfsd_config_set_defaults(&config);
	sub_init[SUB_CONFIG] = true;
	config.node_id = uuid_to_node_id(local_node_uuid);
	gethostname(config.node_name, sizeof(config.node_name));
	config.bind_port = tcp_port;
	strncpy(config.bind_addr, "0.0.0.0", sizeof(config.bind_addr));
	config.daemonize = false;
	config.log_to_syslog = true;
	config.log_level = LOG_INFO;

	/* Add the device as a volume */
	config.volume_count = 1;
	strncpy(config.volumes[0].device, device_path,
	        sizeof(config.volumes[0].device) - 1);
	snprintf(config.volumes[0].name,
	         sizeof(config.volumes[0].name), "vol0");

	/* Init logging (syslog for kernel-spawned daemon) */
	rc = mxfsd_log_init(config.log_file, config.log_level,
			    config.log_to_syslog);
	if (rc) {
		fprintf(stderr, "mxfsd: log init failed\n");
		return 1;
	}
	sub_init[SUB_LOG] = true;

	mxfsd_info("mxfsd v%d.%d.%d starting — node %u (%s)",
		   MXFS_VERSION_MAJOR, MXFS_VERSION_MINOR, MXFS_VERSION_PATCH,
		   config.node_id, config.node_name);
	mxfsd_info("device %s, mountpoint %s, volume %s, port %u",
	           device_path, mountpoint, vol_uuid_str, tcp_port);

	setup_signals();

	/* Initialize pending request slots */
	memset(pending, 0, sizeof(pending));

	/* Compute discovery parameters for init_subsystems.
	 * Pass NULL when empty to let discovery use defaults. */
	const char *iface_arg = iface[0] ? iface : NULL;
	const char *disc_addr = NULL;
	bool disc_bcast = false;

	if (broadcast_addr[0]) {
		disc_addr = broadcast_addr;
		disc_bcast = true;
	} else if (multicast_addr[0]) {
		disc_addr = multicast_addr;
		disc_bcast = false;
	}

	/* Init all subsystems */
	rc = init_subsystems(mountpoint, iface_arg, disc_addr, disc_bcast);
	if (rc) {
		mxfsd_err("subsystem initialization failed");
		shutdown_subsystems();
		mxfsd_log_shutdown();
		return 1;
	}

	/* Signal kernel that daemon is ready */
	rc = mxfsd_netlink_send_daemon_ready(&nl_ctx, config.node_id,
	                                     local_volume_uuid);
	if (rc < 0)
		mxfsd_warn("failed to send daemon ready (rc=%d) — "
		           "kernel may not be listening yet", rc);

	mxfsd_info("mxfsd fully initialized — entering main loop");

	/* ── Main loop ────────────────────────────────────────────── */
	running = 1;
	int reconnect_counter = 0;
	while (running) {
		/* Periodically retry connections to disconnected peers
		 * and refresh the active node list so resource mastering
		 * reflects the current membership. */
		reconnect_counter++;
		if (reconnect_counter >= 20) {  /* every ~5 seconds */
			reconnect_counter = 0;

			/* Retry dynamically-added peers (lower ID convention) */
			for (int i = 0; i < peer_ctx.peer_count; i++) {
				struct mxfsd_peer *p = &peer_ctx.peers[i];
				if (p->node_id >= config.node_id)
					continue;
				if (p->state != MXFSD_CONN_ACTIVE)
					mxfsd_peer_connect(&peer_ctx,
					                   p->node_id);
			}

			update_active_node_list();
		}

		/* Sleep in small intervals so we respond to signals promptly */
		usleep(250000);  /* 250ms */
	}

	/* ── Shutdown ─────────────────────────────────────────────── */
	mxfsd_notice("mxfsd shutting down");

	/* Release journal slot before shutting down peers */
	mxfsd_journal_release_slot(&journal_ctx);

	shutdown_subsystems();

	mxfsd_info("mxfsd shutdown complete");
	mxfsd_log_shutdown();

	return 0;
}
