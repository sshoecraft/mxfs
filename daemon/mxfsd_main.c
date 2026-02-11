/*
 * MXFS — Multinode XFS
 * Daemon entry point
 *
 * mxfsd is the userspace daemon that runs on each node participating in
 * an MXFS cluster. It manages peer connections, runs the DLM protocol,
 * and communicates with the local mxfs.ko kernel module via generic netlink.
 *
 * Usage: mxfsd start --config /etc/mxfs/volumes.conf
 *        mxfsd stop
 *        mxfsd status
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

#define MXFSD_PID_FILE    "/var/run/mxfsd.pid"
#define MXFSD_CTRL_SOCKET "/var/run/mxfsd.sock"
#define MXFSD_DLM_BUCKETS 1024
#define MXFSD_DEFAULT_CONF "/etc/mxfs/volumes.conf"

static volatile sig_atomic_t running;
static volatile sig_atomic_t reload;

static struct mxfsd_config      config;
static struct mxfsd_peer_ctx    peer_ctx;
static struct mxfsd_dlm_ctx     dlm_ctx;
static struct mxfsd_netlink_ctx nl_ctx;
static struct mxfsd_journal_ctx journal_ctx;
static struct mxfsd_volume_ctx  volume_ctx;

/* Control socket for local test tools */
static int ctrl_fd = -1;
static pthread_t ctrl_thread_id;

/* Track which subsystems initialized for orderly shutdown */
enum subsystem {
	SUB_LOG = 0,
	SUB_CONFIG,
	SUB_VOLUME,
	SUB_DLM,
	SUB_NETLINK,
	SUB_PEER,
	SUB_JOURNAL,
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

/* ─── Master determination ────────────────────────────────
 *
 * For simplicity: the node with the lowest ID in the cluster
 * is the master for ALL resources. The master maintains the
 * authoritative DLM lock table.
 */

static bool is_master(void)
{
	for (int i = 0; i < config.peer_count; i++) {
		if (config.peers[i].node_id < config.node_id)
			return false;
	}
	return true;
}

static mxfs_node_id_t get_master_id(void)
{
	mxfs_node_id_t master = config.node_id;
	for (int i = 0; i < config.peer_count; i++) {
		if (config.peers[i].node_id < master)
			master = config.peers[i].node_id;
	}
	return master;
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
		/* A peer is requesting a lock. We must be the master. */
		if (!is_master()) {
			mxfsd_warn("received LOCK_REQ from node %u but "
			           "not master", sender);
			break;
		}

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
			/* Immediately granted */
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
		/* A peer is releasing a lock. Process on master. */
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

		if (is_master()) {
			mxfsd_dlm_lock_release(&dlm_ctx, &rel.resource,
			                       sender);
			/* Promotions handled by the grant callback */
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
	if (is_master()) {
		/* We are the master — process locally */
		int rc = mxfsd_dlm_lock_request(&dlm_ctx, resource,
		                                 config.node_id, mode, flags);
		if (rc == 0) {
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
		/* Forward to the master node */
		mxfs_node_id_t master = get_master_id();
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
	if (is_master()) {
		mxfsd_dlm_lock_release(&dlm_ctx, resource, config.node_id);
		/* Promotions handled by the grant callback */
	} else {
		mxfs_node_id_t master = get_master_id();
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

/* ─── Signal handling ───────────────────────────────────── */

static void signal_handler(int sig)
{
	if (sig == SIGHUP)
		reload = 1;
	else
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
	sigaction(SIGHUP, &sa, NULL);

	/* Ignore SIGPIPE — peer sockets may close unexpectedly */
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s start [--config <path>] [--foreground]\n"
		"       %s stop\n"
		"       %s status\n"
		"\n"
		"Options:\n"
		"  --config, -c <path>   Config file (default: %s)\n"
		"  --foreground, -f      Run in foreground (don't daemonize)\n"
		"  --help, -h            Show this help\n",
		prog, prog, prog, MXFSD_DEFAULT_CONF);
}

static int write_pid_file(void)
{
	FILE *fp = fopen(MXFSD_PID_FILE, "w");
	if (!fp) {
		mxfsd_warn("cannot write pid file '%s': %s",
			   MXFSD_PID_FILE, strerror(errno));
		return -1;
	}
	fprintf(fp, "%d\n", getpid());
	fclose(fp);
	return 0;
}

static void remove_pid_file(void)
{
	unlink(MXFSD_PID_FILE);
}

static int daemonize(void)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "mxfsd: fork failed: %s\n", strerror(errno));
		return -1;
	}
	if (pid > 0)
		_exit(0);  /* parent exits */

	if (setsid() < 0)
		return -1;

	/* Second fork to prevent acquiring a controlling terminal */
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		_exit(0);

	/* Redirect stdio to /dev/null */
	int devnull = open("/dev/null", O_RDWR);
	if (devnull >= 0) {
		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		if (devnull > STDERR_FILENO)
			close(devnull);
	}

	return 0;
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
			if (rc == 0 && is_master()) {
				/* Immediately granted on master */
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

	mxfsd_notice("node %u disconnected — purging locks and "
		     "initiating journal recovery", node);

	/* Purge all DLM locks held by the dead node */
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
	if (sub_init[SUB_VOLUME]) {
		mxfsd_volume_shutdown(&volume_ctx);
		sub_init[SUB_VOLUME] = false;
	}
	/* LOG stays up until the very end so shutdown messages are captured */
}

static int init_subsystems(void)
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

	/* Add configured peers */
	for (int i = 0; i < config.peer_count; i++) {
		mxfsd_peer_add(&peer_ctx,
			       config.peers[i].node_id,
			       config.peers[i].host,
			       config.peers[i].port);
	}

	/* Connect to peers with lower node IDs.
	 * Higher-ID nodes connect to us — this prevents simultaneous
	 * outbound connections between the same pair of nodes. */
	for (int i = 0; i < config.peer_count; i++) {
		if (config.peers[i].node_id >= config.node_id)
			continue;
		rc = mxfsd_peer_connect(&peer_ctx, config.peers[i].node_id);
		if (rc)
			mxfsd_warn("initial connect to node %u failed (will retry)",
				   config.peers[i].node_id);
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

	/* Control socket for local tools */
	rc = ctrl_init();
	if (rc)
		mxfsd_warn("control socket init failed (non-fatal): %d", rc);

	mxfsd_info("dlm: this node is %s",
	           is_master() ? "MASTER" : "NON-MASTER");

	return 0;
}

/* ─── Main ──────────────────────────────────────────────── */

int main(int argc, char **argv)
{
	const char *config_path = MXFSD_DEFAULT_CONF;
	const char *command = NULL;
	int foreground = 0;
	int rc;

	static struct option long_opts[] = {
		{ "config",     required_argument, NULL, 'c' },
		{ "foreground", no_argument,       NULL, 'f' },
		{ "help",       no_argument,       NULL, 'h' },
		{ NULL,         0,                 NULL,  0  },
	};

	/* Parse command */
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	command = argv[1];

	/* Parse options (skip command word) */
	optind = 2;
	int opt;
	while ((opt = getopt_long(argc, argv, "c:fh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			config_path = optarg;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (strcmp(command, "stop") == 0) {
		/* Read PID file and send SIGTERM */
		FILE *fp = fopen(MXFSD_PID_FILE, "r");
		if (!fp) {
			fprintf(stderr, "mxfsd: not running (no pid file)\n");
			return 1;
		}
		int pid = 0;
		if (fscanf(fp, "%d", &pid) != 1 || pid <= 0) {
			fprintf(stderr, "mxfsd: invalid pid file\n");
			fclose(fp);
			return 1;
		}
		fclose(fp);
		if (kill(pid, SIGTERM) < 0) {
			fprintf(stderr, "mxfsd: kill(%d, SIGTERM): %s\n",
				pid, strerror(errno));
			return 1;
		}
		printf("mxfsd: sent SIGTERM to pid %d\n", pid);
		return 0;
	}

	if (strcmp(command, "status") == 0) {
		FILE *fp = fopen(MXFSD_PID_FILE, "r");
		if (!fp) {
			printf("mxfsd: not running\n");
			return 1;
		}
		int pid = 0;
		if (fscanf(fp, "%d", &pid) != 1 || pid <= 0) {
			printf("mxfsd: invalid pid file\n");
			fclose(fp);
			return 1;
		}
		fclose(fp);
		if (kill(pid, 0) == 0) {
			printf("mxfsd: running (pid %d)\n", pid);
			return 0;
		}
		printf("mxfsd: stale pid file (pid %d not running)\n", pid);
		return 1;
	}

	if (strcmp(command, "start") != 0) {
		fprintf(stderr, "mxfsd: unknown command '%s'\n", command);
		usage(argv[0]);
		return 1;
	}

	/* ── Start command ────────────────────────────────────────── */

	/* Set config defaults, then load config file */
	mxfsd_config_set_defaults(&config);
	sub_init[SUB_CONFIG] = true;

	rc = mxfsd_config_load(&config, config_path);
	if (rc) {
		fprintf(stderr, "mxfsd: failed to load config '%s'\n",
			config_path);
		return 1;
	}

	/* Init logging early so everything else can log */
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

	mxfsd_config_dump(&config);

	/* Daemonize unless --foreground */
	if (!foreground && config.daemonize) {
		if (daemonize() < 0) {
			mxfsd_err("daemonize failed");
			return 1;
		}
	}

	setup_signals();
	write_pid_file();

	/* Initialize pending request slots */
	memset(pending, 0, sizeof(pending));

	/* Init all subsystems */
	rc = init_subsystems();
	if (rc) {
		mxfsd_err("subsystem initialization failed");
		shutdown_subsystems();
		mxfsd_log_shutdown();
		remove_pid_file();
		return 1;
	}

	mxfsd_info("mxfsd fully initialized — entering main loop");

	/* ── Main loop ────────────────────────────────────────────── */
	running = 1;
	int reconnect_counter = 0;
	while (running) {
		if (reload) {
			reload = 0;
			mxfsd_notice("SIGHUP received — reloading config");

			struct mxfsd_config new_cfg;
			mxfsd_config_set_defaults(&new_cfg);
			if (mxfsd_config_load(&new_cfg, config_path) == 0) {
				/* Update log level dynamically */
				mxfsd_log_set_level(new_cfg.log_level);
				mxfsd_info("config reloaded successfully");
			} else {
				mxfsd_warn("config reload failed, "
					   "keeping current config");
			}
		}

		/* Periodically retry connections to disconnected peers.
		 * Only connect to peers with lower IDs (convention). */
		reconnect_counter++;
		if (reconnect_counter >= 20) {  /* every ~5 seconds */
			reconnect_counter = 0;
			for (int i = 0; i < config.peer_count; i++) {
				if (config.peers[i].node_id >= config.node_id)
					continue;
				struct mxfsd_peer *p = mxfsd_peer_find(
					&peer_ctx, config.peers[i].node_id);
				if (p && p->state != MXFSD_CONN_ACTIVE)
					mxfsd_peer_connect(&peer_ctx,
						config.peers[i].node_id);
			}
		}

		/* Sleep in small intervals so we respond to signals promptly */
		usleep(250000);  /* 250ms */
	}

	/* ── Shutdown ─────────────────────────────────────────────── */
	mxfsd_notice("mxfsd shutting down");

	/* Release journal slot before shutting down peers */
	mxfsd_journal_release_slot(&journal_ctx);

	shutdown_subsystems();

	remove_pid_file();

	mxfsd_info("mxfsd shutdown complete");
	mxfsd_log_shutdown();

	return 0;
}
