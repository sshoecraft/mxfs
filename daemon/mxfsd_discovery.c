/*
 * MXFS — Multinode XFS
 * UDP peer discovery
 *
 * Automatic peer discovery over UDP multicast or broadcast.
 * Two threads: sender broadcasts periodic announcements, receiver
 * listens for announcements from other nodes and fires a callback
 * when a new peer with a matching volume UUID is detected.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>

#include "mxfsd_discovery.h"
#include "mxfsd_log.h"

/* Get monotonic time in milliseconds */
static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Compare two 16-byte UUIDs */
static int uuid_equal(const uint8_t *a, const uint8_t *b)
{
	return memcmp(a, b, 16) == 0;
}

/* Format a UUID as hex string for logging */
static void uuid_to_str(const uint8_t *uuid, char *buf, size_t buflen)
{
	snprintf(buf, buflen,
	         "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
	         "%02x%02x-%02x%02x%02x%02x%02x%02x",
	         uuid[0], uuid[1], uuid[2], uuid[3],
	         uuid[4], uuid[5], uuid[6], uuid[7],
	         uuid[8], uuid[9], uuid[10], uuid[11],
	         uuid[12], uuid[13], uuid[14], uuid[15]);
}

/*
 * Find a peer in the seen list by node_id.
 * Caller must hold ctx->lock.
 * Returns index, or -1 if not found.
 */
static int seen_find(struct mxfsd_discovery_ctx *ctx, mxfs_node_id_t node_id)
{
	for (int i = 0; i < ctx->seen_count; i++) {
		if (ctx->seen[i].node_id == node_id)
			return i;
	}
	return -1;
}

/*
 * Add or update a peer in the seen list.
 * Caller must hold ctx->lock.
 * Returns 1 if this is a newly added peer, 0 if already known.
 */
static int seen_update(struct mxfsd_discovery_ctx *ctx,
                       mxfs_node_id_t node_id, uint64_t ts)
{
	int idx = seen_find(ctx, node_id);
	if (idx >= 0) {
		ctx->seen[idx].last_seen_ms = ts;
		return 0;
	}

	if (ctx->seen_count >= MXFS_MAX_NODES) {
		mxfsd_warn("discovery: seen list full, cannot track "
		           "node %u", node_id);
		return 0;
	}

	ctx->seen[ctx->seen_count].node_id = node_id;
	ctx->seen[ctx->seen_count].last_seen_ms = ts;
	ctx->seen_count++;
	return 1;
}

/*
 * Create and configure the UDP socket for discovery.
 * Sets up multicast or broadcast depending on ctx->use_broadcast.
 */
static int setup_socket(struct mxfsd_discovery_ctx *ctx)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		mxfsd_err("discovery: socket() failed: %s", strerror(errno));
		return -errno;
	}

	/* Allow multiple processes on same port (for testing) */
	int val = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
	               sizeof(val)) < 0) {
		mxfsd_warn("discovery: SO_REUSEADDR failed: %s",
		           strerror(errno));
	}

	/* Bind to INADDR_ANY on the discovery port */
	struct sockaddr_in bind_addr;
	memset(&bind_addr, 0, sizeof(bind_addr));
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(ctx->port);
	bind_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
		mxfsd_err("discovery: bind(INADDR_ANY:%u) failed: %s",
		          ctx->port, strerror(errno));
		close(fd);
		return -errno;
	}

	if (ctx->use_broadcast) {
		/* Broadcast mode */
		val = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &val,
		               sizeof(val)) < 0) {
			mxfsd_err("discovery: SO_BROADCAST failed: %s",
			          strerror(errno));
			close(fd);
			return -errno;
		}
		mxfsd_info("discovery: broadcast mode, target %s:%u",
		           ctx->mcast_addr, ctx->port);
	} else {
		/* Multicast mode — join the group */
		struct ip_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		if (inet_pton(AF_INET, ctx->mcast_addr,
		              &mreq.imr_multiaddr) != 1) {
			mxfsd_err("discovery: invalid multicast address '%s'",
			          ctx->mcast_addr);
			close(fd);
			return -EINVAL;
		}
		mreq.imr_interface.s_addr = INADDR_ANY;

		if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
		               sizeof(mreq)) < 0) {
			mxfsd_err("discovery: IP_ADD_MEMBERSHIP failed: %s",
			          strerror(errno));
			close(fd);
			return -errno;
		}

		/* TTL = 1 for link-local only */
		uint8_t ttl = 1;
		if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
		               sizeof(ttl)) < 0) {
			mxfsd_warn("discovery: IP_MULTICAST_TTL failed: %s",
			           strerror(errno));
		}

		/* Enable loopback for single-host testing */
		uint8_t loop = 1;
		if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop,
		               sizeof(loop)) < 0) {
			mxfsd_warn("discovery: IP_MULTICAST_LOOP failed: %s",
			           strerror(errno));
		}

		/* If interface specified, bind multicast output to it */
		if (ctx->iface[0] != '\0') {
			unsigned int ifidx = if_nametoindex(ctx->iface);
			if (ifidx == 0) {
				mxfsd_err("discovery: unknown interface '%s'",
				          ctx->iface);
				close(fd);
				return -ENODEV;
			}
			struct ip_mreqn mreqn;
			memset(&mreqn, 0, sizeof(mreqn));
			mreqn.imr_ifindex = (int)ifidx;
			if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
			               &mreqn, sizeof(mreqn)) < 0) {
				mxfsd_warn("discovery: IP_MULTICAST_IF "
				           "failed: %s", strerror(errno));
			}
		}

		mxfsd_info("discovery: multicast mode, group %s:%u",
		           ctx->mcast_addr, ctx->port);
	}

	return fd;
}

/*
 * Sender thread: periodically sends discovery announcements.
 * Sleeps in 100ms increments so it can exit cleanly.
 */
static void *sender_thread_fn(void *arg)
{
	struct mxfsd_discovery_ctx *ctx = arg;

	/* Build destination address */
	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(ctx->port);
	inet_pton(AF_INET, ctx->mcast_addr, &dest.sin_addr);

	char uuid_str[48];
	uuid_to_str(ctx->local_announce.node_uuid, uuid_str, sizeof(uuid_str));
	mxfsd_info("discovery: sender thread started "
	           "(interval %d ms, node %s)",
	           MXFS_DISCOVERY_INTERVAL_MS, uuid_str);

	while (ctx->running) {
		/* Send the announcement */
		ssize_t sent = sendto(ctx->sockfd, &ctx->local_announce,
		                      sizeof(ctx->local_announce), 0,
		                      (struct sockaddr *)&dest, sizeof(dest));
		if (sent < 0) {
			mxfsd_warn("discovery: sendto failed: %s",
			           strerror(errno));
		} else {
			mxfsd_dbg("discovery: sent announcement (%zd bytes)",
			          sent);
		}

		/* Sleep in 100ms increments for clean shutdown */
		uint64_t end = now_ms() + MXFS_DISCOVERY_INTERVAL_MS;
		while (ctx->running && now_ms() < end) {
			struct timespec ts = {
				.tv_sec = 0,
				.tv_nsec = 100000000, /* 100ms */
			};
			nanosleep(&ts, NULL);
		}
	}

	mxfsd_info("discovery: sender thread exiting");
	return NULL;
}

/*
 * Receiver thread: listens for discovery announcements from peers.
 * Uses poll() with 500ms timeout. Validates packets, ignores self,
 * checks volume UUID match, and fires callback for new peers.
 */
static void *receiver_thread_fn(void *arg)
{
	struct mxfsd_discovery_ctx *ctx = arg;

	mxfsd_info("discovery: receiver thread started");

	while (ctx->running) {
		struct pollfd pfd = {
			.fd = ctx->sockfd,
			.events = POLLIN,
		};

		int ret = poll(&pfd, 1, 500);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			mxfsd_err("discovery: poll failed: %s",
			          strerror(errno));
			break;
		}
		if (ret == 0)
			continue;

		/* Read the announcement */
		struct sockaddr_in sender_addr;
		socklen_t addrlen = sizeof(sender_addr);
		struct mxfsd_discovery_announce pkt;

		ssize_t n = recvfrom(ctx->sockfd, &pkt, sizeof(pkt), 0,
		                     (struct sockaddr *)&sender_addr,
		                     &addrlen);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			mxfsd_warn("discovery: recvfrom failed: %s",
			           strerror(errno));
			continue;
		}

		if ((size_t)n < sizeof(pkt)) {
			mxfsd_dbg("discovery: short packet (%zd bytes, "
			          "expected %zu)", n, sizeof(pkt));
			continue;
		}

		/* Validate magic */
		if (pkt.magic != MXFS_DISCOVERY_MAGIC) {
			mxfsd_dbg("discovery: bad magic 0x%08x", pkt.magic);
			continue;
		}

		/* Validate version */
		if (pkt.version != MXFS_DISCOVERY_VERSION) {
			mxfsd_dbg("discovery: version mismatch "
			          "(got %u, want %u)",
			          pkt.version, MXFS_DISCOVERY_VERSION);
			continue;
		}

		/* Ignore our own announcements */
		if (uuid_equal(pkt.node_uuid,
		               ctx->local_announce.node_uuid))
			continue;

		/* Check volume UUID matches ours */
		if (!uuid_equal(pkt.volume_uuid,
		                ctx->local_announce.volume_uuid)) {
			char their_vol[48], our_vol[48];
			uuid_to_str(pkt.volume_uuid, their_vol,
			            sizeof(their_vol));
			uuid_to_str(ctx->local_announce.volume_uuid,
			            our_vol, sizeof(our_vol));
			mxfsd_dbg("discovery: volume mismatch from node %u "
			          "(theirs=%s, ours=%s)",
			          pkt.node_id, their_vol, our_vol);
			continue;
		}

		/* Get sender IP address */
		char ipstr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &sender_addr.sin_addr, ipstr,
		          sizeof(ipstr));

		/* Check if this is a new peer */
		uint64_t ts = now_ms();
		int is_new;

		pthread_mutex_lock(&ctx->lock);
		is_new = seen_update(ctx, pkt.node_id, ts);
		pthread_mutex_unlock(&ctx->lock);

		if (is_new) {
			char node_str[48];
			uuid_to_str(pkt.node_uuid, node_str,
			            sizeof(node_str));
			mxfsd_notice("discovery: new peer detected — "
			             "node %u (%s) at %s:%u [%s]",
			             pkt.node_id, pkt.hostname,
			             ipstr, pkt.tcp_port, node_str);

			if (ctx->peer_cb) {
				ctx->peer_cb(pkt.node_uuid, pkt.node_id,
				             ipstr, pkt.tcp_port,
				             pkt.volume_uuid,
				             pkt.volume_id,
				             ctx->peer_cb_data);
			}
		}
	}

	mxfsd_info("discovery: receiver thread exiting");
	return NULL;
}

int mxfsd_discovery_init(struct mxfsd_discovery_ctx *ctx,
                          const struct mxfsd_discovery_announce *local,
                          const char *mcast_addr, uint16_t port,
                          const char *iface, bool use_broadcast)
{
	if (!ctx || !local)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->sockfd = -1;
	ctx->running = false;
	ctx->peer_cb = NULL;
	ctx->peer_cb_data = NULL;
	ctx->seen_count = 0;

	/* Copy local announcement data */
	ctx->local_announce = *local;

	/* Use defaults if not specified */
	ctx->port = port > 0 ? port : MXFS_DISCOVERY_PORT;
	ctx->use_broadcast = use_broadcast;

	if (mcast_addr && mcast_addr[0] != '\0') {
		strncpy(ctx->mcast_addr, mcast_addr,
		        sizeof(ctx->mcast_addr) - 1);
		ctx->mcast_addr[sizeof(ctx->mcast_addr) - 1] = '\0';
	} else {
		strncpy(ctx->mcast_addr, MXFS_DISCOVERY_MCAST,
		        sizeof(ctx->mcast_addr) - 1);
		ctx->mcast_addr[sizeof(ctx->mcast_addr) - 1] = '\0';
	}

	if (iface && iface[0] != '\0') {
		strncpy(ctx->iface, iface, sizeof(ctx->iface) - 1);
		ctx->iface[sizeof(ctx->iface) - 1] = '\0';
	} else {
		ctx->iface[0] = '\0';
	}

	int rc = pthread_mutex_init(&ctx->lock, NULL);
	if (rc != 0) {
		mxfsd_err("discovery: pthread_mutex_init failed: %s",
		          strerror(rc));
		return -rc;
	}

	/* Create and configure the UDP socket */
	int fd = setup_socket(ctx);
	if (fd < 0) {
		pthread_mutex_destroy(&ctx->lock);
		return fd;
	}
	ctx->sockfd = fd;

	char uuid_str[48];
	uuid_to_str(local->node_uuid, uuid_str, sizeof(uuid_str));
	mxfsd_info("discovery: initialized for node %u (%s) on %s:%u",
	           local->node_id, uuid_str,
	           ctx->use_broadcast ? "broadcast" : ctx->mcast_addr,
	           ctx->port);

	return 0;
}

void mxfsd_discovery_shutdown(struct mxfsd_discovery_ctx *ctx)
{
	if (!ctx)
		return;

	mxfsd_discovery_stop(ctx);

	if (ctx->sockfd >= 0) {
		close(ctx->sockfd);
		ctx->sockfd = -1;
	}

	pthread_mutex_destroy(&ctx->lock);

	mxfsd_info("discovery: shutdown complete");
}

int mxfsd_discovery_start(struct mxfsd_discovery_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	if (ctx->sockfd < 0) {
		mxfsd_err("discovery: cannot start, socket not initialized");
		return -EBADF;
	}

	ctx->running = true;

	int rc = pthread_create(&ctx->sender_thread, NULL,
	                        sender_thread_fn, ctx);
	if (rc != 0) {
		mxfsd_err("discovery: failed to create sender thread: %s",
		          strerror(rc));
		ctx->running = false;
		return -rc;
	}

	rc = pthread_create(&ctx->receiver_thread, NULL,
	                    receiver_thread_fn, ctx);
	if (rc != 0) {
		mxfsd_err("discovery: failed to create receiver thread: %s",
		          strerror(rc));
		ctx->running = false;
		pthread_join(ctx->sender_thread, NULL);
		return -rc;
	}

	mxfsd_info("discovery: started sender and receiver threads");
	return 0;
}

void mxfsd_discovery_stop(struct mxfsd_discovery_ctx *ctx)
{
	if (!ctx || !ctx->running)
		return;

	ctx->running = false;

	pthread_join(ctx->sender_thread, NULL);
	pthread_join(ctx->receiver_thread, NULL);

	mxfsd_info("discovery: stopped");
}

void mxfsd_discovery_set_peer_cb(struct mxfsd_discovery_ctx *ctx,
                                  mxfsd_discovery_peer_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->peer_cb = cb;
	ctx->peer_cb_data = data;
}
