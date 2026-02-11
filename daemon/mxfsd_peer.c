/*
 * MXFS — Multinode XFS
 * Peer connection management
 *
 * Manages TCP connections between mxfsd instances on different nodes.
 * Handles listener socket, outgoing connections, reconnection logic,
 * and message framing (length-prefixed with mxfs_dlm_msg_hdr).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netdb.h>

#include "mxfsd_peer.h"
#include "mxfsd_dlm.h"
#include "mxfsd_log.h"

/* Get monotonic time in milliseconds */
static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Set a file descriptor to non-blocking mode */
static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Set TCP keepalive and nodelay on a connected socket */
static void set_socket_opts(int fd)
{
	int val = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
}

/*
 * Read exactly 'len' bytes from fd into buf.
 * Returns 0 on success, -1 on error/EOF.
 */
static int read_exact(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t remaining = len;

	while (remaining > 0) {
		ssize_t n = read(fd, p, remaining);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1; /* EOF */
		p += n;
		remaining -= (size_t)n;
	}
	return 0;
}

/*
 * Write exactly 'len' bytes from buf to fd.
 * Returns 0 on success, -1 on error.
 */
static int write_exact(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t remaining = len;

	while (remaining > 0) {
		ssize_t n = write(fd, p, remaining);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		remaining -= (size_t)n;
	}
	return 0;
}

/*
 * Accept thread: listens for incoming peer connections.
 * When a peer connects, reads the NODE_JOIN message to identify it,
 * then associates the socket with the correct peer entry.
 */
static void *accept_thread_fn(void *arg)
{
	struct mxfsd_peer_ctx *ctx = arg;

	mxfsd_info("peer: accept thread started on fd %d", ctx->listen_fd);

	while (ctx->running) {
		struct pollfd pfd = {
			.fd = ctx->listen_fd,
			.events = POLLIN,
		};

		int ret = poll(&pfd, 1, 500);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			mxfsd_err("peer: accept poll failed: %s",
			          strerror(errno));
			break;
		}
		if (ret == 0)
			continue;

		struct sockaddr_in addr;
		socklen_t addrlen = sizeof(addr);
		int fd = accept(ctx->listen_fd, (struct sockaddr *)&addr,
		                &addrlen);
		if (fd < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			mxfsd_err("peer: accept failed: %s", strerror(errno));
			continue;
		}

		set_socket_opts(fd);

		char ipstr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &addr.sin_addr, ipstr, sizeof(ipstr));
		mxfsd_info("peer: incoming connection from %s:%d (fd %d)",
		           ipstr, ntohs(addr.sin_port), fd);

		/* Read the full handshake message (NODE_JOIN) */
		struct mxfs_dlm_node_msg join;
		if (read_exact(fd, &join, sizeof(join)) < 0) {
			mxfsd_warn("peer: failed to read handshake from %s",
			           ipstr);
			close(fd);
			continue;
		}

		if (join.hdr.magic != MXFS_DLM_MAGIC) {
			mxfsd_warn("peer: bad magic 0x%08x from %s",
			           join.hdr.magic, ipstr);
			close(fd);
			continue;
		}

		if (join.hdr.type != MXFS_MSG_NODE_JOIN) {
			mxfsd_warn("peer: expected NODE_JOIN (got %u) from %s",
			           join.hdr.type, ipstr);
			close(fd);
			continue;
		}

		mxfs_node_id_t sender = join.hdr.sender;

		/* Find or associate this socket with the peer */
		struct mxfsd_peer *peer = mxfsd_peer_find(ctx, sender);
		if (!peer) {
			mxfsd_warn("peer: connection from unknown node %u, "
			           "rejecting", sender);
			close(fd);
			continue;
		}

		pthread_mutex_lock(&peer->send_lock);
		if (peer->sockfd >= 0) {
			mxfsd_info("peer: closing old connection to node %u "
			           "(fd %d), replacing with fd %d",
			           sender, peer->sockfd, fd);
			close(peer->sockfd);
		}
		peer->sockfd = fd;
		peer->state = MXFSD_CONN_ACTIVE;
		peer->last_seen_ms = now_ms();
		peer->last_epoch = join.hdr.epoch;
		peer->recv_seq = join.hdr.seq;
		pthread_mutex_unlock(&peer->send_lock);

		mxfsd_info("peer: node %u (%s) connected", sender, peer->name);
	}

	mxfsd_info("peer: accept thread exiting");
	return NULL;
}

/*
 * Mark a peer as disconnected and fire the disconnect callback.
 * Caller must NOT hold peer->send_lock.
 */
static void peer_handle_disconnect(struct mxfsd_peer_ctx *ctx,
                                   struct mxfsd_peer *peer)
{
	mxfs_node_id_t node = peer->node_id;

	pthread_mutex_lock(&peer->send_lock);
	if (peer->sockfd >= 0) {
		close(peer->sockfd);
		peer->sockfd = -1;
	}
	peer->state = MXFSD_CONN_DISCONNECTED;
	pthread_mutex_unlock(&peer->send_lock);

	if (ctx->disconnect_cb)
		ctx->disconnect_cb(node, ctx->disconnect_cb_data);
}

/*
 * Receive thread: polls all active peer sockets for incoming messages.
 * Reads complete framed messages (header then payload if any).
 */
static void *recv_thread_fn(void *arg)
{
	struct mxfsd_peer_ctx *ctx = arg;
	struct pollfd pfds[MXFS_MAX_NODES];

	mxfsd_info("peer: receive thread started");

	while (ctx->running) {
		int nfds = 0;
		mxfs_node_id_t fdmap[MXFS_MAX_NODES];

		/* Build pollfd array from active peers */
		for (int i = 0; i < ctx->peer_count; i++) {
			struct mxfsd_peer *p = &ctx->peers[i];
			if (p->state == MXFSD_CONN_ACTIVE && p->sockfd >= 0) {
				pfds[nfds].fd = p->sockfd;
				pfds[nfds].events = POLLIN;
				pfds[nfds].revents = 0;
				fdmap[nfds] = p->node_id;
				nfds++;
			}
		}

		if (nfds == 0) {
			/* No active connections, sleep briefly */
			struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000 };
			nanosleep(&ts, NULL);
			continue;
		}

		int ret = poll(pfds, (nfds_t)nfds, 250);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			mxfsd_err("peer: recv poll failed: %s",
			          strerror(errno));
			break;
		}
		if (ret == 0)
			continue;

		for (int i = 0; i < nfds; i++) {
			if (!(pfds[i].revents & (POLLIN | POLLHUP | POLLERR)))
				continue;

			struct mxfsd_peer *peer = mxfsd_peer_find(ctx,
			                                          fdmap[i]);
			if (!peer)
				continue;

			/* Read message header */
			struct mxfs_dlm_msg_hdr hdr;
			if (read_exact(pfds[i].fd, &hdr, sizeof(hdr)) < 0) {
				mxfsd_warn("peer: read failed from node %u, "
				           "disconnecting", peer->node_id);
				peer_handle_disconnect(ctx, peer);
				continue;
			}

			if (hdr.magic != MXFS_DLM_MAGIC) {
				mxfsd_warn("peer: bad magic 0x%08x from "
				           "node %u", hdr.magic, peer->node_id);
				peer_handle_disconnect(ctx, peer);
				continue;
			}

			/* Read remaining payload if message is larger than header */
			uint32_t payload_len = hdr.length > sizeof(hdr) ?
				hdr.length - sizeof(hdr) : 0;

			uint8_t payload[4096];
			if (payload_len > 0) {
				if (payload_len > sizeof(payload)) {
					mxfsd_err("peer: message too large "
					          "(%u bytes) from node %u",
					          hdr.length, peer->node_id);
					peer_handle_disconnect(ctx, peer);
					continue;
				}
				if (read_exact(pfds[i].fd, payload,
				               payload_len) < 0) {
					mxfsd_warn("peer: payload read failed "
					           "from node %u",
					           peer->node_id);
					peer_handle_disconnect(ctx, peer);
					continue;
				}
			}

			peer->last_seen_ms = now_ms();
			peer->last_epoch = hdr.epoch;
			peer->recv_seq = hdr.seq;

			mxfsd_dbg("peer: received msg type %u seq %u from "
			          "node %u (%u bytes)",
			          hdr.type, hdr.seq, hdr.sender, hdr.length);

			/* Dispatch to message callback */
			if (ctx->msg_cb) {
				ctx->msg_cb(hdr.sender, &hdr,
				            payload_len > 0 ? payload : NULL,
				            payload_len, ctx->msg_cb_data);
			}
		}
	}

	mxfsd_info("peer: receive thread exiting");
	return NULL;
}

int mxfsd_peer_init(struct mxfsd_peer_ctx *ctx, mxfs_node_id_t local_id,
                    const char *bind_addr, uint16_t bind_port)
{
	if (!ctx || !bind_addr)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->local_node_id = local_id;
	ctx->peer_count = 0;
	ctx->running = false;
	ctx->listen_fd = -1;

	/* Initialize all peer slots */
	for (int i = 0; i < MXFS_MAX_NODES; i++) {
		ctx->peers[i].sockfd = -1;
		ctx->peers[i].state = MXFSD_CONN_DISCONNECTED;
		pthread_mutex_init(&ctx->peers[i].send_lock, NULL);
	}

	/* Create listener socket */
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		mxfsd_err("peer: socket() failed: %s", strerror(errno));
		return -errno;
	}

	int val = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(bind_port);

	if (strcmp(bind_addr, "0.0.0.0") == 0 ||
	    strcmp(bind_addr, "") == 0) {
		addr.sin_addr.s_addr = INADDR_ANY;
	} else {
		if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
			mxfsd_err("peer: invalid bind address '%s'", bind_addr);
			close(fd);
			return -EINVAL;
		}
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		mxfsd_err("peer: bind(%s:%u) failed: %s",
		          bind_addr, bind_port, strerror(errno));
		close(fd);
		return -errno;
	}

	if (listen(fd, 16) < 0) {
		mxfsd_err("peer: listen() failed: %s", strerror(errno));
		close(fd);
		return -errno;
	}

	set_nonblocking(fd);
	ctx->listen_fd = fd;
	ctx->running = true;

	/* Start accept and receive threads */
	int rc = pthread_create(&ctx->accept_thread, NULL,
	                        accept_thread_fn, ctx);
	if (rc != 0) {
		mxfsd_err("peer: failed to create accept thread: %s",
		          strerror(rc));
		close(fd);
		ctx->listen_fd = -1;
		ctx->running = false;
		return -rc;
	}

	rc = pthread_create(&ctx->recv_thread, NULL, recv_thread_fn, ctx);
	if (rc != 0) {
		mxfsd_err("peer: failed to create recv thread: %s",
		          strerror(rc));
		ctx->running = false;
		pthread_join(ctx->accept_thread, NULL);
		close(fd);
		ctx->listen_fd = -1;
		return -rc;
	}

	mxfsd_info("peer: listening on %s:%u (fd %d) for node %u",
	           bind_addr, bind_port, fd, local_id);
	return 0;
}

void mxfsd_peer_shutdown(struct mxfsd_peer_ctx *ctx)
{
	if (!ctx)
		return;

	ctx->running = false;

	/* Close listener to unblock accept */
	if (ctx->listen_fd >= 0) {
		close(ctx->listen_fd);
		ctx->listen_fd = -1;
	}

	/* Wait for threads */
	pthread_join(ctx->accept_thread, NULL);
	pthread_join(ctx->recv_thread, NULL);

	/* Close all peer connections */
	for (int i = 0; i < ctx->peer_count; i++) {
		struct mxfsd_peer *p = &ctx->peers[i];
		if (p->sockfd >= 0) {
			close(p->sockfd);
			p->sockfd = -1;
		}
		p->state = MXFSD_CONN_DISCONNECTED;
		pthread_mutex_destroy(&p->send_lock);
	}

	mxfsd_info("peer: shutdown complete");
}

int mxfsd_peer_add(struct mxfsd_peer_ctx *ctx, mxfs_node_id_t id,
                   const char *host, uint16_t port)
{
	if (!ctx || !host)
		return -EINVAL;

	if (ctx->peer_count >= MXFS_MAX_NODES) {
		mxfsd_err("peer: cannot add node %u, max peers (%d) reached",
		          id, MXFS_MAX_NODES);
		return -ENOSPC;
	}

	/* Check for duplicate */
	for (int i = 0; i < ctx->peer_count; i++) {
		if (ctx->peers[i].node_id == id) {
			mxfsd_warn("peer: node %u already registered", id);
			return -EEXIST;
		}
	}

	struct mxfsd_peer *p = &ctx->peers[ctx->peer_count];
	p->node_id = id;
	strncpy(p->host, host, sizeof(p->host) - 1);
	p->host[sizeof(p->host) - 1] = '\0';
	p->port = port;
	p->sockfd = -1;
	p->state = MXFSD_CONN_DISCONNECTED;
	p->send_seq = 0;
	p->recv_seq = 0;
	p->last_seen_ms = 0;
	p->last_epoch = 0;
	snprintf(p->name, sizeof(p->name), "node%u", id);

	ctx->peer_count++;

	mxfsd_info("peer: added node %u at %s:%u", id, host, port);
	return 0;
}

int mxfsd_peer_connect(struct mxfsd_peer_ctx *ctx, mxfs_node_id_t id)
{
	if (!ctx)
		return -EINVAL;

	struct mxfsd_peer *peer = mxfsd_peer_find(ctx, id);
	if (!peer) {
		mxfsd_err("peer: cannot connect to unknown node %u", id);
		return -ENOENT;
	}

	pthread_mutex_lock(&peer->send_lock);

	/* Already connected */
	if (peer->state == MXFSD_CONN_ACTIVE && peer->sockfd >= 0) {
		pthread_mutex_unlock(&peer->send_lock);
		return 0;
	}

	/* Close stale socket if any */
	if (peer->sockfd >= 0) {
		close(peer->sockfd);
		peer->sockfd = -1;
	}

	peer->state = MXFSD_CONN_CONNECTING;

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		mxfsd_err("peer: socket() for node %u failed: %s",
		          id, strerror(errno));
		peer->state = MXFSD_CONN_DISCONNECTED;
		pthread_mutex_unlock(&peer->send_lock);
		return -errno;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(peer->port);

	if (inet_pton(AF_INET, peer->host, &addr.sin_addr) != 1) {
		/* Try DNS resolution */
		struct addrinfo hints, *res;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;

		int rc = getaddrinfo(peer->host, NULL, &hints, &res);
		if (rc != 0) {
			mxfsd_err("peer: cannot resolve '%s': %s",
			          peer->host, gai_strerror(rc));
			close(fd);
			peer->state = MXFSD_CONN_DISCONNECTED;
			pthread_mutex_unlock(&peer->send_lock);
			return -ENOENT;
		}
		struct sockaddr_in *resolved = (struct sockaddr_in *)res->ai_addr;
		addr.sin_addr = resolved->sin_addr;
		freeaddrinfo(res);
	}

	mxfsd_info("peer: connecting to node %u at %s:%u",
	           id, peer->host, peer->port);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		mxfsd_warn("peer: connect to node %u failed: %s",
		           id, strerror(errno));
		close(fd);
		peer->state = MXFSD_CONN_DISCONNECTED;
		pthread_mutex_unlock(&peer->send_lock);
		return -errno;
	}

	set_socket_opts(fd);

	/* Send handshake: a NODE_JOIN message header */
	peer->send_seq++;
	struct mxfs_dlm_node_msg join;
	memset(&join, 0, sizeof(join));
	join.hdr.magic = MXFS_DLM_MAGIC;
	join.hdr.version = MXFS_DLM_VERSION;
	join.hdr.type = MXFS_MSG_NODE_JOIN;
	join.hdr.length = sizeof(join);
	join.hdr.seq = peer->send_seq;
	join.hdr.sender = ctx->local_node_id;
	join.hdr.target = id;
	join.port = peer->port;

	if (write_exact(fd, &join, sizeof(join)) < 0) {
		mxfsd_err("peer: handshake write to node %u failed: %s",
		          id, strerror(errno));
		close(fd);
		peer->state = MXFSD_CONN_DISCONNECTED;
		pthread_mutex_unlock(&peer->send_lock);
		return -EIO;
	}

	peer->sockfd = fd;
	peer->state = MXFSD_CONN_ACTIVE;
	peer->last_seen_ms = now_ms();

	pthread_mutex_unlock(&peer->send_lock);

	mxfsd_info("peer: connected to node %u at %s:%u (fd %d)",
	           id, peer->host, peer->port, fd);
	return 0;
}

void mxfsd_peer_disconnect(struct mxfsd_peer_ctx *ctx, mxfs_node_id_t id)
{
	if (!ctx)
		return;

	struct mxfsd_peer *peer = mxfsd_peer_find(ctx, id);
	if (!peer)
		return;

	pthread_mutex_lock(&peer->send_lock);

	if (peer->sockfd >= 0) {
		mxfsd_info("peer: disconnecting node %u (fd %d)",
		           id, peer->sockfd);
		close(peer->sockfd);
		peer->sockfd = -1;
	}
	peer->state = MXFSD_CONN_DISCONNECTED;

	pthread_mutex_unlock(&peer->send_lock);
}

int mxfsd_peer_send(struct mxfsd_peer_ctx *ctx, mxfs_node_id_t target,
                    const struct mxfs_dlm_msg_hdr *msg)
{
	if (!ctx || !msg)
		return -EINVAL;

	struct mxfsd_peer *peer = mxfsd_peer_find(ctx, target);
	if (!peer) {
		mxfsd_dbg("peer: send to unknown node %u", target);
		return -ENOENT;
	}

	pthread_mutex_lock(&peer->send_lock);

	if (peer->state != MXFSD_CONN_ACTIVE || peer->sockfd < 0) {
		mxfsd_dbg("peer: send to node %u failed, not connected",
		          target);
		pthread_mutex_unlock(&peer->send_lock);
		return -ENOTCONN;
	}

	int rc = write_exact(peer->sockfd, msg, msg->length);
	if (rc < 0) {
		mxfsd_warn("peer: write to node %u failed: %s",
		           target, strerror(errno));
		close(peer->sockfd);
		peer->sockfd = -1;
		peer->state = MXFSD_CONN_DISCONNECTED;
		pthread_mutex_unlock(&peer->send_lock);
		return -EIO;
	}

	peer->send_seq++;

	mxfsd_dbg("peer: sent msg type %u (%u bytes) to node %u",
	          msg->type, msg->length, target);

	pthread_mutex_unlock(&peer->send_lock);
	return 0;
}

int mxfsd_peer_broadcast(struct mxfsd_peer_ctx *ctx,
                         const struct mxfs_dlm_msg_hdr *msg)
{
	if (!ctx || !msg)
		return -EINVAL;

	int sent = 0;
	int errors = 0;

	for (int i = 0; i < ctx->peer_count; i++) {
		struct mxfsd_peer *p = &ctx->peers[i];
		if (p->state != MXFSD_CONN_ACTIVE || p->sockfd < 0)
			continue;

		if (mxfsd_peer_send(ctx, p->node_id, msg) == 0)
			sent++;
		else
			errors++;
	}

	mxfsd_dbg("peer: broadcast msg type %u to %d peers (%d errors)",
	          msg->type, sent, errors);

	return sent > 0 ? 0 : (errors > 0 ? -EIO : -ENOENT);
}

struct mxfsd_peer *mxfsd_peer_find(struct mxfsd_peer_ctx *ctx,
                                   mxfs_node_id_t id)
{
	if (!ctx)
		return NULL;

	for (int i = 0; i < ctx->peer_count; i++) {
		if (ctx->peers[i].node_id == id)
			return &ctx->peers[i];
	}
	return NULL;
}

void mxfsd_peer_set_disconnect_cb(struct mxfsd_peer_ctx *ctx,
                                  mxfsd_peer_disconnect_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->disconnect_cb = cb;
	ctx->disconnect_cb_data = data;
}

void mxfsd_peer_set_msg_cb(struct mxfsd_peer_ctx *ctx,
                            mxfsd_peer_msg_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->msg_cb = cb;
	ctx->msg_cb_data = data;
}

bool mxfsd_peer_is_alive(const struct mxfsd_peer *peer, uint64_t now,
                         uint64_t timeout_ms)
{
	if (!peer)
		return false;

	if (peer->state != MXFSD_CONN_ACTIVE)
		return false;

	if (peer->last_seen_ms == 0)
		return false;

	return (now - peer->last_seen_ms) < timeout_ms;
}
