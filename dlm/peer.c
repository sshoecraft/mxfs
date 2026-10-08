/*
 * MXFS — Multinode XFS
 * Portable TCP peer connection management
 *
 * Port of kernel/mxfs_peer.c to portable C. Uses PAL TCP APIs,
 * PAL threads for accept and per-peer receive loops, and PAL
 * mutex-serialized sends. Wire protocol is the same mxfs_dlm_msg_hdr
 * framing with NODE_JOIN handshake.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */


#include "peer.h"
#include "dlm_user_compat.h"

#define MXFS_PEER_MAX_MSG_SIZE  8192

/*
 * A peer's socket and the handle of the thread that reads it change together,
 * under the peer's send_lock: whoever replaces a connection finds both, joins
 * the thread and only then closes the socket.  The handle used to be stored
 * after the lock that installed the socket had been dropped.  A setup in the
 * other direction that ran between the two found a socket with no handle,
 * closed it and installed its own, and the late store then wrote over that
 * setup's handle: the thread it had named read the same stream as its twin
 * until the connection ended, returned, and was joined by nobody (an unload
 * listed mxfs_peer_recv_fn created by the accept path, its function returned,
 * after eight nodes had mounted together on TCP).
 *
 * CONTROL BUILD ONLY (MXFS_KCFLAGS=-DMXFS_TEST_PEER_HANDLE_UNLOCKED): the
 * setup as it was, the handle stored outside the lock and the replaced
 * connection taken down once, so that a lap can show its mounts are ones for
 * which that setup loses a thread.  The source is the same, so the srcversion
 * is too: the line P-PEER-RECV-UNLOCKED, once a load, is what names the build.
 */
#ifdef MXFS_TEST_PEER_HANDLE_UNLOCKED
#define MXFS_PEER_HANDLE_LOCKED	0
#else
#define MXFS_PEER_HANDLE_LOCKED	1
#endif

/*
 * TEST ONLY.  Milliseconds an outbound setup waits between the install of
 * its socket and the creation of its receive thread, so that a lap puts the
 * inbound setup inside that window whenever both directions connect
 * (tests/peer_recv_orphan.sh).  0 = no wait.
 */
unsigned int mxfs_peer_recv_start_delay_ms;
module_param_named(peer_recv_start_delay_ms, mxfs_peer_recv_start_delay_ms,
		   uint, 0644);
MODULE_PARM_DESC(peer_recv_start_delay_ms,
		 "TEST ONLY: ms between the install of an outbound peer "
		 "connection's socket and the creation of its receive thread "
		 "(0 = none)");

/* stores of a receive thread's handle over one still stored */
static atomic_t mxfs_peer_recv_overwrites;
/* connections a setup found installed after its join and took down too */
static atomic_t mxfs_peer_teardown_repeats;

/* ---- Internal helpers ---- */

static struct mxfs_peer *peer_find_locked(struct mxfs_peer_ctx *ctx,
					   mxfs_node_id_t node_id)
{
	int i;

	for (i = 0; i < ctx->peer_count; i++) {
		if (ctx->peers[i].node_id == node_id)
			return &ctx->peers[i];
	}
	return NULL;
}

/*
 * Handle peer disconnect: shutdown socket, set DISCONNECTED, fire callback.
 * Caller must NOT hold peer->send_lock.
 *
 * Bug 80: Use shutdown instead of close.  The socket is NOT freed here
 * because the recv thread may still be unwinding from kernel_recvmsg
 * after getting woken by the shutdown.  The socket will be properly
 * freed by the next connection setup (peer_connect_impl or accept
 * thread) which joins the recv thread first, or during mxfs_peer_shutdown.
 * Keeping peer->sock non-NULL also lets the next connection code know
 * it needs to join the recv thread and free the old socket.
 */
static void peer_handle_disconnect(struct mxfs_peer_ctx *ctx,
				    struct mxfs_peer *peer)
{
	mxfs_node_id_t node = peer->node_id;

	mxfs_pal_mutex_lock(peer->send_lock);
	if (peer->sock)
		mxfs_pal_tcp_shutdown(peer->sock);
	peer->state = MXFS_CONN_DISCONNECTED;
	mxfs_pal_mutex_unlock(peer->send_lock);

	if (ctx->disconnect_cb)
		ctx->disconnect_cb(ctx->disconnect_cb_data, node);
}

/* ---- Per-peer receive thread ---- */

struct mxfs_recv_data {
	struct mxfs_peer_ctx *ctx;
	mxfs_node_id_t node_id;
};

static void mxfs_peer_recv_fn(void *arg)
{
	struct mxfs_recv_data *rd = arg;
	struct mxfs_peer_ctx *ctx = rd->ctx;
	mxfs_node_id_t node_id = rd->node_id;
	struct mxfs_peer *peer;
	struct mxfs_dlm_msg_hdr hdr;
	uint8_t *msgbuf = NULL;
	int ret;

	mxfs_pal_free(rd);

	msgbuf = mxfs_pal_alloc(MXFS_PEER_MAX_MSG_SIZE);
	if (!msgbuf) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "peer: recv thread node %u: out of memory", node_id);
		return;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "peer: recv thread started for node %u", node_id);

	while (ctx->running) {
		mxfs_pal_mutex_lock(ctx->peer_lock);
		peer = peer_find_locked(ctx, node_id);
		if (!peer || peer->state != MXFS_CONN_ACTIVE || !peer->sock) {
			mxfs_pal_mutex_unlock(ctx->peer_lock);
			break;
		}
		mxfs_pal_mutex_unlock(ctx->peer_lock);

		/* Read message header */
		ret = mxfs_pal_tcp_recv(peer->sock, &hdr, sizeof(hdr));
		if (ret == -EAGAIN) {
			/* Receive timeout -- peer may be slow. Loop back. */
			continue;
		}
		if (ret < 0) {
			if (!ctx->running)
				break;
			mxfs_pal_log(MXFS_LOG_INFO,
				     "peer: node %u disconnected",
				     node_id);
			peer_handle_disconnect(ctx, peer);
			break;
		}

		/* Validate magic */
		if (hdr.magic != MXFS_DLM_MAGIC) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "peer: bad magic 0x%08x from node %u",
				     hdr.magic, node_id);
			peer_handle_disconnect(ctx, peer);
			break;
		}

		/* Validate length */
		if (hdr.length < sizeof(hdr) ||
		    hdr.length > MXFS_PEER_MAX_MSG_SIZE) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "peer: bad length %u from node %u",
				     hdr.length, node_id);
			peer_handle_disconnect(ctx, peer);
			break;
		}

		/* Copy header into msgbuf, then read remaining payload */
		memcpy(msgbuf, &hdr, sizeof(hdr));

		if (hdr.length > sizeof(hdr)) {
			ret = mxfs_pal_tcp_recv(peer->sock,
						 msgbuf + sizeof(hdr),
						 hdr.length - sizeof(hdr));
			if (ret < 0) {
				if (!ctx->running)
					break;
				mxfs_pal_log(MXFS_LOG_INFO,
					     "peer: node %u disconnected",
					     node_id);
				peer_handle_disconnect(ctx, peer);
				break;
			}
		}

		peer->last_seen = mxfs_pal_time_ms();

		/* Dispatch to message callback */
		if (ctx->msg_cb)
			ctx->msg_cb(ctx->msg_cb_data, hdr.sender,
				    msgbuf, hdr.length);
	}

	mxfs_pal_free(msgbuf);
	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "peer: recv thread exiting for node %u", node_id);
}

/*
 * Start a receive thread for a peer whose socket the caller has just
 * installed, and store its handle.  Called with peer->send_lock held, in the
 * critical section of that install (the control build calls it after the
 * unlock, as the setup did).  The thread's creation returns once the thread
 * has started, before its function takes any lock, so making it under the
 * lock cannot wait on the lock.
 */
static int start_recv_thread(struct mxfs_peer_ctx *ctx, struct mxfs_peer *peer,
			     const char *who)
{
	struct mxfs_recv_data *rd;
	mxfs_thread_t *t;
	uint32_t delay_ms = READ_ONCE(mxfs_peer_recv_start_delay_ms);

	/* the outbound setup's window only: the accept thread serves every
	 * peer, and one that sleeps here answers no other's handshake, so no
	 * inbound setup arrives inside anybody's window */
	if (strcmp(who, "connect") != 0)
		delay_ms = 0;

	if (!MXFS_PEER_HANDLE_LOCKED) {
		static atomic_t named;

		if (atomic_inc_return(&named) == 1)
			mxfs_pal_log(MXFS_LOG_ERR,
				     "P-PEER-RECV-UNLOCKED control build: a "
				     "receive thread's handle is stored outside "
				     "the lock that installed its socket");
	}

	rd = mxfs_pal_alloc(sizeof(*rd));
	if (!rd)
		return -ENOMEM;

	rd->ctx = ctx;
	rd->node_id = peer->node_id;

	if (delay_ms)
		mxfs_pal_sleep_ms(delay_ms);

	t = mxfs_pal_thread_create_rt(mxfs_peer_recv_fn, rd);
	if (!t) {
		mxfs_pal_free(rd);
		return -ENOMEM;
	}

	/*
	 * Instrument: a handle still stored here names a thread nothing will
	 * join once this store has replaced it.  The locked setup takes the
	 * old connection down before it installs, so it finds none.
	 */
	if (peer->recv_thread)
		mxfs_pal_log(MXFS_LOG_ERR,
			     "P-PEER-RECV-OVERWRITE node=%u by=%s "
			     "old_pid=%d new_pid=%d delay_ms=%u n=%d -- a receive "
			     "thread's handle is stored over one still stored; "
			     "nothing joins the thread it named",
			     peer->node_id, who,
			     mxfs_pal_thread_pid(peer->recv_thread),
			     mxfs_pal_thread_pid(t), delay_ms,
			     atomic_inc_return(&mxfs_peer_recv_overwrites));
	peer->recv_thread = t;
	peer->recv_started_ms = mxfs_pal_time_ms();

	return 0;
}

/*
 * Take down whatever connection the peer still has: shut its socket down,
 * join the thread that read it, then close it.  Called and returns with
 * peer->send_lock held, and with ctx->peer_lock held too when the caller
 * says it holds it; both are dropped for the join, so a setup in the other
 * direction can install a connection meanwhile.  That one is taken down as
 * well, until nothing is installed: the caller installs over nothing.  With
 * keep_live a connection that is active is left as it is, for the outbound
 * setup, which gives way to a live inbound one.  The control build takes
 * down what it found once, as the setup did.
 */
static void peer_teardown_locked(struct mxfs_peer_ctx *ctx,
				 struct mxfs_peer *peer, bool peer_lock_held,
				 bool keep_live, const char *who)
{
	int rounds = 0;

	while (peer->sock || peer->recv_thread) {
		mxfs_sock_t *old_sock = peer->sock;
		mxfs_thread_t *old_thread = peer->recv_thread;

		if (keep_live && peer->state == MXFS_CONN_ACTIVE && peer->sock)
			break;
		/*
		 * Instrument.  since_start_ms says how long the thread's
		 * handle had been stored (-1: none was): a connection taken
		 * down with no handle, or with one stored a moment before,
		 * is one whose setup the other direction's met.
		 */
		mxfs_pal_log(MXFS_LOG_INFO,
			     "P-PEER-REPLACED node=%u by=%s inst_by=%s state=%d "
			     "sock=%d thread_pid=%d age_ms=%llu "
			     "since_start_ms=%lld delay_ms=%u",
			     peer->node_id, who,
			     old_sock && peer->installed_by ?
				peer->installed_by : "none",
			     (int)peer->state,
			     old_sock ? 1 : 0, mxfs_pal_thread_pid(old_thread),
			     (unsigned long long)(old_sock && peer->installed_ms ?
				mxfs_pal_time_ms() - peer->installed_ms : 0),
			     old_thread ? (long long)(mxfs_pal_time_ms() -
						      peer->recv_started_ms) : -1LL,
			     READ_ONCE(mxfs_peer_recv_start_delay_ms));
		if (rounds++ > 0) {
			if (!MXFS_PEER_HANDLE_LOCKED)
				break;
			mxfs_pal_log(MXFS_LOG_WARN,
				     "P-PEER-TEARDOWN-REPEAT node=%u by=%s "
				     "round=%d sock=%d thread_pid=%d n=%d -- a "
				     "connection was installed while the one "
				     "before it was being joined; taken down too",
				     peer->node_id, who, rounds,
				     old_sock ? 1 : 0,
				     mxfs_pal_thread_pid(old_thread),
				     atomic_inc_return(&mxfs_peer_teardown_repeats));
		}

		/* Shutdown unblocks a thread waiting in tcp_recv; the socket
		 * is freed only after that thread has been joined. */
		if (old_sock)
			mxfs_pal_tcp_shutdown(old_sock);
		peer->sock = NULL;
		peer->recv_thread = NULL;

		mxfs_pal_mutex_unlock(peer->send_lock);
		if (peer_lock_held)
			mxfs_pal_mutex_unlock(ctx->peer_lock);
		if (old_thread)
			mxfs_pal_thread_join(old_thread);
		if (old_sock)
			mxfs_pal_tcp_close(old_sock);
		if (peer_lock_held)
			mxfs_pal_mutex_lock(ctx->peer_lock);
		mxfs_pal_mutex_lock(peer->send_lock);
	}
}

/* ---- Accept thread ---- */

static void mxfs_peer_accept_fn(void *arg)
{
	struct mxfs_peer_ctx *ctx = arg;
	mxfs_sock_t *newsock;
	struct mxfs_dlm_node_msg join;
	struct mxfs_dlm_node_msg reply;
	struct mxfs_peer *peer;
	mxfs_node_id_t sender;
	int ret;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "peer: accept thread started on port %u",
		     ctx->local_port);

	while (ctx->running) {
		newsock = mxfs_pal_tcp_accept(ctx->listen_sock);
		if (!newsock) {
			if (!ctx->running)
				break;
			/* Accept failed or timeout — retry */
			mxfs_pal_sleep_ms(100);
			continue;
		}

		/* Check running again — shutdown may have fired between
		 * kernel_accept returning and here */
		if (!ctx->running) {
			mxfs_pal_tcp_close(newsock);
			break;
		}

		/* peers= (exclusive): only the listed addresses are the cluster */
		if (mxfs_static_peers_exclusive(&ctx->static_peers)) {
			char from[64] = "";

			if (mxfs_pal_tcp_getpeername(newsock, from, sizeof(from)) < 0 ||
			    !mxfs_static_peers_admit(&ctx->static_peers, from)) {
				mxfs_pal_log(MXFS_LOG_WARN,
					     "mxfs: P-PEERS-REFUSED connection from %s, "
					     "which is not in peers=",
					     from[0] ? from : "(unknown address)");
				mxfs_pal_tcp_close(newsock);
				continue;
			}
		}

		mxfs_pal_tcp_set_opts(newsock);

		/* Publish newsock so shutdown can wake us if we block
		 * in the handshake recv below. Without this, the accept
		 * thread can hang forever in tcp_recv on a socket that
		 * the shutdown path doesn't know about. */
		ctx->pending_sock = newsock;

		/* Read NODE_JOIN handshake */
		ret = mxfs_pal_tcp_recv(newsock, &join, sizeof(join));
		if (ret < 0) {
			ctx->pending_sock = NULL;
			if (!ctx->running) {
				mxfs_pal_tcp_close(newsock);
				break;
			}
			mxfs_pal_log(MXFS_LOG_WARN,
				     "peer: handshake read failed: %d", ret);
			mxfs_pal_tcp_close(newsock);
			continue;
		}

		/* Handshake received — clear pending before further processing */
		ctx->pending_sock = NULL;

		if (!ctx->running) {
			mxfs_pal_tcp_close(newsock);
			break;
		}

		if (join.hdr.magic != MXFS_DLM_MAGIC) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "peer: bad handshake magic 0x%08x",
				     join.hdr.magic);
			mxfs_pal_tcp_close(newsock);
			continue;
		}

		if (join.hdr.type != MXFS_MSG_NODE_JOIN) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "peer: expected NODE_JOIN, got %u",
				     join.hdr.type);
			mxfs_pal_tcp_close(newsock);
			continue;
		}

		/* Multi-LUN: reject connections for a different volume.
		 * With SO_REUSEPORT, the kernel may deliver a connection
		 * intended for another mount's accept loop to us.  If the
		 * sender's volume_id is non-zero and doesn't match ours,
		 * close immediately — the sender will retry and the kernel
		 * will probabilistically deliver it to the correct listener. */
		if (join.volume_id != 0 &&
		    ctx->local_volume_id != 0 &&
		    join.volume_id != ctx->local_volume_id) {
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "peer: rejecting node %u "
				     "(volume 0x%llx != ours 0x%llx)",
				     join.hdr.sender,
				     (unsigned long long)join.volume_id,
				     (unsigned long long)ctx->local_volume_id);
			mxfs_pal_tcp_close(newsock);
			continue;
		}

		sender = join.hdr.sender;

		/* Send NODE_JOIN reply */
		memset(&reply, 0, sizeof(reply));
		reply.hdr.magic = MXFS_DLM_MAGIC;
		reply.hdr.version = MXFS_DLM_VERSION;
		reply.hdr.type = MXFS_MSG_NODE_JOIN;
		reply.hdr.length = sizeof(reply);
		reply.hdr.sender = ctx->local_node_id;
		reply.hdr.target = sender;
		reply.port = ctx->local_port;
		reply.volume_id = ctx->local_volume_id;
		memcpy(reply.name, ctx->local_node_uuid,
		       sizeof(ctx->local_node_uuid) < sizeof(reply.name) ?
		       sizeof(ctx->local_node_uuid) : sizeof(reply.name));

		ret = mxfs_pal_tcp_send(newsock, &reply, sizeof(reply));
		if (ret < 0) {
			mxfs_pal_log(MXFS_LOG_WARN,
				     "peer: handshake reply to node %u failed: %d",
				     sender, ret);
			mxfs_pal_tcp_close(newsock);
			continue;
		}

		mxfs_pal_mutex_lock(ctx->peer_lock);

		/* Find or dynamically add this peer */
		peer = peer_find_locked(ctx, sender);
		if (!peer) {
			if (ctx->peer_count >= MXFS_MAX_NODES) {
				mxfs_pal_mutex_unlock(ctx->peer_lock);
				mxfs_pal_log(MXFS_LOG_WARN,
					     "peer: cannot add node %u, max peers reached",
					     sender);
				mxfs_pal_tcp_close(newsock);
				continue;
			}
			peer = &ctx->peers[ctx->peer_count];
			memset(peer, 0, sizeof(*peer));
			peer->node_id = sender;
			peer->port = join.port;
			peer->state = MXFS_CONN_DISCONNECTED;
			peer->send_lock = mxfs_pal_mutex_create();
			ctx->peer_count++;
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "peer: dynamically added node %u", sender);
		}

		/* Replace any existing connection: its socket is shut down,
		 * the thread that read it joined, and only then is it
		 * closed. */
		mxfs_pal_mutex_lock(peer->send_lock);
		peer_teardown_locked(ctx, peer, true, false, "accept");

		peer->sock = newsock;
		peer->state = MXFS_CONN_ACTIVE;
		peer->last_seen = mxfs_pal_time_ms();
		peer->installed_ms = peer->last_seen;
		peer->installed_by = "accept";

		/* Bug 65: Extract the remote IP from the accepted socket
		 * and store it in the peer entry. Without this, if the
		 * connection drops and outbound fallback reconnection is
		 * attempted, peer->host is empty and the connect call
		 * fails (connects to ":7600"). Always update the host
		 * field to reflect the current IP of this peer. */
		{
			char addr[64];
			if (mxfs_pal_tcp_getpeername(newsock, addr,
						     sizeof(addr)) == 0) {
				snprintf(peer->host, sizeof(peer->host), "%s", addr);
			}
		}

		/* Start recv thread for this peer, its handle stored in the
		 * critical section that installed the socket it reads */
		if (MXFS_PEER_HANDLE_LOCKED) {
			mxfs_pal_mutex_unlock(ctx->peer_lock);
			ret = start_recv_thread(ctx, peer, "accept");
			mxfs_pal_mutex_unlock(peer->send_lock);
		} else {
			mxfs_pal_mutex_unlock(peer->send_lock);
			mxfs_pal_mutex_unlock(ctx->peer_lock);
			ret = start_recv_thread(ctx, peer, "accept");
		}
		if (ret < 0) {
			mxfs_pal_log(MXFS_LOG_ERR,
				     "peer: failed to start recv thread "
				     "for node %u: %d", sender, ret);
			peer_handle_disconnect(ctx, peer);
			continue;
		}

		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "peer: node %u connected (inbound) from %s",
			     sender, peer->host);

		/* Notify mount layer about the new inbound peer so it can
		 * register with lease manager and update DLM active nodes.
		 * This is essential for fallback connections where the
		 * higher-ID node connects to us but we never discovered
		 * it via multicast (asymmetric multicast). */
		if (ctx->connect_cb)
			ctx->connect_cb(ctx->connect_cb_data, sender);
	}

	mxfs_pal_log(MXFS_LOG_DEBUG, "peer: accept thread exiting");
}

/* ---- Public API ---- */

struct mxfs_peer_ctx *mxfs_peer_init(mxfs_node_id_t node_id,
				      const uint8_t *uuid,
				      uint16_t port,
				      mxfs_volume_id_t volume_id)
{
	struct mxfs_peer_ctx *ctx;
	int i;

	ctx = mxfs_pal_alloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->local_node_id = node_id;
	if (uuid)
		memcpy(ctx->local_node_uuid, uuid, 16);
	ctx->local_port = port;
	ctx->local_volume_id = volume_id;
	ctx->running = false;
	ctx->peer_count = 0;
	ctx->listen_sock = NULL;
	ctx->accept_thread = NULL;
	ctx->pending_sock = NULL;

	ctx->peer_lock = mxfs_pal_mutex_create();
	if (!ctx->peer_lock) {
		mxfs_pal_free(ctx);
		return NULL;
	}

	/* Initialize all peer slots */
	for (i = 0; i < MXFS_MAX_NODES; i++) {
		ctx->peers[i].state = MXFS_CONN_DISCONNECTED;
		ctx->peers[i].sock = NULL;
		ctx->peers[i].recv_thread = NULL;
		ctx->peers[i].send_lock = mxfs_pal_mutex_create();
	}

	/* Create TCP listen socket */
	ctx->listen_sock = mxfs_pal_tcp_listen(port);
	if (!ctx->listen_sock) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "peer: listen on port %u failed", port);
		for (i = 0; i < MXFS_MAX_NODES; i++) {
			if (ctx->peers[i].send_lock)
				mxfs_pal_mutex_destroy(ctx->peers[i].send_lock);
		}
		mxfs_pal_mutex_destroy(ctx->peer_lock);
		mxfs_pal_free(ctx);
		return NULL;
	}

	ctx->running = true;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "peer: listening on port %u for node %u",
		     port, node_id);
	return ctx;
}

void mxfs_peer_set_static_peers(struct mxfs_peer_ctx *ctx,
				const struct mxfs_static_peers *peers)
{
	if (ctx && mxfs_static_peers_active(peers))
		ctx->static_peers = *peers;
}

int mxfs_peer_start(struct mxfs_peer_ctx *ctx)
{
	if (!ctx || !ctx->running)
		return -EINVAL;

	ctx->accept_thread = mxfs_pal_thread_create_rt(mxfs_peer_accept_fn, ctx);
	if (!ctx->accept_thread) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "peer: failed to start accept thread");
		return -ENOMEM;
	}

	return 0;
}

void mxfs_peer_shutdown(struct mxfs_peer_ctx *ctx)
{
	int i;

	if (!ctx)
		return;

	ctx->running = false;

	/* Phase 0: shutdown ALL peer sockets BEFORE joining the accept thread.
	 *
	 * With 3+ nodes, the accept thread may be in mxfs_pal_thread_join()
	 * joining an old recv thread (when replacing a reconnected peer at
	 * line ~293 of the accept loop).  That old recv thread is blocked in
	 * mxfs_pal_tcp_recv() on the OLD socket.  If we try to join the
	 * accept thread first (before shutting down peer sockets), the
	 * accept thread hangs waiting for the recv thread, which hangs
	 * waiting for data on a socket nobody ever shuts down.
	 *
	 * Fix: shut down all peer sockets first so any recv thread blocked
	 * in tcp_recv will wake up and exit.  Then the accept thread (which
	 * may be joining one of those recv threads) can proceed and exit
	 * when it checks running==false. */
	for (i = 0; i < ctx->peer_count; i++) {
		struct mxfs_peer *peer = &ctx->peers[i];

		mxfs_pal_mutex_lock(peer->send_lock);
		if (peer->sock)
			mxfs_pal_tcp_shutdown(peer->sock);
		mxfs_pal_mutex_unlock(peer->send_lock);
	}

	/* Shutdown the listen socket to wake the accept thread blocked
	 * in kernel_accept.  We must NOT free the socket yet because
	 * the accept thread still references it.  The shutdown unblocks
	 * kernel_accept so the thread can notice running==false and exit. */
	if (ctx->listen_sock)
		mxfs_pal_tcp_shutdown(ctx->listen_sock);

	/* Shutdown the pending socket if the accept thread is blocked
	 * in tcp_recv reading a NODE_JOIN handshake from a newly
	 * accepted connection.  With 3+ nodes, inbound connections
	 * arrive frequently and the accept thread spends significant
	 * time blocked here.  Without this, the accept thread hangs
	 * forever because nobody else knows about this socket. */
	if (ctx->pending_sock)
		mxfs_pal_tcp_shutdown(ctx->pending_sock);

	/* Join the accept thread — it will exit after seeing running==false.
	 * Safe now because all recv threads have been woken (Phase 0). */
	if (ctx->accept_thread) {
		mxfs_pal_thread_join(ctx->accept_thread);
		ctx->accept_thread = NULL;
	}

	/* Now safe to close and free the listen socket */
	if (ctx->listen_sock) {
		mxfs_pal_tcp_close(ctx->listen_sock);
		ctx->listen_sock = NULL;
	}

	/* Phase 1 (already done in Phase 0 above): peer sockets are shut down.
	 *
	 * Phase 2: join recv threads, then close+free sockets.
	 * Some recv threads may have already been joined by the accept thread
	 * during replacement — their recv_thread pointer is NULL. */
	for (i = 0; i < ctx->peer_count; i++) {
		struct mxfs_peer *peer = &ctx->peers[i];

		if (peer->recv_thread) {
			mxfs_pal_thread_join(peer->recv_thread);
			peer->recv_thread = NULL;
		}

		mxfs_pal_mutex_lock(peer->send_lock);
		if (peer->sock) {
			mxfs_pal_tcp_close(peer->sock);
			peer->sock = NULL;
		}
		mxfs_pal_mutex_unlock(peer->send_lock);

		peer->state = MXFS_CONN_DISCONNECTED;
	}

	/* Clean up mutexes */
	for (i = 0; i < MXFS_MAX_NODES; i++) {
		if (ctx->peers[i].send_lock) {
			mxfs_pal_mutex_destroy(ctx->peers[i].send_lock);
			ctx->peers[i].send_lock = NULL;
		}
	}

	mxfs_pal_mutex_destroy(ctx->peer_lock);
	mxfs_pal_free(ctx);

	mxfs_pal_log(MXFS_LOG_DEBUG, "peer: shutdown complete");
}

int mxfs_peer_add(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id,
		   const uint8_t *uuid, const char *host, uint16_t port)
{
	struct mxfs_peer *peer;
	int i;

	if (!ctx || !host)
		return -EINVAL;

	mxfs_pal_mutex_lock(ctx->peer_lock);

	if (ctx->peer_count >= MXFS_MAX_NODES) {
		mxfs_pal_mutex_unlock(ctx->peer_lock);
		mxfs_pal_log(MXFS_LOG_ERR,
			     "peer: cannot add node %u, max peers reached",
			     node_id);
		return -ENOSPC;
	}

	/* Check for duplicate */
	for (i = 0; i < ctx->peer_count; i++) {
		if (ctx->peers[i].node_id == node_id) {
			mxfs_pal_mutex_unlock(ctx->peer_lock);
			mxfs_pal_log(MXFS_LOG_DEBUG,
				     "peer: node %u already registered", node_id);
			return -EEXIST;
		}
	}

	peer = &ctx->peers[ctx->peer_count];
	memset(peer, 0, sizeof(*peer));
	peer->node_id = node_id;
	if (uuid)
		memcpy(peer->node_uuid, uuid, 16);
	snprintf(peer->host, sizeof(peer->host), "%s", host);
	peer->port = port;
	peer->sock = NULL;
	peer->state = MXFS_CONN_DISCONNECTED;
	peer->recv_thread = NULL;
	peer->last_seen = 0;
	peer->send_lock = mxfs_pal_mutex_create();

	ctx->peer_count++;

	mxfs_pal_mutex_unlock(ctx->peer_lock);

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "peer: added node %u at %s:%u", node_id, host, port);
	return 0;
}

/*
 * peer_connect_impl — shared implementation for peer connect.
 * If skip_id_check is true, bypass the lower-ID-initiates rule
 * (used as a fallback when multicast is asymmetric).
 */
static int peer_connect_impl(struct mxfs_peer_ctx *ctx,
			      mxfs_node_id_t node_id,
			      bool skip_id_check)
{
	struct mxfs_peer *peer;
	mxfs_sock_t *sock;
	struct mxfs_dlm_node_msg join;
	struct mxfs_dlm_node_msg reply;
	int ret;

	if (!ctx)
		return -EINVAL;

	/*
	 * Lower-ID-initiates convention: only the node with the lower
	 * node_id initiates the outbound connection. Skip when caller
	 * requests force mode (asymmetric multicast fallback).
	 */
	if (!skip_id_check && ctx->local_node_id >= node_id)
		return 0;

	mxfs_pal_mutex_lock(ctx->peer_lock);
	peer = peer_find_locked(ctx, node_id);
	if (!peer) {
		mxfs_pal_mutex_unlock(ctx->peer_lock);
		mxfs_pal_log(MXFS_LOG_ERR,
			     "peer: cannot connect to unknown node %u", node_id);
		return -ENOENT;
	}
	mxfs_pal_mutex_unlock(ctx->peer_lock);

	mxfs_pal_mutex_lock(peer->send_lock);

	/* Already connected */
	if (peer->state == MXFS_CONN_ACTIVE && peer->sock) {
		mxfs_pal_mutex_unlock(peer->send_lock);
		return 0;
	}

	/*
	 * Take the stale connection down: shut its socket down, join the
	 * thread that read it, then free it.  The lock is dropped for the
	 * join, so the accept thread may have accepted a new inbound
	 * connection from this peer meanwhile, installed its socket and
	 * started its recv thread (Bug 80).  A live one is kept and the
	 * outbound connect skipped; one that has already ended is taken
	 * down like the first.
	 */
	peer->state = MXFS_CONN_CONNECTING;
	peer_teardown_locked(ctx, peer, false, true, "connect");
	if (peer->state == MXFS_CONN_ACTIVE && peer->sock) {
		mxfs_pal_mutex_unlock(peer->send_lock);
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "peer: node %u already reconnected (inbound) "
			     "while joining old thread, skipping outbound connect",
			     node_id);
		return 0;
	}
	mxfs_pal_mutex_unlock(peer->send_lock);

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "peer: %sconnecting to node %u at %s:%u",
		     skip_id_check ? "fallback " : "",
		     node_id, peer->host, peer->port);

	/* Create TCP connection */
	sock = mxfs_pal_tcp_connect(peer->host, peer->port);
	if (!sock) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: connection to cluster node %u failed "
			     "(will retry on next discovery)", node_id);
		mxfs_pal_mutex_lock(peer->send_lock);
		peer->state = MXFS_CONN_DISCONNECTED;
		mxfs_pal_mutex_unlock(peer->send_lock);
		return -ECONNREFUSED;
	}

	mxfs_pal_tcp_set_opts(sock);

	/* Send NODE_JOIN handshake */
	memset(&join, 0, sizeof(join));
	join.hdr.magic = MXFS_DLM_MAGIC;
	join.hdr.version = MXFS_DLM_VERSION;
	join.hdr.type = MXFS_MSG_NODE_JOIN;
	join.hdr.length = sizeof(join);
	join.hdr.sender = ctx->local_node_id;
	join.hdr.target = node_id;
	join.port = ctx->local_port;
	join.volume_id = ctx->local_volume_id;
	memcpy(join.name, ctx->local_node_uuid,
	       sizeof(ctx->local_node_uuid) < sizeof(join.name) ?
	       sizeof(ctx->local_node_uuid) : sizeof(join.name));

	ret = mxfs_pal_tcp_send(sock, &join, sizeof(join));
	if (ret < 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "peer: handshake write to node %u failed: %d",
			     node_id, ret);
		mxfs_pal_tcp_close(sock);
		mxfs_pal_mutex_lock(peer->send_lock);
		peer->state = MXFS_CONN_DISCONNECTED;
		mxfs_pal_mutex_unlock(peer->send_lock);
		return ret;
	}

	/* Read NODE_JOIN reply */
	ret = mxfs_pal_tcp_recv(sock, &reply, sizeof(reply));
	if (ret < 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "peer: handshake reply from node %u failed: %d",
			     node_id, ret);
		mxfs_pal_tcp_close(sock);
		mxfs_pal_mutex_lock(peer->send_lock);
		peer->state = MXFS_CONN_DISCONNECTED;
		mxfs_pal_mutex_unlock(peer->send_lock);
		return ret;
	}

	if (reply.hdr.magic != MXFS_DLM_MAGIC ||
	    reply.hdr.type != MXFS_MSG_NODE_JOIN) {
		mxfs_pal_log(MXFS_LOG_WARN,
			     "peer: bad handshake reply from node %u", node_id);
		mxfs_pal_tcp_close(sock);
		mxfs_pal_mutex_lock(peer->send_lock);
		peer->state = MXFS_CONN_DISCONNECTED;
		mxfs_pal_mutex_unlock(peer->send_lock);
		return -EPROTO;
	}

	/* Multi-LUN: verify reply is from the correct volume.
	 * SO_REUSEPORT may have delivered us to the wrong listener. */
	if (reply.volume_id != 0 &&
	    ctx->local_volume_id != 0 &&
	    reply.volume_id != ctx->local_volume_id) {
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "peer: reply from node %u is for volume 0x%llx "
			     "(ours 0x%llx), retrying",
			     node_id,
			     (unsigned long long)reply.volume_id,
			     (unsigned long long)ctx->local_volume_id);
		mxfs_pal_tcp_close(sock);
		mxfs_pal_mutex_lock(peer->send_lock);
		peer->state = MXFS_CONN_DISCONNECTED;
		mxfs_pal_mutex_unlock(peer->send_lock);
		return -EAGAIN;
	}

	mxfs_pal_mutex_lock(peer->send_lock);

	/* An inbound connection the accept thread installed during the
	 * handshake and which has ended since left its socket and its
	 * thread's handle behind: taken down before this one is installed,
	 * or the install would write over both. */
	if (MXFS_PEER_HANDLE_LOCKED)
		peer_teardown_locked(ctx, peer, false, true, "connect-install");

	/* Bug 80: Check again before installing the new socket.  The accept
	 * thread may have accepted an inbound connection from this peer
	 * during the handshake (which runs without locks).  If the accept
	 * thread already installed a socket and started a recv thread,
	 * we must discard our outbound socket to avoid overwriting the
	 * accept thread's state (which would leak its socket and orphan
	 * its recv thread, leading to a use-after-free crash). */
	if (peer->state == MXFS_CONN_ACTIVE && peer->sock) {
		mxfs_pal_mutex_unlock(peer->send_lock);
		mxfs_pal_log(MXFS_LOG_DEBUG,
			     "peer: node %u already reconnected (inbound) "
			     "during outbound handshake, discarding outbound",
			     node_id);
		mxfs_pal_tcp_close(sock);
		return 0;
	}

	peer->sock = sock;
	peer->state = MXFS_CONN_ACTIVE;
	peer->last_seen = mxfs_pal_time_ms();
	peer->installed_ms = peer->last_seen;
	peer->installed_by = "connect";

	/* Start recv thread for this peer, its handle stored in the
	 * critical section that installed the socket it reads */
	if (MXFS_PEER_HANDLE_LOCKED) {
		ret = start_recv_thread(ctx, peer, "connect");
		mxfs_pal_mutex_unlock(peer->send_lock);
	} else {
		mxfs_pal_mutex_unlock(peer->send_lock);
		ret = start_recv_thread(ctx, peer, "connect");
	}
	if (ret < 0) {
		mxfs_pal_log(MXFS_LOG_ERR,
			     "peer: failed to start recv thread "
			     "for node %u: %d", node_id, ret);
		peer_handle_disconnect(ctx, peer);
		return ret;
	}

	mxfs_pal_log(MXFS_LOG_DEBUG,
		     "peer: connected to node %u at %s:%u",
		     node_id, peer->host, peer->port);

	/*  (16/tcp join-storm false death, instrumented
	 * PROVEN live): connect_cb fired ONLY from the accept path, so an
	 * OUTBOUND reconnect — the announce-driven ensure-connected heal
	 * after a duplicate-connection flap — restored the peer silently.
	 * The mount layer's 40 s suspect timer was never cancelled and
	 * v5_tcp_death_worker_fn then declared a peer with a live ESTAB
	 * socket dead (ss -tn proved ESTAB on test3/test8 → test16 WHILE
	 * P164 rejected its announces): lock-table purge → phantom PR at
	 * the master → root-ino EX starved 120 s → 15-node -110 cascade.
	 * Fire the same callback the accept path fires; the mount layer's
	 * handler is direction-agnostic (P164-gates, cancels the pending
	 * death, re-registers the lease, refreshes membership). */
	if (ctx->connect_cb)
		ctx->connect_cb(ctx->connect_cb_data, node_id);
	return 0;
}

int mxfs_peer_connect(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id)
{
	return peer_connect_impl(ctx, node_id, false);
}

int mxfs_peer_connect_force(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id)
{
	return peer_connect_impl(ctx, node_id, true);
}

int mxfs_peer_send(struct mxfs_peer_ctx *ctx, mxfs_node_id_t node_id,
		    const void *msg, size_t len)
{
	struct mxfs_peer *peer;
	int ret;

	if (!ctx || !msg || len == 0)
		return -EINVAL;

	mxfs_pal_mutex_lock(ctx->peer_lock);
	peer = peer_find_locked(ctx, node_id);
	mxfs_pal_mutex_unlock(ctx->peer_lock);

	if (!peer)
		return -ENOENT;

	mxfs_pal_mutex_lock(peer->send_lock);

	if (peer->state != MXFS_CONN_ACTIVE || !peer->sock) {
		mxfs_pal_mutex_unlock(peer->send_lock);
		return -ENOTCONN;
	}

	ret = mxfs_pal_tcp_send(peer->sock, msg, (uint32_t)len);
	if (ret < 0) {
		/* Bug 83: quick retries for transient TCP hiccups.
		 * Old code: 5 retries, 3.2s total, held send_lock across sleeps.
		 * New code: 3 retries, 1.7s total, drops send_lock during sleep. */
		{
			int retry;
			int retry_delays[] = {200, 500, 1000};
			for (retry = 0; retry < 3; retry++) {
				mxfs_pal_mutex_unlock(peer->send_lock);
				mxfs_pal_sleep_ms(retry_delays[retry]);
				mxfs_pal_mutex_lock(peer->send_lock);
				if (peer->state != MXFS_CONN_ACTIVE || !peer->sock) {
					mxfs_pal_mutex_unlock(peer->send_lock);
					return -ENOTCONN;
				}
				ret = mxfs_pal_tcp_send(peer->sock, msg, (uint32_t)len);
				if (ret == (int)len) {
					mxfs_pal_mutex_unlock(peer->send_lock);
					return 0;
				}
			}
		}
		/*
		 * FLAP FIX — do NOT tear down the socket on a
		 * TRANSIENT send failure (sndtimeo / EAGAIN = the peer's receiver is
		 * slow / its socket buffer is full under the 8-node create storm, NOT a
		 * dead peer).  The OLD code shut the socket down + fired disconnect_cb
		 * on ANY exhausted-retry error, which (a) DROPS every DLM grant/release/
		 * BAST message buffered in that socket — fire-and-forget, never
		 * retransmitted — directly causing the dir_reuse readdir=799 durable
		 * single-dirent loss (PROVEN the loss correlates 1:1 with a
		 * ~500ms "TCP peer disconnected/reconnected (transient flap absorbed)"),
		 * and (b) churns the membership SUSPECT machinery.  A genuinely DEAD
		 * peer is still caught promptly by TCP keepalive (~19s) and the UDP
		 * lease (~75s), both well under the DLM lock-wait timeout, and by a hard
		 * socket error below.  So on a transient timeout keep the connection up
		 * and return an error; the DLM caller retries on the SAME live socket
		 * (its bytes are still buffered in TCP and reach the peer once it
		 * drains).  Only a HARD error (peer reset/closed the connection) is a
		 * real break that must tear down + reconnect.
		 */
		if (ret == -ETIMEDOUT || ret == -EAGAIN || ret == -EWOULDBLOCK) {
			mxfs_pal_mutex_unlock(peer->send_lock);
			mxfs_pal_log(MXFS_LOG_WARN,
				     "mxfs: send to node %u timed out (slow peer under "
				     "load) -- keeping connection, caller will retry "
				     "(keepalive/lease detect true death)", node_id);
			return -EAGAIN;
		}

		/* Hard error (ECONNRESET/EPIPE/ENOTCONN/...) — real break, disconnect. */
		mxfs_pal_log(MXFS_LOG_WARN,
			     "mxfs: communication with node %u lost (err %d) "
			     "(node will be reconnected automatically if still "
			     "available)", node_id, ret);
		mxfs_pal_tcp_shutdown(peer->sock);
		peer->state = MXFS_CONN_DISCONNECTED;
		mxfs_pal_mutex_unlock(peer->send_lock);

		if (ctx->disconnect_cb)
			ctx->disconnect_cb(ctx->disconnect_cb_data, node_id);

		return -ENOTCONN;
	}

	mxfs_pal_mutex_unlock(peer->send_lock);
	return 0;
}

int mxfs_peer_broadcast(struct mxfs_peer_ctx *ctx, const void *msg,
			 size_t len)
{
	int i;
	int sent = 0;
	int errors = 0;

	if (!ctx || !msg || len == 0)
		return -EINVAL;

	mxfs_pal_mutex_lock(ctx->peer_lock);

	for (i = 0; i < ctx->peer_count; i++) {
		struct mxfs_peer *peer = &ctx->peers[i];

		if (peer->state != MXFS_CONN_ACTIVE || !peer->sock)
			continue;

		mxfs_pal_mutex_unlock(ctx->peer_lock);

		if (mxfs_peer_send(ctx, peer->node_id, msg, len) == 0)
			sent++;
		else
			errors++;

		mxfs_pal_mutex_lock(ctx->peer_lock);
	}

	mxfs_pal_mutex_unlock(ctx->peer_lock);

	return sent > 0 ? 0 : (errors > 0 ? -EIO : -ENOENT);
}

struct mxfs_peer *mxfs_peer_find(struct mxfs_peer_ctx *ctx,
				  mxfs_node_id_t node_id)
{
	struct mxfs_peer *peer;

	if (!ctx)
		return NULL;

	mxfs_pal_mutex_lock(ctx->peer_lock);
	peer = peer_find_locked(ctx, node_id);
	mxfs_pal_mutex_unlock(ctx->peer_lock);

	return peer;
}

bool mxfs_peer_is_connected(struct mxfs_peer_ctx *ctx,
			      mxfs_node_id_t node_id)
{
	struct mxfs_peer *peer;
	bool connected;

	if (!ctx)
		return false;

	mxfs_pal_mutex_lock(ctx->peer_lock);
	peer = peer_find_locked(ctx, node_id);
	connected = peer && peer->state == MXFS_CONN_ACTIVE && peer->sock;
	mxfs_pal_mutex_unlock(ctx->peer_lock);

	return connected;
}

void mxfs_peer_set_msg_cb(struct mxfs_peer_ctx *ctx,
			    mxfs_peer_msg_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->msg_cb = cb;
	ctx->msg_cb_data = data;
}

void mxfs_peer_set_disconnect_cb(struct mxfs_peer_ctx *ctx,
				   mxfs_peer_disconnect_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->disconnect_cb = cb;
	ctx->disconnect_cb_data = data;
}

void mxfs_peer_set_connect_cb(struct mxfs_peer_ctx *ctx,
				mxfs_peer_connect_cb cb, void *data)
{
	if (!ctx)
		return;
	ctx->connect_cb = cb;
	ctx->connect_cb_data = data;
}
