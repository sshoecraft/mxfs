/*
 * MXFS — Multinode XFS
 * Userspace netlink interface
 *
 * Opens a genetlink socket, resolves the "mxfs" family registered by
 * mxfs.ko, and handles bidirectional message passing. Lock requests
 * arrive from the kernel, lock grants and cache invalidations are
 * sent back.
 *
 * Uses raw AF_NETLINK sockets with NETLINK_GENERIC to avoid the libnl
 * dependency. Implements just enough of the genetlink protocol to
 * resolve the family ID and exchange messages.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include "mxfsd_netlink.h"
#include "mxfsd_log.h"

/* Buffer size for netlink messages */
#define NL_BUF_SIZE  4096

/* Helper to build a netlink attribute */
static int nla_put(void *buf, int *offset, int type, const void *data, int len)
{
	struct nlattr *nla = (struct nlattr *)((char *)buf + *offset);
	int total = NLA_HDRLEN + len;
	int padded = (total + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1);

	nla->nla_len = (unsigned short)total;
	nla->nla_type = (unsigned short)type;
	memcpy((char *)nla + NLA_HDRLEN, data, len);

	/* Zero padding */
	if (padded > total)
		memset((char *)nla + total, 0, padded - total);

	*offset += padded;
	return 0;
}

static int nla_put_u8(void *buf, int *offset, int type, uint8_t val)
{
	return nla_put(buf, offset, type, &val, sizeof(val));
}

static int nla_put_u32(void *buf, int *offset, int type, uint32_t val)
{
	return nla_put(buf, offset, type, &val, sizeof(val));
}

static int nla_put_u64(void *buf, int *offset, int type, uint64_t val)
{
	return nla_put(buf, offset, type, &val, sizeof(val));
}

/*
 * Send a raw netlink message and receive the response.
 * Returns the number of bytes received, or -errno on error.
 */
static int nl_send_recv(int fd, void *req, int req_len,
			void *resp, int resp_len)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	ssize_t n;

	n = sendto(fd, req, req_len, 0,
		   (struct sockaddr *)&addr, sizeof(addr));
	if (n < 0)
		return -errno;

	n = recv(fd, resp, resp_len, 0);
	if (n < 0)
		return -errno;

	return (int)n;
}

/*
 * Resolve the genetlink family ID for "mxfs" by sending a
 * CTRL_CMD_GETFAMILY request to the generic netlink controller.
 */
static int resolve_family(int fd)
{
	char req_buf[256];
	char resp_buf[NL_BUF_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genlh;
	int offset;
	int n;
	const char *family_name = MXFS_NETLINK_FAMILY;

	memset(req_buf, 0, sizeof(req_buf));

	nlh = (struct nlmsghdr *)req_buf;
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 1;
	nlh->nlmsg_pid = 0;

	genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	genlh->cmd = CTRL_CMD_GETFAMILY;
	genlh->version = 1;

	offset = NLMSG_HDRLEN + GENL_HDRLEN;
	nla_put(req_buf, &offset, CTRL_ATTR_FAMILY_NAME,
		family_name, (int)strlen(family_name) + 1);

	nlh->nlmsg_len = (unsigned int)offset;

	n = nl_send_recv(fd, req_buf, offset, resp_buf, sizeof(resp_buf));
	if (n < 0) {
		mxfsd_err("netlink: family resolve send/recv failed: %s",
			  strerror(-n));
		return n;
	}

	/* Parse response to find CTRL_ATTR_FAMILY_ID */
	nlh = (struct nlmsghdr *)resp_buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		mxfsd_err("netlink: family '%s' not found (err=%d). "
			  "Is mxfs.ko loaded?", family_name, err->error);
		return err->error;
	}

	genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	int attr_len = (int)(nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN);
	struct nlattr *nla = (struct nlattr *)((char *)genlh + GENL_HDRLEN);

	while (attr_len >= (int)NLA_HDRLEN) {
		int nla_total = NLA_ALIGN(nla->nla_len);

		if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
			uint16_t *id = (uint16_t *)((char *)nla + NLA_HDRLEN);
			return (int)*id;
		}

		attr_len -= nla_total;
		nla = (struct nlattr *)((char *)nla + nla_total);
	}

	mxfsd_err("netlink: CTRL_ATTR_FAMILY_ID not found in response");
	return -ENOENT;
}

/*
 * Build and send a genetlink message to the kernel module.
 * attrs_buf contains pre-built NLA attributes, attrs_len is their total size.
 */
static int nl_send_cmd(struct mxfsd_netlink_ctx *ctx, uint8_t cmd,
		       const void *attrs_buf, int attrs_len)
{
	char buf[NL_BUF_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genlh;
	int len;

	if (ctx->nl_fd < 0)
		return -ENOTCONN;

	memset(buf, 0, NLMSG_HDRLEN + GENL_HDRLEN);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type = (unsigned short)ctx->family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_pid = 0;

	genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	genlh->cmd = cmd;
	genlh->version = MXFS_NETLINK_VERSION;

	len = NLMSG_HDRLEN + GENL_HDRLEN;

	if (attrs_buf && attrs_len > 0) {
		if (len + attrs_len > (int)sizeof(buf))
			return -EMSGSIZE;
		memcpy(buf + len, attrs_buf, attrs_len);
		len += attrs_len;
	}

	nlh->nlmsg_len = (unsigned int)len;

	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	ssize_t n = sendto(ctx->nl_fd, buf, len, 0,
			   (struct sockaddr *)&addr, sizeof(addr));
	if (n < 0) {
		mxfsd_err("netlink: send cmd %u failed: %s", cmd, strerror(errno));
		return -errno;
	}

	return 0;
}

/*
 * Receive thread: reads incoming genetlink messages from the kernel
 * and dispatches them via the registered callback.
 */
static void *recv_thread(void *arg)
{
	struct mxfsd_netlink_ctx *ctx = arg;
	char buf[NL_BUF_SIZE];

	mxfsd_info("netlink: receive thread started");

	while (ctx->running) {
		ssize_t n = recv(ctx->nl_fd, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (!ctx->running)
				break;
			mxfsd_err("netlink: recv error: %s", strerror(errno));
			break;
		}

		if (n < (ssize_t)(NLMSG_HDRLEN + GENL_HDRLEN))
			continue;

		struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
			if (err->error)
				mxfsd_warn("netlink: received error %d",
					   err->error);
			continue;
		}

		struct genlmsghdr *genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);

		if (ctx->callback) {
			void *attrs = (char *)genlh + GENL_HDRLEN;
			int attrs_len = (int)(nlh->nlmsg_len -
				NLMSG_HDRLEN - GENL_HDRLEN);
			if (attrs_len < 0)
				attrs_len = 0;
			ctx->callback((enum mxfs_nl_cmd)genlh->cmd,
				      attrs, attrs_len,
				      ctx->callback_data);
		}
	}

	mxfsd_info("netlink: receive thread exiting");
	return NULL;
}

int mxfsd_netlink_init(struct mxfsd_netlink_ctx *ctx)
{
	struct sockaddr_nl addr;
	int fd;
	int family_id;

	memset(ctx, 0, sizeof(*ctx));
	ctx->nl_fd = -1;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0) {
		mxfsd_err("netlink: cannot create socket: %s", strerror(errno));
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = (unsigned int)getpid();

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		mxfsd_err("netlink: bind failed: %s", strerror(errno));
		close(fd);
		return -errno;
	}

	ctx->nl_fd = fd;

	/* Resolve the "mxfs" genetlink family. If the kernel module isn't
	 * loaded yet, this will fail — that's expected during early startup.
	 * The caller can retry later. */
	family_id = resolve_family(fd);
	if (family_id < 0) {
		mxfsd_warn("netlink: could not resolve '%s' family (rc=%d). "
			   "Kernel module may not be loaded.",
			   MXFS_NETLINK_FAMILY, family_id);
		/* Keep the socket open — we'll retry resolution later */
		ctx->family_id = -1;
	} else {
		ctx->family_id = family_id;
		mxfsd_info("netlink: resolved family '%s' id=%d",
			   MXFS_NETLINK_FAMILY, family_id);
	}

	/* Start receive thread */
	ctx->running = true;
	if (pthread_create(&ctx->recv_thread, NULL, recv_thread, ctx) != 0) {
		mxfsd_err("netlink: cannot create recv thread: %s",
			  strerror(errno));
		close(fd);
		ctx->nl_fd = -1;
		ctx->running = false;
		return -errno;
	}

	mxfsd_info("netlink: initialized");
	return 0;
}

void mxfsd_netlink_shutdown(struct mxfsd_netlink_ctx *ctx)
{
	ctx->running = false;

	if (ctx->nl_fd >= 0) {
		/* Shutdown the socket to unblock recv() in the thread */
		shutdown(ctx->nl_fd, SHUT_RDWR);
		pthread_join(ctx->recv_thread, NULL);
		close(ctx->nl_fd);
		ctx->nl_fd = -1;
	}

	mxfsd_info("netlink: shut down");
}

int mxfsd_netlink_set_callback(struct mxfsd_netlink_ctx *ctx,
                               mxfsd_nl_callback cb, void *user_data)
{
	ctx->callback = cb;
	ctx->callback_data = user_data;
	return 0;
}

int mxfsd_netlink_send_lock_grant(struct mxfsd_netlink_ctx *ctx,
                                  const struct mxfs_resource_id *resource,
                                  enum mxfs_lock_mode mode)
{
	char attrs[256];
	int offset = 0;
	uint8_t m = (uint8_t)mode;

	nla_put(attrs, &offset, MXFS_NL_ATTR_RESOURCE,
		resource, sizeof(*resource));
	nla_put_u8(attrs, &offset, MXFS_NL_ATTR_LOCK_MODE, m);

	mxfsd_dbg("netlink: sending lock grant mode=%u", m);
	return nl_send_cmd(ctx, MXFS_NL_CMD_LOCK_GRANT, attrs, offset);
}

int mxfsd_netlink_send_lock_deny(struct mxfsd_netlink_ctx *ctx,
                                 const struct mxfs_resource_id *resource,
                                 enum mxfs_error status)
{
	char attrs[256];
	int offset = 0;
	uint8_t s = (uint8_t)status;

	nla_put(attrs, &offset, MXFS_NL_ATTR_RESOURCE,
		resource, sizeof(*resource));
	nla_put_u8(attrs, &offset, MXFS_NL_ATTR_LOCK_STATUS, s);

	mxfsd_dbg("netlink: sending lock deny status=%u", s);
	return nl_send_cmd(ctx, MXFS_NL_CMD_LOCK_DENY, attrs, offset);
}

int mxfsd_netlink_send_cache_inval(struct mxfsd_netlink_ctx *ctx,
                                   const struct mxfs_resource_id *resource,
                                   uint64_t offset, uint64_t len)
{
	char attrs[256];
	int off = 0;

	nla_put(attrs, &off, MXFS_NL_ATTR_RESOURCE,
		resource, sizeof(*resource));
	nla_put_u64(attrs, &off, MXFS_NL_ATTR_OFFSET, offset);
	nla_put_u64(attrs, &off, MXFS_NL_ATTR_LENGTH, len);

	mxfsd_dbg("netlink: sending cache inval offset=%lu len=%lu",
		  (unsigned long)offset, (unsigned long)len);
	return nl_send_cmd(ctx, MXFS_NL_CMD_CACHE_INVAL, attrs, off);
}

int mxfsd_netlink_send_node_status(struct mxfsd_netlink_ctx *ctx,
                                   mxfs_node_id_t node,
                                   enum mxfs_node_state state)
{
	char attrs[128];
	int offset = 0;
	uint8_t s = (uint8_t)state;

	nla_put_u32(attrs, &offset, MXFS_NL_ATTR_NODE_ID, node);
	nla_put_u8(attrs, &offset, MXFS_NL_ATTR_NODE_STATE, s);

	mxfsd_dbg("netlink: sending node status node=%u state=%u", node, s);
	return nl_send_cmd(ctx, MXFS_NL_CMD_NODE_STATUS, attrs, offset);
}

int mxfsd_netlink_send_recovery_start(struct mxfsd_netlink_ctx *ctx)
{
	mxfsd_info("netlink: sending recovery start");
	return nl_send_cmd(ctx, MXFS_NL_CMD_RECOVERY_START, NULL, 0);
}

int mxfsd_netlink_send_recovery_done(struct mxfsd_netlink_ctx *ctx)
{
	mxfsd_info("netlink: sending recovery done");
	return nl_send_cmd(ctx, MXFS_NL_CMD_RECOVERY_DONE, NULL, 0);
}

int mxfsd_netlink_send_daemon_ready(struct mxfsd_netlink_ctx *ctx,
                                    mxfs_node_id_t node_id,
                                    const uint8_t volume_uuid[16],
                                    mxfs_volume_id_t volume_id)
{
	char attrs[256];
	int offset = 0;
	uint32_t pid = (uint32_t)getpid();

	nla_put_u32(attrs, &offset, MXFS_NL_ATTR_DAEMON_PID, pid);
	nla_put_u32(attrs, &offset, MXFS_NL_ATTR_NODE_ID, node_id);
	nla_put(attrs, &offset, MXFS_NL_ATTR_UUID, volume_uuid, 16);
	nla_put_u64(attrs, &offset, MXFS_NL_ATTR_VOLUME_ID, volume_id);

	mxfsd_info("netlink: sending daemon ready (pid=%u node=%u vol=0x%llx)",
	           pid, node_id, (unsigned long long)volume_id);
	return nl_send_cmd(ctx, MXFS_NL_CMD_DAEMON_READY, attrs, offset);
}
