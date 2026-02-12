/*
 * MXFS — Multinode XFS
 * Kernel-side Generic Netlink interface
 *
 * Handles communication between mxfs.ko and the local mxfsd daemon(s).
 * Lock requests from VFS operations are forwarded to mxfsd via genetlink.
 * Lock grants, cache invalidation, and daemon lifecycle commands arrive
 * from mxfsd.
 *
 * Per-mount portid: Each mounted MXFS volume has its own daemon with a
 * unique netlink portid stored in mxfs_sb_info. Lock send functions
 * accept a portid parameter to support multiple concurrent mounts.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <net/genetlink.h>
#include <mxfs/mxfs_common.h>
#include <mxfs/mxfs_netlink.h>
#include <mxfs/mxfs_dlm.h>
#include "mxfs_internal.h"

/* ─── Pending lock request tracking ───
 *
 * When the kernel sends a lock request to mxfsd, the calling thread blocks
 * on a completion. When the grant/deny arrives, we look up the pending
 * request by resource and complete it.
 */

#define MXFS_PENDING_HASH_BITS 8

struct mxfs_pending_req {
	struct hlist_node	hnode;
	struct mxfs_resource_id resource;
	struct completion	done;
	uint8_t			granted_mode;
	uint8_t			status;		/* mxfs_error */
};

static DEFINE_HASHTABLE(pending_reqs, MXFS_PENDING_HASH_BITS);
static DEFINE_SPINLOCK(pending_lock);
static atomic_t seq_counter = ATOMIC_INIT(0);

/* Node status tracking (prefixed to avoid collision with linux/nodemask.h) */
static uint8_t mxfs_node_states[MXFS_MAX_NODES];
static DEFINE_RWLOCK(mxfs_node_state_lock);

/* Hash a resource ID for the pending table */
static u32 resource_hash(const struct mxfs_resource_id *res)
{
	u32 h = (u32)res->volume;

	h ^= (u32)(res->volume >> 32);
	h ^= (u32)res->ino;
	h ^= (u32)(res->ino >> 32);
	h ^= (u32)res->offset;
	h ^= res->ag_number;
	h ^= res->type;
	return h;
}

static bool resource_eq(const struct mxfs_resource_id *a,
			const struct mxfs_resource_id *b)
{
	return a->volume == b->volume &&
	       a->ino == b->ino &&
	       a->offset == b->offset &&
	       a->ag_number == b->ag_number &&
	       a->type == b->type;
}

/* ─── Forward declaration of family (needed by alloc_msg) ─── */

static struct genl_family mxfs_nl_family;

/* ─── Netlink attribute policy ─── */

static const struct nla_policy mxfs_nl_policy[MXFS_NL_ATTR_MAX + 1] = {
	[MXFS_NL_ATTR_NODE_ID]     = { .type = NLA_U32 },
	[MXFS_NL_ATTR_NODE_STATE]  = { .type = NLA_U8 },
	[MXFS_NL_ATTR_LOCK_TYPE]   = { .type = NLA_U8 },
	[MXFS_NL_ATTR_LOCK_MODE]   = { .type = NLA_U8 },
	[MXFS_NL_ATTR_LOCK_FLAGS]  = { .type = NLA_U32 },
	[MXFS_NL_ATTR_LOCK_STATUS] = { .type = NLA_U8 },
	[MXFS_NL_ATTR_RESOURCE]    = { .len = sizeof(struct mxfs_resource_id) },
	[MXFS_NL_ATTR_VOLUME_ID]   = { .type = NLA_U64 },
	[MXFS_NL_ATTR_INODE]       = { .type = NLA_U64 },
	[MXFS_NL_ATTR_OFFSET]      = { .type = NLA_U64 },
	[MXFS_NL_ATTR_LENGTH]      = { .type = NLA_U64 },
	[MXFS_NL_ATTR_AG_NUMBER]   = { .type = NLA_U32 },
	[MXFS_NL_ATTR_EPOCH]       = { .type = NLA_U64 },
	[MXFS_NL_ATTR_STATUS_CODE] = { .type = NLA_U32 },
	[MXFS_NL_ATTR_DEV_PATH]    = { .type = NLA_NUL_STRING,
					.len  = MXFS_PATH_MAX },
	[MXFS_NL_ATTR_MOUNT_PATH]  = { .type = NLA_NUL_STRING,
					.len  = MXFS_PATH_MAX },
	[MXFS_NL_ATTR_UUID]        = { .len = 16 },
	[MXFS_NL_ATTR_DAEMON_PID]  = { .type = NLA_U32 },
};

/* ─── Handler: LOCK_GRANT (daemon -> kernel) ─── */

static int mxfs_nl_lock_grant(struct sk_buff *skb, struct genl_info *info)
{
	struct mxfs_resource_id *res;
	struct mxfs_pending_req *req;
	uint8_t mode;
	u32 hash;

	if (!info->attrs[MXFS_NL_ATTR_RESOURCE] ||
	    !info->attrs[MXFS_NL_ATTR_LOCK_MODE])
		return -EINVAL;

	res = nla_data(info->attrs[MXFS_NL_ATTR_RESOURCE]);
	mode = nla_get_u8(info->attrs[MXFS_NL_ATTR_LOCK_MODE]);
	hash = resource_hash(res);

	spin_lock(&pending_lock);
	hlist_for_each_entry(req, &pending_reqs[hash_min(hash, MXFS_PENDING_HASH_BITS)],
			     hnode) {
		if (resource_eq(&req->resource, res)) {
			req->granted_mode = mode;
			req->status = MXFS_OK;
			complete(&req->done);
			spin_unlock(&pending_lock);
			return 0;
		}
	}
	spin_unlock(&pending_lock);

	pr_warn("mxfs: lock grant for unknown resource\n");
	return 0;
}

/* ─── Handler: LOCK_DENY (daemon -> kernel) ─── */

static int mxfs_nl_lock_deny(struct sk_buff *skb, struct genl_info *info)
{
	struct mxfs_resource_id *res;
	struct mxfs_pending_req *req;
	uint8_t status;
	u32 hash;

	if (!info->attrs[MXFS_NL_ATTR_RESOURCE])
		return -EINVAL;

	res = nla_data(info->attrs[MXFS_NL_ATTR_RESOURCE]);
	status = MXFS_ERR_DEADLOCK; /* default denial reason */
	if (info->attrs[MXFS_NL_ATTR_LOCK_STATUS])
		status = nla_get_u8(info->attrs[MXFS_NL_ATTR_LOCK_STATUS]);

	hash = resource_hash(res);

	spin_lock(&pending_lock);
	hlist_for_each_entry(req, &pending_reqs[hash_min(hash, MXFS_PENDING_HASH_BITS)],
			     hnode) {
		if (resource_eq(&req->resource, res)) {
			req->granted_mode = MXFS_LOCK_NL;
			req->status = status;
			complete(&req->done);
			spin_unlock(&pending_lock);
			return 0;
		}
	}
	spin_unlock(&pending_lock);

	pr_warn("mxfs: lock deny for unknown resource\n");
	return 0;
}

/* ─── Handler: CACHE_INVAL (daemon -> kernel) ─── */

static int mxfs_nl_cache_inval(struct sk_buff *skb, struct genl_info *info)
{
	uint64_t volume, ino, offset, length;

	if (!info->attrs[MXFS_NL_ATTR_VOLUME_ID] ||
	    !info->attrs[MXFS_NL_ATTR_INODE])
		return -EINVAL;

	volume = nla_get_u64(info->attrs[MXFS_NL_ATTR_VOLUME_ID]);
	ino = nla_get_u64(info->attrs[MXFS_NL_ATTR_INODE]);

	offset = 0;
	if (info->attrs[MXFS_NL_ATTR_OFFSET])
		offset = nla_get_u64(info->attrs[MXFS_NL_ATTR_OFFSET]);

	length = 0;
	if (info->attrs[MXFS_NL_ATTR_LENGTH])
		length = nla_get_u64(info->attrs[MXFS_NL_ATTR_LENGTH]);

	return mxfs_cache_invalidate(volume, ino, offset, length);
}

/* ─── Handler: NODE_STATUS (daemon -> kernel) ─── */

static int mxfs_nl_node_status(struct sk_buff *skb, struct genl_info *info)
{
	uint32_t node_id;
	uint8_t state;

	if (!info->attrs[MXFS_NL_ATTR_NODE_ID] ||
	    !info->attrs[MXFS_NL_ATTR_NODE_STATE])
		return -EINVAL;

	node_id = nla_get_u32(info->attrs[MXFS_NL_ATTR_NODE_ID]);
	state = nla_get_u8(info->attrs[MXFS_NL_ATTR_NODE_STATE]);

	if (node_id >= MXFS_MAX_NODES) {
		pr_warn("mxfs: node_status: invalid node_id %u\n", node_id);
		return -EINVAL;
	}

	write_lock(&mxfs_node_state_lock);
	mxfs_node_states[node_id] = state;
	write_unlock(&mxfs_node_state_lock);

	pr_info("mxfs: node %u state -> %u\n", node_id, state);
	return 0;
}

/* ─── Handler: VOLUME_MOUNT (kernel -> daemon, but daemon acks) ─── */

static int mxfs_nl_volume_mount(struct sk_buff *skb, struct genl_info *info)
{
	/* This command is sent kernel->daemon. If the daemon sends it
	 * back, treat as a no-op ack. */
	return 0;
}

/* ─── Handler: VOLUME_UMOUNT (kernel -> daemon) ─── */

static int mxfs_nl_volume_umount(struct sk_buff *skb, struct genl_info *info)
{
	return 0;
}

/* ─── Handler: STATUS_REQ (either direction) ─── */

static int mxfs_nl_status_req(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("mxfs: status request from portid %u\n", info->snd_portid);
	return 0;
}

/* ─── Handler: STATUS_RESP (either direction) ─── */

static int mxfs_nl_status_resp(struct sk_buff *skb, struct genl_info *info)
{
	return 0;
}

/* ─── Handler: RECOVERY_START (daemon -> kernel) ─── */

static int mxfs_nl_recovery_start(struct sk_buff *skb, struct genl_info *info)
{
	struct mxfs_sb_info *sbi;
	uint64_t volume;

	if (!info->attrs[MXFS_NL_ATTR_VOLUME_ID])
		return -EINVAL;

	volume = nla_get_u64(info->attrs[MXFS_NL_ATTR_VOLUME_ID]);

	sbi = mxfs_cache_find_sbi_by_volume(volume);
	if (!sbi) {
		pr_warn("mxfs: recovery_start: unknown volume 0x%llx\n",
			(unsigned long long)volume);
		return -ENODEV;
	}

	atomic_set(&sbi->recovering, 1);
	pr_info("mxfs: recovery started for volume 0x%llx\n",
		(unsigned long long)volume);
	return 0;
}

/* ─── Handler: RECOVERY_DONE (daemon -> kernel) ─── */

static int mxfs_nl_recovery_done(struct sk_buff *skb, struct genl_info *info)
{
	struct mxfs_sb_info *sbi;
	uint64_t volume;

	if (!info->attrs[MXFS_NL_ATTR_VOLUME_ID])
		return -EINVAL;

	volume = nla_get_u64(info->attrs[MXFS_NL_ATTR_VOLUME_ID]);

	sbi = mxfs_cache_find_sbi_by_volume(volume);
	if (!sbi) {
		pr_warn("mxfs: recovery_done: unknown volume 0x%llx\n",
			(unsigned long long)volume);
		return -ENODEV;
	}

	atomic_set(&sbi->recovering, 0);
	wake_up_all(&sbi->recovery_wait);
	pr_info("mxfs: recovery complete for volume 0x%llx\n",
		(unsigned long long)volume);
	return 0;
}

/* ─── Handler: LOCK_BAST (daemon -> kernel) ─── */

/* Defined in mxfs_lockcache.c */
extern void mxfs_bast_work_fn(struct work_struct *work);

static int mxfs_nl_lock_bast(struct sk_buff *skb, struct genl_info *info)
{
	struct mxfs_resource_id *res;
	uint64_t volume_id;
	struct super_block *sb;
	struct inode *inode;
	struct mxfs_inode_info *ii;

	if (!info->attrs[MXFS_NL_ATTR_RESOURCE] ||
	    !info->attrs[MXFS_NL_ATTR_VOLUME_ID])
		return -EINVAL;

	res = nla_data(info->attrs[MXFS_NL_ATTR_RESOURCE]);
	volume_id = nla_get_u64(info->attrs[MXFS_NL_ATTR_VOLUME_ID]);

	sb = mxfs_cache_find_sb_by_volume(volume_id);
	if (!sb)
		return -ENODEV;

	/* Look up the MXFS inode by ino number */
	inode = ilookup(sb, (unsigned long)res->ino);
	if (!inode) {
		/* Inode not in VFS cache — nothing to release.
		 * Send immediate release to daemon. */
		mxfs_nl_send_lock_release(res);
		return 0;
	}

	ii = MXFS_INODE(inode);

	spin_lock(&ii->lock_spin);
	if (ii->cached_mode == MXFS_LOCK_NL) {
		/* No cached lock — send release immediately */
		spin_unlock(&ii->lock_spin);
		mxfs_nl_send_lock_release(res);
		iput(inode);
		return 0;
	}

	/* Mark BAST pending so new VFS ops bypass cache */
	ii->bast_pending = true;

	if (atomic_read(&ii->lock_holders) == 0) {
		/* No active users — release inline now */
		uint8_t old_mode = ii->cached_mode;

		ii->cached_mode = MXFS_LOCK_NL;
		ii->bast_pending = false;
		spin_unlock(&ii->lock_spin);

		if (old_mode != MXFS_LOCK_NL)
			mxfs_nl_send_lock_release(res);
		iput(inode);
		return 0;
	}

	/* Active holders exist — queue deferred release */
	spin_unlock(&ii->lock_spin);
	INIT_WORK(&ii->bast_work, mxfs_bast_work_fn);
	schedule_work(&ii->bast_work);

	iput(inode);
	return 0;
}

/* ─── Handler: DAEMON_READY (daemon -> kernel) ─── */

static int mxfs_nl_daemon_ready(struct sk_buff *skb, struct genl_info *info)
{
	struct mxfs_sb_info *sbi;
	uint64_t volume_id;
	uint32_t daemon_pid;

	if (!info->attrs[MXFS_NL_ATTR_VOLUME_ID] ||
	    !info->attrs[MXFS_NL_ATTR_DAEMON_PID])
		return -EINVAL;

	volume_id = nla_get_u64(info->attrs[MXFS_NL_ATTR_VOLUME_ID]);
	daemon_pid = nla_get_u32(info->attrs[MXFS_NL_ATTR_DAEMON_PID]);

	sbi = mxfs_cache_find_sbi_by_volume(volume_id);
	if (!sbi) {
		pr_warn("mxfs: daemon_ready: unknown volume 0x%llx\n",
			(unsigned long long)volume_id);
		return -ENODEV;
	}

	sbi->daemon_portid = info->snd_portid;
	sbi->daemon_pid = (pid_t)daemon_pid;
	sbi->daemon_ready = true;
	complete(&sbi->daemon_startup);

	pr_info("mxfs: daemon ready (portid %u, pid %u, volume 0x%llx)\n",
		info->snd_portid, daemon_pid,
		(unsigned long long)volume_id);

	return 0;
}

/* ─── Genetlink operations table ─── */

static const struct genl_ops mxfs_nl_ops[] = {
	{
		.cmd	  = MXFS_NL_CMD_LOCK_GRANT,
		.validate = GENL_DONT_VALIDATE_STRICT,
		.doit	  = mxfs_nl_lock_grant,
		.flags    = GENL_ADMIN_PERM,
	},
	{
		.cmd	  = MXFS_NL_CMD_LOCK_DENY,
		.validate = GENL_DONT_VALIDATE_STRICT,
		.doit	  = mxfs_nl_lock_deny,
		.flags    = GENL_ADMIN_PERM,
	},
	{
		.cmd	  = MXFS_NL_CMD_CACHE_INVAL,
		.validate = GENL_DONT_VALIDATE_STRICT,
		.doit	  = mxfs_nl_cache_inval,
		.flags    = GENL_ADMIN_PERM,
	},
	{
		.cmd	  = MXFS_NL_CMD_NODE_STATUS,
		.validate = GENL_DONT_VALIDATE_STRICT,
		.doit	  = mxfs_nl_node_status,
		.flags    = GENL_ADMIN_PERM,
	},
	{
		.cmd	  = MXFS_NL_CMD_VOLUME_MOUNT,
		.validate = GENL_DONT_VALIDATE_STRICT,
		.doit	  = mxfs_nl_volume_mount,
		.flags    = GENL_ADMIN_PERM,
	},
	{
		.cmd	  = MXFS_NL_CMD_VOLUME_UMOUNT,
		.validate = GENL_DONT_VALIDATE_STRICT,
		.doit	  = mxfs_nl_volume_umount,
		.flags    = GENL_ADMIN_PERM,
	},
	{
		.cmd	  = MXFS_NL_CMD_STATUS_REQ,
		.validate = GENL_DONT_VALIDATE_STRICT,
		.doit	  = mxfs_nl_status_req,
		.flags    = GENL_ADMIN_PERM,
	},
	{
		.cmd	  = MXFS_NL_CMD_STATUS_RESP,
		.validate = GENL_DONT_VALIDATE_STRICT,
		.doit	  = mxfs_nl_status_resp,
		.flags    = GENL_ADMIN_PERM,
	},
	{
		.cmd	  = MXFS_NL_CMD_RECOVERY_START,
		.validate = GENL_DONT_VALIDATE_STRICT,
		.doit	  = mxfs_nl_recovery_start,
		.flags    = GENL_ADMIN_PERM,
	},
	{
		.cmd	  = MXFS_NL_CMD_RECOVERY_DONE,
		.validate = GENL_DONT_VALIDATE_STRICT,
		.doit	  = mxfs_nl_recovery_done,
		.flags    = GENL_ADMIN_PERM,
	},
	{
		.cmd	  = MXFS_NL_CMD_DAEMON_READY,
		.validate = GENL_DONT_VALIDATE_STRICT,
		.doit	  = mxfs_nl_daemon_ready,
		.flags    = GENL_ADMIN_PERM,
	},
	{
		.cmd	  = MXFS_NL_CMD_LOCK_BAST,
		.validate = GENL_DONT_VALIDATE_STRICT,
		.doit	  = mxfs_nl_lock_bast,
		.flags    = GENL_ADMIN_PERM,
	},
};

/* ─── Multicast groups ─── */

static const struct genl_multicast_group mxfs_nl_mcast_groups[] = {
	[MXFS_NL_MCAST_LOCKS]  = { .name = "locks" },
	[MXFS_NL_MCAST_STATUS] = { .name = "status" },
};

/* ─── Genetlink family definition ─── */

static struct genl_family mxfs_nl_family = {
	.name		= MXFS_NETLINK_FAMILY,
	.version	= MXFS_NETLINK_VERSION,
	.maxattr	= MXFS_NL_ATTR_MAX,
	.policy		= mxfs_nl_policy,
	.module		= THIS_MODULE,
	.ops		= mxfs_nl_ops,
	.n_ops		= ARRAY_SIZE(mxfs_nl_ops),
	.mcgrps		= mxfs_nl_mcast_groups,
	.n_mcgrps	= ARRAY_SIZE(mxfs_nl_mcast_groups),
};

/* ─── Message sending helpers ─── */

/*
 * Allocate a genetlink message.
 * Returns the skb or NULL on failure. The caller must nla_put
 * attributes and then call mxfs_nl_send_to_portid().
 */
static struct sk_buff *mxfs_nl_alloc_msg(uint8_t cmd, void **hdr)
{
	struct sk_buff *skb;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return NULL;

	*hdr = genlmsg_put(skb, 0, atomic_inc_return(&seq_counter),
			   &mxfs_nl_family, 0, cmd);
	if (!*hdr) {
		nlmsg_free(skb);
		return NULL;
	}

	return skb;
}

/*
 * Send a genetlink message to a specific portid.
 * Per-mount daemon support: callers provide the target portid
 * from the relevant mxfs_sb_info.
 */
static int mxfs_nl_send_to_portid(struct sk_buff *skb, void *hdr, u32 portid)
{
	int ret;

	genlmsg_end(skb, hdr);

	if (portid == 0) {
		nlmsg_free(skb);
		return -ENOTCONN;
	}

	ret = genlmsg_unicast(&init_net, skb, portid);
	if (ret)
		pr_warn("mxfs: failed to send netlink msg to portid %u: %d\n",
			portid, ret);

	return ret;
}

/*
 * mxfs_nl_send_lock_req — Send a lock request to mxfsd and block until response.
 *
 * Called from VFS operation wrappers when a distributed lock is needed.
 * The calling context must be sleepable (process context).
 *
 * The portid is extracted from the resource's volume_id via the cache
 * module's SBI lookup.
 *
 * Returns 0 on grant, negative errno on failure.
 * On success, *granted_mode is set to the mode actually granted.
 */
int mxfs_nl_send_lock_req(const struct mxfs_resource_id *resource,
			   uint8_t mode, uint32_t flags,
			   uint8_t *granted_mode)
{
	struct mxfs_pending_req pending;
	struct mxfs_sb_info *sbi;
	struct sk_buff *skb;
	void *hdr;
	u32 hash;
	u32 portid;
	unsigned long timeout;
	int ret;

	/* Look up the per-mount daemon portid */
	sbi = mxfs_cache_find_sbi_by_volume(resource->volume);
	if (!sbi || !sbi->daemon_ready) {
		pr_warn("mxfs: lock_req: no daemon for volume 0x%llx\n",
			(unsigned long long)resource->volume);
		return -ENOTCONN;
	}
	portid = sbi->daemon_portid;

	/* Set up the pending request with a completion */
	memcpy(&pending.resource, resource, sizeof(*resource));
	init_completion(&pending.done);
	pending.granted_mode = MXFS_LOCK_NL;
	pending.status = MXFS_OK;

	hash = resource_hash(resource);

	spin_lock(&pending_lock);
	hlist_add_head(&pending.hnode,
		       &pending_reqs[hash_min(hash, MXFS_PENDING_HASH_BITS)]);
	spin_unlock(&pending_lock);

	/* Build and send the netlink message */
	skb = mxfs_nl_alloc_msg(MXFS_NL_CMD_LOCK_REQ, &hdr);
	if (!skb) {
		ret = -ENOMEM;
		goto out_remove;
	}

	if (nla_put(skb, MXFS_NL_ATTR_RESOURCE,
		    sizeof(*resource), resource) ||
	    nla_put_u8(skb, MXFS_NL_ATTR_LOCK_MODE, mode) ||
	    nla_put_u8(skb, MXFS_NL_ATTR_LOCK_TYPE, resource->type) ||
	    nla_put_u32(skb, MXFS_NL_ATTR_LOCK_FLAGS, flags)) {
		nlmsg_free(skb);
		ret = -EMSGSIZE;
		goto out_remove;
	}

	ret = mxfs_nl_send_to_portid(skb, hdr, portid);
	if (ret)
		goto out_remove;

	/* Block waiting for daemon response (grant or deny) */
	timeout = msecs_to_jiffies(MXFS_LOCK_WAIT_TIMEOUT_MS);
	ret = wait_for_completion_interruptible_timeout(&pending.done, timeout);
	if (ret == 0) {
		ret = -ETIMEDOUT;
		goto out_remove;
	}
	if (ret < 0)
		goto out_remove;  /* interrupted by signal */

	/* Check result */
	if (pending.status != MXFS_OK) {
		ret = -EIO;
		goto out_remove;
	}

	*granted_mode = pending.granted_mode;
	ret = 0;

out_remove:
	spin_lock(&pending_lock);
	hlist_del(&pending.hnode);
	spin_unlock(&pending_lock);

	return ret;
}

/*
 * mxfs_nl_send_lock_release — Tell mxfsd we are releasing a distributed lock.
 *
 * Non-blocking. Fire and forget. Looks up portid from volume.
 */
int mxfs_nl_send_lock_release(const struct mxfs_resource_id *resource)
{
	struct mxfs_sb_info *sbi;
	struct sk_buff *skb;
	void *hdr;
	u32 portid;

	sbi = mxfs_cache_find_sbi_by_volume(resource->volume);
	if (!sbi || !sbi->daemon_ready)
		return -ENOTCONN;
	portid = sbi->daemon_portid;

	skb = mxfs_nl_alloc_msg(MXFS_NL_CMD_LOCK_RELEASE, &hdr);
	if (!skb)
		return -ENOMEM;

	if (nla_put(skb, MXFS_NL_ATTR_RESOURCE,
		    sizeof(*resource), resource)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	return mxfs_nl_send_to_portid(skb, hdr, portid);
}

/*
 * mxfs_nl_send_volume_mount — Notify mxfsd that XFS has mounted with MXFS.
 */
int mxfs_nl_send_volume_mount(uint64_t volume_id,
			      const char *dev_path,
			      const char *mount_path)
{
	struct mxfs_sb_info *sbi;
	struct sk_buff *skb;
	void *hdr;
	u32 portid;

	sbi = mxfs_cache_find_sbi_by_volume(volume_id);
	if (!sbi || !sbi->daemon_ready)
		return -ENOTCONN;
	portid = sbi->daemon_portid;

	skb = mxfs_nl_alloc_msg(MXFS_NL_CMD_VOLUME_MOUNT, &hdr);
	if (!skb)
		return -ENOMEM;

	if (nla_put_u64_64bit(skb, MXFS_NL_ATTR_VOLUME_ID, volume_id,
			      MXFS_NL_ATTR_UNSPEC) ||
	    nla_put_string(skb, MXFS_NL_ATTR_DEV_PATH, dev_path) ||
	    nla_put_string(skb, MXFS_NL_ATTR_MOUNT_PATH, mount_path)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	return mxfs_nl_send_to_portid(skb, hdr, portid);
}

/*
 * mxfs_nl_send_volume_umount — Notify mxfsd that XFS is unmounting.
 */
int mxfs_nl_send_volume_umount(uint64_t volume_id)
{
	struct mxfs_sb_info *sbi;
	struct sk_buff *skb;
	void *hdr;
	u32 portid;

	sbi = mxfs_cache_find_sbi_by_volume(volume_id);
	if (!sbi || !sbi->daemon_ready)
		return -ENOTCONN;
	portid = sbi->daemon_portid;

	skb = mxfs_nl_alloc_msg(MXFS_NL_CMD_VOLUME_UMOUNT, &hdr);
	if (!skb)
		return -ENOMEM;

	if (nla_put_u64_64bit(skb, MXFS_NL_ATTR_VOLUME_ID, volume_id,
			      MXFS_NL_ATTR_UNSPEC)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	return mxfs_nl_send_to_portid(skb, hdr, portid);
}

/*
 * mxfs_nl_get_node_state — Query cached node state.
 * Returns the mxfs_node_state for the given node.
 */
uint8_t mxfs_nl_get_node_state(uint32_t node_id)
{
	uint8_t state;

	if (node_id >= MXFS_MAX_NODES)
		return MXFS_NODE_UNKNOWN;

	read_lock(&mxfs_node_state_lock);
	state = mxfs_node_states[node_id];
	read_unlock(&mxfs_node_state_lock);

	return state;
}

/* ─── Init / Exit ─── */

int mxfs_netlink_init(void)
{
	int ret;

	hash_init(pending_reqs);
	memset(mxfs_node_states, MXFS_NODE_UNKNOWN, sizeof(mxfs_node_states));

	ret = genl_register_family(&mxfs_nl_family);
	if (ret) {
		pr_err("mxfs: failed to register genetlink family: %d\n", ret);
		return ret;
	}

	pr_info("mxfs: genetlink family \"%s\" v%d registered\n",
		MXFS_NETLINK_FAMILY, MXFS_NETLINK_VERSION);

	return 0;
}

void mxfs_netlink_exit(void)
{
	genl_unregister_family(&mxfs_nl_family);
	pr_info("mxfs: genetlink family unregistered\n");
}
