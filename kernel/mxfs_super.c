/*
 * MXFS — Multinode XFS
 * Superblock operations, mount/umount, inode cache, dentry helpers
 *
 * Implements the stacking filesystem core: MXFS registers as type "mxfs",
 * mounts XFS internally via vfs_kern_mount, and wraps every XFS inode/dentry
 * with MXFS wrappers that pass through operations while adding distributed
 * lock coordination.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/fs_stack.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/statfs.h>
#include <linux/seq_file.h>
#include <linux/namei.h>
#include <linux/mm.h>
#include <linux/kmod.h>
#include <linux/sched/signal.h>
#include <mxfs/mxfs_common.h>
#include <mxfs/mxfs_dlm.h>
#include "mxfs_internal.h"

/* ─── Inode SLAB cache ─── */

static struct kmem_cache *mxfs_inode_cache;

static void mxfs_init_once(void *obj)
{
	struct mxfs_inode_info *info = obj;

	inode_init_once(&info->vfs_inode);
}

int mxfs_init_inode_cache(void)
{
	mxfs_inode_cache = kmem_cache_create("mxfs_inode_info",
					     sizeof(struct mxfs_inode_info),
					     0,
					     SLAB_RECLAIM_ACCOUNT,
					     mxfs_init_once);
	if (!mxfs_inode_cache)
		return -ENOMEM;

	return 0;
}

void mxfs_destroy_inode_cache(void)
{
	if (mxfs_inode_cache) {
		rcu_barrier();
		kmem_cache_destroy(mxfs_inode_cache);
	}
}

static struct inode *mxfs_alloc_inode(struct super_block *sb)
{
	struct mxfs_inode_info *info;

	info = kmem_cache_alloc(mxfs_inode_cache, GFP_KERNEL);
	if (!info)
		return NULL;

	info->lower_inode = NULL;
	return &info->vfs_inode;
}

static void mxfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(mxfs_inode_cache, MXFS_INODE(inode));
}

/* mxfs_uuid_to_volume_id() is now in mxfs_common.h */

/* ─── Mount option parsing ─── */

enum {
	OPT_IFACE,
	OPT_PORT,
	OPT_MULTICAST,
	OPT_BROADCAST,
	OPT_ERR,
};

static const match_table_t mxfs_tokens = {
	{ OPT_IFACE,     "iface=%s" },
	{ OPT_PORT,      "port=%u" },
	{ OPT_MULTICAST, "multicast=%s" },
	{ OPT_BROADCAST, "broadcast=%s" },
	{ OPT_ERR, NULL },
};

static int mxfs_parse_options(struct mxfs_sb_info *sbi, const char *options)
{
	char *p;
	char *opts;
	substring_t args[MAX_OPT_ARGS];
	int token;
	int val;

	if (!options || !*options)
		return 0;

	opts = kstrdup(options, GFP_KERNEL);
	if (!opts)
		return -ENOMEM;

	while ((p = strsep(&opts, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, mxfs_tokens, args);
		switch (token) {
		case OPT_IFACE:
			match_strlcpy(sbi->iface, &args[0],
				      sizeof(sbi->iface));
			break;
		case OPT_PORT:
			if (match_int(&args[0], &val) || val <= 0 ||
			    val > 65535) {
				pr_err("mxfs: invalid port value\n");
				kfree(opts);
				return -EINVAL;
			}
			sbi->port = (uint16_t)val;
			break;
		case OPT_MULTICAST:
			match_strlcpy(sbi->mcast_addr, &args[0],
				      sizeof(sbi->mcast_addr));
			break;
		case OPT_BROADCAST:
			match_strlcpy(sbi->bcast_addr, &args[0],
				      sizeof(sbi->bcast_addr));
			break;
		default:
			pr_err("mxfs: unrecognized mount option '%s'\n", p);
			kfree(opts);
			return -EINVAL;
		}
	}

	kfree(opts);
	return 0;
}

/* ─── Super operations ─── */

static int mxfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int ret;
	struct path lower_path;

	mxfs_get_lower_path(dentry, &lower_path);
	ret = vfs_statfs(&lower_path, buf);
	mxfs_put_lower_path(dentry, &lower_path);

	if (!ret)
		buf->f_type = MXFS_SUPER_MAGIC;

	return ret;
}

static void mxfs_evict_inode(struct inode *inode)
{
	struct inode *lower_inode;

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	lower_inode = mxfs_lower_inode(inode);
	if (lower_inode)
		iput(lower_inode);
}

static int mxfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct mxfs_sb_info *sbi = MXFS_SB(root->d_sb);

	if (sbi->iface[0])
		seq_printf(m, ",iface=%s", sbi->iface);
	if (sbi->port)
		seq_printf(m, ",port=%u", sbi->port);
	if (sbi->mcast_addr[0])
		seq_printf(m, ",multicast=%s", sbi->mcast_addr);
	if (sbi->bcast_addr[0])
		seq_printf(m, ",broadcast=%s", sbi->bcast_addr);

	return 0;
}

const struct super_operations mxfs_sops = {
	.alloc_inode	= mxfs_alloc_inode,
	.destroy_inode	= mxfs_destroy_inode,
	.statfs		= mxfs_statfs,
	.evict_inode	= mxfs_evict_inode,
	.show_options	= mxfs_show_options,
};

/* ─── Dentry operations ─── */

static void mxfs_d_release(struct dentry *dentry)
{
	struct mxfs_dentry_info *info = MXFS_DENTRY(dentry);

	if (info) {
		path_put(&info->lower_path);
		kfree(info);
		dentry->d_fsdata = NULL;
	}
}

const struct dentry_operations mxfs_dops = {
	.d_release	= mxfs_d_release,
};

/* ─── Inode creation (wrapping a lower XFS inode) ─── */

/*
 * mxfs_iget — Create or find an MXFS inode wrapping a lower XFS inode.
 *
 * Uses iget_locked with the lower inode number. If the inode is new,
 * sets up the wrapper: copies attributes, assigns operation tables,
 * and takes a reference on the lower inode.
 */
struct inode *mxfs_iget(struct super_block *sb, struct inode *lower_inode)
{
	struct mxfs_inode_info *info;
	struct inode *inode;

	if (!lower_inode)
		return ERR_PTR(-ENOENT);

	inode = iget_locked(sb, lower_inode->i_ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode->i_state & I_NEW))
		return inode;

	/* New inode — set up the wrapper */
	info = MXFS_INODE(inode);
	info->lower_inode = igrab(lower_inode);
	if (!info->lower_inode) {
		iget_failed(inode);
		return ERR_PTR(-ESTALE);
	}

	/* Copy attributes from lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);

	/* Assign operation tables based on inode type */
	if (S_ISREG(lower_inode->i_mode)) {
		inode->i_op = &mxfs_main_iops;
		inode->i_fop = &mxfs_main_fops;
	} else if (S_ISDIR(lower_inode->i_mode)) {
		inode->i_op = &mxfs_dir_iops;
		inode->i_fop = &mxfs_dir_fops;
	} else if (S_ISLNK(lower_inode->i_mode)) {
		inode->i_op = &mxfs_symlink_iops;
	} else {
		/*
		 * Special files (block dev, char dev, fifo, socket):
		 * use generic operations, just copy from lower.
		 */
		inode->i_op = &mxfs_main_iops;
		init_special_inode(inode, lower_inode->i_mode,
				   lower_inode->i_rdev);
	}

	/* Inherit the address space ops from lower (passthrough model) */
	inode->i_mapping->a_ops = lower_inode->i_mapping->a_ops;

	unlock_new_inode(inode);
	return inode;
}

/*
 * mxfs_interpose — Connect an MXFS dentry to a lower dentry/vfsmount.
 *
 * Allocates dentry private data, creates the wrapping inode via mxfs_iget,
 * and attaches the inode to the dentry.
 */
int mxfs_interpose(struct dentry *dentry, struct super_block *sb,
		   struct path *lower_path)
{
	struct inode *inode;
	struct inode *lower_inode;
	struct mxfs_dentry_info *info;

	lower_inode = d_inode(lower_path->dentry);
	if (!lower_inode)
		return -ENOENT;

	inode = mxfs_iget(sb, lower_inode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		iput(inode);
		return -ENOMEM;
	}

	info->lower_path.dentry = dget(lower_path->dentry);
	info->lower_path.mnt = mntget(lower_path->mnt);
	dentry->d_fsdata = info;

	d_instantiate(dentry, inode);
	return 0;
}

/* ─── Daemon spawn / kill ─── */

/*
 * mxfs_spawn_daemon — Launch the mxfsd daemon for this mount.
 *
 * Builds the argument vector from the mount's device path, mount point,
 * volume UUID, and optional mount options (iface, port, multicast,
 * broadcast). Uses call_usermodehelper with UMH_WAIT_EXEC so the
 * stack strings remain valid until exec completes.
 *
 * The daemon's PID comes back asynchronously via the DAEMON_READY
 * netlink message.
 */
static int mxfs_spawn_daemon(struct mxfs_sb_info *sbi)
{
	/* Max argv: mxfsd --device X --mountpoint X --uuid X
	 *           [--iface X] [--port X] [--multicast X] [--broadcast X]
	 *           NULL = up to 15 entries + NULL */
	char *argv[16];
	char *envp[] = { "HOME=/", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
	char uuid_hex[33];
	char port_str[8];
	int argc = 0;
	int ret;
	unsigned int i;

	/* Format UUID as hex string (32 chars, no dashes) */
	for (i = 0; i < 16; i++)
		snprintf(uuid_hex + i * 2, 3, "%02x", sbi->volume_uuid[i]);

	argv[argc++] = MXFSD_PATH;
	argv[argc++] = "--device";
	argv[argc++] = sbi->dev_name;
	argv[argc++] = "--mountpoint";
	argv[argc++] = sbi->mount_path;
	argv[argc++] = "--uuid";
	argv[argc++] = uuid_hex;

	if (sbi->iface[0]) {
		argv[argc++] = "--iface";
		argv[argc++] = sbi->iface;
	}

	if (sbi->port) {
		snprintf(port_str, sizeof(port_str), "%u", sbi->port);
		argv[argc++] = "--port";
		argv[argc++] = port_str;
	}

	if (sbi->mcast_addr[0]) {
		argv[argc++] = "--multicast";
		argv[argc++] = sbi->mcast_addr;
	}

	if (sbi->bcast_addr[0]) {
		argv[argc++] = "--broadcast";
		argv[argc++] = sbi->bcast_addr;
	}

	argv[argc] = NULL;

	pr_info("mxfs: spawning daemon: %s --device %s --mountpoint %s\n",
		MXFSD_PATH, sbi->dev_name, sbi->mount_path);

	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (ret) {
		pr_err("mxfs: failed to spawn daemon: %d\n", ret);
		return ret;
	}

	return 0;
}

/*
 * mxfs_kill_daemon — Send SIGTERM to the mount's daemon.
 *
 * Called during umount to cleanly shut down the daemon.
 */
static void mxfs_kill_daemon(struct mxfs_sb_info *sbi)
{
	struct pid *pid_struct;

	if (sbi->daemon_pid <= 0)
		return;

	pid_struct = find_get_pid(sbi->daemon_pid);
	if (pid_struct) {
		pr_info("mxfs: killing daemon pid %d\n", sbi->daemon_pid);
		kill_pid(pid_struct, SIGTERM, 1);
		put_pid(pid_struct);
	}

	sbi->daemon_pid = 0;
	sbi->daemon_ready = false;
	sbi->daemon_portid = 0;
}

/* ─── Recovery freeze helpers ─── */

/*
 * mxfs_wait_for_recovery — Block the calling thread while recovery is
 * in progress on this mount. Called by VFS operation wrappers before
 * sending any lock request.
 *
 * Returns 0 normally, -EINTR if interrupted by a signal.
 */
int mxfs_wait_for_recovery(struct mxfs_sb_info *sbi)
{
	return wait_event_interruptible(sbi->recovery_wait,
					!atomic_read(&sbi->recovering));
}

/* ─── Context struct for passing dev_name through mount_nodev ─── */

struct mxfs_mount_ctx {
	const char	*dev_name;
	const char	*options;
};

/* ─── fill_super — Core mount logic ─── */

static int mxfs_fill_super(struct super_block *sb, void *raw_data, int silent)
{
	struct mxfs_mount_ctx *ctx = raw_data;
	struct mxfs_sb_info *sbi;
	struct vfsmount *lower_mnt;
	struct super_block *lower_sb;
	struct inode *lower_root;
	struct inode *root_inode;
	struct dentry *root_dentry;
	struct mxfs_dentry_info *root_info;
	int ret;

	if (!ctx || !ctx->dev_name) {
		pr_err("mxfs: no device specified\n");
		return -EINVAL;
	}

	/* Allocate per-mount state */
	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sb->s_fs_info = sbi;

	/* Initialize fields */
	init_completion(&sbi->daemon_startup);
	atomic_set(&sbi->recovering, 0);
	init_waitqueue_head(&sbi->recovery_wait);
	sbi->daemon_pid = 0;
	sbi->daemon_portid = 0;
	sbi->daemon_ready = false;

	/* Save device name */
	sbi->dev_name = kstrdup(ctx->dev_name, GFP_KERNEL);
	if (!sbi->dev_name) {
		ret = -ENOMEM;
		goto err_sbi;
	}

	/* Parse mount options */
	ret = mxfs_parse_options(sbi, ctx->options);
	if (ret)
		goto err_devname;

	/* Mount XFS internally on the real block device */
	lower_mnt = vfs_kern_mount(get_fs_type("xfs"), 0,
				   ctx->dev_name, NULL);
	if (IS_ERR(lower_mnt)) {
		ret = PTR_ERR(lower_mnt);
		pr_err("mxfs: failed to mount XFS on %s: %d\n",
		       ctx->dev_name, ret);
		goto err_devname;
	}

	sbi->lower_mnt = lower_mnt;
	lower_sb = lower_mnt->mnt_sb;
	sbi->lower_sb = lower_sb;

	/* Read XFS superblock UUID for volume identity */
	memcpy(sbi->volume_uuid, lower_sb->s_uuid.b,
	       sizeof(sbi->volume_uuid));
	sbi->volume_id = mxfs_uuid_to_volume_id(sbi->volume_uuid,
						 sizeof(sbi->volume_uuid));

	pr_info("mxfs: volume UUID -> volume_id 0x%llx\n",
		(unsigned long long)sbi->volume_id);

	/* Configure superblock */
	sb->s_stack_depth = lower_sb->s_stack_depth + 1;
	if (sb->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("mxfs: maximum stacking depth exceeded\n");
		ret = -EINVAL;
		goto err_lower;
	}

	sb->s_maxbytes = lower_sb->s_maxbytes;
	sb->s_blocksize = lower_sb->s_blocksize;
	sb->s_blocksize_bits = lower_sb->s_blocksize_bits;
	sb->s_magic = MXFS_SUPER_MAGIC;
	sb->s_op = &mxfs_sops;
	sb->s_d_op = &mxfs_dops;
	sb->s_time_gran = lower_sb->s_time_gran;
	sb->s_flags |= SB_NOSEC;

	/* Create root inode wrapping XFS root */
	lower_root = d_inode(lower_sb->s_root);
	root_inode = mxfs_iget(sb, lower_root);
	if (IS_ERR(root_inode)) {
		ret = PTR_ERR(root_inode);
		goto err_lower;
	}

	/* Create root dentry */
	root_dentry = d_make_root(root_inode);
	if (!root_dentry) {
		ret = -ENOMEM;
		goto err_lower;
	}

	/* Set up root dentry's lower path */
	root_info = kmalloc(sizeof(*root_info), GFP_KERNEL);
	if (!root_info) {
		ret = -ENOMEM;
		goto err_root;
	}

	root_info->lower_path.dentry = dget(lower_sb->s_root);
	root_info->lower_path.mnt = mntget(lower_mnt);
	root_dentry->d_fsdata = root_info;

	sb->s_root = root_dentry;

	/* Register lower XFS superblock for cache invalidation.
	 * Must happen before daemon spawn so the DAEMON_READY handler
	 * can find the SBI by volume_id. */
	ret = mxfs_cache_register_sb(sbi->volume_id, sb);
	if (ret) {
		pr_err("mxfs: failed to register cache: %d\n", ret);
		goto err_root;
	}

	/* Set mount path for daemon spawn (uses the dev_name as a
	 * placeholder — the real mount path isn't known inside fill_super,
	 * but the daemon reads it from /proc/mounts or the arg we pass).
	 * We construct a temporary path: the daemon will use it for
	 * disklock placement. */
	sbi->mount_path = kstrdup(ctx->dev_name, GFP_KERNEL);
	if (!sbi->mount_path) {
		ret = -ENOMEM;
		goto err_cache;
	}

	/* Spawn the mxfsd daemon for this mount */
	ret = mxfs_spawn_daemon(sbi);
	if (ret) {
		pr_err("mxfs: daemon spawn failed: %d\n", ret);
		goto err_mount_path;
	}

	/* Wait for daemon to signal readiness via DAEMON_READY */
	{
		unsigned long timeout_jiffies;
		long wret;

		timeout_jiffies = msecs_to_jiffies(
			MXFS_DAEMON_STARTUP_TIMEOUT_S * 1000);
		wret = wait_for_completion_interruptible_timeout(
			&sbi->daemon_startup, timeout_jiffies);

		if (wret == 0) {
			pr_err("mxfs: daemon startup timed out (%ds)\n",
			       MXFS_DAEMON_STARTUP_TIMEOUT_S);
			ret = -ETIMEDOUT;
			goto err_daemon;
		}
		if (wret < 0) {
			pr_err("mxfs: daemon startup interrupted\n");
			ret = (int)wret;
			goto err_daemon;
		}

		if (!sbi->daemon_ready) {
			pr_err("mxfs: daemon startup completed but not ready\n");
			ret = -EIO;
			goto err_daemon;
		}
	}

	pr_info("mxfs: mounted %s (volume 0x%llx, daemon pid %d)\n",
		ctx->dev_name, (unsigned long long)sbi->volume_id,
		sbi->daemon_pid);

	return 0;

err_daemon:
	mxfs_kill_daemon(sbi);
err_mount_path:
	kfree(sbi->mount_path);
	sbi->mount_path = NULL;
err_cache:
	mxfs_cache_unregister_sb(sbi->volume_id);

err_root:
	dput(root_dentry);
	sb->s_root = NULL;
err_lower:
	kern_unmount(lower_mnt);
	sbi->lower_mnt = NULL;
err_devname:
	kfree(sbi->dev_name);
err_sbi:
	sb->s_fs_info = NULL;
	kfree(sbi);
	return ret;
}

/* ─── Mount / Umount ─── */

/*
 * mxfs_mount — Called by VFS for "mount -t mxfs /dev/sdb /mnt/shared"
 *
 * Uses mount_nodev because MXFS does not hold the block device directly;
 * the internal XFS mount (via vfs_kern_mount) handles bdev ownership.
 * We pass the dev_name through to fill_super via a context struct.
 */
static struct dentry *mxfs_mount(struct file_system_type *fs_type, int flags,
				 const char *dev_name, void *raw_data)
{
	struct mxfs_mount_ctx ctx;

	ctx.dev_name = dev_name;
	ctx.options = raw_data;

	return mount_nodev(fs_type, flags, &ctx, mxfs_fill_super);
}

/*
 * mxfs_kill_sb — Clean up on unmount.
 *
 * Kills the daemon, unregisters cache, unmounts lower XFS,
 * frees per-mount state.
 */
static void mxfs_kill_sb(struct super_block *sb)
{
	struct mxfs_sb_info *sbi = MXFS_SB(sb);

	if (sbi) {
		pr_info("mxfs: unmounting volume 0x%llx\n",
			(unsigned long long)sbi->volume_id);

		mxfs_cache_unregister_sb(sbi->volume_id);

		mxfs_kill_daemon(sbi);

		if (sbi->lower_mnt) {
			kern_unmount(sbi->lower_mnt);
			sbi->lower_mnt = NULL;
		}

		kfree(sbi->dev_name);
		kfree(sbi->mount_path);
	}

	generic_shutdown_super(sb);

	if (sbi) {
		sb->s_fs_info = NULL;
		kfree(sbi);
	}
}

/* ─── Filesystem type ─── */

struct file_system_type mxfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "mxfs",
	.mount		= mxfs_mount,
	.kill_sb	= mxfs_kill_sb,
	/* No FS_REQUIRES_DEV — we handle the bdev internally via XFS */
};
