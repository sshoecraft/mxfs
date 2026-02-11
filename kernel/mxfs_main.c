/*
 * MXFS — Multinode XFS
 * Kernel module entry point
 *
 * Registers the MXFS stacking filesystem type. MXFS wraps XFS at the
 * VFS layer, providing distributed locking and cache coherency for
 * concurrent multi-node access to shared block devices.
 *
 * Initialization order: inode_cache -> netlink -> cache -> register_filesystem
 * Shutdown order (reverse): unregister_filesystem -> cache -> netlink -> inode_cache
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <mxfs/mxfs_common.h>
#include <mxfs/mxfs_netlink.h>
#include <mxfs/mxfs_dlm.h>
#include "mxfs_internal.h"

static int __init mxfs_init(void)
{
	int ret;

	pr_info("mxfs: loading module v%d.%d.%d\n",
		MXFS_VERSION_MAJOR, MXFS_VERSION_MINOR, MXFS_VERSION_PATCH);

	/* Step 1: Initialize inode SLAB cache */
	ret = mxfs_init_inode_cache();
	if (ret) {
		pr_err("mxfs: inode cache init failed: %d\n", ret);
		return ret;
	}

	/* Step 2: Register genetlink family */
	ret = mxfs_netlink_init();
	if (ret) {
		pr_err("mxfs: netlink init failed: %d\n", ret);
		goto err_netlink;
	}

	/* Step 3: Initialize page cache invalidation subsystem */
	ret = mxfs_cache_init();
	if (ret) {
		pr_err("mxfs: cache init failed: %d\n", ret);
		goto err_cache;
	}

	/* Step 4: Register filesystem type */
	ret = register_filesystem(&mxfs_fs_type);
	if (ret) {
		pr_err("mxfs: filesystem registration failed: %d\n", ret);
		goto err_register;
	}

	pr_info("mxfs: module loaded successfully\n");
	return 0;

err_register:
	mxfs_cache_exit();
err_cache:
	mxfs_netlink_exit();
err_netlink:
	mxfs_destroy_inode_cache();
	return ret;
}

static void __exit mxfs_exit(void)
{
	pr_info("mxfs: unloading module\n");

	/* Reverse order: fs -> cache -> netlink -> inode_cache */
	unregister_filesystem(&mxfs_fs_type);
	mxfs_cache_exit();
	mxfs_netlink_exit();
	mxfs_destroy_inode_cache();

	pr_info("mxfs: module unloaded\n");
}

module_init(mxfs_init);
module_exit(mxfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MXFS Project");
MODULE_DESCRIPTION("Multinode XFS — shared filesystem coordination");
MODULE_VERSION("1.0.0");
