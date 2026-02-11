/*
 * MXFS — Multinode XFS
 * Kernel module entry point
 *
 * Registers the genetlink family, installs XFS hooks, and sets up
 * communication with the mxfsd userspace daemon.
 *
 * Initialization order: netlink -> hooks -> cache
 * Shutdown order (reverse): cache -> hooks -> netlink
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <mxfs/mxfs_common.h>
#include <mxfs/mxfs_netlink.h>
#include <mxfs/mxfs_dlm.h>
#include "mxfs_internal.h"

#define MXFS_MODULE_NAME "mxfs"

static int __init mxfs_init(void)
{
	int ret;

	pr_info("mxfs: loading module v%d.%d.%d\n",
		MXFS_VERSION_MAJOR, MXFS_VERSION_MINOR, MXFS_VERSION_PATCH);

	/* Step 1: Register genetlink family — must be first so hooks can send */
	ret = mxfs_netlink_init();
	if (ret) {
		pr_err("mxfs: netlink init failed: %d\n", ret);
		return ret;
	}

	/* Step 2: Install XFS lock intercept hooks */
	ret = mxfs_hooks_init();
	if (ret) {
		pr_err("mxfs: hooks init failed: %d\n", ret);
		goto err_hooks;
	}

	/* Step 3: Initialize page cache invalidation subsystem */
	ret = mxfs_cache_init();
	if (ret) {
		pr_err("mxfs: cache init failed: %d\n", ret);
		goto err_cache;
	}

	pr_info("mxfs: module loaded successfully\n");
	return 0;

err_cache:
	mxfs_hooks_exit();
err_hooks:
	mxfs_netlink_exit();
	return ret;
}

static void __exit mxfs_exit(void)
{
	pr_info("mxfs: unloading module\n");

	/* Reverse order: cache -> hooks -> netlink */
	mxfs_cache_exit();
	mxfs_hooks_exit();
	mxfs_netlink_exit();

	pr_info("mxfs: module unloaded\n");
}

module_init(mxfs_init);
module_exit(mxfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MXFS Project");
MODULE_DESCRIPTION("Multinode XFS — shared filesystem coordination");
MODULE_VERSION("0.4.0");
