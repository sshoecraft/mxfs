/*
 * MXFS — Multinode XFS
 * Internal kernel module declarations shared between mxfs_*.c files
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef MXFS_INTERNAL_H
#define MXFS_INTERNAL_H

#include <linux/types.h>
#include <mxfs/mxfs_common.h>

/* mxfs_netlink.c */
int mxfs_netlink_init(void);
void mxfs_netlink_exit(void);
int mxfs_nl_send_lock_req(const struct mxfs_resource_id *resource,
			   uint8_t mode, uint32_t flags,
			   uint8_t *granted_mode);
int mxfs_nl_send_lock_release(const struct mxfs_resource_id *resource);
int mxfs_nl_send_volume_mount(uint64_t volume_id,
			      const char *dev_path,
			      const char *mount_path);
int mxfs_nl_send_volume_umount(uint64_t volume_id);
uint8_t mxfs_nl_get_node_state(uint32_t node_id);

/* mxfs_hooks.c */
int mxfs_hooks_init(void);
void mxfs_hooks_exit(void);
void mxfs_hooks_recovery_start(uint64_t volume_id);
void mxfs_hooks_recovery_done(uint64_t volume_id);
int mxfs_hook_inode_lock(uint64_t volume, uint64_t ino,
			 uint8_t mode, uint32_t flags,
			 uint8_t *granted_mode);
int mxfs_hook_inode_unlock(uint64_t volume, uint64_t ino);
int mxfs_hook_extent_lock(uint64_t volume, uint64_t ino,
			  uint64_t offset, uint8_t mode, uint32_t flags,
			  uint8_t *granted_mode);
int mxfs_hook_extent_unlock(uint64_t volume, uint64_t ino,
			    uint64_t offset);
int mxfs_hook_ag_lock(uint64_t volume, uint32_t ag_number,
		      uint8_t mode, uint32_t flags,
		      uint8_t *granted_mode);
int mxfs_hook_ag_unlock(uint64_t volume, uint32_t ag_number);

/* mxfs_cache.c */
int mxfs_cache_init(void);
void mxfs_cache_exit(void);
int mxfs_cache_invalidate(uint64_t volume, uint64_t ino,
			  uint64_t offset, uint64_t length);
int mxfs_cache_register_sb(uint64_t volume_id, struct super_block *sb);
void mxfs_cache_unregister_sb(uint64_t volume_id);

#endif /* MXFS_INTERNAL_H */
