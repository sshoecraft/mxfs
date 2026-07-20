# SPDX-License-Identifier: GPL-2.0
#
# MXFS — Multinode XFS
# Kernel module build configuration
#
# Architecture:
#   xfs/libxfs/  — portable metadata (from kernel source)
#   xfs/         — portable XFS core (transactions, logging, inode cache)
#   pal/linux/   — ALL Linux-specific code (VFS, buffer I/O, infrastructure)
#   dlm/         — distributed lock manager (portable via PAL, Phase 2)
#

ccflags-y += -I $(src)/compat
ccflags-y += -I $(src)
ccflags-y += -I $(src)/xfs
ccflags-y += -I $(src)/xfs/libxfs
ccflags-y += -I $(src)/mxfs_clayer
ccflags-y += -I $(src)/include
ccflags-y += -DMXFS_MODULE

# Feature disabling done via #undef in xfs_platform.h (after autoconf.h)

obj-m := mxfs.o

# ═══════════════════════════════════════════════════════════
# Portable XFS — libxfs metadata engine
# ═══════════════════════════════════════════════════════════

mxfs-y += $(addprefix xfs/libxfs/, \
		xfs_group.o \
		xfs_ag.o \
		xfs_ag_resv.o \
		xfs_alloc.o \
		xfs_alloc_btree.o \
		xfs_attr.o \
		xfs_attr_leaf.o \
		xfs_attr_remote.o \
		xfs_bit.o \
		xfs_bmap.o \
		xfs_bmap_btree.o \
		xfs_btree.o \
		xfs_btree_staging.o \
		xfs_da_btree.o \
		xfs_defer.o \
		xfs_dir2.o \
		xfs_dir2_block.o \
		xfs_dir2_data.o \
		xfs_dir2_leaf.o \
		xfs_dir2_node.o \
		xfs_dir2_sf.o \
		xfs_dquot_buf.o \
		xfs_exchmaps.o \
		xfs_ialloc.o \
		xfs_ialloc_btree.o \
		xfs_iext_tree.o \
		xfs_inode_fork.o \
		xfs_inode_buf.o \
		xfs_inode_util.o \
		xfs_log_rlimit.o \
		xfs_metadir.o \
		xfs_metafile.o \
		xfs_parent.o \
		xfs_rmap.o \
		xfs_rmap_btree.o \
		xfs_refcount.o \
		xfs_refcount_btree.o \
		xfs_sb.o \
		xfs_symlink_remote.o \
		xfs_trans_inode.o \
		xfs_trans_resv.o \
		xfs_trans_space.o \
		xfs_types.o \
		)

# ═══════════════════════════════════════════════════════════
# Portable XFS — core (transactions, logging, inode cache)
# ═══════════════════════════════════════════════════════════

mxfs-y += $(addprefix xfs/, \
		xfs_attr_inactive.o \
		xfs_attr_list.o \
		xfs_bmap_util.o \
		xfs_dir2_readdir.o \
		xfs_discard.o \
		xfs_error.o \
		xfs_extent_busy.o \
		xfs_filestream.o \
		xfs_fsops.o \
		xfs_globals.o \
		xfs_health.o \
		xfs_icache.o \
		xfs_inode.o \
		xfs_itable.o \
		xfs_iwalk.o \
		xfs_message.o \
		xfs_mount.o \
		xfs_reflink.o \
		xfs_trans.o \
		xfs_trans_ail.o \
		xfs_trans_buf.o \
		xfs_log.o \
		xfs_log_cil.o \
		xfs_log_recover.o \
		xfs_bmap_item.o \
		xfs_extfree_item.o \
		xfs_attr_item.o \
		xfs_icreate_item.o \
		xfs_inode_item.o \
		xfs_inode_item_recover.o \
		xfs_iunlink_item.o \
		xfs_refcount_item.o \
		xfs_rmap_item.o \
		xfs_stubs.o \
		xfs_mxfs_dlm.o \
		)

# Excluded: quota (xfs_dquot*.o, xfs_qm*.o, xfs_quotaops.o, xfs_trans_dquot.o)
# Excluded: realtime (xfs_rtalloc.o)
# Excluded: zones (xfs_zone_*.o)
# Excluded: DAX/pNFS (xfs_pnfs.o)
# Excluded: compat ioctl (xfs_ioctl32.o)
# Excluded: test (xfs_dahash_test.o)
# Excluded: fsmap (xfs_fsmap.o) — depends on scrub infrastructure

# Stubs for excluded features (quota, rt, zones, acl, ioctl)

# ═══════════════════════════════════════════════════════════
# PAL — Linux platform (VFS frontend + block I/O + infra)
# ═══════════════════════════════════════════════════════════

mxfs-y += $(addprefix pal/linux/, \
		xfs_trace.o \
		xfs_super.o \
		xfs_file.o \
		xfs_iops.o \
		xfs_iomap.o \
		xfs_aops.o \
		xfs_export.o \
		xfs_symlink.o \
		xfs_xattr.o \
		xfs_buf.o \
		xfs_bio_io.o \
		xfs_buf_item.o \
		xfs_buf_item_recover.o \
		xfs_stats.o \
		xfs_sysfs.o \
		xfs_mru_cache.o \
		xfs_pwork.o \
		xfs_healthmon.o \
		xfs_notify_failure.o \
		xfs_verify_media.o \
		)

# Excluded from pal/linux: xfs_acl.o (needs CONFIG_XFS_POSIX_ACL)
# Excluded from pal/linux: xfs_sysctl.o (conflicts with kernel XFS sysctl)

# ═══════════════════════════════════════════════════════════
# DLM — Distributed Lock Manager (Phase 2)
# ═══════════════════════════════════════════════════════════

mxfs-y += $(addprefix dlm/, \
		dlm.o \
		dlm_caw.o \
		dlm_shared.o \
		discovery.o \
		peer.o \
		lease.o \
		disklock.o \
		scsipr.o \
		journal.o \
		v5_mount.o \
		net2.o \
		net2_link.o \
		net2_overlay.o \
		net2_midcomms.o \
		net2_fault.o \
		)
mxfs-y += pal/linux/kern.o

# ═══════════════════════════════════════════════════════════
# MXFS Cluster layer (D9 + D10 — Phase 2 onward)
# Phase 7 will progressively migrate cluster code from xfs/ here.
# ═══════════════════════════════════════════════════════════

mxfs-y += $(addprefix mxfs_clayer/, \
		pinned_resource.o \
		yield_quantum.o \
		)
