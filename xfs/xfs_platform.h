// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef _XFS_PLATFORM_H
#define _XFS_PLATFORM_H

#include <linux/types.h>
#include <linux/uuid.h>
#include <linux/semaphore.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/crc32c.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/file.h>
#include <linux/filelock.h>
#include <linux/swap.h>
#include <linux/errno.h>
#include <linux/sched/signal.h>
#include <linux/bitops.h>
#include <linux/major.h>
#include <linux/pagemap.h>
#include <linux/vfs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/sort.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/delay.h>
#include <linux/log2.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/ctype.h>
#include <linux/writeback.h>
#include <linux/capability.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/list_sort.h>
#include <linux/ratelimit.h>
#include <linux/rhashtable.h>
#include <linux/xattr.h>
#include <linux/mnt_idmapping.h>
#include <linux/debugfs.h>
#include <asm/page.h>
#include <asm/div64.h>
#include <asm/param.h>
#include <linux/uaccess.h>
#include <asm/byteorder.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

/* inode_state helpers added in v6.19 (commit d8753f788ab4, Mateusz Guzik,
 * 2025-10-09) -- native version returns enum inode_state_flags_enum, not
 * unsigned long, but that's integer-compatible with our bitwise callers. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 19, 0)
static inline unsigned long inode_state_read_once(struct inode *inode)
{
	return READ_ONCE(inode->i_state);
}
static inline void inode_state_clear(struct inode *inode, unsigned long flags)
{
	inode->i_state &= ~flags;
}
static inline void inode_state_assign_raw(struct inode *inode, unsigned long state)
{
	WRITE_ONCE(inode->i_state, state);
}
static inline void inode_state_set_raw(struct inode *inode, unsigned long flags)
{
	WRITE_ONCE(inode->i_state, inode->i_state | flags);
}
static inline void inode_state_clear_raw(struct inode *inode, unsigned long flags)
{
	WRITE_ONCE(inode->i_state, inode->i_state & ~flags);
}
#endif

/* dax_break_layout helpers — stub for non-DAX builds */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
static inline int dax_break_layout(struct inode *inode, loff_t start,
				   loff_t end, bool *retry)
{
	return 0;
}
static inline int dax_break_layout_inode(struct inode *inode, void *cb)
{
	return 0;
}
#endif

/* mapping_set_folio_min_order added in v6.12 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static inline void mapping_set_folio_min_order(struct address_space *mapping,
					       unsigned int order)
{
	/*
	 * 6.8 has no per-mapping min-order control, but the 6.13+ call
	 * also ENABLES large folios — and that side effect is load-
	 * bearing: native 6.8 XFS calls mapping_set_large_folios() here,
	 * and without it buffered writeback degrades to singleton 4KB
	 * bios under concurrent dirtying (sess21 ccloop: 3254 scattered
	 * 4KB writes per 700MB dd = 2x wall vs native on iSCSI).
	 * min_folio_order is 0 on 4K-block filesystems, so enabling
	 * large folios is the entire remaining semantic.
	 */
	mapping_set_large_folios(mapping);
}
#endif

/* secs_to_jiffies is a macro upstream -- ifndef is robust across versions */
#ifndef secs_to_jiffies
#define secs_to_jiffies(s) ((unsigned long)(s) * HZ)
#endif

/* super_set_uuid added in v6.9 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
static inline void super_set_uuid(struct super_block *sb, const u8 *uuid,
				  unsigned int len)
{
	if (len > sizeof(sb->s_uuid))
		len = sizeof(sb->s_uuid);
	memcpy(&sb->s_uuid, uuid, len);
}
#endif

/* bdev file API changed in v6.9: bdev_handle → struct file */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
static inline struct file *bdev_file_open_by_path(const char *path,
		blk_mode_t mode, void *holder, const struct blk_holder_ops *hops)
{
	struct bdev_handle *handle;
	handle = bdev_open_by_path(path, mode, holder, hops);
	if (IS_ERR(handle))
		return ERR_CAST(handle);
	/* Stash handle pointer in file's private_data for bdev_fput/file_bdev */
	return (struct file *)handle;  /* cast — compat only */
}
static inline struct block_device *file_bdev(struct file *f)
{
	return ((struct bdev_handle *)f)->bdev;
}
static inline void bdev_fput(struct file *f)
{
	bdev_release((struct bdev_handle *)f);
}
#endif

/* super_block s_bdev_file vs s_bdev_handle compat */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
#define mxfs_sb_bdev_file(sb) ((struct file *)(sb)->s_bdev_handle)
#else
#define mxfs_sb_bdev_file(sb) ((sb)->s_bdev_file)
#endif

/* inode_generic_drop added in ~6.19 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 19, 0)
static inline bool inode_generic_drop(struct inode *inode)
{
	return !inode->i_nlink || inode_unhashed(inode);
}
#endif

/* dax_break_layout_final added in v6.15 (commit 0e2f80afcfa6, "fs/dax:
 * ensure all pages are idle prior to filesystem unmount") -- upstream
 * signature is void, not int; older kernels lacking it get a no-op. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
static inline int dax_break_layout_final(struct inode *inode)
{
	return 0;
}
#endif

/* mapping_max_folio_size_supported added in ~6.15 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
static inline unsigned long mapping_max_folio_size_supported(void)
{
	return PAGE_SIZE;
}
#endif

/* SB_I_ALLOW_HSM added in ~6.19 */
#ifndef SB_I_ALLOW_HSM
#define SB_I_ALLOW_HSM 0
#endif

/* FS_MGTIME added in ~6.12 */
#ifndef FS_MGTIME
#define FS_MGTIME 0
#endif

/* FS_LBS added in ~6.15 */
#ifndef FS_LBS
#define FS_LBS 0
#endif

/* kvrealloc changed from 4-arg to 3-arg in ~6.13 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 13, 0)
#define mxfs_kvrealloc(p, newsize, gfp) \
	kvrealloc(p, 0, newsize, gfp)
#else
#define mxfs_kvrealloc(p, newsize, gfp) \
	kvrealloc(p, newsize, gfp)
#endif

/* WQ_PERCPU added in v6.17 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 17, 0)
#define WQ_PERCPU 0
#endif

/* bio_add_vmalloc/bio_add_virt_nofail added in v6.16 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)
#include <linux/bio.h>
static inline int bio_add_vmalloc(struct bio *bio, void *data, unsigned int len)
{
	unsigned int offset = offset_in_page(data);
	while (len > 0) {
		struct page *page = vmalloc_to_page(data);
		unsigned int bytes = min(len, (unsigned int)PAGE_SIZE - offset);
		if (!bio_add_page(bio, page, bytes, offset))
			return -EIO;
		data += bytes;
		len -= bytes;
		offset = 0;
	}
	return 0;
}
static inline void bio_add_virt_nofail(struct bio *bio, void *data,
				       unsigned int len)
{
	bio_add_page(bio, virt_to_page(data), len, offset_in_page(data));
}
#endif

/* max_pow_of_two_factor added in v6.17 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 17, 0)
static inline unsigned int max_pow_of_two_factor(unsigned int n)
{
	return n & -n;
}
#endif

/* memtostr_pad — new in v6.10 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
#define memtostr_pad(dest, src) do { \
	size_t _len = min(sizeof(dest) - 1, sizeof(src)); \
	memcpy(dest, src, _len); \
	(dest)[_len] = '\0'; \
} while (0)
#endif

/* class_super_write_t — RAII cleanup class, new in ~6.19 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 19, 0)
/* Stub: just use sb_start_write/sb_end_write directly */
#endif

/* bdev atomic write helpers — real versions differ per-symbol:
 * bdev_can_atomic_write v6.11, bdev_atomic_write_unit_{min,max}_bytes
 * v6.13, bdev_validate_blocksize v6.15, bio_add_max_vecs v6.16. Gated
 * as one block on the latest (v6.16) since that's the highest bar that
 * still needs to hold for all five to be shimmed together. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)
static inline bool bdev_can_atomic_write(struct block_device *bdev) { return false; }
static inline unsigned int bdev_atomic_write_unit_min_bytes(struct block_device *bdev) { return 0; }
static inline unsigned int bdev_atomic_write_unit_max_bytes(struct block_device *bdev) { return 0; }
static inline int bdev_validate_blocksize(struct block_device *bdev, int block_size) { return 0; }
static inline unsigned int bio_add_max_vecs(void *data, unsigned int len) {
	return DIV_ROUND_UP(len, PAGE_SIZE) + 1;
}
#endif

/* bdev_rw_virt — new in v6.16 */
/* Compat provided after xfs_rw_bdev declaration (see bottom of this file) */

/* bio_add_vmalloc_chunk — new in v6.16, differs from bio_add_vmalloc */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)
#define bio_add_vmalloc_chunk bio_add_vmalloc
#endif

/* super_set_sysfs_name_id — added in v6.10 (commit ae8c51175730, "fs: add
 * FS_IOC_GETFSSYSFSPATH") */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
static inline void super_set_sysfs_name_id(struct super_block *sb) { }
#endif

/* freeze_super/thaw_super gained 3rd arg (owner) in v6.16 (commit
 * 1af3331764b9, "super: add filesystem freezing helpers for suspend and
 * hibernate") */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)
#define mxfs_freeze_super(sb, who) freeze_super(sb, who)
#define mxfs_thaw_super(sb, who) thaw_super(sb, who)
#else
#define mxfs_freeze_super(sb, who) freeze_super(sb, who, NULL)
#define mxfs_thaw_super(sb, who) thaw_super(sb, who, NULL)
#endif

/* fd_file/fd_empty added in v6.12 (commit 1da91ea87aef, "introduce
 * fd_file(), convert all accessors to it") -- struct fd was repacked
 * from a plain .file pointer to a packed .word bitfield around the
 * same change, so fd_file()/fd_empty() are the only portable accessors
 * on 6.12+; kernels below that still expose fd.file directly. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
#include <linux/file.h>
static inline bool fd_empty(struct fd f) { return !f.file; }
static inline struct file *fd_file(struct fd f) { return f.file; }
#endif

/* struct file_kattr renamed from struct fileattr in v6.17 (commit
 * ca115d7e7546) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 17, 0)
#include <linux/fileattr.h>
#define file_kattr fileattr
#endif

/* mkdir return type changed from int to struct dentry * in ~6.15 */
/* Handled via version guards in xfs_iops.c */

/* STATX_DIO_READ_ALIGN, STATX_WRITE_ATOMIC — new in ~6.15 */
#ifndef STATX_DIO_READ_ALIGN
#define STATX_DIO_READ_ALIGN 0
#endif
#ifndef STATX_WRITE_ATOMIC
#define STATX_WRITE_ATOMIC 0
#endif

/* generic_fill_statx_atomic_writes — new in v6.11 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 11, 0)
static inline void generic_fill_statx_atomic_writes(struct kstat *stat,
		unsigned int unit_min, unsigned int unit_max,
		unsigned int unit_max_opt) { }
#endif

/* fill_mg_cmtime — new in v6.13, takes 3 args (stat, request_mask, inode) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 13, 0)
#define fill_mg_cmtime(stat, mask, inode) do { \
	(stat)->ctime = inode_get_ctime(inode); \
	(stat)->mtime = inode_get_mtime(inode); \
} while (0)
#endif

/* iomap constants and types — new in 6.15+ */
#ifndef IOMAP_F_BOUNDARY
#define IOMAP_F_BOUNDARY 0
#endif
#ifndef IOMAP_ATOMIC
#define IOMAP_ATOMIC 0
#endif
#ifndef IOMAP_F_ATOMIC_BIO
#define IOMAP_F_ATOMIC_BIO 0
#endif
#ifndef IOMAP_F_ANON_WRITE
#define IOMAP_F_ANON_WRITE 0
#endif

/* struct iomap_write_ops — new in ~6.15 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
#include <linux/types.h>
struct iomap_write_ops {
	bool (*iomap_valid)(struct inode *inode, const struct iomap *iomap);
};
#endif

/* iomap_last_written_block / iomap_write_delalloc_release — new in v6.12 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static inline loff_t iomap_last_written_block(struct inode *inode,
		loff_t pos, ssize_t written)
{
	if (unlikely(!written))
		return round_down(pos, i_blocksize(inode));
	return round_up(pos + written, i_blocksize(inode));
}
#define iomap_write_delalloc_release(inode, start, end, flags, iomap, punch) \
	do { if (punch) (punch)(inode, start, (end) - (start), iomap); } while (0)
#endif

/* iomap_fill_dirty_folios — new in v6.19 (commit ed61378b4dc6, real
 * signature `unsigned int iomap_fill_dirty_folios(struct iomap_iter *,
 * loff_t *, ...)`, differs from this no-op stub's signature -- fine
 * since the stub is only ever called, never compared/assigned by type). */
/* No-op stub: on kernels lacking this, there is no dirty-folio-driven
 * early cutoff, so the caller's intended range must be preserved as-is.
 * Leaving *foffset at its caller-supplied starting value (instead of
 * advancing it to fend) made xfs_buffered_write_iomap_begin's caller
 * (the IOMAP_ZERO unwritten-mapping trim in pal/linux/xfs_iomap.c)
 * collapse end_fsb down to offset_fsb -- a zero-length iomap that
 * iomap_iter can never advance past, spinning forever. PROVEN live via
 * ftrace on 6.17.2-1-pve: identical xfs_buffered_write_iomap_begin call
 * sequence repeating at microsecond intervals during a QEMU zero-range
 * write (detect-zeroes) to a sparse raw disk image, zero disk progress. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 19, 0)
static inline int iomap_fill_dirty_folios(void *iter, loff_t *foffset,
		loff_t fend, unsigned int *flags)
{
	*foffset = fend;
	return 0;
}
#endif

/* iomap_zero_range gained write_ops param in v6.15, then a further
 * trailing `void *private` param in v6.17 (commit 2a5574fc57d1). */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
#define mxfs_iomap_zero_range(inode, pos, len, did_zero, ops, wops) \
	iomap_zero_range(inode, pos, len, did_zero, ops)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 17, 0)
#define mxfs_iomap_zero_range(inode, pos, len, did_zero, ops, wops) \
	iomap_zero_range(inode, pos, len, did_zero, ops, wops)
#else
#define mxfs_iomap_zero_range(inode, pos, len, did_zero, ops, wops) \
	iomap_zero_range(inode, pos, len, did_zero, ops, wops, NULL)
#endif

/* iomap_truncate_page gained write_ops param in v6.15, then a further
 * trailing `void *private` param in v6.17 (same commit as above). */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
#define mxfs_iomap_truncate_page(inode, pos, did_zero, ops, wops) \
	iomap_truncate_page(inode, pos, did_zero, ops)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 17, 0)
#define mxfs_iomap_truncate_page(inode, pos, did_zero, ops, wops) \
	iomap_truncate_page(inode, pos, did_zero, ops, wops)
#else
#define mxfs_iomap_truncate_page(inode, pos, did_zero, ops, wops) \
	iomap_truncate_page(inode, pos, did_zero, ops, wops, NULL)
#endif

/* IOMAP_IOEND_DIRECT, IOMAP_DIO_BOUNCE, IOMAP_DIO_FSBLOCK_ALIGNED — new in 6.15+ */
#ifndef IOMAP_IOEND_DIRECT
#define IOMAP_IOEND_DIRECT 0
#endif
#ifndef IOMAP_DIO_BOUNCE
#define IOMAP_DIO_BOUNCE 0
#endif
#ifndef IOMAP_DIO_FSBLOCK_ALIGNED
#define IOMAP_DIO_FSBLOCK_ALIGNED 0
#endif

/* iomap_init_ioend added in ~6.15 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
struct iomap_ioend;
static inline struct iomap_ioend *iomap_init_ioend(struct inode *inode,
		struct bio *bio, loff_t offset, u16 flags)
{
	return NULL;  /* not used on older kernels */
}
#endif

/* iomap_ioend_bioset added in ~6.15 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
static struct bio_set _mxfs_ioend_bioset_compat;
#define iomap_ioend_bioset _mxfs_ioend_bioset_compat
#endif

/* iomap_file_buffered_write gained write_ops+private in ~6.15 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
#define mxfs_iomap_file_buffered_write(iocb, from, ops, wops, priv) \
	iomap_file_buffered_write(iocb, from, ops)
#else
#define mxfs_iomap_file_buffered_write(iocb, from, ops, wops, priv) \
	iomap_file_buffered_write(iocb, from, ops, wops, priv)
#endif

/* iomap_page_mkwrite gained write_ops param in ~6.15 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
#define mxfs_iomap_page_mkwrite(vmf, ops, wops) \
	iomap_page_mkwrite(vmf, ops)
#else
#define mxfs_iomap_page_mkwrite(vmf, ops, wops) \
	iomap_page_mkwrite(vmf, ops, wops)
#endif

/* IOCB_ATOMIC added in ~6.13 */
#ifndef IOCB_ATOMIC
#define IOCB_ATOMIC 0
#endif

/* FMODE_CAN_ATOMIC_WRITE added in ~6.13 */
#ifndef FMODE_CAN_ATOMIC_WRITE
#define FMODE_CAN_ATOMIC_WRITE 0
#endif

/* generic_atomic_write_valid added in ~6.13 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 13, 0)
static inline bool generic_atomic_write_valid(struct kiocb *iocb,
					      struct iov_iter *iter)
{
	return false;  /* atomic writes not supported on old kernels */
}
#endif

/* iomap_file_unshare gained write_ops param in ~6.15 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
#define mxfs_iomap_file_unshare(inode, pos, len, ops, wops) \
	iomap_file_unshare(inode, pos, len, ops)
#else
#define mxfs_iomap_file_unshare(inode, pos, len, ops, wops) \
	iomap_file_unshare(inode, pos, len, ops, wops)
#endif

/* iomap_bio_read_folio/iomap_bio_readahead renamed in ~6.14 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
#define iomap_bio_read_folio(folio, ops)  iomap_read_folio(folio, ops)
#define iomap_bio_readahead(rac, ops)     iomap_readahead(rac, ops)
#endif

/* icount_read added to linux/fs.h in v6.18 (commit 37b27bd5d621) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
static inline int icount_read(const struct inode *inode)
{
	return atomic_read(&inode->i_count);
}
#endif

/* cmp_int added to linux/sort.h in ~6.13 */
#ifndef cmp_int
#define cmp_int(l, r) (((l) > (r)) - ((l) < (r)))
#endif

/* EFSCORRUPTED and EFSBADCRC added to uapi in 6.13 */
#ifndef EFSCORRUPTED
#define EFSCORRUPTED	EUCLEAN		/* Filesystem is corrupted */
#endif
#ifndef EFSBADCRC
#define EFSBADCRC	EBADMSG		/* Bad CRC detected */
#endif

/* MXFS: Disable XFS features we don't build */
#ifdef MXFS_MODULE
#undef CONFIG_XFS_QUOTA
#undef CONFIG_XFS_RT
#undef CONFIG_XFS_POSIX_ACL
#undef CONFIG_XFS_ONLINE_SCRUB
#undef CONFIG_XFS_ONLINE_REPAIR
#undef CONFIG_XFS_DRAIN_INTENTS
#undef CONFIG_XFS_LIVE_HOOKS
#undef CONFIG_XFS_MEMORY_BUFS
#undef CONFIG_XFS_BTREE_IN_MEM
#undef CONFIG_XFS_DEBUG
#undef CONFIG_XFS_DEBUG_EXPENSIVE
#endif

#ifdef CONFIG_XFS_DEBUG
#define DEBUG 1
#endif

#ifdef CONFIG_XFS_DEBUG_EXPENSIVE
#define DEBUG_EXPENSIVE 1
#endif

#ifdef CONFIG_XFS_ASSERT_FATAL
#define XFS_ASSERT_FATAL 1
#endif

#ifdef CONFIG_XFS_WARN
#define XFS_WARN 1
#endif

/*
 * Kernel specific type declarations for XFS
 */
typedef __s64			xfs_off_t;	/* <file offset> type */
typedef unsigned long long	xfs_ino_t;	/* <inode> type */
typedef __s64			xfs_daddr_t;	/* <disk address> type */
typedef __u32			xfs_dev_t;
typedef __u32			xfs_nlink_t;

#include "xfs_types.h"
#include "xfs_fs.h"
#include "xfs_stats.h"
#include "xfs_sysctl.h"
#include "xfs_iops.h"
#include "xfs_aops.h"
#include "xfs_super.h"
#include "xfs_cksum.h"
#include "xfs_buf.h"
#include "xfs_message.h"
#include "xfs_drain.h"
#include "xfs_hooks.h"

#ifdef __BIG_ENDIAN
#define XFS_NATIVE_HOST 1
#else
#undef XFS_NATIVE_HOST
#endif

#define xfs_panic_mask		xfs_params.panic_mask.val
#define xfs_error_level		xfs_params.error_level.val
#define xfs_syncd_centisecs	xfs_params.syncd_timer.val
#define xfs_stats_clear		xfs_params.stats_clear.val
#define xfs_inherit_sync	xfs_params.inherit_sync.val
#define xfs_inherit_nodump	xfs_params.inherit_nodump.val
#define xfs_inherit_noatime	xfs_params.inherit_noatim.val
#define xfs_inherit_nosymlinks	xfs_params.inherit_nosym.val
#define xfs_rotorstep		xfs_params.rotorstep.val
#define xfs_inherit_nodefrag	xfs_params.inherit_nodfrg.val
#define xfs_fstrm_centisecs	xfs_params.fstrm_timer.val
#define xfs_blockgc_secs	xfs_params.blockgc_timer.val

#define current_cpu()		(raw_smp_processor_id())
#define current_set_flags_nested(sp, f)		\
		(*(sp) = current->flags, current->flags |= (f))
#define current_restore_flags_nested(sp, f)	\
		(current->flags = ((current->flags & ~(f)) | (*(sp) & (f))))

#define NBBY		8		/* number of bits per byte */

/*
 * Size of block device i/o is parameterized here.
 * Currently the system supports page-sized i/o.
 */
#define	BLKDEV_IOSHIFT		PAGE_SHIFT
#define	BLKDEV_IOSIZE		(1<<BLKDEV_IOSHIFT)
/* number of BB's per block device block */
#define	BLKDEV_BB		BTOBB(BLKDEV_IOSIZE)

#define ENOATTR		ENODATA		/* Attribute not found */
#define EWRONGFS	EINVAL		/* Mount with wrong filesystem type */

#define __return_address __builtin_return_address(0)

/*
 * Return the address of a label.  Use barrier() so that the optimizer
 * won't reorder code to refactor the error jumpouts into a single
 * return, which throws off the reported address.
 */
#define __this_address	({ __label__ __here; __here: barrier(); &&__here; })

#define howmany(x, y)	(((x)+((y)-1))/(y))

static inline void delay(long ticks)
{
	schedule_timeout_uninterruptible(ticks);
}

/*
 * XFS wrapper structure for sysfs support. It depends on external data
 * structures and is embedded in various internal data structures to implement
 * the XFS sysfs object heirarchy. Define it here for broad access throughout
 * the codebase.
 */
struct xfs_kobj {
	struct kobject		kobject;
	struct completion	complete;
};

struct xstats {
	struct xfsstats __percpu	*xs_stats;
	struct xfs_kobj			xs_kobj;
};

extern struct xstats xfsstats;

static inline dev_t xfs_to_linux_dev_t(xfs_dev_t dev)
{
	return MKDEV(sysv_major(dev) & 0x1ff, sysv_minor(dev));
}

static inline xfs_dev_t linux_to_xfs_dev_t(dev_t dev)
{
	return sysv_encode_dev(dev);
}

/*
 * Various platform dependent calls that don't fit anywhere else
 */
#define xfs_sort(a,n,s,fn)	sort(a,n,s,fn,NULL)
#define xfs_stack_trace()	dump_stack()

static inline uint64_t rounddown_64(uint64_t x, uint32_t y)
{
	do_div(x, y);
	return x * y;
}

static inline uint64_t roundup_64(uint64_t x, uint32_t y)
{
	x += y - 1;
	do_div(x, y);
	return x * y;
}

static inline uint64_t howmany_64(uint64_t x, uint32_t y)
{
	x += y - 1;
	do_div(x, y);
	return x;
}

static inline bool isaligned_64(uint64_t x, uint32_t y)
{
	return do_div(x, y) == 0;
}

/* If @b is a power of 2, return log2(b).  Else return -1. */
static inline int8_t log2_if_power2(unsigned long b)
{
	return is_power_of_2(b) ? ilog2(b) : -1;
}

/* If @b is a power of 2, return a mask of the lower bits, else return zero. */
static inline unsigned long long mask64_if_power2(unsigned long b)
{
	return is_power_of_2(b) ? b - 1 : 0;
}

int xfs_rw_bdev(struct block_device *bdev, sector_t sector, unsigned int count,
		char *data, enum req_op op);

#define ASSERT_ALWAYS(expr)	\
	(likely(expr) ? (void)0 : assfail(NULL, #expr, __FILE__, __LINE__))

#ifdef DEBUG
#define ASSERT(expr)	\
	(likely(expr) ? (void)0 : assfail(NULL, #expr, __FILE__, __LINE__))

#else	/* !DEBUG */

#ifdef XFS_WARN

#define ASSERT(expr)	\
	(likely(expr) ? (void)0 : asswarn(NULL, #expr, __FILE__, __LINE__))

#else	/* !DEBUG && !XFS_WARN */

#define ASSERT(expr)		((void)0)

#endif /* XFS_WARN */
#endif /* DEBUG */

#define XFS_IS_CORRUPT(mp, expr)	\
	(unlikely(expr) ? xfs_corruption_error(#expr, XFS_ERRLEVEL_LOW, (mp), \
					       NULL, 0, __FILE__, __LINE__, \
					       __this_address), \
			  true : false)

#define STATIC static noinline

#ifdef CONFIG_XFS_RT

/*
 * make sure we ignore the inode flag if the filesystem doesn't have a
 * configured realtime device.
 */
#define XFS_IS_REALTIME_INODE(ip)			\
	(((ip)->i_diflags & XFS_DIFLAG_REALTIME) &&	\
	 (ip)->i_mount->m_rtdev_targp)
#define XFS_IS_REALTIME_MOUNT(mp) ((mp)->m_rtdev_targp ? 1 : 0)
#else
#define XFS_IS_REALTIME_INODE(ip) (0)
#define XFS_IS_REALTIME_MOUNT(mp) (0)
#endif

/*
 * Starting in Linux 4.15, the %p (raw pointer value) printk modifier
 * prints a hashed version of the pointer to avoid leaking kernel
 * pointers into dmesg.  If we're trying to debug the kernel we want the
 * raw values, so override this behavior as best we can.
 */
#ifdef DEBUG
# define PTR_FMT "%px"
#else
# define PTR_FMT "%p"
#endif

/*
 * Helper for IO routines to grab backing pages from allocated kernel memory.
 */
static inline struct page *
kmem_to_page(void *addr)
{
	if (is_vmalloc_addr(addr))
		return vmalloc_to_page(addr);
	return virt_to_page(addr);
}

/* xfs_bmap_punch_delalloc_range — gained whichfork+ac params in 6.19.
 * 6.8 code calls (ip, start, end). Wrap to add defaults. */
#define mxfs_bmap_punch_delalloc_range(ip, start, end) \
	xfs_bmap_punch_delalloc_range(ip, XFS_DATA_FORK, start, end, NULL)

/* bdev_rw_virt — new in ~6.15, must come after xfs_rw_bdev declaration */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
static inline int bdev_rw_virt(struct block_device *bdev, sector_t sector,
			       void *data, size_t len, enum req_op op)
{
	struct bio_vec	bv;
	struct bio	bio;
	int		error;

	bio_init(&bio, bdev, &bv, 1, op);
	bio.bi_iter.bi_sector = sector;
	bio_add_virt_nofail(&bio, data, len);
	error = submit_bio_wait(&bio);
	bio_uninit(&bio);
	return error;
}
#endif

#endif /* _XFS_PLATFORM_H */
