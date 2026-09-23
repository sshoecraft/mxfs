// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS symmetric directory sharding — kernel-side API.
 *
 * sess464.  Design: docs/dir-sharding.md ("Stage 1-2 concrete shape" and
 * "Stage 1 implementation decisions").  On-disk format and the pure manifest
 * check: include/mxfs/mxfs_dirshard.h.  Implementation: xfs_mxfs_dirshard.c.
 *
 * Three objects (sess463 ruling):
 *   Manifest pin     — parent DLM PR (ILOCK_SHARED on the visible parent);
 *                      the PUBLISHED manifest is immutable under it and is
 *                      cached in the parent's in-core state.
 *   Resolver         — name -> {logical parent, physical shard}: canonical
 *                      bytes, SipHash-2-4 under the manifest key, index =
 *                      hash & (N-1), internal iget with {ino, gen, flag,
 *                      owner} validation; returns the shard for the caller
 *                      to lock and use as the physical directory.
 *   Parent barrier   — parent DLM EX (ILOCK_EXCL): lifecycle transitions,
 *                      rmdir/emptiness, parent-core metadata, fsync, repair.
 *
 * Nothing here changes the dir2 primitives: a sharded operation resolves
 * FIRST, then calls the unchanged xfs_create/xfs_lookup/xfs_remove/xfs_readdir
 * with the shard as its directory inode.
 */
#ifndef XFS_MXFS_DIRSHARD_H
#define XFS_MXFS_DIRSHARD_H

#include <mxfs/mxfs_dirshard.h>

struct xfs_inode;
struct xfs_mount;
struct xfs_trans;
struct xfs_name;
struct mnt_idmap;
struct dir_context;

/* Feature gate: sb incompat bit + envelope flag + clustered mode. */
bool mxfs_dirshard_enabled(struct xfs_mount *mp);

static inline bool mxfs_is_dirshard_container(const struct xfs_inode *ip)
{
	return (ip->i_diflags2 & MXFS_DIFLAG2_DIRSHARD_CONTAINER) != 0;
}
static inline bool mxfs_is_dirshard_parent(const struct xfs_inode *ip)
{
	return (ip->i_diflags2 & MXFS_DIFLAG2_DIRSHARD_PARENT) != 0;
}

/* The manifest block's buffer ops (recovery restores them from the BLFT). */
extern const struct xfs_buf_ops mxfs_dirshard_buf_ops;

/*
 * In-core cache of a validated manifest, hung off the visible parent
 * (ip->i_mxfs_dirshard).  Built under the pin by
 * mxfs_dirshard_manifest_load(); invalidated by every barrier-side mutation
 * (which holds parent EX, so no pin holder is racing) and dropped with the
 * parent's DLM grant (mxfs_dirshard_cache_drop from the inode release path).
 */
struct mxfs_dirshard_cache {
	struct mxfs_dirshard_view	view;	/* decoded, validated */
	uint32_t			gen;	/* parent i_generation it was
						 * loaded for */
	unsigned long			dlm_epoch; /* parent i_dlm_epoch it was
						 * loaded under: the epoch bumps
						 * every time this node loses the
						 * parent's DLM grant (a peer's
						 * barrier BASTs our pin away), so
						 * a changed epoch = table stale */
	uint64_t			holder_ino;
	xfs_daddr_t			daddr;	/* the manifest block */
	bool				valid;
};
void mxfs_dirshard_cache_drop(struct xfs_inode *dp);

/*
 * Logical emptiness of a sharded parent for rmdir.  Caller holds the parent
 * ILOCK_EXCL (the barrier, so no pin holder can be adding an entry) inside a
 * still-clean transaction; returns 0 when every live container is empty,
 * -ENOTEMPTY otherwise.  The parent's own dir2 is always empty, so without
 * this xfs_dir_remove_child would let a full sharded directory be removed
 * and its files orphaned.
 */
int mxfs_dirshard_isempty(struct xfs_inode *dp);

/*
 * Name -> inode number through the resolver, for d_revalidate.  Caller holds
 * the parent pin (ILOCK_SHARED); the shard is locked shared for the dir2
 * lookup and released before return.  -ENOENT when the name is absent.
 */
int mxfs_dirshard_lookup_ino(struct xfs_inode *dp, const struct xfs_name *name,
			     xfs_ino_t *inop);

/*
 * Manifest load under the pin (caller holds the parent ILOCK shared or
 * exclusive).  Reads the ROOT xattr, verifies crc32c, runs the pure check
 * bound to {parent ino, gen}, and fills/caches the view.  A parent that
 * carries the PARENT flag but no valid manifest is corruption: -EFSCORRUPTED
 * with a P-DIRSHARD-MANIFEST line naming the reason.
 */
int mxfs_dirshard_manifest_load(struct xfs_inode *dp,
				struct mxfs_dirshard_view *view);

/*
 * Internal container iget: validates {ino, gen, CONTAINER flag, S_IFDIR,
 * '..' == owner} and returns the shard inode referenced (no lock held).
 * Never called on an inode number that did not come from a validated
 * manifest.  -EFSCORRUPTED on any mismatch (the manifest names a stranger),
 * -ENOENT when the number is free.  A TRUSTED iget since 0.64.11 (sess470):
 * XFS_IGET_UNTRUSTED consulted the unlocked inobt and refused peer-allocated
 * members with -EINVAL.
 */
int mxfs_dirshard_iget(struct xfs_mount *mp, struct xfs_inode *owner,
		       uint64_t ino, uint32_t gen, uint8_t expect_ftype,
		       struct xfs_inode **ipp);

/*
 * Resolver.  Caller holds the parent pin (ILOCK_SHARED).  Routes @name to
 * its shard, igets it, returns it referenced and UNLOCKED; the caller locks
 * it in the mode the operation needs (PR for lookup/readdir-of-one-shard, EX
 * for create/unlink) and releases the parent pin only after the operation.
 * Refuses (-EOPNOTSUPP) a parent whose manifest is not PUBLISHED.
 */
int mxfs_dirshard_resolve(struct xfs_inode *dp, const struct xfs_name *name,
			  struct xfs_inode **shardp, unsigned int *indexp);

/* SipHash-2-4 of the canonical name bytes under the manifest key. */
uint64_t mxfs_dirshard_hash(const struct mxfs_dirshard_view *v,
			    const unsigned char *name, unsigned int len);

/*
 * Lifecycle (parent barrier side).
 *
 * mxfs_dirshard_mkdir: create the sharded directory @name under @dp with
 * @nshards containers, publish it, and return the new visible parent.  Each
 * step is one transaction (see docs/dir-sharding.md "Stage 1 implementation
 * decisions"): allocate the unlinked ALLOCATING parent + manifest; per
 * container allocate + append; publish.  On error after the first commit
 * the unlinked set is left for inactivation/replay to reap.
 */
int mxfs_dirshard_mkdir(struct mnt_idmap *idmap, struct xfs_inode *dp,
			const struct xfs_name *name, umode_t mode,
			unsigned int nshards, struct xfs_inode **ipp);

/*
 * Shard-aware inactivation.  Called from xfs_inactive BEFORE the generic
 * truncate/free for an inode carrying the PARENT flag: walks the manifest
 * (any state), frees every live container under its own AG/inode authority,
 * clears its valid_mask bit, and only then lets the caller free the parent.
 * Restartable: a container whose {ino, gen} no longer matches is "already
 * gone" and is skipped, never freed.
 */
int mxfs_dirshard_inactive_parent(struct xfs_inode *dp);

/*
 * Ordinary operations on a sharded parent (pal-layer dispatch).  Each takes
 * the pin, resolves, locks ONE shard, runs the unchanged primitive with the
 * shard as the directory, and releases in reverse order.
 */
int mxfs_dirshard_lookup(struct xfs_inode *dp, const struct xfs_name *name,
			 struct xfs_inode **ipp, bool create_intent);
int mxfs_dirshard_create(struct mnt_idmap *idmap, struct xfs_inode *dp,
			 struct xfs_name *name, umode_t mode, dev_t rdev,
			 unsigned int icreate_flags, struct xfs_inode **ipp);
int mxfs_dirshard_remove(struct xfs_inode *dp, struct xfs_name *name,
			 struct xfs_inode *ip);
int mxfs_dirshard_readdir(struct xfs_inode *dp, struct dir_context *ctx,
			  size_t bufsize);

/*
 * stat synthesis: logical nlink = 2 + sum(container_nlink - 2); mtime/ctime
 * = max(parent core, shards); size/blocks = sums.  Fills @out only — never
 * the parent's in-core inode.
 */
struct mxfs_dirshard_stat {
	unsigned int	nlink;
	uint64_t	size;
	uint64_t	blocks;
	struct timespec64 mtime;
	struct timespec64 ctime;
};
int mxfs_dirshard_stat(struct xfs_inode *dp, struct mxfs_dirshard_stat *out);

/* ioctl entry (pal/linux/xfs_ioctl.c dispatches MXFS_IOC_DIRSHARD_*). */
long mxfs_dirshard_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long arg);

#endif /* XFS_MXFS_DIRSHARD_H */
