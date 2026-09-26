// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- shortform directory ownership and three-way merge
 */
#define MXFS_TU_ID 20	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/* ─── Inode reload ─── */

/*
 * Reload inode metadata from disk after losing a DLM lock.
 *
 * When a BAST releases a cached lock, in-memory inode state becomes
 * stale: inline directory data, extent lists, timestamps, etc.
 * This function re-reads the on-disk inode and repopulates the
 * in-memory struct, ensuring the next operation sees fresh data.
 *
 * Called from mxfs_dlm_ilock_begin on cache miss when i_dlm_stale is set.
 * The DLM lock has already been acquired, so on-disk data is stable.
 *
 * Also called externally from xfs_iget_cache_hit when an iget(CREATE) hits
 * a cached inode whose i_dlm_stale flag is set: the AG DLM lock held by
 * the caller serialises with peer free/alloc, so on-disk state is stable
 * for the duration of the reload.
 */
int mxfs_sf_merge = 1;	/* 3-way SF merge toggle (default ON) */
int mxfs_sfm_dbg;	/* SF 3-way merge re-add/drop diag (slow path, no µs perturbation) */

/*
 * 0.84.18 (D-0963): the ring of shortform images THIS node flushed during its
 * current EX tenure (declared at i_dlm_dir_sf_own in xfs_inode.h).
 *
 * THE DEFECT, measured on the two-node TCP board (cache_coherency
 * unlink_visibility, dir ino 2246, tests/evidence/run_cache_coherency_
 * 20260912T161757Z): the deleter's fork was stale-gen for its whole removal
 * loop (its re-acquire after the peer's tenure skipped the rebuild because its
 * own inode was pinned), so every removal took the P174-STALEGEN-ADOPT
 * refresh; the directory shrank back to shortform in-core; the node's own
 * flushes landed one removal behind; the refresh read the platter, found the
 * node's OWN previous image (holding the entry just removed), and the 3-way
 * merge classified that entry -- in theirs, absent from ours, absent from a
 * base that predated every entry this node had created -- as a peer's fresh
 * add and re-added it (P-SFMERGE 146->166 bytes, the name moving from first
 * to last in the successive P56-DIRWRITE lists).  The last image the node
 * published held only the name it had removed: a dangling dirent naming a
 * freed inode, which the peer could still stat from its cache.
 *
 * THE RULE: a platter image byte-identical to one this node itself flushed in
 * this tenure carries no peer change (a peer can modify only while we do not
 * hold EX), so the in-core fork is authoritative and no merge runs; the base
 * advances to that image.  The ring is retired at every release drain, so an
 * image from a previous tenure -- which a peer's tenure could legitimately
 * recreate byte-for-byte by removing what we added -- can never match; it
 * is NOT cleared inside a tenure (a base captured there from the pre-tenure
 * platter image must not forget our writes still in flight).  Base is also
 * captured from the platter at the EX release itself, because that image is
 * what the peer's tenure builds on and therefore the one true common ancestor
 * for the merge at our next stale-gen re-acquire; without it, entries added
 * after the last refresh-captured base and deleted by the peer would read as
 * "ours, changed" and survive.
 *
 * All ring access is under i_flags_lock (the writer runs in xfs_iflush under
 * ILOCK_SHARED with the cluster buffer locked; the readers hold no ILOCK).
 * Allocation and freeing happen outside the lock.
 */
int mxfs_sf_own_image = 1;
module_param_named(sf_own_image, mxfs_sf_own_image, int, 0644);
MODULE_PARM_DESC(sf_own_image,
		 "A platter shortform image this node itself flushed in the current EX tenure makes the in-core fork authoritative instead of being merged as a peer's (1=on default, 0=off: the D-0963 control arm)");
atomic_t mxfs_sf_own_image_hits = ATOMIC_INIT(0);
atomic_t mxfs_sf_own_image_recorded = ATOMIC_INIT(0);
atomic_t mxfs_sf_release_base = ATOMIC_INIT(0);

/* Detach every ring image under the lock; free them outside it. */
static void
mxfs_dir_sf_own_clear(struct xfs_inode *ip)
{
	void	*old[MXFS_SF_OWN_RING];
	int	k;

	spin_lock(&ip->i_flags_lock);
	for (k = 0; k < MXFS_SF_OWN_RING; k++) {
		old[k] = ip->i_dlm_dir_sf_own[k];
		ip->i_dlm_dir_sf_own[k] = NULL;
		ip->i_dlm_dir_sf_own_bytes[k] = 0;
	}
	ip->i_dlm_dir_sf_own_next = 0;
	spin_unlock(&ip->i_flags_lock);
	for (k = 0; k < MXFS_SF_OWN_RING; k++)
		kfree(old[k]);
}

/*
 * Record the shortform image xfs_iflush just copied into the cluster buffer.
 * Called with ILOCK_SHARED and the cluster buffer held, so the bytes are
 * exactly what will land; a later flush of the same inode waits for the
 * buffer and records its own image after this one.
 */
void
mxfs_dir_sf_own_record(struct xfs_inode *ip, const void *img, uint32_t bytes)
{
	void	*cp, *old;
	int	k;

	if (!mxfs_sf_own_image || !img || !bytes ||
	    bytes > ip->i_mount->m_sb.sb_inodesize)
		return;
	cp = kmalloc(bytes, GFP_NOFS | __GFP_NOWARN);
	if (!cp)
		return;
	memcpy(cp, img, bytes);
	spin_lock(&ip->i_flags_lock);
	k = ip->i_dlm_dir_sf_own_next % MXFS_SF_OWN_RING;
	old = ip->i_dlm_dir_sf_own[k];
	ip->i_dlm_dir_sf_own[k] = cp;
	ip->i_dlm_dir_sf_own_bytes[k] = bytes;
	ip->i_dlm_dir_sf_own_next = (k + 1) % MXFS_SF_OWN_RING;
	spin_unlock(&ip->i_flags_lock);
	kfree(old);
	atomic_inc(&mxfs_sf_own_image_recorded);
}
EXPORT_SYMBOL(mxfs_dir_sf_own_record);

/* Is this platter image one this node flushed in the current tenure? */
static bool
mxfs_dir_sf_own_match(struct xfs_inode *ip, const void *img, uint32_t bytes)
{
	bool	hit = false;
	int	k;

	if (!mxfs_sf_own_image || !img || !bytes)
		return false;
	spin_lock(&ip->i_flags_lock);
	for (k = 0; k < MXFS_SF_OWN_RING; k++) {
		if (ip->i_dlm_dir_sf_own[k] &&
		    ip->i_dlm_dir_sf_own_bytes[k] == bytes &&
		    memcmp(ip->i_dlm_dir_sf_own[k], img, bytes) == 0) {
			hit = true;
			break;
		}
	}
	spin_unlock(&ip->i_flags_lock);
	return hit;
}

/*
 * Capture/replace the merge BASE snapshot from a shortform image (bytes valid).
 * The own-image ring is NOT touched here: inside a tenure no peer writes, so
 * a platter image that is not ours can only be the one from before the
 * tenure, and our own writes that are still in flight must stay recognisable
 * when they land.  The ring is retired at the release only.
 */
void
mxfs_dir_sf_capture_base(struct xfs_inode *ip, const void *img, uint32_t bytes)
{
	void *cp;

	if (!img || !bytes || bytes > ip->i_mount->m_sb.sb_inodesize)
		return;
	cp = kmalloc(bytes, GFP_NOFS);
	if (!cp)
		return;
	memcpy(cp, img, bytes);
	if (ip->i_dlm_dir_sf_base)
		kfree(ip->i_dlm_dir_sf_base);
	ip->i_dlm_dir_sf_base = cp;
	ip->i_dlm_dir_sf_base_bytes = bytes;
}

/*
 * At a directory's release drain, after it has made this node's last image
 * durable.  The tenure is over, so the own-image ring is retired first, for
 * every directory (a peer's tenure can legitimately recreate an old image of
 * ours byte for byte by removing what we had added, and that must never read
 * as "nothing changed").  Then, for an EX release of a shortform directory,
 * the platter holds the image the peer's tenure will build on, so it is the
 * merge base for our next stale-gen re-acquire: read it coherently and
 * capture it.  A read failure, a foreign incarnation or a non-shortform
 * platter image leaves the base as it was (the next reload/merge recaptures
 * it as before).
 */
void
mxfs_dir_sf_release_base(struct xfs_inode *ip, bool held_ex)
{
	struct xfs_mount	*mp = ip->i_mount;
	uint32_t		clen;
	void			*rb;
	struct xfs_dinode	*ddip;
	unsigned		disk_size = 0;
	int			gen_match = 0, fmt = -1, rrc = -1;
	static atomic_t		pn = ATOMIC_INIT(0);
	int			n;

	if (!mxfs_sf_own_image)
		return;
	mxfs_dir_sf_own_clear(ip);
	if (!held_ex || !S_ISDIR(VFS_I(ip)->i_mode))
		return;
	if (ip->i_df.if_format != XFS_DINODE_FMT_LOCAL || !ip->i_df.if_data)
		return;
	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return;
	if (xfs_is_shutdown(mp))
		return;
	clen = BBTOB(ip->i_imap.im_len);
	if ((clen & 511) != 0 || clen == 0)
		return;
	rb = kmalloc(clen, GFP_NOFS);
	if (!rb)
		return;
	{
		extern int mxfs_pal_bdev_read_plain_bdev(
			struct block_device *, uint64_t, void *, uint32_t);
		extern int mxfs_pal_scsi_read_fua_bdev(
			struct block_device *, uint64_t, void *, uint32_t);
		uint64_t lba = (uint64_t)ip->i_imap.im_blkno +
			mp->m_ddev_targp->bt_sector_offset;

		if (mxfs_fua_disable)
			rrc = mxfs_pal_bdev_read_plain_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, clen);
		else
			rrc = mxfs_pal_scsi_read_fua_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, clen);
	}
	if (rrc == 0) {
		ddip = (struct xfs_dinode *)((char *)rb + ip->i_imap.im_boffset);
		fmt = ddip->di_format;
		gen_match = be32_to_cpu(ddip->di_gen) == VFS_I(ip)->i_generation;
		disk_size = (unsigned)be64_to_cpu(ddip->di_size);
		if (gen_match && fmt == XFS_DINODE_FMT_LOCAL && disk_size &&
		    ddip->di_magic == cpu_to_be16(MXFS_DINODE_MAGIC)) {
			mxfs_dir_sf_capture_base(ip,
				(char *)ddip + xfs_dinode_size(ddip->di_version),
				disk_size);
			atomic_inc(&mxfs_sf_release_base);
		}
	}
	n = atomic_inc_return(&pn);
	if (n <= 32 || (n % 500) == 0)
		mxfs_probe("mxfs: P963-SF-RELEASE-BASE ino=%llu rrc=%d gen_match=%d fmt=%d disk_size=%u incore_bytes=%lld n=%d\n",
			(unsigned long long)ip->i_ino, rrc, gen_match, fmt,
			disk_size, (long long)ip->i_df.if_bytes, n);
	kfree(rb);
}

/*
 * (instrumented — PROVEN write-side shortform resurrection, n2_r6 stuck):
 * 3-WAY MERGE of a shortform directory.  ours = ip->i_df.if_data, theirs = the
 * coherent on-disk image, base = i_dlm_dir_sf_base (the disk image at our last
 * sync).  For each name in (base ∪ ours ∪ theirs): if WE changed it (absent
 * from base, or its inode differs from base) keep OURS; otherwise follow
 * THEIRS.  This keeps our own committed-not-yet-durable rename/rm (no
 * self-revert when the disk read lags a destage) AND adopts the peer's
 * committed adds/removes (no resurrection of a peer's removed dirent — the
 * dlm_fairness `drained got=1` / tcp_dlm_scaling silent-loss family).  For the
 * disjoint-name churn workload this is exact (each node touches only its own
 * names).  Requires both base and ours; returns true iff it reconciled (base
 * advanced to theirs, in-core fork rebuilt if it differs).  false => caller
 * falls back to the adopt-or-skip path.  Takes i_lock EXCL itself (caller must
 * NOT hold it and must have already done the sleeping disk read).
 */
/*
 * i_lock-held CORE: build merged(base, ours, theirs) and install it into
 * ip->i_df iff it differs from the CURRENT in-core fork; capture base = theirs.
 * Returns true iff a valid merge was produced (base advanced).  Caller holds
 * ip->i_lock EXCL.  Used by both the sf_refresh fast-path (ours == current
 * in-core) AND mxfs_dlm_reload_inode after it adopts disk (ours == the
 * pre-reload snapshot, theirs == the just-adopted disk fork) so a reload no
 * longer reverts our own committed-not-durable delta.
 */
bool
mxfs_dir_sf_merge_into(struct xfs_inode *ip, struct xfs_dir2_sf_hdr *base,
		       struct xfs_dir2_sf_hdr *ours,
		       struct xfs_dir2_sf_hdr *theirs, uint32_t theirs_bytes,
		       int *ours_only_dirs)
{
	struct xfs_mount		*mp = ip->i_mount;
	struct xfs_dir2_sf_hdr		*out;
	struct xfs_dir2_sf_entry	*sfep, *oe, *te;
	int				has_ftype = xfs_has_ftype(mp) ? 1 : 0;
	xfs_ino_t			pino;
	int				count, i8count, namelen_tot, i;
	unsigned			offset, size, dfork_size;
	void				*buf;
	bool				changed;

	if (!mxfs_sf_merge || !base || !ours || !theirs)
		return false;
	pino = xfs_dir2_sf_get_parent_ino(ours);

	buf = kmalloc(mp->m_sb.sb_inodesize, GFP_NOFS);
	if (!buf)
		return false;
	out = buf;

	/* pass 1: tally count / i8count / namelen of the merged set */
	count = 0;
	namelen_tot = 0;
	i8count = (pino > XFS_DIR2_MAX_SHORT_INUM) ? 1 : 0;
	oe = xfs_dir2_sf_firstentry(ours);
	for (i = 0; i < ours->count; i++) {
		struct xfs_dir2_sf_entry *be =
			mxfs_sf_find(mp, base, oe->name, oe->namelen);
		xfs_ino_t oino = xfs_dir2_sf_get_ino(mp, ours, oe);
		bool we_changed = !be ||
			xfs_dir2_sf_get_ino(mp, base, be) != oino;
		bool keep = we_changed;
		xfs_ino_t useino = oino;

		if (!we_changed) {
			te = mxfs_sf_find(mp, theirs, oe->name, oe->namelen);
			if (te) {
				keep = true;
				useino = xfs_dir2_sf_get_ino(mp, theirs, te);
			}
		}
		if (keep) {
			count++;
			namelen_tot += oe->namelen + has_ftype;
			if (useino > XFS_DIR2_MAX_SHORT_INUM)
				i8count++;
			/*
			 * an entry WE contribute that the disk image
			 * does not have is a dirent whose parent-link bump is
			 * likewise absent from the di_nlink we just adopted.
			 * Count the SUBDIRECTORY ones so the caller can put
			 * the link count back; without this the merged fork
			 * lists N children while the core says fewer, and once
			 * those children are removed the count underflows (an
			 * empty directory left at nlink=1, or wrapped to
			 * 4294967295, that can never be rmdir'd).
			 */
			if (ours_only_dirs && has_ftype &&
			    xfs_dir2_sf_get_ftype(mp, oe) == XFS_DIR3_FT_DIR &&
			    !mxfs_sf_find(mp, theirs, oe->name, oe->namelen))
				(*ours_only_dirs)++;
		}
		oe = xfs_dir2_sf_nextentry(mp, ours, oe);
	}
	te = xfs_dir2_sf_firstentry(theirs);
	for (i = 0; i < theirs->count; i++) {
		if (!mxfs_sf_find(mp, ours, te->name, te->namelen) &&
		    !mxfs_sf_find(mp, base, te->name, te->namelen)) {
			xfs_ino_t tino = xfs_dir2_sf_get_ino(mp, theirs, te);

			count++;
			namelen_tot += te->namelen + has_ftype;
			if (tino > XFS_DIR2_MAX_SHORT_INUM)
				i8count++;
		}
		te = xfs_dir2_sf_nextentry(mp, theirs, te);
	}

	size = xfs_dir2_sf_hdr_size(i8count) + count * 3 + namelen_tot +
	       count * (i8count ? XFS_INO64_SIZE : XFS_INO32_SIZE);
	dfork_size = xfs_inode_data_fork_size(ip);
	if (size > dfork_size) {		/* would overflow SF -> fall back */
		kfree(buf);
		return false;
	}

	/* pass 2: write hdr + entries with fresh sequential offsets */
	out->count = count;
	out->i8count = i8count;
	xfs_dir2_sf_put_parent_ino(out, pino);
	sfep = xfs_dir2_sf_firstentry(out);
	offset = mp->m_dir_geo->data_first_offset;
	oe = xfs_dir2_sf_firstentry(ours);
	for (i = 0; i < ours->count; i++) {
		struct xfs_dir2_sf_entry *be =
			mxfs_sf_find(mp, base, oe->name, oe->namelen);
		xfs_ino_t oino = xfs_dir2_sf_get_ino(mp, ours, oe);
		bool we_changed = !be ||
			xfs_dir2_sf_get_ino(mp, base, be) != oino;
		bool keep = we_changed;
		xfs_ino_t useino = oino;
		uint8_t uft = xfs_dir2_sf_get_ftype(mp, oe);

		if (!we_changed) {
			te = mxfs_sf_find(mp, theirs, oe->name, oe->namelen);
			if (te) {
				keep = true;
				useino = xfs_dir2_sf_get_ino(mp, theirs, te);
				uft = xfs_dir2_sf_get_ftype(mp, te);
			} else {
				keep = false;
				if (mxfs_sfm_dbg)
					mxfs_probe_ratelimited(
					    "mxfs: P-SFM-DROP ino=%llu name=%.*s (in ours+base, gone from theirs=peer-delete) base_n=%u ours_n=%u theirs_n=%u\n",
					    (unsigned long long)ip->i_ino,
					    oe->namelen, oe->name,
					    base->count, ours->count, theirs->count);
			}
		}
		if (keep) {
			sfep->namelen = oe->namelen;
			xfs_dir2_sf_put_offset(sfep, offset);
			memcpy(sfep->name, oe->name, oe->namelen);
			xfs_dir2_sf_put_ino(mp, out, sfep, useino);
			xfs_dir2_sf_put_ftype(mp, sfep, uft);
			offset += xfs_dir2_data_entsize(mp, oe->namelen);
			sfep = xfs_dir2_sf_nextentry(mp, out, sfep);
		}
		oe = xfs_dir2_sf_nextentry(mp, ours, oe);
	}
	te = xfs_dir2_sf_firstentry(theirs);
	for (i = 0; i < theirs->count; i++) {
		/* (instrumented PROVE): a name in THEIRS (disk) + BASE but NOT in
		 * OURS is SILENTLY SKIPPED by the union below (the base check treats it
		 * as "not a fresh peer add").  HYPOTHESIS: this is exactly node1_f1 —
		 * a peer entry we never owned, present on disk, captured into our base
		 * by a prior disk read, and now dropped because in-core lacks it.  Log
		 * it to confirm the deterministic node1_f1 loss path. */
		if (mxfs_sfm_dbg &&
		    !mxfs_sf_find(mp, ours, te->name, te->namelen) &&
		    mxfs_sf_find(mp, base, te->name, te->namelen))
			pr_warn_ratelimited(
			    "mxfs: P64-SFM-SKIP-BASE ino=%llu name=%.*s in_theirs+base_not_ours base_n=%u ours_n=%u theirs_n=%u — DROPPED (suspected node1_f1 loss)\n",
			    (unsigned long long)ip->i_ino,
			    te->namelen, te->name,
			    base->count, ours->count, theirs->count);
		if (!mxfs_sf_find(mp, ours, te->name, te->namelen) &&
		    !mxfs_sf_find(mp, base, te->name, te->namelen)) {
			if (mxfs_sfm_dbg)
				mxfs_probe_ratelimited(
				    "mxfs: P-SFM-READD ino=%llu name=%.*s ino_t=%llu base_n=%u ours_n=%u theirs_n=%u mode=%u state=%u dir_gen=%llu loaded_gen=%llu peer_mod=%d\n",
				    (unsigned long long)ip->i_ino,
				    te->namelen, te->name,
				    (unsigned long long)xfs_dir2_sf_get_ino(mp, theirs, te),
				    base->count, ours->count, theirs->count,
				    ip->i_dlm_mode, ip->i_dlm_state,
				    (unsigned long long)ip->i_dlm_dir_gen,
				    (unsigned long long)ip->i_dlm_dir_loaded_gen,
				    (ip->i_dlm_dir_gen > ip->i_dlm_dir_loaded_gen) ? 1 : 0);
			sfep->namelen = te->namelen;
			xfs_dir2_sf_put_offset(sfep, offset);
			memcpy(sfep->name, te->name, te->namelen);
			xfs_dir2_sf_put_ino(mp, out, sfep,
					    xfs_dir2_sf_get_ino(mp, theirs, te));
			xfs_dir2_sf_put_ftype(mp, sfep,
					      xfs_dir2_sf_get_ftype(mp, te));
			offset += xfs_dir2_data_entsize(mp, te->namelen);
			sfep = xfs_dir2_sf_nextentry(mp, out, sfep);
		}
		te = xfs_dir2_sf_nextentry(mp, theirs, te);
	}

	/* sanity: exact byte count + valid SF image, else fall back */
	if ((unsigned)((char *)sfep - (char *)out) != size ||
	    xfs_dir2_sf_verify(mp, out, size) != NULL) {
		kfree(buf);
		return false;
	}

	/* install iff the merge differs from the CURRENT in-core fork (works
	 * for both callers: sf_refresh in-core==ours, reload in-core==theirs). */
	changed = (ip->i_df.if_bytes != (int)size) ||
		  !ip->i_df.if_data ||
		  memcmp(ip->i_df.if_data, out, size) != 0;
	/* capture base = THEIRS now, BEFORE the install may free theirs (in the
	 * reload caller theirs IS ip->i_df.if_data). */
	mxfs_dir_sf_capture_base(ip, theirs, theirs_bytes);
	if (changed) {
		mxfs_probe_ratelimited(
			"mxfs: P-SFMERGE ino=%llu incore_bytes=%lld theirs_bytes=%u merged_bytes=%u count=%d\n",
			(unsigned long long)ip->i_ino, (long long)ip->i_df.if_bytes,
			theirs_bytes, size, count);
		xfs_idestroy_fork(&ip->i_df);
		xfs_init_local_fork(ip, XFS_DATA_FORK, out, size);
		ip->i_df.if_format = XFS_DINODE_FMT_LOCAL;
		ip->i_disk_size = size;
		i_size_write(VFS_I(ip), size);
	}
	kfree(buf);
	return true;
}

/*
 * Locking wrapper for the sf_refresh fast-path: take i_lock EXCL (bounded
 * trylock, never wedge) and merge the coherent on-disk image into the in-core
 * shortform fork.  Caller must NOT hold i_lock and must have already done the
 * sleeping disk read (theirs points at a stable buffer the caller owns).
 */
static bool
mxfs_dir_sf_3way_merge(struct xfs_inode *ip, struct xfs_dir2_sf_hdr *theirs,
		       uint32_t theirs_bytes)
{
	bool	ret, got = false;
	int	tries = 0;

	if (!mxfs_sf_merge)
		return false;
	while (tries++ < 1000) {
		if (down_write_trylock(&ip->i_lock)) {
			mxfs_ilk_note_lock(ip, XFS_ILOCK_EXCL, _THIS_IP_);	/* attribute raw down_write */
			got = true; break;
		}
		cond_resched();
	}
	if (!got)
		return false;
	if (ip->i_df.if_format != XFS_DINODE_FMT_LOCAL) {
		up_write(&ip->i_lock);
		return false;
	}
	ret = mxfs_dir_sf_merge_into(ip, ip->i_dlm_dir_sf_base,
				     ip->i_df.if_data, theirs, theirs_bytes,
				     NULL);
	up_write(&ip->i_lock);
	return ret;
}

/*
 * reconcile a SHORTFORM directory's in-core fork with the platter
 * immediately before the release drain publishes it.  Dossier at the call site
 * (the RELFLUSH arm of the publish drain loop).
 *
 * Read the coherent on-disk image and, when it differs, run the same 3-way
 * merge the acquire path uses, so the drain publishes peers' durable names
 * UNION our unlanded ones.  Then log the merged fork so the flush actually
 * copies it in (the merge only rewrites in-core state; without XFS_ILOG_DDATA
 * on this tenure's log item xfs_iflush_int would copy nothing and the platter
 * would keep the pre-merge image).
 *
 * Everything here is best-effort and non-blocking: a declined merge, a failed
 * read, an unavailable lock or a shut-down mount all leave the previous
 * behaviour exactly as it was.
 */
/*
 * DEFAULT 0 — REFUTED, measured.  Same build, same storm
 * (tests/sf_mkdir_storm.sh 30 32 2 1), only this param changed:
 *     dir_release_premerge=1  ->  21 of 30 rounds inconsistent
 *     dir_release_premerge=0  ->   9 of 30 rounds inconsistent
 * and it fired only 11 times in the bad run, far too few to have changed
 * that much content.  So the regression is LATENCY, not merge content: the
 * extra FUA read + merge + re-log inside the release drain delays the drain,
 * and the loss rate rises with drain lateness.  That is itself evidence about
 * the root — the drain's write is racing peers who have already published —
 * so keep the lever for A/B, but never default it on.
 */
int mxfs_dir_release_premerge;		/* default OFF — see refutation above */

int mxfs_dir_nl_require_grant = 1;	/* default ON */
module_param_named(dir_nl_require_grant, mxfs_dir_nl_require_grant, int, 0644);
MODULE_PARM_DESC(dir_nl_require_grant,
		 "A logged dir slot at NL may be published on the RELFLUSH token "
		 "only while the on-disk grant is genuinely still held (1=on "
		 "default; 0 restores the token-only exemption)");
module_param_named(dir_release_premerge, mxfs_dir_release_premerge, int, 0644);
MODULE_PARM_DESC(dir_release_premerge,
		 "Reconcile a shortform dir's fork against the platter before "
		 "the release drain publishes it (0=off default; measured to "
		 "make the loss WORSE by adding drain latency)");

void
mxfs_dir_sf_premerge_for_release(struct xfs_inode *ip)
{
	struct xfs_mount	*mp;
	uint32_t		clen;
	void			*rb;
	struct xfs_dinode	*ddip;
	unsigned		disk_size;
	void			*disk_sf;
	bool			merged;
	static atomic_t		p182n = ATOMIC_INIT(0);

	if (!mxfs_dir_release_premerge || !ip)
		return;
	mp = ip->i_mount;
	if (!mp || !mp->m_mxfs_dlm || xfs_is_shutdown(mp))
		return;
	if (mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!S_ISDIR(VFS_I(ip)->i_mode))
		return;
	if (ip->i_df.if_format != XFS_DINODE_FMT_LOCAL || !ip->i_df.if_data)
		return;
	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return;

	clen = BBTOB(ip->i_imap.im_len);
	if (!clen || (clen & 511))
		return;
	rb = kmalloc(clen, GFP_NOFS);
	if (!rb)
		return;
	{
		extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
							 uint64_t, void *,
							 uint32_t);
		extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *,
						       uint64_t, void *,
						       uint32_t);
		uint64_t lba = (uint64_t)ip->i_imap.im_blkno +
			mp->m_ddev_targp->bt_sector_offset;
		int rrc;

		if (mxfs_fua_disable)
			rrc = mxfs_pal_bdev_read_plain_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, clen);
		else
			rrc = mxfs_pal_scsi_read_fua_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, clen);
		if (rrc != 0) {
			kfree(rb);
			return;
		}
	}

	ddip = (struct xfs_dinode *)((char *)rb + ip->i_imap.im_boffset);
	/* Same incarnation only — a different generation is genuine inode
	 * reuse and belongs to the normal reload guards, not to a merge. */
	if (be16_to_cpu(ddip->di_magic) != MXFS_DINODE_MAGIC ||
	    be32_to_cpu(ddip->di_gen) != VFS_I(ip)->i_generation ||
	    ddip->di_format != XFS_DINODE_FMT_LOCAL) {
		kfree(rb);
		return;
	}
	disk_size = (unsigned)be64_to_cpu(ddip->di_size);
	disk_sf = (char *)ddip + xfs_dinode_size(ddip->di_version);
	if (!disk_size || disk_size > XFS_DFORK_DSIZE(ddip, mp)) {
		kfree(rb);
		return;
	}
	if (disk_size == (unsigned)ip->i_df.if_bytes &&
	    memcmp(disk_sf, ip->i_df.if_data, ip->i_df.if_bytes) == 0) {
		kfree(rb);		/* already coherent — nothing to do */
		return;
	}

	/* the merge rewrites i_df in place and then re-logs it — a
	 * synthetic publication.  Authorize BEFORE touching the fork: without
	 * EX tenure on this inode the in-core image must not become platter
	 * truth (the P146V clobber shape; mxfs_dlm_relog_authorized). */
	if (!mxfs_dlm_relog_authorized(ip, "P182", be32_to_cpu(ddip->di_gen))) {
		kfree(rb);
		return;
	}

	merged = mxfs_dir_sf_3way_merge(ip, (struct xfs_dir2_sf_hdr *)disk_sf,
					disk_size);
	if (!merged) {
		kfree(rb);
		return;
	}

	/*
	 * Publish-ability: the merge rewrote i_df in place, so this tenure's
	 * log item must carry XFS_ILOG_DDATA or xfs_iflush_int copies nothing.
	 * A tiny self-contained transaction, exactly like the drain's P146V
	 * re-log arm; never blocks (nowait ilock, cancel on failure).
	 */
	{
		struct xfs_trans *ptp;

		WRITE_ONCE(ip->i_mxfs_pipe_relog, 1);
		if (!xfs_is_shutdown(mp) &&
		    !xfs_trans_alloc(mp, &M_RES(mp)->tr_ichange, 0, 0, 0,
				     &ptp)) {
			if (xfs_ilock_nowait(ip, XFS_ILOCK_EXCL)) {
				/* D-0532: join with 0 (the commit must not
				 * xfs_iunlock a lock that had no DLM begin). */
				xfs_trans_ijoin(ptp, ip, 0);
				xfs_trans_log_inode(ptp, ip,
					XFS_ILOG_CORE | XFS_ILOG_DDATA);
				(void)xfs_trans_commit(ptp);
				xfs_iunlock_nodlm(ip, XFS_ILOCK_EXCL);
			} else {
				xfs_trans_cancel(ptp);
			}
		}
		WRITE_ONCE(ip->i_mxfs_pipe_relog, 0);
	}

	if (atomic_inc_return(&p182n) <= 2000)
		mxfs_probe("mxfs: P182-RELMERGE ino=%llu disk_size=%u merged_bytes=%lld nlink=%u chg=%llu disk_chg=%llu comm=%s realns=%llu — release drain reconciled its shortform image with the platter before publishing\n",
			(unsigned long long)ip->i_ino, disk_size,
			(long long)ip->i_df.if_bytes, VFS_I(ip)->i_nlink,
			(unsigned long long)inode_peek_iversion(VFS_I(ip)),
			(unsigned long long)be64_to_cpu(ddip->di_changecount),
			current->comm,
			(unsigned long long)ktime_get_real_ns());
	kfree(rb);
}

void
mxfs_dir_sf_refresh_if_disk_differs(struct xfs_inode *ip)
{
	struct xfs_mount		*mp = ip->i_mount;
	struct xfs_inode_log_item	*iip;
	uint32_t			clen;
	void				*rb;
	struct xfs_dinode		*ddip;
	unsigned			disk_size;
	bool				differs = false;

	if (!S_ISDIR(VFS_I(ip)->i_mode))
		return;
	if (ip->i_df.if_format != XFS_DINODE_FMT_LOCAL || !ip->i_df.if_data)
		return;
	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return;

	clen = BBTOB(ip->i_imap.im_len);
	if ((clen & 511) != 0 || clen == 0)
		return;
	rb = kmalloc(clen, GFP_NOFS);
	if (!rb)
		return;

	{
		extern int mxfs_pal_bdev_read_plain_bdev(
			struct block_device *, uint64_t, void *, uint32_t);
		extern int mxfs_pal_scsi_read_fua_bdev(
			struct block_device *, uint64_t, void *, uint32_t);
		uint64_t lba = (uint64_t)ip->i_imap.im_blkno +
			mp->m_ddev_targp->bt_sector_offset;
		int rrc;

		if (mxfs_fua_disable)
			rrc = mxfs_pal_bdev_read_plain_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, clen);
		else
			rrc = mxfs_pal_scsi_read_fua_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, clen);
		if (rrc != 0) {
			kfree(rb);
			return;
		}
	}

	ddip = (struct xfs_dinode *)((char *)rb + ip->i_imap.im_boffset);
	/* Same incarnation only — a different gen is genuine reuse, left to the
	 * normal reload guards. */
	if (be32_to_cpu(ddip->di_gen) != VFS_I(ip)->i_generation) {
		kfree(rb);
		return;
	}
	disk_size = (unsigned)be64_to_cpu(ddip->di_size);
	/*
	 * 0.84.18 (D-0963): the platter holds an image THIS node flushed in
	 * the current tenure -- our own publication, lagging the in-core fork
	 * by the removals since that flush.  Nothing in it is a peer's, so
	 * the in-core fork is authoritative; merging it re-added the entry
	 * just removed.  The base advances to it (it is what the platter
	 * holds), the ring is kept (a later flush may still be in flight).
	 */
	if (ddip->di_format == XFS_DINODE_FMT_LOCAL && disk_size &&
	    mxfs_dir_sf_own_match(ip,
			(char *)ddip + xfs_dinode_size(ddip->di_version),
			disk_size)) {
		static atomic_t	pn = ATOMIC_INIT(0);
		int		n = atomic_inc_return(&pn);

		atomic_inc(&mxfs_sf_own_image_hits);
		if (n <= 32 || (n % 500) == 0)
			mxfs_probe("mxfs: P963-SF-OWN-IMAGE ino=%llu disk_size=%u incore_bytes=%lld disk_count=%u incore_count=%u dir_gen=%u loaded_gen=%u same=%d n=%d\n",
				(unsigned long long)ip->i_ino, disk_size,
				(long long)ip->i_df.if_bytes,
				((struct xfs_dir2_sf_hdr *)((char *)ddip +
					xfs_dinode_size(ddip->di_version)))->count,
				((struct xfs_dir2_sf_hdr *)ip->i_df.if_data)->count,
				ip->i_dlm_dir_gen, ip->i_dlm_dir_loaded_gen,
				(disk_size == ip->i_df.if_bytes &&
				 memcmp((char *)ddip +
					xfs_dinode_size(ddip->di_version),
					ip->i_df.if_data, disk_size) == 0) ? 1 : 0,
				n);
		mxfs_dir_sf_capture_base(ip,
			(char *)ddip + xfs_dinode_size(ddip->di_version),
			disk_size);
		kfree(rb);
		return;
	}
	if (ddip->di_format != XFS_DINODE_FMT_LOCAL) {
		differs = true;		/* format changed under us → stale */
	} else {
		void *disk_sf = (char *)ddip + xfs_dinode_size(ddip->di_version);

		if (disk_size != ip->i_df.if_bytes)
			differs = true;
		else if (memcmp(disk_sf, ip->i_df.if_data,
				ip->i_df.if_bytes) != 0)
			differs = true;
	}

	if (!differs) {
		/* in-core already matches disk: (re)capture this as the merge
		 * BASE — the shared point both nodes agree on right now. */
		if (ddip->di_format == XFS_DINODE_FMT_LOCAL)
			mxfs_dir_sf_capture_base(ip,
				(char *)ddip + xfs_dinode_size(ddip->di_version),
				disk_size);
		kfree(rb);
		return;
	}

	/*
	 * — PROVEN BY INSTRUMENT (tds leftover n2_r130, a
	 * NODE2 entry surviving on NODE1's CLEAN cached shortform fork after
	 * node2 created+removed it): the 3-way merge is SAFE to preserve a local
	 * delta only when THIS inode is DIRTY (we actually committed something
	 * not yet durable).  When the inode is CLEAN it has NO valid local delta,
	 * and "in-core vs base" is a phantom diff over a STALE prior-tenure image
	 * (entries the peer has since removed).  Merging then RE-UNIONS the
	 * peer-removed entry = the durable resurrection.  So gate the merge on
	 * DIRTY; a CLEAN inode adopts the authoritative on-disk image wholesale
	 * (disk = the latest state the previous EX owner published before
	 * release).  This is the read-side mirror of the slow-path reload's
	 * !xfs_inode_clean() merge gate (line ~7854).
	 */
	iip = ip->i_itemp;
	{
		bool icd_clean = (atomic_read(&ip->i_pincount) == 0 &&
			(!iip || (!iip->ili_fields &&
			 !test_bit(XFS_LI_IN_AIL,
				   &iip->ili_item.li_flags))));

		if (!icd_clean && mxfs_sf_merge &&
		    ddip->di_format == XFS_DINODE_FMT_LOCAL) {
			struct xfs_dir2_sf_hdr *theirs =
				(struct xfs_dir2_sf_hdr *)((char *)ddip +
					xfs_dinode_size(ddip->di_version));

			if (mxfs_dir_sf_3way_merge(ip, theirs, disk_size)) {
				kfree(rb);
				return;
			}
		}

		/*
		 * DIRTY but no merge (no base / SF-overflow / disk format
		 * changed / merge declined): the in-core fork is authoritative
		 * (our committed-not-durable delta) — never adopt disk (would
		 * revert our own change, and the on-disk image may be
		 * transiently mid-destage = older than ours).
		 */
		if (!icd_clean) {
			kfree(rb);
			return;
		}
	}
	/* CLEAN: adopt the authoritative on-disk shortform. */
	mxfs_probe_ratelimited(
		"mxfs: P9-SFREFRESH ino=%llu incore_bytes=%lld disk_size=%u — clean in-core shortform fork differs from coherent disk; reloading\n",
		(unsigned long long)ip->i_ino,
		(long long)ip->i_df.if_bytes, disk_size);
	ip->i_dlm_stale = true; ip->i_dlm_stale_src = 9;
	mxfs_dlm_reload_inode(ip, XFS_DIR3_FT_UNKNOWN, false);
	if (ddip->di_format == XFS_DINODE_FMT_LOCAL)
		mxfs_dir_sf_capture_base(ip,
			(char *)ddip + xfs_dinode_size(ddip->di_version),
			disk_size);
	kfree(rb);
}

/* 3-way shortform-dir merge on a coherent-disk-differs refresh
 * (base/ours/theirs). 1=on (default), 0=off (revert to adopt-or-skip). */
module_param_named(sf_merge, mxfs_sf_merge, int, 0644);
MODULE_PARM_DESC(sf_merge,
                 "3-way shortform-dir merge (1=on default, 0=off)");

/* SF 3-way merge re-add/drop diagnostic.  Logs (ratelimited) each
 * entry the merge RE-ADDS from theirs (peer-add path) or DROPS from ours
 * (peer-delete path), with the merge base/ours/theirs counts.  Slow path only
 * (fires on a coherent-disk-differs refresh), so it does NOT perturb the
 * sub-microsecond DLM lock race the way dirwr/instr lock-path probes do. */
module_param_named(sfm_dbg, mxfs_sfm_dbg, int, 0644);
MODULE_PARM_DESC(sfm_dbg,
                 "SF 3-way merge re-add/drop name diagnostic (0=off default)");
