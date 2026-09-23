// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS symmetric directory sharding — manifest block, lifecycle, resolver,
 * and the dispatch wrappers that run the unchanged XFS directory primitives
 * against a shard container as the physical directory.
 *
 * sess464 — D-32NODE-SHARED-DIR-CREATE-PACE (board face D-401), on the
 * critical path of D-FOREIGN-REPLAY-UNGATED-IMAGES since sess463.
 * Design: docs/dir-sharding.md.  Format: include/mxfs/mxfs_dirshard.h.
 * Rulings: ccmemory ccloop-c7ee71c6-sess463-GPT-ruling-dirshard-stage1-2-
 * concrete-shape and ccloop-c7ee71c6-sess464-GPT-ruling-dirshard-manifest-
 * block-S3-amendment.
 *
 * LOCK ORDER (documented for lockdep, ruling Q3):
 *   1. visible parent: ILOCK_SHARED (= DLM PR, the "manifest pin") for every
 *      ordinary operation; ILOCK_EXCL (= DLM EX, the "parent barrier") for
 *      lifecycle, rmdir/emptiness, parent-core metadata, fsync, repair.
 *   2. the manifest HOLDER inode (only while reading/writing its block; never
 *      held while a shard is locked).
 *   3. exactly ONE shard container per ordinary operation, in the mode the
 *      primitive needs (PR for lookup/readdir, EX for create/unlink).
 *   4. target inode locks per the usual XFS rules; then AG DLM / AGI / AGF in
 *      the established order (never iget or lock a shard while holding AG
 *      locks — the resolver runs BEFORE transaction setup).
 *
 * ONE COMMIT PER LIFECYCLE STEP (ruling STOP-SHIP #3).  Every manifest change
 * is a memcpy into the manifest block plus xfs_trans_log_buf in the same
 * transaction as the inode work it describes.  The only transaction rolls in
 * these paths are xfs_dialloc's (a new inode chunk), and they happen BEFORE
 * anything of ours is dirtied in that transaction, so every commit boundary
 * shows one of exactly two shapes: nothing, or a strictly earlier complete
 * step.  The one torn shape a dialloc roll can leave — an unlinked PARENT-
 * flagged directory with no locator yet — is reaped by the shard-aware
 * inactivation as a plain unlinked directory.
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_bit.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_buf_item.h"
#include <mxfs/mxfs_super.h>
#include "xfs_trans_space.h"
#include "xfs_bmap.h"
#include "xfs_bmap_btree.h"
#include "xfs_dir2.h"
#include "xfs_attr.h"
#include "xfs_attr_sf.h"
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "libxfs/xfs_dir2_priv.h"	/* xfs_readdir */
#include "xfs_ialloc.h"
#include "xfs_icache.h"
#include "xfs_quota.h"
#include "xfs_log.h"
#include "xfs_error.h"
#include "xfs_health.h"
#include "xfs_ag.h"
#include "xfs_inode_util.h"
#include "xfs_mxfs_dlm.h"
#include <linux/version.h>
#include <linux/namei.h>	/* try_lookup_noperm, 6.16+ */
#include "../dlm/v5_mount.h"	/* sess473: mxfs_v5_dlm_is_single_node (D-0533 probe revalidation) */
#include <linux/delay.h>	/* sess470: msleep in the per-shard settle */
#include "xfs_mxfs_dirshard.h"
#include <linux/siphash.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>	/* 6.8 rig kernel: pre-rename location */
#endif
#include <linux/uuid.h>
#include <linux/fs.h>

/* ------------------------------------------------------------------------ *
 * Feature gate and flag helpers
 * ------------------------------------------------------------------------ */

/*
 * Creating a sharded directory is off unless the administrator turns it on.
 * Sharding is unfinished (rename, links, child directories, fsync and the
 * ecosystem stages are unbuilt), and a sharded directory is otherwise
 * something any directory owner can create with one ioctl.  The on-disk
 * feature bit and envelope flag stay as they are: they say the format
 * understands sharding, not that anything is sharded.  With this off no
 * directory ever becomes sharded, so no other sharding path runs; a volume
 * that already holds sharded directories is still read and removed normally.
 */
static bool mxfs_dirshard_mkdir_enable;
module_param_named(dirshard_mkdir_enable, mxfs_dirshard_mkdir_enable, bool, 0644);
MODULE_PARM_DESC(dirshard_mkdir_enable,
	"allow MXFS_IOC_DIRSHARD_MKDIR to create sharded directories (default 0 = refused with EOPNOTSUPP; experimental)");

/*
 * The three gates must agree (format header): sb incompat bit, envelope flag
 * (recorded on the mount by xfs_super.c when it validates the MXFS envelope),
 * and clustered mode.  A block size that cannot hold the N=64 manifest
 * disables the feature rather than sizing N down silently.
 */
bool
mxfs_dirshard_enabled(
	struct xfs_mount	*mp)
{
	if (!mp->m_mxfs_dlm)
		return false;
	if (!xfs_sb_has_incompat_feature(&mp->m_sb,
					  XFS_SB_FEAT_INCOMPAT_MXFS_DIRSHARD))
		return false;
	if (!mp->m_mxfs_dirshard_env)
		return false;
	if (mp->m_sb.sb_blocksize < MXFS_DIRSHARD_BLK_MIN_BLOCKSIZE)
		return false;
	return true;
}

static inline uint32_t
mxfs_dirshard_igen(
	const struct xfs_inode	*ip)
{
	return VFS_I((struct xfs_inode *)ip)->i_generation;
}

/* ------------------------------------------------------------------------ *
 * Manifest block: buffer ops (symlink-remote pattern, own type)
 * ------------------------------------------------------------------------ */

static xfs_failaddr_t
mxfs_dirshard_blk_verify(
	struct xfs_buf			*bp)
{
	struct xfs_mount		*mp = bp->b_mount;
	struct mxfs_dirshard_blk	*blk = bp->b_addr;
	uint32_t			bytes;

	if (!xfs_has_crc(mp))
		return __this_address;		/* v5 only, always */
	if (!xfs_verify_magic(bp, blk->magic))
		return __this_address;
	if (!uuid_equal((uuid_t *)blk->uuid, &mp->m_sb.sb_meta_uuid))
		return __this_address;
	if (xfs_buf_daddr(bp) != be64_to_cpu(blk->blkno))
		return __this_address;
	if (blk->offset != 0)
		return __this_address;
	bytes = be32_to_cpu(blk->bytes);
	if (bytes < MXFS_DIRSHARD_MANIFEST_HDR_LEN ||
	    bytes > BBTOB(bp->b_length) - MXFS_DIRSHARD_BLK_HDR_LEN)
		return __this_address;
	if (blk->owner == 0 || blk->parent_ino == 0)
		return __this_address;
	if (!xfs_verify_ino(mp, be64_to_cpu(blk->owner)) ||
	    !xfs_verify_ino(mp, be64_to_cpu(blk->parent_ino)))
		return __this_address;
	if (blk->reserved[0] != 0 || blk->reserved[1] != 0)
		return __this_address;
	if (!xfs_log_check_lsn(mp, be64_to_cpu(blk->lsn)))
		return __this_address;
	return NULL;
}

static void
mxfs_dirshard_blk_read_verify(
	struct xfs_buf		*bp)
{
	xfs_failaddr_t		fa;

	if (!xfs_buf_verify_cksum(bp, MXFS_DIRSHARD_BLK_CRC_OFF)) {
		xfs_verifier_error(bp, -EFSBADCRC, __this_address);
		return;
	}
	fa = mxfs_dirshard_blk_verify(bp);
	if (fa)
		xfs_verifier_error(bp, -EFSCORRUPTED, fa);
}

static void
mxfs_dirshard_blk_write_verify(
	struct xfs_buf		*bp)
{
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	xfs_failaddr_t		fa;

	fa = mxfs_dirshard_blk_verify(bp);
	if (fa) {
		xfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}
	if (bip) {
		struct mxfs_dirshard_blk *blk = bp->b_addr;

		blk->lsn = cpu_to_be64(bip->bli_item.li_lsn);
	}
	xfs_buf_update_cksum(bp, MXFS_DIRSHARD_BLK_CRC_OFF);
}

const struct xfs_buf_ops mxfs_dirshard_buf_ops = {
	.name = "mxfs_dirshard",
	.magic = { 0, cpu_to_be32(MXFS_DIRSHARD_BLK_MAGIC) },
	.verify_read = mxfs_dirshard_blk_read_verify,
	.verify_write = mxfs_dirshard_blk_write_verify,
	.verify_struct = mxfs_dirshard_blk_verify,
};

/* ------------------------------------------------------------------------ *
 * Diagnostics
 * ------------------------------------------------------------------------ */

static void
mxfs_dirshard_corrupt(
	struct xfs_inode	*dp,
	const char		*what,
	enum mxfs_dirshard_check c,
	uint64_t		aux)
{
	xfs_alert(dp->i_mount,
		"MXFS P-DIRSHARD-CORRUPT parent=%llu gen=%u %s reason=%s aux=%llu",
		(unsigned long long)dp->i_ino, mxfs_dirshard_igen(dp), what,
		mxfs_dirshard_check_name(c), (unsigned long long)aux);
	xfs_inode_mark_sick(dp, XFS_SICK_INO_DIR);
}

/* ------------------------------------------------------------------------ *
 * Locator xattr on the visible parent
 * ------------------------------------------------------------------------ */

static void
mxfs_dirshard_locator_args_init(
	struct xfs_da_args	*args,
	struct xfs_inode	*dp,
	struct xfs_trans	*tp,
	struct mxfs_dirshard_locator *loc)
{
	memset(args, 0, sizeof(*args));
	args->geo = dp->i_mount->m_attr_geo;
	args->whichfork = XFS_ATTR_FORK;
	args->attr_filter = XFS_ATTR_ROOT;
	args->op_flags = XFS_DA_OP_OKNOENT;
	args->trans = tp;
	args->dp = dp;
	args->owner = dp->i_ino;
	args->name = (const uint8_t *)MXFS_DIRSHARD_XATTR_NAME;
	args->namelen = MXFS_DIRSHARD_XATTR_NAMELEN;
	args->value = loc;
	args->valuelen = MXFS_DIRSHARD_LOCATOR_LEN;
	xfs_attr_sethash(args);
}

/* Caller holds the parent ILOCK (shared or exclusive). */
static int
mxfs_dirshard_locator_get(
	struct xfs_inode	*dp,
	uint64_t		*inop,
	uint32_t		*genp)
{
	struct mxfs_dirshard_locator loc;
	struct xfs_da_args	args;
	int			error;

	mxfs_dirshard_locator_args_init(&args, dp, NULL, &loc);
	error = xfs_attr_get_ilocked(&args);
	if (error == -ENOATTR)
		return -ENOENT;
	if (error)
		return error;
	if (args.valuelen != MXFS_DIRSHARD_LOCATOR_LEN)
		return -EFSCORRUPTED;
	*inop = mxfs_dirshard_be64(loc.manifest_ino);
	*genp = mxfs_dirshard_be32(loc.manifest_gen);
	if (*inop == 0 || *genp == 0 || !xfs_verify_ino(dp->i_mount, *inop))
		return -EFSCORRUPTED;
	return 0;
}

/*
 * Written ONCE, inside the parent's allocation transaction, while the attr
 * fork is the empty local fork XFS_ICREATE_INIT_XATTRS created.  That is
 * the guarantee that the add is the synchronous shortform path with no roll
 * and no deferred intent (ruling STOP-SHIP #4).  xfs_attr_setname takes the
 * shortform shortcut whenever the value fits, and only falls back to the
 * deferred attr intent on -ENOSPC — which cannot happen with a 12-byte value
 * in an empty fork.  The guard below turns "cannot happen" into a checked
 * invariant: if the call queued deferred work, the caller cancels the
 * transaction (nothing committed) instead of rolling.
 */
static int
mxfs_dirshard_locator_set(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	struct xfs_inode	*holder)
{
	struct mxfs_dirshard_locator loc;
	struct xfs_da_args	args;
	size_t			ndef;
	int			error;

	loc.manifest_ino = mxfs_dirshard_be64(holder->i_ino);
	loc.manifest_gen = mxfs_dirshard_be32(mxfs_dirshard_igen(holder));
	mxfs_dirshard_locator_args_init(&args, dp, tp, &loc);
	/*
	 * sess468 (chain 98b, 0.64.4: every MXFS_IOC_DIRSHARD_MKDIR returned
	 * EUCLEAN with nothing logged): XFS_ICREATE_INIT_XATTRS initialises
	 * the attr fork as an EMPTY EXTENTS fork (xfs_inode_init ->
	 * xfs_ifork_init_attr(ip, XFS_DINODE_FMT_EXTENTS, 0)), never LOCAL —
	 * LOCAL is what xfs_attr_shortform_create turns it into on the first
	 * shortform add.  The guard that demanded LOCAL up front therefore
	 * refused every parent.  The invariant that matters is the one the
	 * comment above states: the add must take the synchronous shortform
	 * path.  Its precondition is xfs_attr_is_shortform() (LOCAL, or EXTENTS
	 * with no extents); its postcondition is a LOCAL fork with no deferred
	 * work queued.  Check both, and NAME the refusal.
	 */
	if (!xfs_attr_is_shortform(dp)) {
		xfs_alert(dp->i_mount,
			"MXFS P-DIRSHARD-LOCATOR-FORK parent=%llu format=%d nextents=%llu — attr fork is not shortform-capable at the locator add; refusing",
			(unsigned long long)dp->i_ino, (int)dp->i_af.if_format,
			(unsigned long long)dp->i_af.if_nextents);
		return -EFSCORRUPTED;
	}
	/*
	 * sess472 (D-0531 item 3, design-consult review): this runs inside the
	 * parent's ALLOCATION transaction, which is already dirty (dialloc,
	 * icreate), so a refusal here is a dirty cancel = shutdown.  The two
	 * post-conditions are impossible by construction once the
	 * precondition above held (a 12-byte value in an empty shortform-
	 * capable fork adds synchronously and lands LOCAL); if one ever
	 * fails, NAME it and commit — a deferred intent is finished by the
	 * commit's roll and recovery, a non-LOCAL landing is still a readable
	 * locator (xfs_attr_get_ilocked reads every format) — never cancel.
	 * Count what the add itself queued, not whatever the allocation
	 * already deferred.
	 */
	ndef = list_count_nodes(&tp->t_dfops);
	error = xfs_attr_setname(&args, 0);
	if (error)
		return error;
	if (list_count_nodes(&tp->t_dfops) != ndef)
		xfs_alert(dp->i_mount,
			"MXFS P-DIRSHARD-LOCATOR-DEFERRED parent=%llu dfops=%zu->%zu — shortform add queued a deferred attr intent despite the precondition; committing with the intent",
			(unsigned long long)dp->i_ino, ndef,
			list_count_nodes(&tp->t_dfops));
	if (dp->i_af.if_format != XFS_DINODE_FMT_LOCAL)
		xfs_alert(dp->i_mount,
			"MXFS P-DIRSHARD-LOCATOR-FORK parent=%llu format=%d after the add — the locator did not land shortform; committing as is",
			(unsigned long long)dp->i_ino, (int)dp->i_af.if_format);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Holder inode and manifest block access
 * ------------------------------------------------------------------------ */

/*
 * Map fsblock 0 of the holder.  The holder must be ILOCKed by the caller.
 * Exactly one real extent of one block is legal; anything else is
 * corruption (ruling: fixed size, no holes/COW/shared).
 */
static int
mxfs_dirshard_holder_daddr(
	struct xfs_inode	*holder,
	xfs_daddr_t		*daddrp)
{
	struct xfs_bmbt_irec	map;
	int			nmaps = 1;
	int			error;

	error = xfs_bmapi_read(holder, 0, 1, &map, &nmaps, 0);
	if (error)
		return error;
	if (nmaps != 1 || !xfs_bmap_is_real_extent(&map) ||
	    map.br_blockcount != 1)
		return -EFSCORRUPTED;
	*daddrp = XFS_FSB_TO_DADDR(holder->i_mount, map.br_startblock);
	return 0;
}

/*
 * Read the manifest block, locked and (if @tp) joined to the transaction.
 * The buffer verifier already validated magic/crc/uuid/blkno/lsn; the
 * reciprocal identity and the manifest structure are checked here against
 * the parent and holder the caller resolved.
 */
static int
mxfs_dirshard_blk_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	struct xfs_inode	*holder,
	xfs_daddr_t		daddr,
	struct xfs_buf		**bpp,
	struct mxfs_dirshard_view *view)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_buf		*bp;
	enum mxfs_dirshard_check c;
	int			error;

	error = xfs_trans_read_buf(mp, tp, mp->m_ddev_targp, daddr,
				   XFS_FSB_TO_BB(mp, 1), 0, &bp,
				   &mxfs_dirshard_buf_ops);
	if (error)
		return error;
	c = mxfs_dirshard_blk_check(bp->b_addr, mp->m_sb.sb_blocksize,
				    holder->i_ino, mxfs_dirshard_igen(holder),
				    dp->i_ino, mxfs_dirshard_igen(dp), 1, view);
	if (c != MXFS_DSC_OK) {
		mxfs_dirshard_corrupt(dp, "manifest-block", c, daddr);
		xfs_trans_brelse(tp, bp);
		return -EFSCORRUPTED;
	}
	*bpp = bp;
	return 0;
}

static inline struct mxfs_dirshard_manifest *
mxfs_dirshard_blk_manifest(
	struct xfs_buf		*bp)
{
	return (struct mxfs_dirshard_manifest *)
		((char *)bp->b_addr + MXFS_DIRSHARD_BLK_HDR_LEN);
}

/* Bump mgen and log the whole formatted region of the block. */
static void
mxfs_dirshard_blk_log(
	struct xfs_trans	*tp,
	struct xfs_buf		*bp)
{
	struct mxfs_dirshard_blk *blk = bp->b_addr;
	struct mxfs_dirshard_manifest *m = mxfs_dirshard_blk_manifest(bp);
	uint32_t		mgen = be32_to_cpu(m->mgen) + 1;

	if (mgen == 0)
		mgen = 1;		/* never zero: zero means "unwritten" */
	m->mgen = cpu_to_be32(mgen);
	xfs_trans_buf_set_type(tp, bp, XFS_BLFT_MXFS_DIRSHARD_BUF);
	xfs_trans_log_buf(tp, bp, 0,
			  MXFS_DIRSHARD_BLK_HDR_LEN + be32_to_cpu(blk->bytes) - 1);
}

/* ------------------------------------------------------------------------ *
 * Internal iget with identity validation
 * ------------------------------------------------------------------------ */

/*
 * Never called on an inode number that did not come from a validated locator
 * or manifest.
 *
 * sess470 (0.64.11): this was an XFS_IGET_UNTRUSTED iget "so a manifest
 * naming a freed/never-allocated number fails instead of instantiating
 * garbage".  On MXFS that flag is wrong: xfs_imap_lookup answers it from the
 * inobt read WITHOUT the AG DLM lock, i.e. from whatever AGI/inobt image this
 * node last cached, and a peer's allocation of the number is invisible there
 * until this node next takes the AG.  chain 103 (0.64.6, stage-1 selftest
 * 14:11Z): the peer's every readdir/lookup/create in a freshly published
 * sharded dir returned a bare -EINVAL (xfs_imap_lookup's "untrusted and
 * free"), and — worse — mxfs_dirshard_free_container read that -EINVAL as
 * "already freed", cleared the manifest bit and left container 133 allocated
 * with nlink 2 (chk: "named by no manifest and is not unlinked — leaked
 * internal inode"; parent 131 DELETING valid_mask=0xfffe).
 *
 * A manifest entry is a dirent: a CRC-covered {ino, gen} written by a
 * committed transaction.  It gets the dirent's iget — trusted mapping, then
 * the identity check below.  A freed number returns -ENOENT from xfs_iget
 * (mode 0, and the P-IGET-ENOENT machinery already arbitrates a peer-fresh
 * cluster read for exactly this cross-node case); a reused number fails the
 * {gen, CONTAINER flag, nlink} check.  Garbage numbers cannot come from a
 * verified manifest; if one ever does, the inode cluster verifier refuses it
 * loudly as the corruption it is.
 *
 * Returns -ESTALE when the number now names a different inode (the
 * "stranger" case) so the deletion path can tell "already gone" from a real
 * failure; every ordinary caller goes through mxfs_dirshard_iget, which
 * folds that into -EFSCORRUPTED (a live manifest naming a stranger IS
 * corruption).
 */
/*
 * sess473 (D-0533, chain 113 on 0.64.18): the iget above is lock-less, so a
 * member number this node still has CACHED from a previous incarnation comes
 * back as a cache HIT — no inode DLM acquire, no stale reload — and its old
 * generation is compared against the manifest.  Measured on the peer
 * (stage-1 N=64): 'P-DIRSHARD-STRANGER ino=268435584 want_gen=3559689165
 * have_gen=50462169' x8, where have_gen is the generation of the 16-shard
 * PARENT that number carried before the creator's rmdir freed it and the
 * next mkdir reused it as a container; the peer had cached that parent under
 * a PR grant and released it before the free, so nothing ever BASTed the
 * shell (i_dlm_stale clear) and xfs_iget_cache_hit had no reason to reload.
 * -ESTALE x8 -> -EFSCORRUPTED -> 'ls: Structure needs cleaning' on a healthy
 * directory.  On the deletion path the same stale shell would read as
 * "already gone" and the manifest bit would be cleared over a LIVE container
 * (the D-0526 leak shape).
 *
 * The manifest entry is a stronger identity than a dirent (it carries the
 * generation), so the arbitration is exact: FUA-read the platter's dinode.
 * If the platter carries the wanted generation, OUR shell is the stale one
 * — adopt the live incarnation in place (the xfs_lookup P95-SAMETYPE-RELOAD
 * discipline: arm i_dlm_stale, mxfs_dlm_reload_inode, bounded retry until
 * it lands; expect_ftype lets a REG->DIR / DIR->REG reuse through the
 * typeflip guard the way a dirent ftype does).  If the platter does not
 * carry it either, the member really is gone and the caller's identity
 * check rules; a creator that has not flushed yet (Type A) is BASTed once
 * via a PR acquire before that verdict.  Match case: zero extra I/O.
 */
/*
 * Design-consult review of the first cut (sess473) — what this shape now honours:
 *  - "adopted" requires the stale flag CLEAR, the generation equal AND the
 *    type equal to expect_ftype (a bailed trylock reload could otherwise
 *    report a half-adopted shell as converged);
 *  - the wait is SHORT (20 x 10 ms) when the caller is inside a transaction
 *    (current->journal_info — log reservation held) or on the teardown path
 *    (parent ILOCK_EXCL + EX held from inactivation); the reader paths get
 *    the lookup path's 200 x 10 ms;
 *  - a platter that holds a LIVE inode of a DIFFERENT generation is never
 *    "gone": a live manifest naming a stranger is corruption for a reader
 *    (-EFSCORRUPTED, the existing P-DIRSHARD-STRANGER verdict) and the
 *    deletion path fails CLOSED on it (any error other than -ENOENT/-ESTALE
 *    leaves the set on the unlinked list) — only a platter that reads FREE
 *    (mode 0) after the forced flush is "gone";
 *  - an unconverged shell is -EBUSY here; mxfs_dirshard_iget turns that into
 *    -ESTALE for readers (the revalidate-and-retry contract xfs_lookup uses
 *    for an unresolved reuse), never EBUSY out of getdents, and the deletion
 *    path keeps the set.
 * Left as documented hazards (tree-wide, not this fix): the in-place reload
 * of a referenced shell is the tree's established same-type reuse discipline
 * (xfs_lookup P95-SAMETYPE-RELOAD); the reload's own serialization is the
 * trylock + bail contract every caller of mxfs_dlm_reload_inode relies on.
 *
 * Returns 0 with the in-core gen == manifest gen (adopted, or it already
 * matched by the time we looked); 0 with the platter FREE (the caller's
 * identity check then yields -ESTALE = gone); -EFSCORRUPTED (platter live,
 * other gen); -EBUSY (would not converge); -EIO (platter unreadable).
 */
static int
mxfs_dirshard_probe_revalidate(
	struct xfs_mount	*mp,
	struct xfs_inode	*owner,
	struct xfs_inode	*ip,
	uint32_t		gen,
	uint8_t			expect_ftype,
	bool			teardown)
{
	uint16_t		dmode = 0;
	uint32_t		dgen = 0;
	uint64_t		dsz;
	uint32_t		have_gen = mxfs_dirshard_igen(ip);
	int			rounds = 0;
	int			max_rounds;
	bool			flushed = false;
	bool			in_trans = current->journal_info != NULL;
	extern uint64_t		mxfs_inode_disk_di_size(struct xfs_inode *,
							uint16_t *, uint32_t *);
	extern void		mxfs_dlm_force_peer_flush(struct xfs_inode *);

	dsz = mxfs_inode_disk_di_size(ip, &dmode, &dgen);
	if (dsz != (uint64_t)-1 && dgen != gen) {
		/* the creator may still hold the new dinode unflushed under a
		 * sticky EX: a PR acquire BASTs it into draining (Invariant 1:
		 * the releaser drains its inode buffers before the unlock), then
		 * re-read */
		mxfs_dlm_force_peer_flush(ip);
		flushed = true;
		dmode = 0;
		dgen = 0;
		dsz = mxfs_inode_disk_di_size(ip, &dmode, &dgen);
	}
	/*
	 * Review item 8: the helper reports a failed read (I/O error, bad
	 * magic) as dsz == -1 with dmode left 0 — which the "platter FREE"
	 * verdict below would read as GONE and the deletion path would clear
	 * the bit over a live container.  A read failure is -EIO: never gone,
	 * never adopted; the deletion path keeps the set.
	 */
	if (dsz == (uint64_t)-1) {
		xfs_alert(mp,
			"MXFS P-DIRSHARD-SHELL-READFAIL owner=%llu ino=%llu want_gen=%u have_gen=%u flushed=%d — platter dinode unreadable; refusing (EIO, never 'gone')",
			(unsigned long long)owner->i_ino,
			(unsigned long long)ip->i_ino, gen, have_gen, flushed ? 1 : 0);
		return -EIO;
	}
	xfs_notice(mp,
		"MXFS P-DIRSHARD-SHELL owner=%llu ino=%llu want_gen=%u have_gen=%u disk_gen=%u disk_mode=0%o incore_mode=0%o nlink=%u dlm_mode=%u stale=%d src=%u i_count=%d flushed=%d teardown=%d in_trans=%d — cached shell disagrees with the manifest",
		(unsigned long long)owner->i_ino, (unsigned long long)ip->i_ino,
		gen, have_gen, dgen, dmode, VFS_I(ip)->i_mode,
		VFS_I(ip)->i_nlink, ip->i_dlm_mode, ip->i_dlm_stale ? 1 : 0,
		ip->i_dlm_stale_src, atomic_read(&VFS_I(ip)->i_count),
		flushed ? 1 : 0, teardown ? 1 : 0, in_trans ? 1 : 0);
	if (dmode == 0)
		return 0;	/* platter FREE: the member is gone */
	if (dgen != gen) {
		xfs_alert(mp,
			"MXFS P-DIRSHARD-STRANGER-LIVE owner=%llu ino=%llu want_gen=%u have_gen=%u disk_gen=%u disk_mode=0%o — platter holds a LIVE inode of another generation under a live manifest entry; refusing (never 'gone')",
			(unsigned long long)owner->i_ino,
			(unsigned long long)ip->i_ino, gen, have_gen, dgen, dmode);
		return -EFSCORRUPTED;
	}

	max_rounds = (teardown || in_trans) ? 20 : 200;
	while (rounds++ < max_rounds && !xfs_is_shutdown(mp)) {
		ip->i_dlm_stale = true;
		ip->i_dlm_stale_src = 28;	/* dirshard probe: platter carries the manifest's gen */
		mxfs_dlm_reload_inode(ip, expect_ftype, false);
		if (!ip->i_dlm_stale && mxfs_dirshard_igen(ip) == gen &&
		    xfs_mode_to_ftype(VFS_I(ip)->i_mode) == expect_ftype)
			break;
		msleep(10);
	}
	if (!ip->i_dlm_stale && mxfs_dirshard_igen(ip) == gen &&
	    xfs_mode_to_ftype(VFS_I(ip)->i_mode) == expect_ftype) {
		xfs_notice(mp,
			"MXFS P-DIRSHARD-SHELL-ADOPTED owner=%llu ino=%llu gen=%u (was %u) rounds=%d mode=0%o nlink=%u flags2=0x%llx",
			(unsigned long long)owner->i_ino,
			(unsigned long long)ip->i_ino, gen, have_gen, rounds,
			VFS_I(ip)->i_mode, VFS_I(ip)->i_nlink,
			(unsigned long long)ip->i_diflags2);
		return 0;
	}
	/*
	 * The platter names the manifest's incarnation but our shell would not
	 * take it (every reload bailed, or the typeflip guard kept the old
	 * type).  Neither "gone" nor corruption: transient, fail closed.
	 */
	xfs_alert(mp,
		"MXFS P-DIRSHARD-SHELL-UNCONVERGED owner=%llu ino=%llu want_gen=%u have_gen=%u disk_gen=%u rounds=%d/%d stale=%d incore_mode=0%o disk_mode=0%o — stale shell would not adopt; refusing (EBUSY)",
		(unsigned long long)owner->i_ino, (unsigned long long)ip->i_ino,
		gen, mxfs_dirshard_igen(ip), dgen, rounds, max_rounds,
		ip->i_dlm_stale ? 1 : 0, VFS_I(ip)->i_mode, dmode);
	return -EBUSY;
}

static int
mxfs_dirshard_iget_probe(
	struct xfs_mount	*mp,
	struct xfs_inode	*owner,
	uint64_t		ino,
	uint32_t		gen,
	uint8_t			expect_ftype,
	bool			teardown,
	struct xfs_inode	**ipp)
{
	struct xfs_inode	*ip;
	int			error;

	error = xfs_iget(mp, NULL, ino, 0, 0, &ip);
	if (error) {
		if (error != -ENOENT)
			xfs_alert_ratelimited(mp,
				"MXFS P-DIRSHARD-IGET-FAIL owner=%llu ino=%llu want_gen=%u err=%d",
				(unsigned long long)owner->i_ino,
				(unsigned long long)ino, gen, error);
		return error;
	}
	if (mxfs_dirshard_igen(ip) != gen && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		error = mxfs_dirshard_probe_revalidate(mp, owner, ip, gen,
						       expect_ftype, teardown);
		if (error) {
			xfs_irele(ip);
			return error;
		}
	}
	/*
	 * Identity.  Two answers, ruled apart by the sess470 design-consult review:
	 *  - a different generation, or our generation with nlink 0: the
	 *    member this manifest named is GONE (freed and reused, or already
	 *    on an unlinked list where the sweep frees it) -> -ESTALE;
	 *  - our generation, still linked, but the flags contradict the
	 *    manifest (not a CONTAINER, or a PARENT): a LIVE inode with
	 *    damaged metadata.  Never "gone" — clearing a manifest bit over it
	 *    is exactly the leak the -EINVAL misreading produced -> -EFSCORRUPTED.
	 */
	if (mxfs_dirshard_igen(ip) != gen || VFS_I(ip)->i_nlink == 0) {
		xfs_notice(mp,
			"MXFS P-DIRSHARD-STRANGER owner=%llu ino=%llu want_gen=%u have_gen=%u nlink=%u flags2=0x%llx mode=0%o — member gone",
			(unsigned long long)owner->i_ino,
			(unsigned long long)ino, gen, mxfs_dirshard_igen(ip),
			VFS_I(ip)->i_nlink, (unsigned long long)ip->i_diflags2,
			VFS_I(ip)->i_mode);
		xfs_irele(ip);
		return -ESTALE;
	}
	if (!mxfs_is_dirshard_container(ip) || mxfs_is_dirshard_parent(ip)) {
		xfs_alert(mp,
			"MXFS P-DIRSHARD-STRANGER owner=%llu ino=%llu gen=%u nlink=%u flags2=0x%llx mode=0%o — live inode contradicts the manifest (not a container); refusing",
			(unsigned long long)owner->i_ino,
			(unsigned long long)ino, gen, VFS_I(ip)->i_nlink,
			(unsigned long long)ip->i_diflags2, VFS_I(ip)->i_mode);
		xfs_irele(ip);
		return -EFSCORRUPTED;
	}
	*ipp = ip;
	return 0;
}

int
mxfs_dirshard_iget(
	struct xfs_mount	*mp,
	struct xfs_inode	*owner,
	uint64_t		ino,
	uint32_t		gen,
	uint8_t			expect_ftype,
	struct xfs_inode	**ipp)
{
	int			error;

	error = mxfs_dirshard_iget_probe(mp, owner, ino, gen, expect_ftype,
					 false, ipp);
	if (error == -ESTALE)
		return -EFSCORRUPTED;
	if (error == -EBUSY)	/* sess473: unconverged stale shell -> revalidate-and-retry */
		return -ESTALE;
	return error;
}

/* The deletion path's "is this member already gone?" reading of a probe. */
static inline bool
mxfs_dirshard_iget_gone(
	int			error)
{
	return error == -ENOENT || error == -ESTALE;
}

/* ------------------------------------------------------------------------ *
 * Manifest load under the pin (+ per-parent cache)
 * ------------------------------------------------------------------------ */

/*
 * The cache lives on the parent (ip->i_mxfs_dirshard) and is valid for one
 * (parent generation, mgen) pair.  Ordinary operations hold the pin (parent
 * PR) while they use it; every mutation runs under the parent EX and
 * invalidates it, so no pin holder can observe a stale table.  Cross-node:
 * a peer's EX barrier BASTs our PR away, and the cache is dropped with the
 * grant (mxfs_dirshard_cache_drop, called from the inode DLM release path).
 */
void
mxfs_dirshard_cache_drop(
	struct xfs_inode	*dp)
{
	struct mxfs_dirshard_cache *c = dp->i_mxfs_dirshard;

	if (c)
		c->valid = false;
}

static int
mxfs_dirshard_cache_get(
	struct xfs_inode	*dp,
	struct mxfs_dirshard_cache **cp)
{
	struct mxfs_dirshard_cache *c = dp->i_mxfs_dirshard;

	if (!c) {
		c = kzalloc(sizeof(*c), GFP_KERNEL);
		if (!c)
			return -ENOMEM;
		/* one winner; the parent ILOCK (shared or excl) is held, so a
		 * racing allocator is another pin holder — cmpxchg decides */
		if (cmpxchg(&dp->i_mxfs_dirshard, NULL, c) != NULL) {
			kfree(c);
			c = dp->i_mxfs_dirshard;
		}
	}
	*cp = c;
	return 0;
}

/*
 * sess473 (D-0534, chain 115 on 0.64.20): the manifest block is a plain
 * metadata buffer keyed by daddr.  A peer that cached the PREVIOUS set's
 * block at this address (holder freed, a new holder's one-block extent landed
 * on the same fsblock) gets a buffer-cache HIT — XBF_DONE, never invalidated,
 * because a REG holder's data buffer belongs to no inode-DLM release drain —
 * and the verifier refuses it on the holder generation ('manifest-block
 * reason=blk_owner aux=<daddr>' x100 on the peer, EUCLEAN for every listing
 * of a dir whose holder reused a block).  Within one set's life the same hit
 * would serve an OLDER mgen of the right block to a node that just took the
 * parent EX after a peer's mutations — a lost update.  So every read that
 * starts from the holder's bmap (the slow manifest load, which runs exactly
 * when the per-parent cache is invalid: first load, parent incarnation
 * change, grant handoff; and the parent's inactivation walk) is a coherency
 * point: stale a clean cached copy so xfs_trans_read_buf reads the platter;
 * keep one that carries this node's own uncheckpointed modification (we hold
 * the EX and wrote it — the P91-RECYCLE-PROTECT rule from xfs_iget_recycle).
 */
static void
mxfs_dirshard_blk_refresh(
	struct xfs_inode	*dp,
	struct xfs_inode	*holder,
	xfs_daddr_t		daddr)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_buf		*sbp = NULL;

	if (xfs_buf_incore(mp->m_ddev_targp, daddr, XFS_FSB_TO_BB(mp, 1), 0,
			   &sbp) != 0)
		return;
	if (mxfs_buf_has_uncheckpointed_mods(sbp)) {
		xfs_notice(mp,
			"MXFS P-DIRSHARD-BLK-KEEP parent=%llu holder=%llu daddr=%lld flags=0x%x — cached manifest block carries our uncheckpointed modification; keeping",
			(unsigned long long)dp->i_ino,
			(unsigned long long)holder->i_ino,
			(long long)daddr, sbp->b_flags);
	} else {
		xfs_notice(mp,
			"MXFS P-DIRSHARD-BLK-REFRESH parent=%llu gen=%u holder=%llu hgen=%u daddr=%lld flags=0x%x — staling the cached manifest block for a fresh read",
			(unsigned long long)dp->i_ino, mxfs_dirshard_igen(dp),
			(unsigned long long)holder->i_ino,
			mxfs_dirshard_igen(holder),
			(long long)daddr, sbp->b_flags);
		xfs_buf_stale(sbp);
		sbp->b_flags &= ~XBF_DONE;
	}
	xfs_buf_relse(sbp);
}

/*
 * Slow path: locator -> holder -> block.  Locks the holder ILOCK_SHARED
 * (lock order 2) only for the bmap, then reads the block.
 */
static int
mxfs_dirshard_manifest_load_slow(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	struct xfs_inode	**holderp,
	xfs_daddr_t		*daddrp,
	struct xfs_buf		**bpp,
	struct mxfs_dirshard_view *view)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_inode	*holder;
	uint64_t		hino;
	uint32_t		hgen;
	xfs_daddr_t		daddr;
	int			error;

	error = mxfs_dirshard_locator_get(dp, &hino, &hgen);
	if (error == -ENOENT) {
		mxfs_dirshard_corrupt(dp, "locator-missing", MXFS_DSC_SHORT, 0);
		return -EFSCORRUPTED;
	}
	if (error) {
		xfs_alert_ratelimited(mp,
			"MXFS P-DIRSHARD-LOAD-FAIL parent=%llu step=locator err=%d",
			(unsigned long long)dp->i_ino, error);
		return error;
	}
	error = mxfs_dirshard_iget(mp, dp, hino, hgen, XFS_DIR3_FT_REG_FILE,
				   &holder);
	if (error) {
		xfs_alert_ratelimited(mp,
			"MXFS P-DIRSHARD-LOAD-FAIL parent=%llu step=holder-iget hino=%llu hgen=%u err=%d",
			(unsigned long long)dp->i_ino, (unsigned long long)hino,
			hgen, error);
		return error;
	}
	if (!S_ISREG(VFS_I(holder)->i_mode)) {
		xfs_irele(holder);
		mxfs_dirshard_corrupt(dp, "holder-not-reg", MXFS_DSC_BLK_OWNER,
				      hino);
		return -EFSCORRUPTED;
	}
	xfs_ilock(holder, XFS_ILOCK_SHARED);
	error = mxfs_dirshard_holder_daddr(holder, &daddr);
	xfs_iunlock(holder, XFS_ILOCK_SHARED);
	if (error) {
		xfs_irele(holder);
		if (error == -EFSCORRUPTED)
			mxfs_dirshard_corrupt(dp, "holder-bmap",
					      MXFS_DSC_BLK_BYTES, hino);
		else
			xfs_alert_ratelimited(mp,
				"MXFS P-DIRSHARD-LOAD-FAIL parent=%llu step=holder-daddr hino=%llu err=%d",
				(unsigned long long)dp->i_ino,
				(unsigned long long)hino, error);
		return error;
	}
	mxfs_dirshard_blk_refresh(dp, holder, daddr);
	error = mxfs_dirshard_blk_read(tp, dp, holder, daddr, bpp, view);
	if (error) {
		xfs_irele(holder);
		if (error != -EFSCORRUPTED)
			xfs_alert_ratelimited(mp,
				"MXFS P-DIRSHARD-LOAD-FAIL parent=%llu step=blk-read daddr=%lld err=%d",
				(unsigned long long)dp->i_ino, (long long)daddr,
				error);
		return error;
	}
	*holderp = holder;
	*daddrp = daddr;
	return 0;
}

/*
 * mxfs_dirshard_manifest_load — fill @view from the cache or from disk.
 * Caller holds the parent ILOCK (shared = pin, exclusive = barrier).
 */
int
mxfs_dirshard_manifest_load(
	struct xfs_inode	*dp,
	struct mxfs_dirshard_view *view)
{
	struct mxfs_dirshard_cache *c;
	struct xfs_inode	*holder;
	struct xfs_buf		*bp;
	xfs_daddr_t		daddr;
	int			error;

	xfs_assert_ilocked(dp, XFS_ILOCK_SHARED | XFS_ILOCK_EXCL);
	if (!mxfs_is_dirshard_parent(dp))
		return -EINVAL;

	error = mxfs_dirshard_cache_get(dp, &c);
	if (error)
		return error;
	/*
	 * i_dlm_epoch is stable while the caller holds the ILOCK (the grant
	 * is held, so this node cannot be losing it), and it bumps on every
	 * release/stale (xfs_mxfs_dlm.c: "grant lost — invalidate
	 * epoch-stamped dentries").  A peer's barrier EX therefore invalidates
	 * this table exactly as it invalidates the dentries: no hook in the
	 * release path itself is needed.
	 */
	if (c->valid && c->gen == mxfs_dirshard_igen(dp) &&
	    c->dlm_epoch == dp->i_dlm_epoch) {
		*view = c->view;
		return 0;
	}
	error = mxfs_dirshard_manifest_load_slow(NULL, dp, &holder, &daddr,
						 &bp, view);
	if (error)
		return error;
	xfs_buf_relse(bp);
	c->view = *view;
	c->gen = mxfs_dirshard_igen(dp);
	c->dlm_epoch = dp->i_dlm_epoch;
	c->holder_ino = holder->i_ino;
	c->daddr = daddr;
	c->valid = true;
	xfs_irele(holder);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Routing
 * ------------------------------------------------------------------------ */

/*
 * SipHash-2-4 over the exact name bytes under the per-directory key.  The
 * key bytes are consumed as two little-endian u64s (k0 = bytes 0-7, k1 =
 * bytes 8-15), the reference-implementation convention chk_mxfs mirrors.
 */
uint64_t
mxfs_dirshard_hash(
	const struct mxfs_dirshard_view *v,
	const unsigned char	*name,
	unsigned int		len)
{
	siphash_key_t		key;

	key.key[0] = get_unaligned_le64(v->hash_key);
	key.key[1] = get_unaligned_le64(v->hash_key + 8);
	return siphash(name, len, &key);
}

int
mxfs_dirshard_resolve(
	struct xfs_inode	*dp,
	const struct xfs_name	*name,
	struct xfs_inode	**shardp,
	unsigned int		*indexp)
{
	struct mxfs_dirshard_view v;
	unsigned int		idx;
	int			error;

	error = mxfs_dirshard_manifest_load(dp, &v);
	if (error)
		return error;
	if (v.state != MXFS_DIRSHARD_ST_PUBLISHED)
		return -EOPNOTSUPP;
	idx = mxfs_dirshard_index(mxfs_dirshard_hash(&v, name->name, name->len),
				  v.nshards);
	if (!(v.valid_mask & (1ULL << idx))) {
		mxfs_dirshard_corrupt(dp, "shard-not-live", MXFS_DSC_VALID_MASK,
				      idx);
		return -EFSCORRUPTED;
	}
	error = mxfs_dirshard_iget(dp->i_mount, dp, v.shard[idx].ino,
				   v.shard[idx].gen, XFS_DIR3_FT_DIR, shardp);
	if (error)
		return error;
	if (!S_ISDIR(VFS_I(*shardp)->i_mode)) {
		xfs_irele(*shardp);
		mxfs_dirshard_corrupt(dp, "shard-not-dir", MXFS_DSC_ENTRY_ZERO,
				      idx);
		return -EFSCORRUPTED;
	}
	if (indexp)
		*indexp = idx;
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Lifecycle: allocation (step A), containers (step B), publication (step C)
 * ------------------------------------------------------------------------ */

/*
 * Space reservation for step A: two inodes (parent, holder), one data block
 * for the holder plus its bmap, the locator (shortform, no blocks).
 */
static unsigned int
mxfs_dirshard_stepa_space_res(
	struct xfs_mount	*mp)
{
	return 2 * XFS_IALLOC_SPACE_RES(mp) +
	       XFS_DIOSTRAT_SPACE_RES(mp, 1);
}

/*
 * Format a fresh manifest block image: ALLOCATING, zero entries, random key
 * and set uuid, mgen 1.
 */
static void
mxfs_dirshard_blk_init(
	struct xfs_mount	*mp,
	struct xfs_buf		*bp,
	struct xfs_inode	*dp,
	struct xfs_inode	*holder,
	unsigned int		nshards)
{
	struct mxfs_dirshard_blk *blk = bp->b_addr;
	struct mxfs_dirshard_manifest *m;
	uint32_t		bytes = MXFS_DIRSHARD_MANIFEST_LEN(nshards);

	memset(bp->b_addr, 0, BBTOB(bp->b_length));
	blk->magic = cpu_to_be32(MXFS_DIRSHARD_BLK_MAGIC);
	blk->offset = 0;
	blk->bytes = cpu_to_be32(bytes);
	uuid_copy((uuid_t *)blk->uuid, &mp->m_sb.sb_meta_uuid);
	blk->owner = cpu_to_be64(holder->i_ino);
	blk->blkno = cpu_to_be64(xfs_buf_daddr(bp));
	blk->parent_ino = cpu_to_be64(dp->i_ino);
	blk->parent_gen = cpu_to_be32(mxfs_dirshard_igen(dp));
	blk->holder_gen = cpu_to_be32(mxfs_dirshard_igen(holder));

	m = mxfs_dirshard_blk_manifest(bp);
	m->magic = cpu_to_be32(MXFS_DIRSHARD_MANIFEST_MAGIC);
	m->version = cpu_to_be16(MXFS_DIRSHARD_MANIFEST_VERSION);
	m->hash_id = cpu_to_be16(MXFS_DIRSHARD_HASH_SIPHASH24);
	m->length = cpu_to_be32(bytes);
	m->mgen = cpu_to_be32(0);		/* blk_log bumps to 1 */
	m->nshards = cpu_to_be16(nshards);
	m->state = cpu_to_be16(MXFS_DIRSHARD_ST_ALLOCATING);
	m->name_canon_version = cpu_to_be16(MXFS_DIRSHARD_CANON_EXACT);
	m->nentries = 0;
	do {
		get_random_bytes(m->hash_key, sizeof(m->hash_key));
	} while (!memchr_inv(m->hash_key, 0, sizeof(m->hash_key)));
	generate_random_uuid(m->set_uuid);
	m->parent_ino = cpu_to_be64(dp->i_ino);
	m->parent_gen = cpu_to_be32(mxfs_dirshard_igen(dp));
	m->valid_mask = 0;
}

/*
 * Step A: one transaction (modulo xfs_dialloc's own chunk roll, which
 * precedes every dirtying of ours) that leaves either nothing or a
 * complete ALLOCATING set anchor: unlinked PARENT directory with its
 * locator + holder inode + initialised manifest block.
 */
static int
mxfs_dirshard_alloc_parent(
	struct mnt_idmap	*idmap,
	struct xfs_inode	*dp,
	umode_t			mode,
	unsigned int		nshards,
	struct xfs_inode	**parentp,
	struct xfs_inode	**holderp)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_icreate_args	pargs = {
		.idmap		= idmap,
		.pip		= dp,
		.mode		= S_IFDIR | (mode & ~S_IFMT),
		.flags		= XFS_ICREATE_TMPFILE | XFS_ICREATE_INIT_XATTRS,
	};
	struct xfs_icreate_args	hargs = {
		.idmap		= idmap,
		.pip		= dp,
		.mode		= S_IFREG,
		.flags		= XFS_ICREATE_UNLINKABLE,
	};
	struct xfs_dquot	*udqp, *gdqp, *pdqp;
	struct xfs_inode	*parent = NULL, *holder = NULL;
	struct xfs_trans	*tp;
	struct xfs_bmbt_irec	map;
	struct xfs_buf		*bp;
	xfs_ino_t		ino;
	unsigned int		resblks;
	int			nmaps = 1;
	int			error;

	error = xfs_icreate_dqalloc(&pargs, &udqp, &gdqp, &pdqp);
	if (error)
		return error;

	resblks = mxfs_dirshard_stepa_space_res(mp);
	error = xfs_trans_alloc_icreate(mp, &M_RES(mp)->tr_mkdir, udqp, gdqp,
					pdqp, resblks, &tp);
	if (error)
		goto out_dqrele;

	/* the parent first: the only thing a later dialloc roll can leave
	 * committed alone is an unlinked PARENT dir, which is reapable */
	error = xfs_dialloc(&tp, &pargs, &ino);
	if (!error)
		error = xfs_icreate(tp, ino, &pargs, &parent);
	if (error)
		goto out_cancel;
	xfs_qm_vop_create_dqattach(tp, parent, udqp, gdqp, pdqp);
	parent->i_diflags2 |= MXFS_DIFLAG2_DIRSHARD_PARENT;
	xfs_trans_log_inode(tp, parent, XFS_ILOG_CORE);
	error = xfs_dir_init(tp, parent, dp);
	if (error)
		goto out_cancel;
	error = xfs_iunlink(tp, parent);
	if (error)
		goto out_cancel;
	xfs_iflags_set(parent, MXFS_IF_LOCAL_UNLINK);

	/* the holder */
	error = xfs_dialloc(&tp, &hargs, &ino);
	if (!error)
		error = xfs_icreate(tp, ino, &hargs, &holder);
	if (error)
		goto out_cancel;
	holder->i_diflags2 |= MXFS_DIFLAG2_DIRSHARD_CONTAINER;
	xfs_trans_log_inode(tp, holder, XFS_ILOG_CORE);

	/* its one block, formatted and logged in this transaction */
	error = xfs_bmapi_write(tp, holder, 0, 1, XFS_BMAPI_METADATA, resblks,
				&map, &nmaps);
	if (error)
		goto out_cancel;
	if (nmaps != 1 || !xfs_bmap_is_real_extent(&map)) {
		error = -EFSCORRUPTED;
		goto out_cancel;
	}
	holder->i_disk_size = mp->m_sb.sb_blocksize;
	xfs_trans_log_inode(tp, holder, XFS_ILOG_CORE);
	error = xfs_trans_get_buf(tp, mp->m_ddev_targp,
				  XFS_FSB_TO_DADDR(mp, map.br_startblock),
				  XFS_FSB_TO_BB(mp, 1), 0, &bp);
	if (error)
		goto out_cancel;
	bp->b_ops = &mxfs_dirshard_buf_ops;
	mxfs_dirshard_blk_init(mp, bp, parent, holder, nshards);
	mxfs_dirshard_blk_log(tp, bp);

	/* the locator, inline, last */
	error = mxfs_dirshard_locator_set(tp, parent, holder);
	if (error)
		goto out_cancel;

	if (xfs_has_wsync(mp))
		xfs_trans_set_sync(tp);
	error = xfs_trans_commit(tp);
	if (error)
		goto out_release;

	xfs_qm_dqrele(udqp);
	xfs_qm_dqrele(gdqp);
	xfs_qm_dqrele(pdqp);
	xfs_iunlock(parent, XFS_ILOCK_EXCL);
	xfs_iunlock(holder, XFS_ILOCK_EXCL);
	/*
	 * Neither inode ever gets a dentry through this path (the parent is
	 * published by name later, the holder never), so finish the VFS
	 * setup here: clears I_NEW, which every later iget of these numbers
	 * (resolver, inactivation) would otherwise block on.
	 *
	 * sess470 (0.64.11, chain 103 stage-1 on 0.64.6): the operation
	 * vtables are NOT installed by xfs_icreate/xfs_inode_init — only
	 * xfs_setup_inode (mode, mapping) is; xfs_generic_create installs
	 * i_op/i_fop itself with xfs_setup_iops before d_instantiate.  This
	 * path skipped that, so the creator's in-core parent kept the VFS's
	 * empty_iops: d_flags_for_inode() saw S_IFDIR with no ->lookup and
	 * typed the dentry DCACHE_AUTODIR_TYPE, and every walk into the
	 * sharded dir, O_DIRECTORY open, mkdir/ln/create under it returned
	 * -ENOTDIR on the node that made it (the peer igets it from disk
	 * through xfs_setup_existing_inode and was never affected).  Same
	 * for the holder and each container: keep every inode this module
	 * instantiates vtable-consistent with its type (the P-RELOAD-IOPS-
	 * REWIRE lesson: a mode/vtable mismatch is a latent -EISDIR/-ENOTDIR).
	 */
	xfs_setup_iops(parent);
	xfs_setup_iops(holder);
	xfs_finish_inode_setup(parent);
	xfs_finish_inode_setup(holder);
	*parentp = parent;
	*holderp = holder;
	return 0;

out_cancel:
	xfs_trans_cancel(tp);
out_release:
	if (holder) {
		xfs_iunlock(holder, XFS_ILOCK_EXCL);
		xfs_setup_iops(holder);
		xfs_finish_inode_setup(holder);
		xfs_irele(holder);
	}
	if (parent) {
		xfs_iunlock(parent, XFS_ILOCK_EXCL);
		xfs_setup_iops(parent);
		xfs_finish_inode_setup(parent);
		xfs_irele(parent);
	}
out_dqrele:
	xfs_qm_dqrele(udqp);
	xfs_qm_dqrele(gdqp);
	xfs_qm_dqrele(pdqp);
	return error;
}

/*
 * Step B: one container per transaction.  Allocate the container directory
 * (UNLINKABLE, CONTAINER flag, ".." = the visible parent, nlink 2 from
 * xfs_inode_init), then append {ino, gen} to the manifest and log the block
 * in the SAME transaction.  The parent is held ILOCK_EXCL (barrier) by the
 * caller across all of step B and C.
 */
static int
mxfs_dirshard_alloc_container(
	struct mnt_idmap	*idmap,
	struct xfs_inode	*parent,
	struct xfs_inode	*holder,
	xfs_daddr_t		daddr,
	unsigned int		index)
{
	struct xfs_mount	*mp = parent->i_mount;
	struct xfs_icreate_args	cargs = {
		.idmap		= idmap,
		.pip		= parent,
		.mode		= S_IFDIR | (VFS_I(parent)->i_mode & ~S_IFMT),
		.flags		= XFS_ICREATE_UNLINKABLE,
	};
	struct mxfs_dirshard_view v;
	struct xfs_inode	*c = NULL;
	struct xfs_trans	*tp;
	struct xfs_buf		*bp;
	struct mxfs_dirshard_manifest *m;
	xfs_ino_t		ino;
	int			error;

	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_mkdir,
				XFS_IALLOC_SPACE_RES(mp), 0, 0, &tp);
	if (error)
		return error;
	error = xfs_dialloc(&tp, &cargs, &ino);
	if (!error)
		error = xfs_icreate(tp, ino, &cargs, &c);
	if (error)
		goto out_cancel;
	c->i_diflags2 |= MXFS_DIFLAG2_DIRSHARD_CONTAINER;
	xfs_trans_log_inode(tp, c, XFS_ILOG_CORE);
	error = xfs_dir_init(tp, c, parent);
	if (error)
		goto out_cancel;

	error = mxfs_dirshard_blk_read(tp, parent, holder, daddr, &bp, &v);
	if (error)
		goto out_cancel;
	if (v.state != MXFS_DIRSHARD_ST_ALLOCATING || v.nentries != index ||
	    index >= v.nshards) {
		mxfs_dirshard_corrupt(parent, "append-state", MXFS_DSC_STATE,
				      index);
		error = -EFSCORRUPTED;
		goto out_cancel;
	}
	m = mxfs_dirshard_blk_manifest(bp);
	m->entries[index].ino = cpu_to_be64(c->i_ino);
	m->entries[index].gen = cpu_to_be32(mxfs_dirshard_igen(c));
	m->entries[index].reserved = 0;
	m->nentries = cpu_to_be16(index + 1);
	m->valid_mask = cpu_to_be64(be64_to_cpu(m->valid_mask) | (1ULL << index));
	if (index + 1 == v.nshards)
		m->state = cpu_to_be16(MXFS_DIRSHARD_ST_COMPLETE);
	mxfs_dirshard_blk_log(tp, bp);

	error = xfs_trans_commit(tp);
	if (error)
		goto out_release;
	xfs_iunlock(c, XFS_ILOCK_EXCL);
	xfs_setup_iops(c);		/* sess470: see mxfs_dirshard_alloc_parent */
	xfs_finish_inode_setup(c);
	xfs_irele(c);		/* referenced again by the resolver on demand */
	return 0;

out_cancel:
	xfs_trans_cancel(tp);
out_release:
	if (c) {
		xfs_iunlock(c, XFS_ILOCK_EXCL);
		xfs_setup_iops(c);
		xfs_finish_inode_setup(c);
		xfs_irele(c);
	}
	return error;
}

/*
 * Step C: publication — one transaction under the grandparent's and the
 * parent's ILOCK_EXCL: dirent in @dp, @dp's nlink for the new "..", parent
 * nlink 0 -> 2, off the AGI unlinked list, manifest COMPLETE -> PUBLISHED.
 * xfs_link refuses directories, so this is a dedicated path; the unlinked
 * removal brackets the AGI with the AG DLM exactly as xfs_dir_add_child does
 * for O_TMPFILE linkat (sess399).
 */
static int
mxfs_dirshard_publish(
	struct xfs_inode	*dp,
	const struct xfs_name	*name,
	struct xfs_inode	*parent,
	struct xfs_inode	*holder,
	xfs_daddr_t		daddr)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct mxfs_dirshard_view v;
	struct xfs_trans	*tp;
	struct xfs_buf		*bp;
	struct xfs_perag	*pag;
	unsigned int		resblks;
	int			error;

	resblks = xfs_mkdir_space_res(mp, name->len);
	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_mkdir, resblks, 0, 0, &tp);
	if (error)
		return error;

	/* mkdir's own order: the directory being modified (PARENT subclass),
	 * then the new child; both are joined without the lock so the
	 * explicit unlocks below stay symmetric on every path */
	xfs_ilock(dp, XFS_ILOCK_EXCL | XFS_ILOCK_PARENT);
	xfs_ilock(parent, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(tp, dp, 0);
	xfs_trans_ijoin(tp, parent, 0);

	error = xfs_dir_canenter(tp, dp, name);
	if (error)
		goto out_cancel;

	error = mxfs_dirshard_blk_read(tp, parent, holder, daddr, &bp, &v);
	if (error)
		goto out_cancel;
	if (v.state != MXFS_DIRSHARD_ST_COMPLETE || v.nentries != v.nshards) {
		mxfs_dirshard_corrupt(parent, "publish-state", MXFS_DSC_STATE,
				      v.state);
		error = -EFSCORRUPTED;
		goto out_cancel;
	}

	error = xfs_dir_createname(tp, dp, name, parent->i_ino, resblks);
	if (error)
		goto out_cancel;
	xfs_trans_ichgtime(tp, dp, XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);
	xfs_trans_log_inode(tp, dp, XFS_ILOG_CORE);
	xfs_bumplink(tp, dp);			/* the new dir's ".." */

	mxfs_set_nlink(parent, 2);
	xfs_trans_ichgtime(tp, parent, XFS_ICHGTIME_CHG);
	xfs_trans_log_inode(tp, parent, XFS_ILOG_CORE);

	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, parent->i_ino));
	error = mxfs_ag_dlm_lock(mp, pag);
	if (!error) {
		error = xfs_iunlink_remove(tp, pag, parent);
		if (error)
			mxfs_ag_dlm_unlock(mp, pag);
		else
			mxfs_ag_dlm_unlock_deferred(tp, pag);
	}
	xfs_perag_put(pag);
	if (error)
		goto out_cancel;
	xfs_iflags_clear(parent, MXFS_IF_LOCAL_UNLINK);

	mxfs_dirshard_blk_manifest(bp)->state =
		cpu_to_be16(MXFS_DIRSHARD_ST_PUBLISHED);
	mxfs_dirshard_blk_log(tp, bp);
	mxfs_dirshard_cache_drop(parent);

	if (xfs_has_wsync(mp))
		xfs_trans_set_sync(tp);
	error = xfs_trans_commit(tp);
	xfs_iunlock(dp, XFS_ILOCK_EXCL);
	xfs_iunlock(parent, XFS_ILOCK_EXCL);
	return error;

out_cancel:
	xfs_trans_cancel(tp);
	xfs_iunlock(dp, XFS_ILOCK_EXCL);
	xfs_iunlock(parent, XFS_ILOCK_EXCL);
	return error;
}

int
mxfs_dirshard_mkdir(
	struct mnt_idmap	*idmap,
	struct xfs_inode	*dp,
	const struct xfs_name	*name,
	umode_t			mode,
	unsigned int		nshards,
	struct xfs_inode	**ipp)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_inode	*parent, *holder;
	xfs_daddr_t		daddr;
	unsigned int		i;
	int			error;

	if (!mxfs_dirshard_enabled(mp))
		return -EOPNOTSUPP;
	if (!mxfs_dirshard_n_valid(nshards))
		return -EINVAL;
	if (mxfs_is_dirshard_parent(dp) || mxfs_is_dirshard_container(dp))
		return -EOPNOTSUPP;	/* no sharded dir inside one (stage 2) */
	if (xfs_is_shutdown(mp))
		return -EIO;

	/* cheap early refusal; the authoritative check is in publish */
	xfs_ilock(dp, XFS_ILOCK_SHARED);
	error = xfs_dir_canenter(NULL, dp, name);
	xfs_iunlock(dp, XFS_ILOCK_SHARED);
	if (error)
		return error;

	error = mxfs_dirshard_alloc_parent(idmap, dp, mode, nshards, &parent,
					   &holder);
	if (error) {
		/*
		 * sess468: step A commits nothing on failure, but a silent
		 * errno (chain 98b's EUCLEAN) cost a rig lap to attribute —
		 * name it.  -ENOSPC/-EDQUOT are ordinary and stay quiet.
		 */
		if (error != -ENOSPC && error != -EDQUOT)
			xfs_alert(mp,
				"MXFS P-DIRSHARD-STEPA-FAIL dir=%llu name=%.*s nshards=%u err=%d — set anchor not created (nothing committed)",
				(unsigned long long)dp->i_ino, name->len,
				name->name, nshards, error);
		return error;
	}

	xfs_ilock(holder, XFS_ILOCK_SHARED);
	error = mxfs_dirshard_holder_daddr(holder, &daddr);
	xfs_iunlock(holder, XFS_ILOCK_SHARED);
	if (error)
		goto out_abandon;

	/* barrier on the new parent for the whole of step B */
	xfs_ilock(parent, XFS_ILOCK_EXCL);
	for (i = 0; i < nshards; i++) {
		error = mxfs_dirshard_alloc_container(idmap, parent, holder,
						      daddr, i);
		if (error) {
			xfs_iunlock(parent, XFS_ILOCK_EXCL);
			goto out_abandon;
		}
	}
	xfs_iunlock(parent, XFS_ILOCK_EXCL);

	error = mxfs_dirshard_publish(dp, name, parent, holder, daddr);
	if (error)
		goto out_abandon;

	xfs_irele(holder);
	*ipp = parent;
	return 0;

out_abandon:
	/*
	 * The set is anchored on the unlinked list by the parent; releasing
	 * our reference runs the shard-aware inactivation, which frees the
	 * containers, the holder and the parent — or, if we die first, a
	 * survivor's unlinked-bucket sweep does the same.
	 */
	xfs_alert(mp,
		"MXFS P-DIRSHARD-ABANDON parent=%llu name=%.*s nshards=%u err=%d — unlinked set left for inactivation",
		(unsigned long long)parent->i_ino, name->len, name->name,
		nshards, error);
	xfs_irele(holder);
	xfs_irele(parent);
	return error;
}

/* ------------------------------------------------------------------------ *
 * Deletion / inactivation (restartable)
 * ------------------------------------------------------------------------ */

/*
 * Queue one internal inode for freeing: nlink -> 0 and onto the AGI
 * unlinked list in @tp.  The inode is then freed by its own inactivation
 * when the last reference drops (containers) — the ordinary XFS path, no
 * special free.  Caller holds ip ILOCK_EXCL and has joined it.
 */
static int
mxfs_dirshard_iunlink_internal(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip)
{
	mxfs_set_nlink(ip, 0);
	xfs_trans_ichgtime(tp, ip, XFS_ICHGTIME_CHG);
	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
	return xfs_iunlink(tp, ip);
}

/*
 * Free one live container: clear its manifest bit and put it on the
 * unlinked list in ONE transaction; its inactivation (on irele) frees the
 * directory blocks and the inode.  A container whose {ino, gen} no longer
 * matches is "already gone" (freed and reused): the bit is cleared without
 * touching the stranger.
 */
static int
mxfs_dirshard_free_container(
	struct xfs_inode	*parent,
	struct xfs_inode	*holder,
	xfs_daddr_t		daddr,
	unsigned int		index,
	const struct mxfs_dirshard_view *v)
{
	struct xfs_mount	*mp = parent->i_mount;
	struct mxfs_dirshard_view now;
	struct xfs_inode	*c = NULL;
	struct xfs_trans	*tp;
	struct xfs_buf		*bp;
	struct mxfs_dirshard_manifest *m;
	int			error;

	/*
	 * sess470: only "free" (-ENOENT) or "reused" (-ESTALE) mean gone.
	 * -EINVAL was accepted here too and it was the unlocked-inobt refusal
	 * of the old UNTRUSTED iget (see mxfs_dirshard_iget_probe): the bit
	 * was cleared under a live container, which leaked it.  Any other
	 * error leaves the set on the unlinked list for the next pass.
	 */
	error = mxfs_dirshard_iget_probe(mp, parent, v->shard[index].ino,
					 v->shard[index].gen, XFS_DIR3_FT_DIR,
					 true, &c);
	if (mxfs_dirshard_iget_gone(error)) {
		xfs_notice(mp,
			"MXFS P-DIRSHARD-GONE parent=%llu index=%u ino=%llu gen=%u err=%d — already freed; clearing entry",
			(unsigned long long)parent->i_ino, index,
			(unsigned long long)v->shard[index].ino,
			v->shard[index].gen, error);
		c = NULL;
	} else if (error) {
		return error;
	}

	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_remove, 0, 0, 0, &tp);
	if (error)
		goto out_irele;
	if (c) {
		xfs_ilock(c, XFS_ILOCK_EXCL);
		xfs_trans_ijoin(tp, c, XFS_ILOCK_EXCL);
		if (VFS_I(c)->i_nlink != 2) {
			/* child directories inside the shard: refuse to free
			 * a non-empty container (rmdir emptiness is checked by
			 * the caller under the barrier; this is the backstop) */
			error = -ENOTEMPTY;
			goto out_cancel;
		}
		xfs_iflags_set(c, MXFS_IF_LOCAL_UNLINK);
		error = mxfs_dirshard_iunlink_internal(tp, c);
		if (error)
			goto out_cancel;
	}
	error = mxfs_dirshard_blk_read(tp, parent, holder, daddr, &bp, &now);
	if (error)
		goto out_cancel;
	m = mxfs_dirshard_blk_manifest(bp);
	m->state = cpu_to_be16(MXFS_DIRSHARD_ST_DELETING);
	m->valid_mask = cpu_to_be64(be64_to_cpu(m->valid_mask) & ~(1ULL << index));
	mxfs_dirshard_blk_log(tp, bp);
	/*
	 * sess471 (D-0530, chain 109 on 0.64.12): the container was joined
	 * with XFS_ILOCK_EXCL, so commit AND cancel release its ILOCK
	 * (xfs_inode_item_release).  This path used to unlock it again —
	 * an unpaired up_write on i_lock (WARN in mxfs_ilk_note_unlock,
	 * P71-UNDERFLOW on the DLM count) under rmdir.  No explicit unlock
	 * after the join, on either path.
	 */
	error = xfs_trans_commit(tp);
	goto out_irele;

out_cancel:
	xfs_trans_cancel(tp);
out_irele:
	if (c)
		xfs_irele(c);
	return error;
}

/*
 * Free the holder: invalidate the manifest buffer, unmap its block, nlink ->
 * 0 and onto the unlinked list — one transaction — then its inactivation
 * frees the inode.  xfs_trans_binval is what keeps a later reuse of that
 * block as another metadata type from meeting a stale cached buffer with our
 * ops (the symlink-remote truncate does the same).
 *
 * sess470 (0.64.11, design-consult review item 3): the SAME transaction removes the
 * parent's locator.  The holder's unlink is the irreversible step, and a
 * crash between it and the parent's free used to be restarted by probing
 * the holder's number — which, once the holder's whole inode chunk has been
 * freed and reused, answers with the cluster verifier's -EFSCORRUPTED, not
 * "gone", and would have parked the parent on the unlinked list forever.
 * With the locator gone in the same commit the restart takes the
 * no-locator branch of mxfs_dirshard_inactive_parent (free as a plain
 * empty directory) and never has to ask.  The caller holds the parent
 * ILOCK_EXCL (the barrier) and the locator is shortform (the set-time
 * guard), so the remove is the synchronous shortform path: no roll, no
 * deferred intent — checked below, as at set time.
 */
static int
mxfs_dirshard_free_holder(
	struct xfs_inode	*parent,
	struct xfs_inode	*holder,
	xfs_daddr_t		daddr)
{
	struct xfs_mount	*mp = parent->i_mount;
	struct xfs_da_args	*largs;	/* heap: keeps the inlined frame < 1 KiB */
	struct xfs_trans	*tp;
	struct xfs_buf		*bp;
	size_t			ndef;
	int			done = 0;
	int			error;

	xfs_assert_ilocked(parent, XFS_ILOCK_EXCL);
	largs = kzalloc(sizeof(*largs), GFP_KERNEL);
	if (!largs)
		return -ENOMEM;
	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_itruncate, 0, 0, 0, &tp);
	if (error) {
		kfree(largs);
		return error;
	}
	xfs_trans_ijoin(tp, parent, 0);
	xfs_ilock(holder, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(tp, holder, XFS_ILOCK_EXCL);
	/*
	 * sess472 (D-0531, chain 109 s472a on 0.64.14): the locator remove
	 * below is only synchronous when the parent's attr fork can take the
	 * shortform shortcut (xfs_attr_removename: attr fork present AND
	 * shortform).  On the rig it could not — xfs_attr_removename queued
	 * the deferred attr intent, the post-check refused with -EFSCORRUPTED,
	 * and cancelling the by-then DIRTY transaction (binval + bunmapi +
	 * iunlink) shut the filesystem down and got the node fenced.  Decide
	 * BEFORE the first dirty: a refusal here cancels a clean transaction
	 * and leaves the set on the unlinked list for the next pass, and the
	 * line names the fork state so the next lap answers WHY it is not
	 * shortform (the locator is written shortform at set time and nothing
	 * in stage 1 adds a second attr).
	 */
	if (!xfs_inode_has_attr_fork(parent) || !xfs_attr_is_shortform(parent)) {
		xfs_alert(mp,
			"MXFS P-DIRSHARD-LOCATOR-NOTSF parent=%llu forkoff=%u af_format=%d af_nextents=%llu af_bytes=%d df_format=%d — locator remove cannot take the shortform path; refusing before any dirty",
			(unsigned long long)parent->i_ino,
			(unsigned)parent->i_forkoff,
			xfs_inode_has_attr_fork(parent) ? (int)parent->i_af.if_format : -1,
			xfs_inode_has_attr_fork(parent) ?
				(unsigned long long)parent->i_af.if_nextents : 0ULL,
			xfs_inode_has_attr_fork(parent) ? (int)parent->i_af.if_bytes : -1,
			(int)parent->i_df.if_format);
		error = -EFSCORRUPTED;
		goto out_cancel;
	}
	error = xfs_trans_get_buf(tp, mp->m_ddev_targp, daddr,
				  XFS_FSB_TO_BB(mp, 1), 0, &bp);
	if (error)
		goto out_cancel;
	xfs_trans_binval(tp, bp);
	error = xfs_bunmapi(tp, holder, 0, 1, 0, 1, &done);
	if (error)
		goto out_cancel;
	if (!done) {
		error = -EFSCORRUPTED;
		goto out_cancel;
	}
	holder->i_disk_size = 0;
	xfs_iflags_set(holder, MXFS_IF_LOCAL_UNLINK);
	error = mxfs_dirshard_iunlink_internal(tp, holder);
	if (error)
		goto out_cancel;
	/* the parent's locator, in the same commit (see above) */
	mxfs_dirshard_locator_args_init(largs, parent, tp, NULL);
	largs->value = NULL;
	largs->valuelen = 0;
	/*
	 * sess472 (D-0531 root, design-consult reviewed): the 0.64.12 check below
	 * asked "is t_dfops non-empty?" AFTER xfs_bunmapi — and freeing the
	 * holder's real extent ALWAYS queues a deferred extent free (EFI,
	 * P3-EFREE-Q on the holder right before the refusal in chain 112's
	 * log), so the check fired on every holder free, blamed the locator
	 * remove, and cancelled a dirty transaction (shutdown, node fenced).
	 * Count what the attr remove itself adds: with the shortform
	 * precondition above it adds nothing (xfs_attr_sf_removename never
	 * defers).  And no refusal after the first dirty: if it ever grows,
	 * say so and commit — xfs_trans_commit finishes the intent with a
	 * roll, which the "no-locator" / "holder gone" restart branches of
	 * mxfs_dirshard_inactive_parent tolerate.
	 */
	ndef = list_count_nodes(&tp->t_dfops);
	error = xfs_attr_removename(largs);
	if (error == -ENOATTR)
		error = 0;		/* an older partial pass already took it */
	if (error)
		goto out_cancel;
	if (list_count_nodes(&tp->t_dfops) != ndef)
		xfs_alert(mp,
			"MXFS P-DIRSHARD-LOCATOR-DEFERRED parent=%llu dfops=%zu->%zu — locator remove queued a deferred attr intent despite the shortform precondition; committing with the intent",
			(unsigned long long)parent->i_ino, ndef,
			list_count_nodes(&tp->t_dfops));
	/* sess471 (D-0530): the holder was joined with XFS_ILOCK_EXCL —
	 * commit/cancel release it; no second unlock (see free_container). */
	error = xfs_trans_commit(tp);
	kfree(largs);
	return error;

out_cancel:
	xfs_trans_cancel(tp);
	kfree(largs);
	return error;
}

/*
 * mxfs_dirshard_inactive_parent — shard-aware inactivation of a PARENT
 * whose nlink reached 0 (rmdir published it out of the namespace, or an
 * allocation was abandoned, or a survivor is sweeping a dead node's
 * unlinked bucket).  Frees the live containers, then the holder, then lets
 * the caller free the parent.  Restartable at every commit boundary.
 *
 * Returns 0 when the parent may be freed as an ordinary empty directory.
 * A parent with the flag but no locator (the dialloc-roll torn shape) has
 * nothing to walk and returns 0 immediately.
 */
int
mxfs_dirshard_inactive_parent(
	struct xfs_inode	*dp)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct mxfs_dirshard_view v;
	struct xfs_inode	*holder;
	struct xfs_buf		*bp;
	xfs_daddr_t		daddr;
	uint64_t		hino;
	uint32_t		hgen;
	unsigned int		i;
	int			error;

	xfs_ilock(dp, XFS_ILOCK_EXCL);
	error = mxfs_dirshard_locator_get(dp, &hino, &hgen);
	if (error == -ENOENT) {
		/* torn step A (the parent committed on a dialloc roll before its
		 * locator existed) or a restart after the holder free took the
		 * locator with it (sess470) — nothing to walk, free it as a
		 * plain empty directory */
		xfs_notice(mp,
			"MXFS P-DIRSHARD-INACTIVE parent=%llu no locator — torn allocation or post-holder-free restart, freeing as plain directory",
			(unsigned long long)dp->i_ino);
		xfs_iunlock(dp, XFS_ILOCK_EXCL);
		return 0;
	}
	if (error)
		goto out_unlock;
	/* sess472 (D-0531): the parent's attr-fork state at inactivation entry,
	 * beside the locator read that just succeeded — the shortform remove
	 * in free_holder depends on it. */
	xfs_notice(mp,
		"MXFS P-DIRSHARD-INACTIVE-AF parent=%llu forkoff=%u af_format=%d af_nextents=%llu af_bytes=%d holder=%llu gen=%u",
		(unsigned long long)dp->i_ino, (unsigned)dp->i_forkoff,
		xfs_inode_has_attr_fork(dp) ? (int)dp->i_af.if_format : -1,
		xfs_inode_has_attr_fork(dp) ?
			(unsigned long long)dp->i_af.if_nextents : 0ULL,
		xfs_inode_has_attr_fork(dp) ? (int)dp->i_af.if_bytes : -1,
		(unsigned long long)hino, hgen);
	/*
	 * Frees run containers -> holder -> parent, so a holder that is
	 * already gone (freed, or freed and reused) proves every container
	 * went before it: this is a restart after the holder step.
	 */
	error = mxfs_dirshard_iget_probe(mp, dp, hino, hgen,
					 XFS_DIR3_FT_REG_FILE, true, &holder);
	if (mxfs_dirshard_iget_gone(error)) {
		xfs_notice(mp,
			"MXFS P-DIRSHARD-INACTIVE parent=%llu holder=%llu gen=%u gone (%d) — restart after holder free, freeing parent",
			(unsigned long long)dp->i_ino, (unsigned long long)hino,
			hgen, error);
		error = 0;
		goto out_unlock;
	}
	if (error)	/* sess470: an I/O or lock failure is not "gone" */
		goto out_unlock;
	xfs_ilock(holder, XFS_ILOCK_SHARED);
	error = mxfs_dirshard_holder_daddr(holder, &daddr);
	xfs_iunlock(holder, XFS_ILOCK_SHARED);
	if (error)
		goto out;
	mxfs_dirshard_blk_refresh(dp, holder, daddr);	/* sess473 D-0534: same coherency point as the slow load */
	error = mxfs_dirshard_blk_read(NULL, dp, holder, daddr, &bp, &v);
	if (error)
		goto out;
	xfs_buf_relse(bp);

	for (i = 0; i < v.nshards; i++) {
		if (!(v.valid_mask & (1ULL << i)))
			continue;
		error = mxfs_dirshard_free_container(dp, holder, daddr, i, &v);
		if (error)
			goto out;
	}
	error = mxfs_dirshard_free_holder(dp, holder, daddr);
	if (error)
		goto out;
	mxfs_dirshard_cache_drop(dp);
out:
	xfs_irele(holder);
out_unlock:
	xfs_iunlock(dp, XFS_ILOCK_EXCL);
	if (error)
		xfs_alert(mp,
			"MXFS P-DIRSHARD-INACTIVE parent=%llu err=%d — set left on the unlinked list for the next pass",
			(unsigned long long)dp->i_ino, error);
	return error;
}

/* ------------------------------------------------------------------------ *
 * Ordinary operations: pin + resolve + one shard + unchanged primitive
 * ------------------------------------------------------------------------ */

int
mxfs_dirshard_lookup(
	struct xfs_inode	*dp,
	const struct xfs_name	*name,
	struct xfs_inode	**ipp,
	bool			create_intent)
{
	struct xfs_inode	*shard;
	int			error;

	xfs_ilock(dp, XFS_ILOCK_SHARED);		/* pin */
	error = mxfs_dirshard_resolve(dp, name, &shard, NULL);
	if (!error) {
		error = xfs_lookup(shard, name, ipp, NULL, create_intent);
		xfs_irele(shard);
	}
	xfs_iunlock(dp, XFS_ILOCK_SHARED);
	return error;
}

int
mxfs_dirshard_create(
	struct mnt_idmap	*idmap,
	struct xfs_inode	*dp,
	struct xfs_name		*name,
	umode_t			mode,
	dev_t			rdev,
	unsigned int		icreate_flags,
	struct xfs_inode	**ipp)
{
	struct xfs_icreate_args	args = {
		.idmap		= idmap,
		.rdev		= rdev,
		.mode		= mode,
		.flags		= icreate_flags,
	};
	struct xfs_inode	*shard;
	int			error;

	/*
	 * Stage 2 Model A: a directory child inside a sharded directory needs
	 * the logical-".." and summary semantics (ruling Q3); refuse until
	 * stage 5 rather than create a child whose ".." names the container.
	 */
	if (S_ISDIR(mode))
		return -EOPNOTSUPP;

	xfs_ilock(dp, XFS_ILOCK_SHARED);		/* pin */
	error = mxfs_dirshard_resolve(dp, name, &shard, NULL);
	if (!error) {
		args.pip = shard;
		error = xfs_create(&args, name, ipp);
		xfs_irele(shard);
	}
	xfs_iunlock(dp, XFS_ILOCK_SHARED);
	return error;
}

int
mxfs_dirshard_lookup_ino(
	struct xfs_inode	*dp,
	const struct xfs_name	*name,
	xfs_ino_t		*inop)
{
	struct xfs_inode	*shard;
	int			error;

	xfs_assert_ilocked(dp, XFS_ILOCK_SHARED | XFS_ILOCK_EXCL);
	error = mxfs_dirshard_resolve(dp, name, &shard, NULL);
	if (error)
		return error;
	xfs_ilock(shard, XFS_ILOCK_SHARED);
	error = xfs_dir_lookup(NULL, shard, name, inop, NULL, NULL);
	xfs_iunlock(shard, XFS_ILOCK_SHARED);
	xfs_irele(shard);
	return error;
}

int
mxfs_dirshard_isempty(
	struct xfs_inode	*dp)
{
	struct mxfs_dirshard_view v;
	struct xfs_inode	*shard;
	unsigned int		i;
	int			error;

	xfs_assert_ilocked(dp, XFS_ILOCK_EXCL);		/* the barrier */
	error = mxfs_dirshard_manifest_load(dp, &v);
	if (error)
		return error;
	for (i = 0; i < v.nshards; i++) {
		bool	empty;

		if (!(v.valid_mask & (1ULL << i)))
			continue;
		error = mxfs_dirshard_iget(dp->i_mount, dp, v.shard[i].ino,
					   v.shard[i].gen, XFS_DIR3_FT_DIR,
					   &shard);
		if (error)
			return error;
		xfs_ilock(shard, XFS_ILOCK_SHARED);
		empty = xfs_dir_isempty(shard) && VFS_I(shard)->i_nlink <= 2;
		xfs_iunlock(shard, XFS_ILOCK_SHARED);
		xfs_irele(shard);
		if (!empty)
			return -ENOTEMPTY;
	}
	return 0;
}

int
mxfs_dirshard_remove(
	struct xfs_inode	*dp,
	struct xfs_name		*name,
	struct xfs_inode	*ip)
{
	struct xfs_inode	*shard;
	int			error;

	if (S_ISDIR(VFS_I(ip)->i_mode))
		return -EOPNOTSUPP;			/* stage 5 */

	xfs_ilock(dp, XFS_ILOCK_SHARED);		/* pin */
	error = mxfs_dirshard_resolve(dp, name, &shard, NULL);
	if (!error) {
		error = xfs_remove(shard, name, ip);
		xfs_irele(shard);
	}
	xfs_iunlock(dp, XFS_ILOCK_SHARED);
	return error;
}

/*
 * readdir: logical cookies {slot, local dataptr}.  Slot 0 emits the
 * synthesized "." and "..", shard i occupies slot i+1, slot
 * MXFS_DIRSHARD_COOKIE_EOF_SLOT is EOF.  Each shard's own "." and ".." are
 * skipped.  The inner xfs_readdir sets its context position to the local
 * dataptr of the entry it is about to emit, so on a full buffer the outer
 * position is left at the logical cookie of that not-yet-emitted entry and
 * the next call resumes exactly there.
 */
struct mxfs_dirshard_rdctx {
	struct dir_context	sub;
	struct dir_context	*outer;
	unsigned int		slot;
	bool			full;	/* the outer actor refused an entry */
};

static bool
mxfs_dirshard_readdir_actor(
	struct dir_context	*sub,
	const char		*name,
	int			namelen,
	loff_t			local,
	u64			ino,
	unsigned int		type)
{
	struct mxfs_dirshard_rdctx *r =
		container_of(sub, struct mxfs_dirshard_rdctx, sub);
	uint64_t		cookie;

	if (namelen == 1 && name[0] == '.')
		return true;
	if (namelen == 2 && name[0] == '.' && name[1] == '.')
		return true;
	cookie = mxfs_dirshard_cookie(r->slot, (uint32_t)local);
	r->outer->pos = cookie;
	if (!r->outer->actor(r->outer, name, namelen, cookie, ino, type)) {
		r->full = true;
		return false;
	}
	return true;
}

/*
 * sess470 (0.64.11): what xfs_file_readdir does for an ordinary directory
 * before reading it — the sess97 consumer-side dir-block refresh and the
 * sess11 stale-reload settle — has to happen per CONTAINER.  The VFS only
 * ever sees the parent, so the parent's settle in xfs_file_readdir settles a
 * directory that holds no entries.  chain 103's cc laps on 0.64.6 (test1
 * ring, 14:35-14:43Z) logged 20x "P173-RELOAD-SELFREAD ino=133 ...
 * rd_last=mxfs_dirshard_readdir ... caller holds ILOCK_SHARED; reload
 * deferred": the peer-armed reload of a shortform container could only
 * fire inside xfs_readdir, under our own ILOCK_SHARED, where it must bail —
 * so the stale inline body was served.  Same contract as xfs_file_readdir:
 * no locks of the shard held here; bounded retry; the flag stays armed on
 * a bail.
 */
static int
mxfs_dirshard_shard_settle(
	struct xfs_inode	*shard)
{
	int			rounds = 0;
	int			error;

	/* 0.84.4: the refresh's cluster acquire may be refused; the listing
	 * then fails at this shard with its position intact. */
	error = mxfs_dlm_dir_consumer_refresh_fallible(shard);
	if (error)
		return error;
	if (!shard->i_dlm_stale)
		return 0;
	while (rounds++ < 200 && !xfs_is_shutdown(shard->i_mount)) {
		mxfs_dlm_reload_inode(shard, XFS_DIR3_FT_UNKNOWN, false);
		if (!shard->i_dlm_stale)
			break;
		shard->i_dlm_stale = true;
		shard->i_dlm_stale_src = 27;	/* keep armed across bails */
		msleep(10);
	}
	pr_warn_ratelimited(
		"mxfs: P95D-READDIR-WAIT ino=%llu resolved=%d rounds=%d fmt=%d shard=1\n",
		(unsigned long long)shard->i_ino, shard->i_dlm_stale ? 0 : 1,
		rounds, shard->i_df.if_format);
	return 0;
}

int
mxfs_dirshard_readdir(
	struct xfs_inode	*dp,
	struct dir_context	*ctx,
	size_t			bufsize)
{
	struct mxfs_dirshard_view v;
	struct mxfs_dirshard_rdctx r = {
		.sub.actor	= mxfs_dirshard_readdir_actor,
		.outer		= ctx,
	};
	struct xfs_inode	*shard;
	unsigned int		slot;
	int			error;

	if (mxfs_dirshard_cookie_malformed(ctx->pos))
		return -EINVAL;

	/*
	 * 0.84.4: the pin is the parent's cluster acquire on the readdir
	 * path and may be refused (the master never acknowledged the request
	 * past the budget, or the task was killed); the listing then fails
	 * with nothing held and the position untouched.
	 */
	error = mxfs_ilock_fallible(dp, XFS_ILOCK_SHARED);	/* pin */
	if (error)
		return mxfs_readdir_refused(dp, "shard-pin", error);
	error = mxfs_dirshard_manifest_load(dp, &v);
	if (error)
		goto out;
	if (v.state != MXFS_DIRSHARD_ST_PUBLISHED) {
		error = -EOPNOTSUPP;
		goto out;
	}

	slot = mxfs_dirshard_cookie_slot(ctx->pos);
	if (slot == 0) {
		xfs_ino_t	pino;

		if (ctx->pos == MXFS_DIRSHARD_COOKIE_DOT) {
			if (!dir_emit(ctx, ".", 1, dp->i_ino, DT_DIR))
				goto out;
			ctx->pos = MXFS_DIRSHARD_COOKIE_DOTDOT;
		}
		if (ctx->pos == MXFS_DIRSHARD_COOKIE_DOTDOT) {
			error = xfs_dir_lookup(NULL, dp, &xfs_name_dotdot, &pino,
					       NULL, NULL);
			if (error)
				goto out;
			if (!dir_emit(ctx, "..", 2, pino, DT_DIR))
				goto out;
		}
		slot = 1;
		ctx->pos = mxfs_dirshard_cookie(slot, 0);
	}

	for (; slot >= 1 && slot <= v.nshards; slot++) {
		unsigned int	idx = slot - 1;

		/* Named first so an error anywhere in this pass re-encodes
		 * THIS slot's position, never the previous shard's. */
		r.slot = slot;
		r.sub.pos = mxfs_dirshard_cookie_local(ctx->pos);
		if (!(v.valid_mask & (1ULL << idx))) {
			mxfs_dirshard_corrupt(dp, "readdir-shard-not-live",
					      MXFS_DSC_VALID_MASK, idx);
			error = -EFSCORRUPTED;
			goto out;
		}
		error = mxfs_dirshard_iget(dp->i_mount, dp, v.shard[idx].ino,
					   v.shard[idx].gen, XFS_DIR3_FT_DIR,
					   &shard);
		if (error)
			goto out;
		/*
		 * No IOLOCK is taken on the container: the parent's i_rwsem,
		 * which the VFS holds for the whole iterate_dir, is the
		 * container's namespace lock (every container mutation runs
		 * under the parent's i_rwsem EXCL, and a container never has a
		 * dentry of its own).  xfs_readdir's IOLOCK assertion knows
		 * this (sess470; it WARNed 588x on chain 103's cc laps).
		 */
		if (S_ISDIR(VFS_I(shard)->i_mode)) {
			error = mxfs_dirshard_shard_settle(shard);
			if (error) {
				/* nothing emitted from this shard yet */
			} else if (shard->i_df.if_format == XFS_DINODE_FMT_LOCAL) {
				/* 0.84.4: the shard's own cluster acquire, and
				 * it may be refused like the pin above. */
				error = mxfs_ilock_fallible(shard, XFS_ILOCK_SHARED);
				if (error) {
					mxfs_readdir_refused(shard, "shard-sf", error);
				} else {
					error = xfs_readdir(NULL, shard, &r.sub, bufsize);
					xfs_iunlock(shard, XFS_ILOCK_SHARED);
				}
			} else {
				error = xfs_readdir(NULL, shard, &r.sub, bufsize);
			}
		} else {
			error = -EFSCORRUPTED;
		}
		xfs_irele(shard);
		if (error) {
			/*
			 * 0.84.4: the inner listing may now stop between two
			 * data blocks of this shard after entries from it were
			 * emitted.  The actor left the outer position at the
			 * cookie of the LAST EMITTED entry; the inner position
			 * names the next unconsumed one.  Re-encode it so the
			 * next call resumes there and repeats nothing — and
			 * for an error before anything was emitted this is the
			 * cookie the call started with.
			 */
			ctx->pos = mxfs_dirshard_cookie(slot, (uint32_t)r.sub.pos);
			goto out;
		}
		/*
		 * The outer actor refused an entry: the outer position already
		 * names it; stop here and resume there next call.  Otherwise
		 * this shard is exhausted; continue with the next slot at
		 * local 0.
		 */
		if (r.full)
			break;
		ctx->pos = mxfs_dirshard_cookie(slot + 1, 0);
	}
	if (!r.full && slot > v.nshards)
		ctx->pos = mxfs_dirshard_cookie(MXFS_DIRSHARD_COOKIE_EOF_SLOT, 0);
out:
	xfs_iunlock(dp, XFS_ILOCK_SHARED);
	return error;
}

int
mxfs_dirshard_stat(
	struct xfs_inode	*dp,
	struct mxfs_dirshard_stat *out)
{
	struct mxfs_dirshard_view v;
	struct xfs_inode	*shard;
	struct inode		*vp = VFS_I(dp);
	unsigned int		i;
	int			error;

	xfs_ilock(dp, XFS_ILOCK_SHARED);		/* pin */
	error = mxfs_dirshard_manifest_load(dp, &v);
	if (error)
		goto out;
	out->nlink = 2;
	out->size = dp->i_disk_size;
	out->blocks = dp->i_nblocks;
	out->mtime = inode_get_mtime(vp);
	out->ctime = inode_get_ctime(vp);
	for (i = 0; i < v.nshards; i++) {
		struct inode	*sv;
		struct timespec64 t;

		if (!(v.valid_mask & (1ULL << i)))
			continue;
		error = mxfs_dirshard_iget(dp->i_mount, dp, v.shard[i].ino,
					   v.shard[i].gen, XFS_DIR3_FT_DIR,
					   &shard);
		if (error)
			goto out;
		sv = VFS_I(shard);
		xfs_ilock(shard, XFS_ILOCK_SHARED);
		if (sv->i_nlink >= 2)
			out->nlink += sv->i_nlink - 2;
		out->size += shard->i_disk_size;
		out->blocks += shard->i_nblocks;
		t = inode_get_mtime(sv);
		if (timespec64_compare(&t, &out->mtime) > 0)
			out->mtime = t;
		t = inode_get_ctime(sv);
		if (timespec64_compare(&t, &out->ctime) > 0)
			out->ctime = t;
		xfs_iunlock(shard, XFS_ILOCK_SHARED);
		xfs_irele(shard);
	}
out:
	xfs_iunlock(dp, XFS_ILOCK_SHARED);
	return error;
}

/* ------------------------------------------------------------------------ *
 * ioctls
 * ------------------------------------------------------------------------ */

static long
mxfs_dirshard_ioc_mkdir(
	struct file		*filp,
	void __user		*uarg)
{
	struct mxfs_ioc_dirshard_mkdir req;
	struct inode		*dir = file_inode(filp);
	struct xfs_inode	*dp = XFS_I(dir);
	struct xfs_inode	*ip;
	struct xfs_name		name;
	struct dentry		*dentry;
	struct qstr		q;
	int			error;

	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;
	if (req.flags || req.reserved)
		return -EINVAL;
	if (!S_ISDIR(dir->i_mode))
		return -ENOTDIR;
	if (!inode_owner_or_capable(file_mnt_idmap(filp), dir))
		return -EPERM;
	req.name[sizeof(req.name) - 1] = '\0';
	name.len = strnlen(req.name, sizeof(req.name));
	if (name.len == 0 || name.len >= MAXNAMELEN ||
	    memchr(req.name, '/', name.len))
		return -EINVAL;
	if ((name.len == 1 && req.name[0] == '.') ||
	    (name.len == 2 && req.name[0] == '.' && req.name[1] == '.'))
		return -EINVAL;
	name.name = (const unsigned char *)req.name;
	name.type = XFS_DIR3_FT_DIR;

	/* mkdir(2) semantics for the namespace lock: serialize with the VFS */
	inode_lock_nested(dir, I_MUTEX_PARENT);
	error = mxfs_dirshard_mkdir(file_mnt_idmap(filp), dp, &name,
				    req.mode & ~current_umask(), req.nshards,
				    &ip);
	if (!error) {
		/* a cached negative dentry for the name is now stale */
		q.name = req.name;
		q.len = name.len;
		q.hash_len = hashlen_string(filp->f_path.dentry, req.name);
		/*
		 * From 6.16 d_hash_and_lookup() is VFS-internal; its public
		 * replacement is try_lookup_noperm(), arguments reversed.  Both
		 * return an ERR_PTR when the filesystem's ->d_hash fails (the
		 * ASCII case-insensitive dentry ops have one), never a dentry.
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
		dentry = try_lookup_noperm(&q, filp->f_path.dentry);
#else
		dentry = d_hash_and_lookup(filp->f_path.dentry, &q);
#endif
		if (!IS_ERR_OR_NULL(dentry)) {
			if (d_is_negative(dentry))
				d_invalidate(dentry);
			dput(dentry);
		}
		xfs_irele(ip);
	}
	inode_unlock(dir);
	return error;
}

static long
mxfs_dirshard_ioc_info(
	struct file		*filp,
	void __user		*uarg)
{
	struct mxfs_ioc_dirshard_info *rep;
	struct inode		*dir = file_inode(filp);
	struct xfs_inode	*dp = XFS_I(dir);
	struct mxfs_dirshard_view v;
	struct xfs_inode	*shard;
	unsigned int		i, len;
	long			error = 0;

	if (!S_ISDIR(dir->i_mode))
		return -ENOTDIR;
	rep = kzalloc(sizeof(*rep), GFP_KERNEL);
	if (!rep)
		return -ENOMEM;
	if (copy_from_user(rep->name, uarg, sizeof(rep->name))) {
		error = -EFAULT;
		goto out;
	}
	rep->name[sizeof(rep->name) - 1] = '\0';
	len = strnlen(rep->name, sizeof(rep->name));

	if (!mxfs_is_dirshard_parent(dp))
		goto copy;		/* state 0, nshards 0 */

	xfs_ilock(dp, XFS_ILOCK_SHARED);
	error = mxfs_dirshard_manifest_load(dp, &v);
	if (error) {
		xfs_iunlock(dp, XFS_ILOCK_SHARED);
		goto out;
	}
	rep->state = v.state;
	rep->nshards = v.nshards;
	rep->nentries = v.nentries;
	rep->hash_id = v.hash_id;
	rep->valid_mask = v.valid_mask;
	memcpy(rep->set_uuid, v.set_uuid, 16);
	if (capable(CAP_SYS_ADMIN))
		memcpy(rep->hash_key, v.hash_key, 16);
	if (len) {
		rep->name_hash = mxfs_dirshard_hash(&v,
				(const unsigned char *)rep->name, len);
		rep->name_shard = mxfs_dirshard_index(rep->name_hash,
						      v.nshards);
	}
	for (i = 0; i < v.nshards; i++) {
		rep->shard[i].ino = v.shard[i].ino;
		rep->shard[i].gen = v.shard[i].gen;
		if (!(v.valid_mask & (1ULL << i)))
			continue;
		if (!mxfs_dirshard_iget(dp->i_mount, dp, v.shard[i].ino,
					v.shard[i].gen, XFS_DIR3_FT_DIR,
					&shard)) {
			rep->shard[i].nlink = VFS_I(shard)->i_nlink;
			xfs_irele(shard);
		}
	}
	xfs_iunlock(dp, XFS_ILOCK_SHARED);
copy:
	if (copy_to_user(uarg, rep, sizeof(*rep)))
		error = -EFAULT;
out:
	kfree(rep);
	return error;
}

long
mxfs_dirshard_ioctl(
	struct file		*filp,
	unsigned int		cmd,
	unsigned long		arg)
{
	void __user		*uarg = (void __user *)arg;

	switch (cmd) {
	case MXFS_IOC_DIRSHARD_MKDIR:
		if (!READ_ONCE(mxfs_dirshard_mkdir_enable))
			return -EOPNOTSUPP;
		return mxfs_dirshard_ioc_mkdir(filp, uarg);
	case MXFS_IOC_DIRSHARD_INFO:
		return mxfs_dirshard_ioc_info(filp, uarg);
	default:
		return -ENOTTY;
	}
}

/* Compile-time layout pins for the shared format header. */
static void __maybe_unused
mxfs_dirshard_build_checks(void)
{
	MXFS_DIRSHARD_BUILD_CHECKS();
	MXFS_DIRSHARD_IOC_BUILD_CHECKS();
	BUILD_BUG_ON(XFS_BLFT_MXFS_DIRSHARD_BUF != MXFS_DIRSHARD_BLFT);
	BUILD_BUG_ON(XFS_SB_FEAT_INCOMPAT_MXFS_DIRSHARD !=
		     MXFS_DIRSHARD_SB_INCOMPAT);
	BUILD_BUG_ON(XFS_DIFLAG2_DIRSHARD_CONTAINER !=
		     MXFS_DIFLAG2_DIRSHARD_CONTAINER);
	BUILD_BUG_ON(XFS_DIFLAG2_DIRSHARD_PARENT != MXFS_DIFLAG2_DIRSHARD_PARENT);
	BUILD_BUG_ON(MXFS_FORMAT_F_DIRSHARD_VALUE != MXFS_FORMAT_F_DIRSHARD);
}
