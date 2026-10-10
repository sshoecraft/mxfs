/*
 * MXFS — Multinode XFS
 * Platform Abstraction Layer — Linux: the DRBD dual-primary attachment.
 *
 * docs/rulings/drbd-dual-primary-attachment.md.  Two nodes, a local disk
 * each, DRBD 8.4 replicating them on protocol C, MXFS on /dev/drbd<minor>.
 * DRBD carries no SCSI underneath, so this file supplies the two things the
 * cluster otherwise takes from the storage:
 *
 * THE WITNESS.  DRBD exports no in-kernel interface to its state or its
 * configuration, so a node-local helper (/usr/sbin/mxfs_drbd_witness.py)
 * reads them — /proc/drbd, drbdadm's parse of the resource, the fence-peer
 * handler's receipts and the fence authority's live answer — and writes a
 * report back through /proc/fs/mxfs/drbd_report.  The channel has the shape
 * of the LU-reset witness's (lureset.c): a fresh nonce in argv, required back
 * in the report; one invocation outstanding at a time; a report that names
 * another nonce discarded; a bound on the wait.  This file parses the report
 * and decides nothing: dlm/drbdfence.c judges it.
 *
 * THE COMPARE-AND-SWAP.  Every on-disk record the cluster updates with SCSI
 * COMPARE AND WRITE (heartbeat, slot claim, recovery milestones, bootstrap
 * owner, ledger tickets) is updated here by a read-compare-write held under a
 * two-party lock built on the device itself (mxfs_drbd_lock).  Each participant
 * writes only its own register sector, and DRBD protocol C completes a write
 * only once both disks hold it, which is the order the lock needs.  The
 * registers carry the filesystem's UUID, the participant's index and both
 * endpoints, so a pair that both believe they are participant 0 is detected
 * and refused rather than silently sharing a register.  The emulated swap is
 * atomic only against other emulated swaps: no plain write may touch a
 * protected sector, which is why the bootstrap and ledger fallbacks to a plain
 * write were removed.
 *
 * THE WRITE BOUND.  Those swaps are ordinary writes in the same ordered stream
 * as the guests' data, so the mount's own data and metadata writes are held to
 * a bounded amount in flight (mxfs_ioq.h says why and what).
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/blkdev.h>
#include <linux/major.h>
#include <linux/list.h>
#include <linux/bio.h>
#include <linux/mempool.h>
#include <linux/sched.h>

#include "../pal.h"
#include "mxfs_ioq.h"

int mxfs_pal_bio_write_fua_bdev(struct block_device *bdev, uint64_t lba_512,
				const void *buf, uint32_t len);
int mxfs_pal_bio_write_sync_bdev(struct block_device *bdev, uint64_t lba_512,
				 const void *buf, uint32_t len);
int mxfs_pal_bdev_read_plain_bdev(struct block_device *bdev, uint64_t lba_512,
				   void *buf, uint32_t len);
int mxfs_pal_bio_read_sectors_bdev(struct block_device *bdev, int n,
				   const uint64_t *lbas, void *const *bufs, int *rcs);
int mxfs_pal_bio_write_fua_sectors_bdev(struct block_device *bdev, int n,
					const uint64_t *lbas, void *const *bufs, int *rcs);
int mxfs_pal_bio_write_fua_spans_bdev(struct block_device *bdev, int n,
				      const uint64_t *lbas, void *const *bufs,
				      const uint32_t *lens, int *rcs);

#define MXFS_DRBDW_PROC_NAME	"fs/mxfs/drbd_report"
#define MXFS_DRBDW_PROC_PATH	"/proc/" MXFS_DRBDW_PROC_NAME
#define MXFS_DRBDW_END_MARK	"MXFS-DRBDW-END"

int mxfs_pal_bdev_drbd_minor(mxfs_bdev_t *dev)
{
	struct block_device *bdev = dev ? mxfs_pal_bdev_get_bdev(dev) : NULL;

	if (!bdev)
		return -EINVAL;
	if (MAJOR(bdev->bd_dev) != DRBD_MAJOR || bdev_is_partition(bdev))
		return -ENODEV;
	return MINOR(bdev->bd_dev);
}
EXPORT_SYMBOL_GPL(mxfs_pal_bdev_drbd_minor);

/* ═══════════════════════════ the witness ═══════════════════════════ */

/*
 * Node-local, like the LU-reset helper: a witness that upcalls into the
 * build host's NFS export makes one node's recovery depend on a third
 * machine.  A path that does not exist is a refusal, never a pass.
 */
static char *mxfs_drbd_witness_helper = "/usr/sbin/mxfs_drbd_witness.py";
module_param_named(drbd_witness_helper, mxfs_drbd_witness_helper, charp, 0644);
MODULE_PARM_DESC(drbd_witness_helper,
		 "absolute path to the node-local DRBD witness helper");

/*
 * THE BOUND, derived: the helper's local reads (/proc/drbd, three drbdadm
 * parses) measured well under a second on the rig; its one remote step is
 * the fence authority's status over ssh, bounded by its own 10 s connect
 * timeout and 30 s overall.  45 s covers both with margin.  A report that
 * does not arrive within it is not evidence.
 */
static unsigned int mxfs_drbd_witness_timeout_ms = 45000;
module_param_named(drbd_witness_timeout_ms, mxfs_drbd_witness_timeout_ms, uint, 0644);
MODULE_PARM_DESC(drbd_witness_timeout_ms,
		 "bound on one DRBD witness upcall; no report within it is no evidence");

static DEFINE_MUTEX(mxfs_drbdw_invoke_lock);

static struct {
	spinlock_t		lock;
	bool			armed;
	bool			complete;
	char			nonce_str[17];
	size_t			len;
	struct completion	done;
	char			buf[MXFS_PAL_DRBD_REPORT_MAX];
} mxfs_drbdw_slot = {
	.lock = __SPIN_LOCK_UNLOCKED(mxfs_drbdw_slot.lock),
};

static struct proc_dir_entry *mxfs_drbdw_pde;

/* One `KEY=value` line's value, parsed as data: nothing is trusted to exist,
 * to be terminated or to fit.  False when the key is absent. */
static bool mxfs_drbdw_field(const char *rep, size_t replen, const char *key,
			     char *out, size_t outsz)
{
	size_t keylen = strlen(key);
	size_t i = 0;

	if (!out || outsz == 0)
		return false;
	out[0] = '\0';
	while (i < replen) {
		size_t eol = i;
		size_t linelen;

		while (eol < replen && rep[eol] != '\n')
			eol++;
		linelen = eol - i;
		if (linelen > keylen && rep[i + keylen] == '=' &&
		    !strncmp(rep + i, key, keylen)) {
			size_t vlen = linelen - keylen - 1;

			if (vlen > outsz - 1)
				vlen = outsz - 1;
			memcpy(out, rep + i + keylen + 1, vlen);
			out[vlen] = '\0';
			while (vlen > 0 && (out[vlen - 1] == '\r' ||
					    out[vlen - 1] == ' '))
				out[--vlen] = '\0';
			return true;
		}
		i = eol + 1;
	}
	return false;
}

static ssize_t mxfs_drbdw_report_write(struct file *file,
				       const char __user *ubuf,
				       size_t count, loff_t *ppos)
{
	char *stage;
	char nonce_seen[24];
	size_t take;
	bool finished = false;

	if (count == 0)
		return 0;
	take = min_t(size_t, count, MXFS_PAL_DRBD_REPORT_MAX);
	stage = kmalloc(take, GFP_KERNEL);
	if (!stage)
		return -ENOMEM;
	if (copy_from_user(stage, ubuf, take)) {
		kfree(stage);
		return -EFAULT;
	}

	spin_lock(&mxfs_drbdw_slot.lock);
	/* Nothing outstanding: a report nobody asked for is not evidence. */
	if (!mxfs_drbdw_slot.armed || mxfs_drbdw_slot.complete) {
		spin_unlock(&mxfs_drbdw_slot.lock);
		kfree(stage);
		return -EPERM;
	}
	if (mxfs_drbdw_slot.len + take > MXFS_PAL_DRBD_REPORT_MAX - 1)
		take = MXFS_PAL_DRBD_REPORT_MAX - 1 - mxfs_drbdw_slot.len;
	if (take) {
		memcpy(mxfs_drbdw_slot.buf + mxfs_drbdw_slot.len, stage, take);
		mxfs_drbdw_slot.len += take;
		mxfs_drbdw_slot.buf[mxfs_drbdw_slot.len] = '\0';
	}
	/* A report naming another invocation (a helper that outlived an earlier
	 * wait) is discarded, so it cannot end the current wait. */
	if (mxfs_drbdw_field(mxfs_drbdw_slot.buf, mxfs_drbdw_slot.len, "NONCE",
			     nonce_seen, sizeof(nonce_seen)) &&
	    strcasecmp(nonce_seen, mxfs_drbdw_slot.nonce_str)) {
		mxfs_drbdw_slot.len = 0;
		mxfs_drbdw_slot.buf[0] = '\0';
		spin_unlock(&mxfs_drbdw_slot.lock);
		kfree(stage);
		mxfs_probe("mxfs: P-DRBDW-STALE a report naming nonce=%s arrived while another invocation is outstanding -- discarded\n",
			   nonce_seen);
		return -EPERM;
	}
	if (strstr(mxfs_drbdw_slot.buf, MXFS_DRBDW_END_MARK)) {
		mxfs_drbdw_slot.complete = true;
		finished = true;
	}
	spin_unlock(&mxfs_drbdw_slot.lock);
	kfree(stage);
	if (finished)
		complete(&mxfs_drbdw_slot.done);
	*ppos += count;
	return count;
}

static const struct proc_ops mxfs_drbdw_report_ops = {
	.proc_write	= mxfs_drbdw_report_write,
	.proc_lseek	= noop_llseek,
};

static const char *mxfs_drbdw_mode_name(int mode)
{
	switch (mode) {
	case MXFS_PAL_DRBD_ARM:		return "arm";
	case MXFS_PAL_DRBD_FENCE:	return "fence";
	case MXFS_PAL_DRBD_RECHECK:	return "recheck";
	case MXFS_PAL_DRBD_MONITOR:	return "monitor";
	case MXFS_PAL_DRBD_STARTFENCE:	return "startfence";
	}
	return NULL;
}

static void mxfs_drbdw_parse(struct mxfs_pal_drbd_report *r)
{
	const char *rep = r->report;
	size_t n = r->report_len;

#define F(key, field) mxfs_drbdw_field(rep, n, key, r->field, sizeof(r->field))
	F("MODE", mode);
	F("MINOR", minor);
	F("HOST", host);
	F("CSTATE", cstate);
	F("ROLE_LOCAL", role_local);
	F("ROLE_PEER", role_peer);
	F("DISK_LOCAL", disk_local);
	F("DISK_PEER", disk_peer);
	F("PROTOCOL", protocol);
	F("SUSPENDED", suspended);
	F("RESOURCE", resource);
	F("GI", gi);
	F("PROTOCOL_CFG", protocol_cfg);
	F("TWO_PRIMARIES", two_primaries);
	F("FENCING", fencing);
	F("FENCE_HANDLER", fence_handler);
	F("AFTER_SB", after_sb);
	F("ENDPOINTS", endpoints);
	F("LOCAL_ADDR", local_addr);
	F("PEER_HOST", peer_host);
	F("PEER_ADDR", peer_addr);
	F("HANDLER_INSTALLED", handler_installed);
	F("FENCE_SELF", fence_self);
	F("RECEIPT_TIME", receipt_time);
	F("RECEIPT_PEER", receipt_peer);
	F("RECEIPT_EPISODE", receipt_episode);
	F("RECEIPT_KIND", receipt_kind);
	F("AUTH_STATE", auth_state);
	F("AUTH_INHIBIT", auth_inhibit);
#undef F
}

static int mxfs_drbdw_run(int minor, int mode, struct mxfs_pal_drbd_report *out);

int mxfs_pal_drbd_witness(mxfs_bdev_t *dev, int mode,
			  struct mxfs_pal_drbd_report *out)
{
	int minor;

	if (!out)
		return -EINVAL;
	minor = mxfs_pal_bdev_drbd_minor(dev);
	if (minor < 0) {
		memset(out, 0, sizeof(*out));
		strscpy(out->reason, "not-a-drbd-device", sizeof(out->reason));
		return minor;
	}
	return mxfs_drbdw_run(minor, mode, out);
}

static int mxfs_drbdw_run(int minor, int mode, struct mxfs_pal_drbd_report *out)
{
	static char *envp[] = {
		"HOME=/",
		"PATH=/usr/lib/drbd:/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin",
		NULL
	};
	char nonce_str[17], minor_str[12], helper[192], nonce_seen[24];
	const char *mode_name = mxfs_drbdw_mode_name(mode);
	char *argv[6];
	unsigned long left;
	ktime_t t0;
	int rc;

	if (!out || !mode_name)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!mxfs_drbdw_pde) {
		strscpy(out->reason, "no-report-channel", sizeof(out->reason));
		return -ENODEV;
	}
	{
		/* `echo /path > .../drbd_witness_helper` stores the newline too:
		 * trim before anything looks the path up (see lureset.c). */
		const char *hp = mxfs_drbd_witness_helper ? mxfs_drbd_witness_helper : "";
		size_t hn;

		while (*hp == ' ' || *hp == '\t' || *hp == '\n' || *hp == '\r')
			hp++;
		hn = strlen(hp);
		while (hn && (hp[hn - 1] == ' ' || hp[hn - 1] == '\t' ||
			      hp[hn - 1] == '\n' || hp[hn - 1] == '\r'))
			hn--;
		if (hn >= sizeof(helper) || !hn || hp[0] != '/') {
			strscpy(out->reason, "helper-path-unset", sizeof(out->reason));
			return -ENOENT;
		}
		memcpy(helper, hp, hn);
		helper[hn] = '\0';
	}

	mutex_lock(&mxfs_drbdw_invoke_lock);
	out->nonce = get_random_u64();
	if (!out->nonce)
		out->nonce = 1;
	snprintf(nonce_str, sizeof(nonce_str), "%016llx", (unsigned long long)out->nonce);
	snprintf(minor_str, sizeof(minor_str), "%d", minor);

	spin_lock(&mxfs_drbdw_slot.lock);
	strscpy(mxfs_drbdw_slot.nonce_str, nonce_str, sizeof(mxfs_drbdw_slot.nonce_str));
	mxfs_drbdw_slot.len = 0;
	mxfs_drbdw_slot.buf[0] = '\0';
	mxfs_drbdw_slot.complete = false;
	mxfs_drbdw_slot.armed = true;
	spin_unlock(&mxfs_drbdw_slot.lock);
	init_completion(&mxfs_drbdw_slot.done);

	argv[0] = helper;
	argv[1] = nonce_str;
	argv[2] = (char *)mode_name;
	argv[3] = minor_str;
	argv[4] = (char *)MXFS_DRBDW_PROC_PATH;
	argv[5] = NULL;

	t0 = ktime_get();
	/* UMH_WAIT_EXEC: the wait is for the REPORT, which is bounded; a helper
	 * that never exits must not park the caller. */
	rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (rc) {
		spin_lock(&mxfs_drbdw_slot.lock);
		mxfs_drbdw_slot.armed = false;
		spin_unlock(&mxfs_drbdw_slot.lock);
		snprintf(out->reason, sizeof(out->reason), "exec-failed-%d", rc);
		pr_err("mxfs: P-DRBDW-NOEXEC helper='%s' mode=%s rc=%d -- no report, no evidence\n",
		       helper, mode_name, rc);
		mutex_unlock(&mxfs_drbdw_invoke_lock);
		return rc;
	}

	left = wait_for_completion_timeout(&mxfs_drbdw_slot.done,
					   msecs_to_jiffies(mxfs_drbd_witness_timeout_ms));
	out->upcall_wall_ms = ktime_to_ms(ktime_sub(ktime_get(), t0));

	spin_lock(&mxfs_drbdw_slot.lock);
	mxfs_drbdw_slot.armed = false;
	out->report_len = min_t(size_t, mxfs_drbdw_slot.len, sizeof(out->report) - 1);
	memcpy(out->report, mxfs_drbdw_slot.buf, out->report_len);
	out->report[out->report_len] = '\0';
	spin_unlock(&mxfs_drbdw_slot.lock);
	mutex_unlock(&mxfs_drbdw_invoke_lock);

	if (!left) {
		strscpy(out->reason, out->report_len ? "report-truncated-at-bound" :
			"no-report-within-bound", sizeof(out->reason));
	} else if (!mxfs_drbdw_field(out->report, out->report_len, "NONCE",
				     nonce_seen, sizeof(nonce_seen)) ||
		   strcasecmp(nonce_seen, nonce_str)) {
		strscpy(out->reason, "nonce-mismatch", sizeof(out->reason));
	} else {
		mxfs_drbdw_parse(out);
		if (strcmp(out->mode, mode_name)) {
			strscpy(out->reason, "mode-mismatch", sizeof(out->reason));
		} else if (strcmp(out->minor, minor_str)) {
			strscpy(out->reason, "minor-mismatch", sizeof(out->reason));
		} else {
			out->delivered = true;
		}
	}
	mxfs_probe("mxfs: P-DRBDW-REPORT mode=%s minor=%d nonce=%s delivered=%d upcall_ms=%u reason=%s cstate=%s roles=%s/%s disks=%s/%s susp=%s auth=%s/%s receipt=%s\n",
		   mode_name, minor, nonce_str, out->delivered, out->upcall_wall_ms,
		   out->delivered ? "-" : out->reason, out->cstate, out->role_local,
		   out->role_peer, out->disk_local, out->disk_peer, out->suspended,
		   out->auth_state, out->auth_inhibit, out->receipt_episode);
	return 0;
}
EXPORT_SYMBOL_GPL(mxfs_pal_drbd_witness);

/* ═══════════════════════ the compare-and-swap ═══════════════════════ */

#define MXFS_DRBD_ENROLL_MAGIC	0x45425843u	/* "CXBE" little-endian: enrollment */
#define MXFS_DRBD_REG_MAGIC	0x4b42584du	/* "MXBK": a lock register */
/* The enrollment's format, unchanged since the first release: its sector is
 * compared byte for byte at every attach. */
#define MXFS_DRBD_ENROLL_VERSION	1
/*
 * The lock registers' protocol.  1 was a two-party Lamport bakery
 * {choosing, ticket}; 2 is the one-bit lock {want, raised} described at
 * mxfs_drbd_lock.  The two must never run against each other: a register of
 * the other version reads as busy unless it is all idle (both fields zero, the
 * state every release and attach leaves), so a mixed pair fails its swaps
 * rather than both entering.
 */
#define MXFS_DRBD_REG_VERSION	2
#define MXFS_DRBD_REG_VERSION_BAKERY	1
#define MXFS_DRBD_EP_LEN	48
/*
 * How long participant 0 holds back for participant 1 when 1 has lost a race
 * and is waiting (its `want`), before it raises its own flag regardless.  It
 * only orders the two: 0 still waits for 1's flag to drop.  A swap on the
 * physical pair takes up to ~3 s under guest load, so 4 s lets the waiting
 * peer's whole swap through; a peer that died with `want` set costs one
 * such wait, then its unchanged register is not deferred to again.
 */
#define MXFS_DRBD_DEFER_MS	4000

/* Sector 0 of the area: who the two participants are. */
struct mxfs_drbd_enroll {
	__le32	magic;
	__le16	version;
	__le16	pad;
	u8	fs_uuid[16];
	char	endpoint[2][MXFS_DRBD_EP_LEN];	/* participant 0's and 1's DRBD address */
	u8	reserved[512 - 24 - 2 * MXFS_DRBD_EP_LEN - 4];
	__le32	crc;
} __packed;

/* Sectors 1 and 2: one lock register per participant, written only by it. */
struct mxfs_drbd_reg {
	__le32	magic;
	__le16	version;
	__le16	index;
	u8	fs_uuid[16];
	__le64	boot_nonce;	/* this attachment's incarnation on that node */
	__le64	membership_gen;	/* advanced only when a fenced peer's register is cleared */
	__le32	want;		/* 1: lost a race, waiting for the peer's flag to drop
				 * (version 1: `choosing`) */
	__le32	pad;
	__le64	raised;		/* 1: entering or holding the lock (version 1: the ticket) */
	char	endpoint[MXFS_DRBD_EP_LEN];
	u8	reserved[512 - 56 - MXFS_DRBD_EP_LEN - 4];
	__le32	crc;
} __packed;

/* A leader serves at most this many swaps under one acquisition of the lock, so the
 * peer's wait for the lock stays bounded by a few dozen sector writes. */
#define MXFS_DRBD_CAS_BATCH	32

struct mxfs_drbd_cas {
	struct list_head	list;
	dev_t			devt;
	struct block_device	*bdev;
	u64			area_lba;	/* absolute LBA of the enrollment sector */
	unsigned int		index;
	u8			fs_uuid[16];
	char			endpoint[MXFS_DRBD_EP_LEN];
	char			peer_endpoint[MXFS_DRBD_EP_LEN];
	u64			boot_nonce;
	u64			membership_gen;	/* advanced each time a fenced peer's register is cleared */
	struct mutex		lock;		/* one local participant at a time */
	spinlock_t		qlock;		/* guards queue */
	struct list_head	queue;		/* swaps waiting for the next leader */
	int			refs;
	u64			ops, contended, miscompares, deferred, backoffs;
	/*
	 * THE RELEASE, AFTER THE CALLERS.  A batch's results are known once its
	 * target writes have completed, so the register write that drops our
	 * flag runs from rel_work, from its own buffer, after the callers have
	 * theirs.  Our register is then written from two places, and two writes
	 * in flight to one sector land in no defined order, so every writer of
	 * it waits for rel_work first (mxfs_drbd_rel_wait, under `lock`), and
	 * only the leader queues it, under `lock`.  rel_rc and rel_ns are its
	 * result, read after that wait.
	 */
	struct work_struct	rel_work;
	struct mxfs_drbd_reg	*rel_reg;
	int			rel_rc;
	u64			rel_ns;
	/*
	 * Participant 0's deferral that ran its bound (MXFS_DRBD_DEFER_MS): the
	 * peer's register as it read then.  While the peer's register still
	 * holds exactly these bytes it is not deferred to again; any write of
	 * the peer changes them.
	 */
	bool			defer_stale_set;
	u8			defer_stale_img[512];
	/*
	 * Where a swap's time goes, in ns, summed since the last stats line:
	 * waiting for this node's other swaps (lock), raising our flag (raise),
	 * waiting on the peer: deferral, its flag, backing off (wait), the
	 * target's read-compare-write (crit), the release's write, which no
	 * caller waits for (rel).  Read under `lock`; printed every
	 * MXFS_DRBD_STATS_EVERY swaps.
	 */
	u64			st_n, st_batches, st_lock, st_enter, st_wait, st_crit, st_rel, st_max;
	/*
	 * The exclusion judgment the mount supplies (dlm/drbdfence.c
	 * mxfs_drbd_judge_excluded): stateless, so it outlives any one mount.
	 * excl_next paces the witness while a swap waits on the peer's flag.
	 */
	int			(*judge_excluded)(const struct mxfs_pal_drbd_report *r,
						  char *why, size_t whylen);
	unsigned long		excl_next;
	/*
	 * A PEER REGISTER SET ASIDE.  After both nodes crash, the peer's
	 * register keeps whatever its dead attachment last wrote — a raised
	 * flag, or a want — until the peer mounts again, and every swap here
	 * would wait on it and fail.  A peer that is Secondary on a Connected
	 * link (judge_quiescent, kind 27's judgment) has no attachment at all:
	 * DRBD refuses a Secondary every write open, and a Primary cannot demote
	 * while a mount holds it open.  So a register read before such a
	 * report, while our own register was already written, was written by an
	 * attachment that is gone, and its exact 512 bytes are recorded here and
	 * read as idle for as long as the sector still holds them.  The register
	 * is never written: a later attachment of the peer first rewrites it
	 * under a fresh random boot_nonce, so its content differs from these
	 * bytes from its first write on, and its own raise then reads ours as
	 * the lock requires.  Zeroing it instead could erase the live flag of a
	 * peer that attached between the report and the write.  Any read that
	 * differs ends the setting aside for good.
	 */
	int			(*judge_quiescent)(const struct mxfs_pal_drbd_report *r,
						   char *why, size_t whylen);
	bool			void_set;
	u8			void_img[512];
	/*
	 * /proc/drbd as last read by a swap waiting on the peer's flag
	 * (mxfs_drbd_witness_could_pass), under `lock`; witness_skipped counts
	 * the waits that state answered without the witness.
	 */
	char			proc_buf[4096];
	u64			witness_skipped;
	/*
	 * The critical section's buffers, under `lock`, kmalloc'd at attach (a
	 * bio cannot be built on a caller's stack image): one read sector per
	 * swap of a batch (crit_buf), one write buffer per swap of a wave, long
	 * enough for a span swap's whole range (crit_wbuf), and the vectors
	 * handed to the PAL for a wave (mxfs_drbd_cas_serve).
	 */
	u8			*crit_buf;
	void			*crit_wbuf[MXFS_DRBD_CAS_BATCH];
	u64			crit_lba[MXFS_DRBD_CAS_BATCH];
	void			*crit_ptr[MXFS_DRBD_CAS_BATCH];
	u32			crit_len[MXFS_DRBD_CAS_BATCH];
	int			crit_rc[MXFS_DRBD_CAS_BATCH];
	int			crit_idx[MXFS_DRBD_CAS_BATCH];
	u64			st_waves;	/* waves served, since the last stats line */
};
#define MXFS_DRBD_STATS_EVERY	512
#define MXFS_DRBD_CRIT_BUF_BYTES	(MXFS_DRBD_CAS_BATCH * 512)
/* the longest write a span swap makes: one ledger page (crit_wbuf's length) */
#define MXFS_DRBD_SPAN_MAX	4096

static LIST_HEAD(mxfs_drbd_cas_list);
static DEFINE_MUTEX(mxfs_drbd_cas_list_lock);

/*
 * THE WAIT BOUND.  A critical section is one sector read and one replicated
 * write: milliseconds.  A peer that holds its flag for longer than this is
 * not in a critical section — it died holding it, or its I/O is frozen.  The
 * swap then FAILS (-EIO, the caller's I/O-error path) rather than proceeding:
 * a dead participant's flag may be set aside only once that participant is
 * fenced, which is the fence path's decision, never a timeout's.
 */
static unsigned int mxfs_drbd_cas_wait_ms = 10000;
module_param_named(drbd_cas_wait_ms, mxfs_drbd_cas_wait_ms, uint, 0644);
MODULE_PARM_DESC(drbd_cas_wait_ms,
		 "longest a DRBD compare-and-swap waits for the peer's lock flag before it fails");

/* DEBUG one-shot: the next swap on this node holds the lock this long inside
 * the critical section, so a test can kill the node while it holds the lock
 * (scripts/drbd_rig.sh death-test DEATH_HOLD_TICKET=1).  Never in production. */
static int mxfs_dbg_drbd_cas_hold_ms;
module_param_named(dbg_drbd_cas_hold_ms, mxfs_dbg_drbd_cas_hold_ms, int, 0644);
MODULE_PARM_DESC(dbg_drbd_cas_hold_ms,
		 "DEBUG one-shot: the next DRBD compare-and-swap holds the lock this many ms. Never enable in production.");

/*
 * SPAN SWAPS SHARE A WAVE.  Every ledger page commit on a DRBD store is a span
 * swap (one compared sector, the whole 4 KiB page written), and a span swap was
 * always served in a wave of its own: under one acquisition of the pair's lock,
 * a batch of N commits paid N reads and N replicated FUA writes in series.
 * Measured on the physical pair (0.90.109, a departure handing 621 pages with 8
 * threads): 2.2 swaps a batch, 14.4 ms of critical section a batch, 46 ms a
 * batch in all.  With this set, a wave holds every swap of the batch, in queue
 * order, up to the first whose range overlaps one already in the wave, whatever
 * their lengths: their compared sectors are read together and the matched
 * swaps' ranges written together.  Swaps whose ranges are disjoint touch no
 * sector of each other's, so serving them together reads and writes exactly
 * what serving them one after the other would.  Measured on the same pair
 * (0.90.110, tests/pve_depart_wall.sh KNOB=drbd_span_waves): a batch of ~4
 * page commits held the lock's critical section 17.5 ms against 25-26 ms, and
 * a departure cost 12.4-13.3 ms a page against 13.7-15.6.  The peer's disks
 * still take the writes one at a time (queue depth 1), which bounds the gain.
 * 0 = the old waves.
 */
static int mxfs_drbd_span_waves = 1;
module_param_named(drbd_span_waves, mxfs_drbd_span_waves, int, 0644);
MODULE_PARM_DESC(drbd_span_waves,
		 "1 = span swaps (ledger page commits) with disjoint ranges share a wave of the DRBD swap's critical section (the default); 0 = each span swap its own wave");

static u32 mxfs_drbd_crc(const void *sec)
{
	return mxfs_pal_crc32c(0, sec, 508);
}

static struct mxfs_drbd_cas *mxfs_drbd_cas_find(dev_t devt)
{
	struct mxfs_drbd_cas *e;

	list_for_each_entry(e, &mxfs_drbd_cas_list, list)
		if (e->devt == devt)
			return e;
	return NULL;
}

static int mxfs_drbd_sec_read(struct mxfs_drbd_cas *e, u64 lba, void *buf)
{
	return mxfs_pal_bdev_read_plain_bdev(e->bdev, lba, buf, 512);
}

static int mxfs_drbd_sec_write(struct mxfs_drbd_cas *e, u64 lba, const void *buf)
{
	return mxfs_pal_bio_write_fua_bdev(e->bdev, lba, buf, 512);
}

static bool mxfs_drbd_all_zero(const void *sec)
{
	const u8 *p = sec;
	int i;

	for (i = 0; i < 512; i++)
		if (p[i])
			return false;
	return true;
}

/* Write this node's register: {want, raised}. */
static int mxfs_drbd_reg_put(struct mxfs_drbd_cas *e, struct mxfs_drbd_reg *r,
			     u32 want, u64 raised)
{
	memset(r, 0, sizeof(*r));
	r->magic = cpu_to_le32(MXFS_DRBD_REG_MAGIC);
	r->version = cpu_to_le16(MXFS_DRBD_REG_VERSION);
	r->index = cpu_to_le16(e->index);
	memcpy(r->fs_uuid, e->fs_uuid, 16);
	r->boot_nonce = cpu_to_le64(e->boot_nonce);
	r->membership_gen = cpu_to_le64(e->membership_gen);
	r->want = cpu_to_le32(want);
	r->raised = cpu_to_le64(raised);
	strscpy(r->endpoint, e->endpoint, sizeof(r->endpoint));
	r->crc = cpu_to_le32(mxfs_drbd_crc(r));
	/*
	 * Without FUA.  A register excludes only live participants: what the
	 * lock needs is that the peer's next read sees it, and protocol C
	 * completes a write only once both disks have accepted it, which is
	 * what the peer's read of its own disk returns.  Stable media adds
	 * nothing across a crash (a participant's register is rewritten when it
	 * attaches, and a fenced one's is cleared by its survivor) and costs a
	 * cache flush on both disks for each register write of a swap.
	 * Measured: a departure's ~6,600 serial swaps at 10-15 ms each held two
	 * unmounts for 98 s.  The target's own write keeps FUA.
	 */
	return mxfs_pal_bio_write_sync_bdev(e->bdev, e->area_lba + 1 + e->index, r, 512);
}

/*
 * Read the peer's register.  Never written (all zero) reads as idle, and so
 * do the exact bytes set aside under void_img.  Any other content must be a
 * valid register of THIS filesystem, of the peer's index, from the peer's
 * endpoint.  Anything else — a sector torn by a power cut, corruption, a
 * misconfigured pair — reads as BUSY (raised), never as idle: the swap waits
 * on it and fails at the wait bound unless the peer is proven excluded (the
 * register is cleared) or without an attachment (it is set aside).  A
 * register of the bakery protocol (version 1) is idle only with both of its
 * fields zero: a peer still running it must never enter beside this one.
 */
static int mxfs_drbd_reg_get_peer(struct mxfs_drbd_cas *e, struct mxfs_drbd_reg *r,
				  u32 *want, u64 *raised)
{
	unsigned int peer = 1 - e->index;
	int rc = mxfs_drbd_sec_read(e, e->area_lba + 1 + peer, r);
	u16 ver;

	if (rc)
		return rc;
	if (e->void_set) {
		if (!memcmp(r, e->void_img, 512)) {
			*want = 0;
			*raised = 0;
			return 0;
		}
		e->void_set = false;
		pr_warn("mxfs: P-DRBD-CAS-PEER-SET-ASIDE-ENDED minor=%u index=%u -- the peer's register changed (an attachment of the peer wrote it); its flag counts again\n",
			MINOR(e->devt), e->index);
	}
	if (mxfs_drbd_all_zero(r)) {
		*want = 0;
		*raised = 0;
		return 0;
	}
	ver = le16_to_cpu(r->version);
	if (le32_to_cpu(r->magic) != MXFS_DRBD_REG_MAGIC ||
	    (ver != MXFS_DRBD_REG_VERSION && ver != MXFS_DRBD_REG_VERSION_BAKERY) ||
	    le32_to_cpu(r->crc) != mxfs_drbd_crc(r) ||
	    le16_to_cpu(r->index) != peer ||
	    memcmp(r->fs_uuid, e->fs_uuid, 16) ||
	    strncmp(r->endpoint, e->peer_endpoint, sizeof(r->endpoint)) ||
	    le32_to_cpu(r->want) > 1 ||
	    (ver == MXFS_DRBD_REG_VERSION && le64_to_cpu(r->raised) > 1)) {
		pr_err_ratelimited("mxfs: P-DRBD-CAS-PEER-REG-INVALID minor=%u peer_index=%u magic=0x%x version=%u crc_ok=%d index=%u endpoint='%.48s' want='%s' -- read as busy: the swap waits on it\n",
				   MINOR(e->devt), peer, le32_to_cpu(r->magic), ver,
				   le32_to_cpu(r->crc) == mxfs_drbd_crc(r),
				   le16_to_cpu(r->index), r->endpoint, e->peer_endpoint);
		*want = 0;
		*raised = 1;
		return 0;
	}
	if (ver == MXFS_DRBD_REG_VERSION_BAKERY) {
		bool idle = !r->want && !r->raised;

		if (!idle)
			pr_warn_ratelimited("mxfs: P-DRBD-CAS-PEER-BAKERY minor=%u peer_index=%u choosing=%u ticket=%llu -- the peer runs the older bakery lock; read as busy: the swap waits on it\n",
					    MINOR(e->devt), peer, le32_to_cpu(r->want),
					    (unsigned long long)le64_to_cpu(r->raised));
		*want = 0;
		*raised = idle ? 0 : 1;
		return 0;
	}
	*want = le32_to_cpu(r->want);
	*raised = le64_to_cpu(r->raised);
	return 0;
}

/*
 * The deferred releases run here.  Swaps are made from writeback and from the
 * module's own reclaim-safe workers, which wait for a release before the
 * next write of the register (flush_work), so its queue must be able to make
 * progress under memory pressure: WQ_MEM_RECLAIM gives it a rescuer thread.
 * Measured on the rig: flushing a release queued on system_unbound_wq from
 * such a worker drew the kernel's check_flush_dependency WARNING.
 */
static struct workqueue_struct *mxfs_drbd_rel_wq;

/* Our register's last write, if the deferred release made it, has completed. */
static void mxfs_drbd_rel_wait(struct mxfs_drbd_cas *e)
{
	flush_work(&e->rel_work);
}

static void mxfs_drbd_rel_fn(struct work_struct *w)
{
	struct mxfs_drbd_cas *e = container_of(w, struct mxfs_drbd_cas, rel_work);
	u64 t = ktime_get_ns();

	e->rel_rc = mxfs_drbd_reg_put(e, e->rel_reg, 0, 0);
	e->rel_ns = ktime_get_ns() - t;
	if (e->rel_rc)
		/* A flag that could not be dropped stays visible to the peer,
		 * which then waits and fails its own swaps until our next swap
		 * rewrites the register: never a correctness loss, but loud. */
		pr_err("mxfs: P-DRBD-CAS-RELEASE-FAILED minor=%u index=%u rc=%d\n",
		       MINOR(e->devt), e->index, e->rel_rc);
}

/*
 * Called with e->lock held from a swap waiting on the peer's flag, our own
 * register already written as {mywant, myraised}.  `reg` holds the peer's
 * register as last read.  The witness is taken for the attachment's minor;
 * if the judgment says the peer is excluded, its register is cleared, the
 * membership generation advanced and our own register (still {mywant,
 * myraised}) re-published under it.  If instead the peer is Secondary on a
 * Connected link, the register as read BEFORE the witness ran is set aside
 * (void_img).  1 = cleared or set aside: the caller reads the peer's register
 * again.
 */
static int mxfs_drbd_peer_excluded_locked(struct mxfs_drbd_cas *e,
					  struct mxfs_drbd_reg *reg,
					  u32 mywant, u64 myraised)
{
	struct mxfs_pal_drbd_report *r;
	char why[160] = "", whyq[160] = "";
	u8 *zero, *img;
	int rc;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	zero = kzalloc(1024, GFP_KERNEL);
	if (!r || !zero) {
		kfree(r);
		kfree(zero);
		return 0;
	}
	img = zero + 512;
	memcpy(img, reg, 512);
	rc = mxfs_drbdw_run(MINOR(e->devt), MXFS_PAL_DRBD_RECHECK, r);
	if (rc == 0)
		rc = e->judge_excluded ? e->judge_excluded(r, why, sizeof(why)) : -EPERM;
	if (rc && r->delivered && e->judge_quiescent &&
	    e->judge_quiescent(r, whyq, sizeof(whyq)) == 0) {
		/* No attachment exists on the peer at the report, and the image
		 * was read before it: the attachment that wrote it is gone. */
		memcpy(e->void_img, img, 512);
		e->void_set = true;
		pr_warn("mxfs: P-DRBD-CAS-PEER-SET-ASIDE minor=%u index=%u raised=%llu peer_version=%u peer_want=%u peer_raised=%llu peer_nonce=%016llx -- the peer is Secondary on a Connected link, so no attachment of it is alive; the register its dead attachment left is read as idle while unchanged, and never written\n",
			MINOR(e->devt), e->index, (unsigned long long)myraised,
			le16_to_cpu(((struct mxfs_drbd_reg *)img)->version),
			le32_to_cpu(((struct mxfs_drbd_reg *)img)->want),
			(unsigned long long)le64_to_cpu(((struct mxfs_drbd_reg *)img)->raised),
			(unsigned long long)le64_to_cpu(((struct mxfs_drbd_reg *)img)->boot_nonce));
		kfree(r);
		kfree(zero);
		return 1;
	}
	if (rc) {
		pr_warn_ratelimited("mxfs: P-DRBD-CAS-PEER-NOT-EXCLUDED minor=%u index=%u why='%s' quiescent='%s' -- the peer's flag stands\n",
				    MINOR(e->devt), e->index, why, whyq);
		kfree(r);
		kfree(zero);
		return 0;
	}
	e->membership_gen++;
	rc = mxfs_drbd_sec_write(e, e->area_lba + 1 + (1 - e->index), zero);
	if (!rc)
		rc = mxfs_drbd_reg_put(e, reg, mywant, myraised);
	pr_warn("mxfs: P-DRBD-CAS-PEER-EXCLUDED minor=%u index=%u peer=%s episode=%s membership_gen=%llu rc=%d -- the peer is excluded (kind-25 evidence); its register is cleared\n",
		MINOR(e->devt), e->index, r->peer_host, r->receipt_episode,
		e->membership_gen, rc);
	kfree(r);
	kfree(zero);
	return rc == 0;
}

/*
 * This minor's connection state and the peer's role, from /proc/drbd as DRBD
 * 8.4 prints a minor (" 0: cs:Connected ro:Primary/Primary ds:UpToDate/..."),
 * read in this process.  1 = the minor's line was found; `peer` is empty when
 * the line has no roles (Unconfigured).  0 = unreadable, or no such line.
 */
static int mxfs_drbd_proc_state(struct mxfs_drbd_cas *e, char *cs, size_t cslen,
				char *peer, size_t peerlen)
{
	unsigned int minor = MINOR(e->devt);
	struct file *f;
	loff_t pos = 0;
	ssize_t n;
	char *line, *next;

	f = filp_open("/proc/drbd", O_RDONLY, 0);
	if (IS_ERR(f))
		return 0;
	n = kernel_read(f, e->proc_buf, sizeof(e->proc_buf) - 1, &pos);
	filp_close(f, NULL);
	if (n <= 0)
		return 0;
	e->proc_buf[n] = '\0';
	for (line = e->proc_buf; line; line = next) {
		unsigned int m;
		int used = 0;
		size_t k;
		char *ro;

		next = strchr(line, '\n');
		if (next)
			*next++ = '\0';
		if (sscanf(line, " %u: cs:%n", &m, &used) != 1 || !used || m != minor)
			continue;
		for (k = 0; k + 1 < cslen && line[used + k] && line[used + k] != ' '; k++)
			cs[k] = line[used + k];
		cs[k] = '\0';
		peer[0] = '\0';
		ro = strstr(line + used, " ro:");
		if (ro) {
			ro = strchr(ro, '/');
			for (k = 0; ro && k + 1 < peerlen && ro[k + 1] && ro[k + 1] != ' '; k++)
				peer[k] = ro[k + 1];
			peer[k] = '\0';
		}
		return 1;
	}
	return 0;
}

/*
 * Whether the witness could find the peer excluded or quiescent now.  The
 * judgments it feeds (dlm/drbdfence.c) need the link WFConnection or
 * StandAlone (excluded), or Connected with the peer Secondary (quiescent).
 * In any other state, the peer Primary on a Connected or syncing link above
 * all, both refuse whatever else the report says, so the witness is not run.
 * It is a userspace program that runs drbdadm and the fence authority, and
 * this swap waits for it with its own register written, which the peer's own
 * swaps wait on in turn.  Measured on the physical pair under VM installs
 * (0.90.76): on a host short of memory one such run took at least 21 s,
 * though the peer was Primary on a Connected link throughout.  Both hosts'
 * heartbeat swaps failed, and that host's authority lease expired.
 * /proc/drbd unreadable, or no line for this minor: the witness decides.
 */
static bool mxfs_drbd_witness_could_pass(struct mxfs_drbd_cas *e)
{
	char cs[24], peer[24];

	if (!mxfs_drbd_proc_state(e, cs, sizeof(cs), peer, sizeof(peer)))
		return true;
	if (!strcmp(cs, "WFConnection") || !strcmp(cs, "StandAlone"))
		return true;
	return !strcmp(cs, "Connected") && !strcmp(peer, "Secondary");
}

/* Register the mount's judgments on the attachment of `dev`. */
void mxfs_pal_drbd_cas_set_judge(mxfs_bdev_t *dev,
				 int (*excluded)(const struct mxfs_pal_drbd_report *r,
						 char *why, size_t whylen),
				 int (*quiescent)(const struct mxfs_pal_drbd_report *r,
						  char *why, size_t whylen))
{
	struct block_device *bdev = dev ? mxfs_pal_bdev_get_bdev(dev) : NULL;
	struct mxfs_drbd_cas *e;

	if (!bdev)
		return;
	mutex_lock(&mxfs_drbd_cas_list_lock);
	e = mxfs_drbd_cas_find(bdev->bd_dev);
	mutex_unlock(&mxfs_drbd_cas_list_lock);
	if (!e)
		return;
	mutex_lock(&e->lock);
	e->judge_excluded = excluded;
	e->judge_quiescent = quiescent;
	mutex_unlock(&e->lock);
}
EXPORT_SYMBOL_GPL(mxfs_pal_drbd_cas_set_judge);

/* One swap waiting for a leader.  Lives on its caller's stack; the caller
 * sleeps on e->lock until a leader has set `done`. */
struct mxfs_drbd_cas_req {
	struct list_head	node;
	u64			lba;
	const void		*compare_buf;
	const void		*write_buf;
	u32			wlen;		/* bytes written from lba on a match: 512, or
						 * up to MXFS_DRBD_SPAN_MAX for a span swap */
	u64			tq;		/* when it was queued */
	int			rc;
	bool			done;
};

/*
 * One pause while the peer's register holds this swap up, with our own
 * register written as {mywant, myraised}.  `*start` is when the swap first
 * had to wait (0: not yet); the wait bound runs from there.  0 = read the
 * peer's register again; <0 = fail the swap.
 */
static int mxfs_drbd_wait_step(struct mxfs_drbd_cas *e, struct mxfs_drbd_reg *reg,
			       unsigned long *start, unsigned int *sleep_us,
			       u32 mywant, u64 myraised, u32 pwant, u64 praised)
{
	if (!*start) {
		*start = jiffies;
		e->contended++;
	}
	/*
	 * A peer that died holding its flag keeps it for ever, and the
	 * certificate that would clear it (mxfs_pal_drbd_cas_peer_fenced) needs
	 * swaps to be written: measured, every swap on the survivor then failed
	 * after 10 s and it withdrew itself.  So once a swap has waited a
	 * second, ask the witness whether the peer is excluded by the evidence
	 * kind 25 or 26 is built from (link disconnected, peer Outdated, a
	 * receipt, the authority holding it off under that episode).  If it is,
	 * its register is cleared and the membership generation advanced
	 * exactly as the certificate path does.  If the peer is instead
	 * Secondary on a Connected link (both nodes restarted after a pair
	 * outage), the register its dead attachment left is set aside unwritten
	 * (void_img).  Never on age alone.  Only in a DRBD state where either
	 * can be true: mxfs_drbd_witness_could_pass says why.
	 */
	if ((e->judge_excluded || e->judge_quiescent) &&
	    time_after(jiffies, *start + HZ) &&
	    time_after_eq(jiffies, e->excl_next)) {
		e->excl_next = jiffies + 2 * HZ;
		if (!mxfs_drbd_witness_could_pass(e)) {
			e->witness_skipped++;
		} else if (mxfs_drbd_peer_excluded_locked(e, reg, mywant, myraised)) {
			*sleep_us = 100;
			return 0;
		}
	}
	if (time_after(jiffies, *start + msecs_to_jiffies(mxfs_drbd_cas_wait_ms))) {
		pr_err("mxfs: P-DRBD-CAS-WAIT-TIMEOUT minor=%u index=%u want=%u raised=%llu peer_want=%u peer_raised=%llu waited_ms=%u -- the peer holds its flag past any critical section; failing the swap\n",
		       MINOR(e->devt), e->index, mywant, (unsigned long long)myraised,
		       pwant, (unsigned long long)praised, mxfs_drbd_cas_wait_ms);
		return -EIO;
	}
	usleep_range(*sleep_us, *sleep_us * 2);
	if (*sleep_us < 5000)
		*sleep_us *= 2;
	return 0;
}

/*
 * THE LOCK: a one-bit lock for two (Burns and Lamport), participant 0 first.
 * Each register is a sector written only by its participant, every write is
 * waited for before the next read (protocol C completes a write once both
 * disks hold it, so a read issued after a write's completion on one host and
 * a read issued after the other's on the other cannot both miss), and so of
 * two participants that raise their flags and then read the other's, at
 * least one sees the other's.
 *
 *   participant 0:  raise {want 0, raised 1}; wait until the peer's flag is
 *                   down; enter.
 *   participant 1:  raise {want w, raised 1}; read the peer's flag: down,
 *                   enter; up, lower {want 1, raised 0}, wait until the
 *                   peer's flag is down, and raise again with w = 1.
 *   release:        {0, 0}, after every target write has completed.
 *
 * FAIRNESS.  Participant 1 yields every race, so 0 could take the lock again
 * and again while 1 waits.  1's `want` stays set from its first lost race to
 * its release, and 0 does not raise while the peer's `want` is set
 * (MXFS_DRBD_DEFER_MS bounds that wait, which only orders the two: 0 still
 * waits for 1's flag).  Checked over every interleaving and every order in
 * which a write lands on the two disks by tests/drbd_cas_lock_model.py:
 * mutual exclusion, no deadlock, and no second entry of 0 once 1's `want` is
 * on 0's disk.
 *
 * WHY NOT THE BAKERY.  A bakery acquisition is two register writes (choosing,
 * then the ticket) before the target's read-compare-write, and one after it,
 * each a replicated write.  On the physical pair (non-NCQ SATA SSDs, queue
 * depth 1, under guest load) one such write takes up to ~2 s, and a swap that
 * paid four of them in a row took up to 11.6 s, past the heartbeat's 8 s stall
 * bound.  This lock enters with one write, and its release runs after the
 * callers have their results (rel_work), so a swap waits for one register
 * write and its own target write.
 *
 * Returns 0 holding the lock.  *dirty: our register was written, so a release
 * is owed whatever the outcome.  *t_raised: when the first raise completed.
 */
static int mxfs_drbd_lock(struct mxfs_drbd_cas *e, struct mxfs_drbd_reg *reg,
			  bool *dirty, u64 *t_raised)
{
	unsigned long start = 0;
	unsigned int sleep_us = 100;
	u32 pwant, w = 0;
	u64 praised;
	int rc;

	*dirty = false;
	*t_raised = 0;
	if (e->index == 0) {
		unsigned long dstart = jiffies;
		bool counted = false;

		for (;;) {
			rc = mxfs_drbd_reg_get_peer(e, reg, &pwant, &praised);
			if (rc)
				return rc;
			if (!pwant) {
				e->defer_stale_set = false;
				break;
			}
			if (e->defer_stale_set && !memcmp(reg, e->defer_stale_img, 512))
				break;
			if (time_after(jiffies, dstart + msecs_to_jiffies(MXFS_DRBD_DEFER_MS))) {
				memcpy(e->defer_stale_img, reg, 512);
				e->defer_stale_set = true;
				pr_warn_ratelimited("mxfs: P-DRBD-CAS-DEFER-BOUND minor=%u peer_raised=%llu -- the peer's want stood for %u ms; raising regardless, and not deferring to this register again while it is unchanged\n",
						    MINOR(e->devt), (unsigned long long)praised,
						    MXFS_DRBD_DEFER_MS);
				break;
			}
			if (!counted) {
				e->deferred++;
				counted = true;
			}
			usleep_range(sleep_us, sleep_us * 2);
			if (sleep_us < 5000)
				sleep_us *= 2;
		}
		sleep_us = 100;
	}

	for (;;) {
		rc = mxfs_drbd_reg_put(e, reg, w, 1);
		*dirty = true;
		if (rc)
			return rc;
		if (!*t_raised)
			*t_raised = ktime_get_ns();
		for (;;) {
			rc = mxfs_drbd_reg_get_peer(e, reg, &pwant, &praised);
			if (rc)
				return rc;
			if (!praised)
				return 0;
			if (e->index == 1)
				break;
			rc = mxfs_drbd_wait_step(e, reg, &start, &sleep_us, w, 1,
						 pwant, praised);
			if (rc)
				return rc;
		}
		/* participant 1 lost the race: flag down, want up, wait for 0 */
		e->backoffs++;
		w = 1;
		rc = mxfs_drbd_reg_put(e, reg, 1, 0);
		if (rc)
			return rc;
		for (;;) {
			rc = mxfs_drbd_reg_get_peer(e, reg, &pwant, &praised);
			if (rc)
				return rc;
			if (!praised)
				break;
			rc = mxfs_drbd_wait_step(e, reg, &start, &sleep_us, 1, 0,
						 pwant, praised);
			if (rc)
				return rc;
		}
	}
}

/*
 * The swap: lock, read-compare-write the target, release.  The release is
 * ordered after the target write has completed with FUA, so the peer can
 * never hold the lock while our write is still in flight.
 *
 * GROUP COMMIT.  Every swap on this node is serialised by e->lock, and each
 * acquisition costs at least one replicated register write to enter and one
 * to release, on top of the target's read-compare-write.
 * Measured on the 2-node rig: ~3 ms doorway, ~1 ms release, ~1-2 ms target,
 * and swaps queued behind e->lock for 130 ms on average under a directory
 * workload, which pushed lock handoffs past the 1 s acquire wait.  So swaps
 * queue, and whoever takes e->lock serves every queued swap (up to
 * MXFS_DRBD_CAS_BATCH) inside one acquisition, and releases once, after every
 * target write has completed.  Mutual exclusion with the peer and the release
 * ordering are those of a single swap.
 *
 * THE BATCH IN WAVES.  Inside the acquisition the swaps are served in waves of
 * distinct sectors: a wave's target reads are issued together, each compared,
 * and the writes of those that matched issued together and all waited for.  A
 * swap whose sector an earlier swap of the batch targets starts the next wave,
 * so it reads that swap's write, as it would served one after the other in
 * queue order.  Served one at a time, every target write was a replicated FUA
 * round trip of its own with the pair's lock held, and a batch of them cost
 * that many in series.
 */
static void mxfs_drbd_cas_serve(struct mxfs_drbd_cas *e)
{
	struct mxfs_drbd_cas_req *batch[MXFS_DRBD_CAS_BATCH];
	struct mxfs_drbd_cas_req *r, *tmp;
	struct mxfs_drbd_reg *reg;
	bool dirty = false, spanw;
	int n = 0, i, j, k, m, nw, rc, vrc;
	u64 t1, t2, t3, t4, traised;

	spin_lock(&e->qlock);
	list_for_each_entry_safe(r, tmp, &e->queue, node) {
		if (n == MXFS_DRBD_CAS_BATCH)
			break;
		list_del_init(&r->node);
		batch[n++] = r;
	}
	spin_unlock(&e->qlock);
	if (!n)
		return;

	reg = kmalloc(512, GFP_KERNEL);
	if (!reg) {
		for (i = 0; i < n; i++) {
			batch[i]->rc = -ENOMEM;
			batch[i]->done = true;
		}
		return;
	}
	/*
	 * A target image is written from e->crit_wbuf, never from the caller's
	 * buffer: COMPARE AND WRITE copies its data into a page of its own, so
	 * callers hand it stack images (mxfs_bootstrap_claim's `want`), and a
	 * bio cannot be built on a vmalloc'd kernel stack.  Measured: the
	 * bootstrap claim on /dev/drbd0 failed -EINVAL after a pair outage.
	 */

	/* our register's last write (the previous release) has landed */
	mxfs_drbd_rel_wait(e);
	e->st_rel += e->rel_ns;
	e->rel_ns = 0;

	t1 = ktime_get_ns();
	e->ops += n;
	rc = mxfs_drbd_lock(e, reg, &dirty, &traised);
	t3 = t4 = ktime_get_ns();
	t2 = traised ? traised : t3;
	if (rc)
		goto release;

	/* critical section: every queued swap, in order */
	{
		int hold = READ_ONCE(mxfs_dbg_drbd_cas_hold_ms);

		if (unlikely(hold > 0) && xchg(&mxfs_dbg_drbd_cas_hold_ms, 0) == hold) {
			pr_warn("mxfs: P-DBG-DRBD-CAS-HOLD minor=%u index=%u hold_ms=%d -- holding the lock (test)\n",
				MINOR(e->devt), e->index, hold);
			msleep(hold);
		}
	}
	spanw = READ_ONCE(mxfs_drbd_span_waves);
	for (i = 0; i < n; i = j) {
		/* the wave: swaps i..j-1, up to the first whose range overlaps one
		 * already in it (for one-sector swaps: whose sector repeats).  A
		 * span swap writes sectors past the one it compares; without
		 * drbd_span_waves it is served in a wave of its own, so no other
		 * swap of the wave can target a sector it writes, in either order */
		for (j = i + 1; j < n; j++) {
			if (!spanw && (batch[i]->wlen > 512 || batch[j]->wlen > 512))
				break;
			for (k = i; k < j; k++)
				if (batch[k]->lba < batch[j]->lba + batch[j]->wlen / 512 &&
				    batch[j]->lba < batch[k]->lba + batch[k]->wlen / 512)
					break;
			if (k < j)
				break;
		}
		e->st_waves++;
		for (k = i; k < j; k++) {
			e->crit_lba[k - i] = batch[k]->lba;
			e->crit_ptr[k - i] = e->crit_buf + (k - i) * 512;
		}
		vrc = mxfs_pal_bio_read_sectors_bdev(e->bdev, j - i, e->crit_lba,
						     e->crit_ptr, e->crit_rc);
		nw = 0;
		for (k = i; k < j; k++) {
			r = batch[k];
			r->rc = vrc ? vrc : e->crit_rc[k - i];
			if (r->rc)
				continue;
			if (memcmp(e->crit_buf + (k - i) * 512, r->compare_buf, 512)) {
				e->miscompares++;
				r->rc = -EAGAIN;
				continue;
			}
			/* from a buffer of our own: a caller's image may be on a
			 * stack, which no bio is built on */
			memcpy(e->crit_wbuf[nw], r->write_buf, r->wlen);
			e->crit_idx[nw++] = k;
		}
		if (!nw)
			continue;
		/* every matched swap's whole range, FUA, issued together */
		for (m = 0; m < nw; m++) {
			r = batch[e->crit_idx[m]];
			e->crit_lba[m] = r->lba;
			e->crit_ptr[m] = e->crit_wbuf[m];
			e->crit_len[m] = r->wlen;
		}
		vrc = mxfs_pal_bio_write_fua_spans_bdev(e->bdev, nw, e->crit_lba,
							e->crit_ptr, e->crit_len,
							e->crit_rc);
		for (m = 0; m < nw; m++)
			batch[e->crit_idx[m]]->rc = vrc ? vrc : e->crit_rc[m];
	}
	t4 = ktime_get_ns();
release:
	/*
	 * Every target write has completed (with FUA), so each caller's result
	 * is final: the flag drops from rel_work while they go on.  The next
	 * writer of our register waits for it (mxfs_drbd_rel_wait).
	 */
	if (dirty)
		queue_work(mxfs_drbd_rel_wq, &e->rel_work);
	for (i = 0; i < n; i++) {
		r = batch[i];
		if (rc)			/* never reached the critical section */
			r->rc = rc;
		r->done = true;
	}

	e->st_n += n;
	e->st_batches++;
	for (i = 0; i < n; i++)
		e->st_lock += t1 - batch[i]->tq;
	e->st_enter += t2 - t1;
	e->st_wait += t3 - t2;
	e->st_crit += t4 - t3;
	if (t4 - batch[0]->tq > e->st_max)
		e->st_max = t4 - batch[0]->tq;
	if (e->st_n >= MXFS_DRBD_STATS_EVERY) {
		/* per swap: lock (its own wait); per batch: the rest */
		mxfs_probe("mxfs: P-DRBD-CAS-STATS minor=%u swaps=%llu batches=%llu waves=%llu avg_us lock/swap=%llu enter/batch=%llu wait/batch=%llu crit/batch=%llu rel/batch=%llu max_us=%llu ops=%llu contended=%llu deferred=%llu backoffs=%llu miscompares=%llu witness_skipped=%llu\n",
			   MINOR(e->devt), e->st_n, e->st_batches, e->st_waves,
			   e->st_lock / e->st_n / 1000,
			   e->st_enter / e->st_batches / 1000,
			   e->st_wait / e->st_batches / 1000,
			   e->st_crit / e->st_batches / 1000,
			   e->st_rel / e->st_batches / 1000, e->st_max / 1000,
			   e->ops, e->contended, e->deferred, e->backoffs,
			   e->miscompares, e->witness_skipped);
		e->st_n = e->st_batches = e->st_waves = e->st_lock = e->st_enter = 0;
		e->st_wait = e->st_crit = e->st_rel = e->st_max = 0;
	}
	kfree(reg);
}

static int mxfs_drbd_cas_run(struct mxfs_drbd_cas *e, u64 lba,
			     const void *compare_buf, const void *write_buf, u32 wlen)
{
	struct mxfs_drbd_cas_req req = {
		.lba = lba, .compare_buf = compare_buf, .write_buf = write_buf,
		.wlen = wlen, .tq = ktime_get_ns(),
	};

	spin_lock(&e->qlock);
	list_add_tail(&req.node, &e->queue);
	spin_unlock(&e->qlock);
	/*
	 * Whoever holds e->lock serves the queue; a swap it took is done when
	 * this caller gets the lock.  One that is not (it queued after the
	 * leader's sweep, or past the batch cap) is served by this caller as the
	 * next leader — it is at the head of what remains, so it is in the batch.
	 */
	mutex_lock(&e->lock);
	while (!req.done)
		mxfs_drbd_cas_serve(e);
	mutex_unlock(&e->lock);
	return req.rc;
}

/* The absolute LBA a swap at `offset` on `dev` targets, or a negative errno. */
static int mxfs_drbd_cas_target(struct mxfs_drbd_cas *e, mxfs_bdev_t *dev,
				uint64_t offset, u64 *lba)
{
	u64 abs = offset + mxfs_pal_bdev_get_base_offset(dev);

	if (abs & 511)
		return -EINVAL;
	/* The lock's own sectors are never a swap target. */
	if (abs / 512 >= e->area_lba && abs / 512 < e->area_lba + 3)
		return -EINVAL;
	*lba = abs / 512;
	return 0;
}

static struct mxfs_drbd_cas *mxfs_drbd_cas_of(mxfs_bdev_t *dev)
{
	struct block_device *bdev = mxfs_pal_bdev_get_bdev(dev);
	struct mxfs_drbd_cas *e;

	if (!bdev)
		return NULL;
	mutex_lock(&mxfs_drbd_cas_list_lock);
	e = mxfs_drbd_cas_find(bdev->bd_dev);
	mutex_unlock(&mxfs_drbd_cas_list_lock);
	return e;
}

/* Called by mxfs_pal_bdev_compare_and_write for a device with no SCSI underneath. */
int mxfs_pal_drbd_cas_emulate(mxfs_bdev_t *dev, uint64_t offset,
			      const void *compare_buf, const void *write_buf)
{
	struct mxfs_drbd_cas *e;
	u64 lba;
	int rc;

	if (!mxfs_pal_bdev_get_bdev(dev))
		return -EINVAL;
	e = mxfs_drbd_cas_of(dev);
	if (!e)
		return -EOPNOTSUPP;
	rc = mxfs_drbd_cas_target(e, dev, offset, &lba);
	if (rc)
		return rc;
	return mxfs_drbd_cas_run(e, lba, compare_buf, write_buf, 512);
}

/*
 * Called by mxfs_pal_bdev_compare_and_write_span for a device with no SCSI
 * underneath: compare the sector at `offset`, and on a match write `write_len`
 * bytes from it, all inside one acquisition of the pair's lock.  Every write to
 * the range that is not a swap's is the caller's to exclude (the ledger's page
 * copies are written only by swaps on such a device).
 */
int mxfs_pal_drbd_cas_emulate_span(mxfs_bdev_t *dev, uint64_t offset,
				   const void *compare_buf, const void *write_buf,
				   uint32_t write_len)
{
	struct mxfs_drbd_cas *e;
	u64 lba;
	int rc;

	if (!mxfs_pal_bdev_get_bdev(dev) || !compare_buf || !write_buf ||
	    write_len < 512 || write_len > MXFS_DRBD_SPAN_MAX || (write_len & 511))
		return -EINVAL;
	e = mxfs_drbd_cas_of(dev);
	if (!e)
		return -EOPNOTSUPP;
	rc = mxfs_drbd_cas_target(e, dev, offset, &lba);
	if (rc)
		return rc;
	/* nor may the range reach the lock's own sectors */
	if (lba < e->area_lba + 3 && lba + write_len / 512 > e->area_lba)
		return -EINVAL;
	return mxfs_drbd_cas_run(e, lba, compare_buf, write_buf, write_len);
}

/*
 * Called by mxfs_pal_bdev_compare_and_write_many for a device with no SCSI
 * underneath.  Every swap is queued at once, in order, so one leader serves
 * them under as few acquisitions of the pair's lock as the batch cap allows
 * (one for up to MXFS_DRBD_CAS_BATCH of them), where swaps issued one after
 * the other each pay a whole acquisition.  Each swap's result is its own.
 */
int mxfs_pal_drbd_cas_emulate_many(mxfs_bdev_t *dev, int n, const uint64_t *offsets,
				   const void *const *compare_bufs,
				   const void *const *write_bufs, int *rcs)
{
	struct mxfs_drbd_cas_req *reqs;
	struct mxfs_drbd_cas *e;
	bool pending;
	u64 tq;
	int i;

	if (!mxfs_pal_bdev_get_bdev(dev) || n <= 0 || !offsets || !compare_bufs ||
	    !write_bufs || !rcs)
		return -EINVAL;
	e = mxfs_drbd_cas_of(dev);
	if (!e)
		return -EOPNOTSUPP;
	reqs = kcalloc(n, sizeof(*reqs), GFP_KERNEL);
	if (!reqs)
		return -ENOMEM;
	tq = ktime_get_ns();
	for (i = 0; i < n; i++) {
		INIT_LIST_HEAD(&reqs[i].node);
		reqs[i].compare_buf = compare_bufs[i];
		reqs[i].write_buf = write_bufs[i];
		reqs[i].wlen = 512;
		reqs[i].tq = tq;
		reqs[i].rc = mxfs_drbd_cas_target(e, dev, offsets[i], &reqs[i].lba);
		if (reqs[i].rc || !compare_bufs[i] || !write_bufs[i]) {
			if (!reqs[i].rc)
				reqs[i].rc = -EINVAL;
			reqs[i].done = true;
		}
	}
	spin_lock(&e->qlock);
	for (i = 0; i < n; i++)
		if (!reqs[i].done)
			list_add_tail(&reqs[i].node, &e->queue);
	spin_unlock(&e->qlock);
	mutex_lock(&e->lock);
	for (;;) {
		pending = false;
		for (i = 0; i < n && !pending; i++)
			pending = !reqs[i].done;
		if (!pending)
			break;
		mxfs_drbd_cas_serve(e);
	}
	mutex_unlock(&e->lock);
	for (i = 0; i < n; i++)
		rcs[i] = reqs[i].rc;
	kfree(reqs);
	return 0;
}

/* An attachment's buffers (struct mxfs_drbd_cas says what each is for).  A
 * kmalloc of MXFS_DRBD_SPAN_MAX bytes is naturally aligned, so a span swap's
 * write never crosses a page. */
static int mxfs_drbd_cas_bufs_alloc(struct mxfs_drbd_cas *e)
{
	int i;

	e->crit_buf = kmalloc(MXFS_DRBD_CRIT_BUF_BYTES, GFP_KERNEL);
	e->rel_reg = kmalloc(512, GFP_KERNEL);
	if (!e->crit_buf || !e->rel_reg)
		return -ENOMEM;
	for (i = 0; i < MXFS_DRBD_CAS_BATCH; i++) {
		e->crit_wbuf[i] = kmalloc(MXFS_DRBD_SPAN_MAX, GFP_KERNEL);
		if (!e->crit_wbuf[i])
			return -ENOMEM;
	}
	return 0;
}

static void mxfs_drbd_cas_free(struct mxfs_drbd_cas *e)
{
	int i;

	if (!e)
		return;
	for (i = 0; i < MXFS_DRBD_CAS_BATCH; i++)
		kfree(e->crit_wbuf[i]);
	kfree(e->crit_buf);
	kfree(e->rel_reg);
	kfree(e);
}

/*
 * The pair's enrollment: participant 0's and 1's endpoints, bound to the
 * filesystem.  Written by whichever node arrives first; both nodes, if they
 * agree, write the same bytes.  A node that finds an enrollment naming a
 * different pair — or that reads back something other than what it wrote —
 * refuses: two nodes that disagree about who is participant 0 must never both
 * run the lock.
 */
static int mxfs_drbd_enroll(struct mxfs_drbd_cas *e)
{
	struct mxfs_drbd_enroll *want, *got;
	int rc;

	want = kzalloc(1024, GFP_KERNEL);
	if (!want)
		return -ENOMEM;
	got = (void *)((u8 *)want + 512);
	want->magic = cpu_to_le32(MXFS_DRBD_ENROLL_MAGIC);
	want->version = cpu_to_le16(MXFS_DRBD_ENROLL_VERSION);
	memcpy(want->fs_uuid, e->fs_uuid, 16);
	strscpy(want->endpoint[e->index], e->endpoint, MXFS_DRBD_EP_LEN);
	strscpy(want->endpoint[1 - e->index], e->peer_endpoint, MXFS_DRBD_EP_LEN);
	want->crc = cpu_to_le32(mxfs_drbd_crc(want));

	rc = mxfs_drbd_sec_read(e, e->area_lba, got);
	if (!rc && mxfs_drbd_all_zero(got)) {
		rc = mxfs_drbd_sec_write(e, e->area_lba, want);
		if (!rc)
			rc = mxfs_drbd_sec_read(e, e->area_lba, got);
	}
	if (!rc && memcmp(want, got, 512)) {
		pr_err("mxfs: P-DRBD-CAS-ENROLL-MISMATCH minor=%u this node: index=%u endpoints=[%s,%s]; on disk: magic=0x%x endpoints=[%.48s,%.48s] -- refusing: the pair disagrees about who is participant 0\n",
		       MINOR(e->devt), e->index, want->endpoint[0], want->endpoint[1],
		       le32_to_cpu(got->magic), got->endpoint[0], got->endpoint[1]);
		rc = -EIO;
	}
	kfree(want);
	return rc;
}

int mxfs_pal_drbd_cas_attach(mxfs_bdev_t *dev, uint64_t region_off,
			     unsigned int index, const uint8_t fs_uuid[16],
			     const char *endpoint, const char *peer_endpoint)
{
	struct block_device *bdev = mxfs_pal_bdev_get_bdev(dev);
	struct mxfs_drbd_cas *e, *have;
	struct mxfs_drbd_reg *r;
	u64 abs = region_off + mxfs_pal_bdev_get_base_offset(dev);
	int rc;

	if (!bdev || index > 1 || !fs_uuid || !endpoint || !peer_endpoint ||
	    !endpoint[0] || !peer_endpoint[0] || !strcmp(endpoint, peer_endpoint) ||
	    strlen(endpoint) >= MXFS_DRBD_EP_LEN ||
	    strlen(peer_endpoint) >= MXFS_DRBD_EP_LEN || (abs & 511))
		return -EINVAL;
	if (mxfs_pal_bdev_drbd_minor(dev) < 0)
		return -ENODEV;

	mutex_lock(&mxfs_drbd_cas_list_lock);
	have = mxfs_drbd_cas_find(bdev->bd_dev);
	if (have) {
		/* Another mount handle on this node: it must be the same pair. */
		if (have->index != index || have->area_lba != abs / 512 ||
		    memcmp(have->fs_uuid, fs_uuid, 16) ||
		    strcmp(have->endpoint, endpoint)) {
			mutex_unlock(&mxfs_drbd_cas_list_lock);
			return -EBUSY;
		}
		have->refs++;
		mutex_unlock(&mxfs_drbd_cas_list_lock);
		mxfs_pal_bdev_set_drbd_cas(dev, true);
		return 0;
	}
	mutex_unlock(&mxfs_drbd_cas_list_lock);

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	r = kmalloc(512, GFP_KERNEL);
	if (!e || !r || mxfs_drbd_cas_bufs_alloc(e)) {
		mxfs_drbd_cas_free(e);
		kfree(r);
		return -ENOMEM;
	}
	INIT_WORK(&e->rel_work, mxfs_drbd_rel_fn);
	e->devt = bdev->bd_dev;
	e->bdev = bdev;
	e->area_lba = abs / 512;
	e->index = index;
	memcpy(e->fs_uuid, fs_uuid, 16);
	strscpy(e->endpoint, endpoint, sizeof(e->endpoint));
	strscpy(e->peer_endpoint, peer_endpoint, sizeof(e->peer_endpoint));
	e->boot_nonce = get_random_u64();
	mutex_init(&e->lock);
	spin_lock_init(&e->qlock);
	INIT_LIST_HEAD(&e->queue);
	e->refs = 1;

	rc = mxfs_drbd_enroll(e);
	/*
	 * Our own register: one left by an earlier incarnation of THIS node is
	 * set to idle — nothing on this node holds the lock, since no attachment
	 * of this device exists here.  One that names another endpoint is a
	 * second node claiming our index, and is refused.
	 */
	if (!rc)
		rc = mxfs_drbd_sec_read(e, e->area_lba + 1 + index, r);
	if (!rc && !mxfs_drbd_all_zero(r) &&
	    (le32_to_cpu(r->magic) != MXFS_DRBD_REG_MAGIC ||
	     le32_to_cpu(r->crc) != mxfs_drbd_crc(r) ||
	     memcmp(r->fs_uuid, fs_uuid, 16) ||
	     strncmp(r->endpoint, endpoint, sizeof(r->endpoint)))) {
		pr_err("mxfs: P-DRBD-CAS-OWN-REG-FOREIGN minor=%u index=%u register names endpoint='%.48s' crc_ok=%d -- another node holds this index; refusing\n",
		       MINOR(e->devt), index, r->endpoint,
		       le32_to_cpu(r->crc) == mxfs_drbd_crc(r));
		rc = -EIO;
	}
	if (!rc)
		rc = mxfs_drbd_reg_put(e, r, 0, 0);
	kfree(r);
	if (rc) {
		mxfs_drbd_cas_free(e);
		return rc;
	}

	mutex_lock(&mxfs_drbd_cas_list_lock);
	have = mxfs_drbd_cas_find(bdev->bd_dev);
	if (have) {
		/* A concurrent attach on this node won: use it. */
		have->refs++;
		mutex_unlock(&mxfs_drbd_cas_list_lock);
		mxfs_drbd_cas_free(e);
		mxfs_pal_bdev_set_drbd_cas(dev, true);
		return 0;
	}
	list_add(&e->list, &mxfs_drbd_cas_list);
	mutex_unlock(&mxfs_drbd_cas_list_lock);
	mxfs_pal_bdev_set_drbd_cas(dev, true);
	pr_info("mxfs: P-DRBD-CAS-ATTACH minor=%u index=%u endpoint=%s peer=%s area_lba=%llu nonce=%016llx\n",
		MINOR(e->devt), index, endpoint, peer_endpoint,
		(unsigned long long)e->area_lba, (unsigned long long)e->boot_nonce);
	return 0;
}
EXPORT_SYMBOL_GPL(mxfs_pal_drbd_cas_attach);

void mxfs_pal_drbd_cas_detach(mxfs_bdev_t *dev)
{
	struct block_device *bdev = dev ? mxfs_pal_bdev_get_bdev(dev) : NULL;
	struct mxfs_drbd_cas *e;

	if (!bdev)
		return;
	mutex_lock(&mxfs_drbd_cas_list_lock);
	e = mxfs_drbd_cas_find(bdev->bd_dev);
	mxfs_pal_bdev_set_drbd_cas(dev, false);
	if (e && --e->refs == 0)
		list_del(&e->list);
	else
		e = NULL;
	mutex_unlock(&mxfs_drbd_cas_list_lock);
	if (!e)
		return;
	/* the last release lands before its buffer and work item are freed */
	mxfs_drbd_rel_wait(e);
	pr_info("mxfs: P-DRBD-CAS-DETACH minor=%u index=%u ops=%llu contended=%llu deferred=%llu backoffs=%llu miscompares=%llu witness_skipped=%llu\n",
		MINOR(e->devt), e->index, e->ops, e->contended, e->deferred,
		e->backoffs, e->miscompares, e->witness_skipped);
	mxfs_drbd_cas_free(e);
}
EXPORT_SYMBOL_GPL(mxfs_pal_drbd_cas_detach);

/*
 * THE WRITE BOUND (mxfs_ioq.h says why).  4 MiB and 64 requests per mount: on
 * the two-host pair it was measured on (non-NCQ SATA SSDs, gigabit) that
 * keeps one replicated 512-byte write under ~2 s with both hosts writing flat
 * out, where 16 MiB let it reach 9 s and no bound 34 s; and it costs nothing
 * where writes complete quickly, since what flows is the bound divided by the
 * time one write takes.  The count matters for small writes: 4 MiB of 4 KiB
 * writes is a thousand of them.  Both are read at each admission, so a change
 * applies to the next write; 0 removes that half of the bound.
 */
static unsigned int mxfs_drbd_inflight_kb = 4096;
module_param_named(drbd_inflight_kb, mxfs_drbd_inflight_kb, uint, 0644);
MODULE_PARM_DESC(drbd_inflight_kb,
		 "most KiB of data and metadata writes one mount keeps in flight on a DRBD device (0 = no byte bound)");
static unsigned int mxfs_drbd_inflight_reqs = 64;
module_param_named(drbd_inflight_reqs, mxfs_drbd_inflight_reqs, uint, 0644);
MODULE_PARM_DESC(drbd_inflight_reqs,
		 "most data and metadata write requests one mount keeps in flight on a DRBD device (0 = no count bound)");

/*
 * THE WINDOW ABOVE THE BOUND.  The bound above is a floor, not the window: a
 * fixed 4 MiB also held a lone writer to 19-20 MB/s on that pair, where 32
 * MiB gave it 46 and XFS on a scratch DRBD resource there 29-37, while its
 * coordination swaps then took at most ~2 s, no more than the 4 MiB bound
 * leaves them with both hosts writing flat out (2026-10-08).  So the window
 * grows past the floor while the writes it admits complete within
 * drbd_inflight_target_ms (doubling each window's worth of completions up to
 * the last cut, then 1 MiB a window), up to drbd_inflight_max_kb, and halves,
 * never below the floor and at most once a target interval, when one takes
 * longer.  A write's completion time is the depth of the queues a
 * coordination write would wait behind, so the window shrinks when the peer's
 * writes deepen them too.  drbd_inflight_max_kb at or below the floor, or a
 * target of 0, is the fixed bound.
 */
static unsigned int mxfs_drbd_inflight_max_kb = 32768;
module_param_named(drbd_inflight_max_kb, mxfs_drbd_inflight_max_kb, uint, 0644);
MODULE_PARM_DESC(drbd_inflight_max_kb,
		 "most KiB the in-flight window may grow to while writes complete within drbd_inflight_target_ms (at or below drbd_inflight_kb = a fixed bound)");
static unsigned int mxfs_drbd_inflight_target_ms = 500;
module_param_named(drbd_inflight_target_ms, mxfs_drbd_inflight_target_ms, uint, 0644);
MODULE_PARM_DESC(drbd_inflight_target_ms,
		 "completion time of an admitted write above which the in-flight window halves (0 = a fixed bound)");

#define MXFS_IOQ_DEPTH_BUCKETS	4	/* <=4, <=8, <=16, >16 MiB in flight */
#define MXFS_IOQ_LAT_BUCKETS	6	/* <100, <250, <500, <1000, <2000, >=2000 ms */

struct mxfs_ioq {
	spinlock_t		lock;		/* irq-safe: completions release */
	unsigned long		bytes;		/* admitted and not yet completed */
	unsigned int		reqs;
	bool			dead;		/* the mount is gone */
	struct list_head	wait[MXFS_IOQ_NCLASS];	/* each first come, first served */
	mempool_t		*pool;		/* completion hooks */
	dev_t			devt;
	bool			(*admitted)(void *ctx);
	void			*ctx;
	/* since the mount */
	u64			n_admit, n_wait, n_refused, n_split, wait_ns, wait_ns_max;
	unsigned long		bytes_peak;
	unsigned int		reqs_peak;
	/*
	 * Spans whose earlier bios their submitter had already sent without
	 * asking (`ahead`): how many, their bytes, the largest.  Each of those
	 * bytes was in flight outside the bound.
	 */
	u64			n_ahead, ahead_bytes;
	unsigned int		ahead_max;
	/*
	 * The window: what may be in flight now (bytes), the size it doubles
	 * up to before growing a MiB at a time (half the window at the last
	 * cut), when it was last cut; how often it was cut, its largest, and
	 * the slowest completion it saw.
	 */
	unsigned long		win, win_grow_to;
	u64			cut_ns;
	u64			n_cut;
	unsigned long		win_peak;
	u64			lat_max_ns;
	/*
	 * Completion times by class and by the bytes in flight when the write
	 * was admitted (MXFS_IOQ_DEPTH_BUCKETS x MXFS_IOQ_LAT_BUCKETS): whether
	 * a slow completion follows the window's own depth or comes at any
	 * depth decides what the window should cut on.
	 */
	u64			lat_hist[MXFS_IOQ_NCLASS][MXFS_IOQ_DEPTH_BUCKETS][MXFS_IOQ_LAT_BUCKETS];
};

static unsigned int mxfs_ioq_depth_bucket(unsigned long depth)
{
	if (depth <= 4UL << 20)
		return 0;
	if (depth <= 8UL << 20)
		return 1;
	if (depth <= 16UL << 20)
		return 2;
	return 3;
}

static unsigned int mxfs_ioq_lat_bucket(u64 lat_ns)
{
	u64 ms = lat_ns / NSEC_PER_MSEC;

	if (ms < 100)
		return 0;
	if (ms < 250)
		return 1;
	if (ms < 500)
		return 2;
	if (ms < 1000)
		return 3;
	if (ms < 2000)
		return 4;
	return 5;
}

/* A writer waiting for its share; lives on its own stack until `go`. */
struct mxfs_ioq_waiter {
	struct list_head	node;
	struct task_struct	*task;
	unsigned int		bytes;
	unsigned long		depth;		/* in flight once it was granted */
	bool			go;
};

/* What an admitted bio's completion gives back, and to whom. */
struct mxfs_ioq_hook {
	bio_end_io_t		*end_io;
	void			*private;
	struct mxfs_ioq		*q;
	unsigned int		bytes;
	unsigned int		cls;
	unsigned long		depth;		/* in flight once it was admitted */
	u64			t_ns;		/* admitted, about to be submitted */
};

#define MXFS_IOQ_POOL_MIN	64
#define MXFS_IOQ_STATS_EVERY	1024	/* waits between P-DRBD-IOQ-STATS lines */

/* Under q->lock: whether the window may move past the floor at all. */
static bool mxfs_ioq_adaptive(unsigned long floor, unsigned long ceil)
{
	return floor && ceil > floor && READ_ONCE(mxfs_drbd_inflight_target_ms);
}

static bool mxfs_ioq_fits(struct mxfs_ioq *q, unsigned int bytes)
{
	unsigned long floor = (unsigned long)READ_ONCE(mxfs_drbd_inflight_kb) << 10;
	unsigned long ceil = (unsigned long)READ_ONCE(mxfs_drbd_inflight_max_kb) << 10;
	unsigned long max_bytes = floor;
	unsigned int max_reqs = READ_ONCE(mxfs_drbd_inflight_reqs);

	/* the request bound scales with the window, so small writes keep
	 * their share of it */
	if (mxfs_ioq_adaptive(floor, ceil) && q->win > floor) {
		max_bytes = min(q->win, ceil);
		if (max_reqs)
			max_reqs = (unsigned int)min_t(u64,
				(u64)max_reqs * max_bytes / floor, UINT_MAX);
	}

	/* Never refuse the only write: one larger than the bound still goes. */
	if (!q->reqs)
		return true;
	if (max_bytes && q->bytes + bytes > max_bytes)
		return false;
	if (max_reqs && q->reqs >= max_reqs)
		return false;
	return true;
}

static void mxfs_ioq_take(struct mxfs_ioq *q, unsigned int bytes)
{
	q->bytes += bytes;
	q->reqs++;
	q->n_admit++;
	if (q->bytes > q->bytes_peak)
		q->bytes_peak = q->bytes;
	if (q->reqs > q->reqs_peak)
		q->reqs_peak = q->reqs;
}

/*
 * Under q->lock: hand a freed share to the waiters, metadata before data and
 * each class in arrival order.  A waiter that does not fit stops the hand-out:
 * nothing behind it, in its class or a later one, overtakes it.
 */
static void mxfs_ioq_grant(struct mxfs_ioq *q)
{
	struct mxfs_ioq_waiter *w;
	int c;

	for (c = 0; c < MXFS_IOQ_NCLASS; c++) {
		while (!list_empty(&q->wait[c])) {
			w = list_first_entry(&q->wait[c], struct mxfs_ioq_waiter, node);
			if (!mxfs_ioq_fits(q, w->bytes))
				return;
			list_del_init(&w->node);
			mxfs_ioq_take(q, w->bytes);
			w->depth = q->bytes;
			w->go = true;
			wake_up_process(w->task);
		}
	}
}

static void mxfs_ioq_free(struct mxfs_ioq *q)
{
	int c;

	pr_info("mxfs: P-DRBD-IOQ-DONE minor=%u admitted=%llu split=%llu waited=%llu refused=%llu wait_avg_ms=%llu wait_max_ms=%llu peak_kib=%lu peak_reqs=%u unbounded_spans=%llu unbounded_kib=%llu unbounded_max_kib=%u win_kib=%lu win_peak_kib=%lu cuts=%llu lat_max_ms=%llu\n",
		MINOR(q->devt), q->n_admit, q->n_split, q->n_wait, q->n_refused,
		q->n_wait ? q->wait_ns / q->n_wait / NSEC_PER_MSEC : 0,
		q->wait_ns_max / NSEC_PER_MSEC, q->bytes_peak >> 10, q->reqs_peak,
		q->n_ahead, q->ahead_bytes >> 10, q->ahead_max >> 10,
		q->win >> 10, q->win_peak >> 10, q->n_cut,
		q->lat_max_ns / NSEC_PER_MSEC);
	for (c = 0; c < MXFS_IOQ_NCLASS; c++) {
		u64 (*hd)[MXFS_IOQ_LAT_BUCKETS] = q->lat_hist[c];

		/* one line per class; each depth's counts <100/<250/<500/<1000/<2000/>=2000 ms */
		pr_info("mxfs: P-DRBD-IOQ-LAT minor=%u class=%s depth<=4M=%llu/%llu/%llu/%llu/%llu/%llu depth<=8M=%llu/%llu/%llu/%llu/%llu/%llu depth<=16M=%llu/%llu/%llu/%llu/%llu/%llu depth>16M=%llu/%llu/%llu/%llu/%llu/%llu\n",
			MINOR(q->devt), c == MXFS_IOQ_META ? "meta" : "data",
			hd[0][0], hd[0][1], hd[0][2], hd[0][3], hd[0][4], hd[0][5],
			hd[1][0], hd[1][1], hd[1][2], hd[1][3], hd[1][4], hd[1][5],
			hd[2][0], hd[2][1], hd[2][2], hd[2][3], hd[2][4], hd[2][5],
			hd[3][0], hd[3][1], hd[3][2], hd[3][3], hd[3][4], hd[3][5]);
	}
	mempool_destroy(q->pool);
	kfree(q);
}

/*
 * Under q->lock: move the window by one completion that took `lat_ns`
 * (0: none measured, as for a share handed back unsubmitted).
 */
static void mxfs_ioq_adapt(struct mxfs_ioq *q, unsigned int bytes, u64 lat_ns)
{
	unsigned long floor = (unsigned long)READ_ONCE(mxfs_drbd_inflight_kb) << 10;
	unsigned long ceil = (unsigned long)READ_ONCE(mxfs_drbd_inflight_max_kb) << 10;
	u64 target = (u64)READ_ONCE(mxfs_drbd_inflight_target_ms) * NSEC_PER_MSEC;
	u64 now;

	if (!lat_ns)
		return;
	if (lat_ns > q->lat_max_ns)
		q->lat_max_ns = lat_ns;
	if (!mxfs_ioq_adaptive(floor, ceil)) {
		q->win = floor;
		return;
	}
	q->win = clamp(q->win, floor, ceil);
	if (lat_ns > target) {
		now = ktime_get_ns();
		if (now - q->cut_ns < target)
			return;		/* one cut per episode, not one per write */
		q->win = max(floor, q->win / 2);
		q->win_grow_to = q->win;
		q->cut_ns = now;
		q->n_cut++;
		return;
	}
	if (!q->win_grow_to || q->win < q->win_grow_to)
		q->win += bytes;
	else
		q->win += max_t(unsigned long, 1,
				(unsigned long)((u64)bytes * SZ_1M / q->win));
	q->win = min(q->win, ceil);
	if (q->win > q->win_peak)
		q->win_peak = q->win;
}

/* Give a share back and hand it on; the last one back after the mount is gone
 * frees the bound.  Any context: completions call it.  `depth` is what was in
 * flight when the write was admitted. */
static void mxfs_ioq_put(struct mxfs_ioq *q, unsigned int bytes, u64 lat_ns,
			 unsigned int cls, unsigned long depth)
{
	unsigned long flags;
	bool gone;

	spin_lock_irqsave(&q->lock, flags);
	q->bytes -= bytes;
	q->reqs--;
	if (lat_ns && cls < MXFS_IOQ_NCLASS)
		q->lat_hist[cls][mxfs_ioq_depth_bucket(depth)][mxfs_ioq_lat_bucket(lat_ns)]++;
	mxfs_ioq_adapt(q, bytes, lat_ns);
	mxfs_ioq_grant(q);
	gone = q->dead && !q->reqs;
	spin_unlock_irqrestore(&q->lock, flags);
	if (gone)
		mxfs_ioq_free(q);
}

static void mxfs_ioq_end_io(struct bio *bio)
{
	struct mxfs_ioq_hook *h = bio->bi_private;
	struct mxfs_ioq *q = h->q;
	unsigned int bytes = h->bytes;
	unsigned int cls = h->cls;
	unsigned long depth = h->depth;
	u64 lat_ns = ktime_get_ns() - h->t_ns;

	bio->bi_end_io = h->end_io;
	bio->bi_private = h->private;
	/* the hook goes back first: q is alive while this share is held */
	mempool_free(h, q->pool);
	/* a failed write's time says nothing about the queues */
	mxfs_ioq_put(q, bytes, bio->bi_status ? 0 : max_t(u64, lat_ns, 1),
		     cls, depth);
	/*
	 * Completed through bio_endio(), never by calling the restored
	 * bi_end_io.  A piece mxfs_pal_ioq_admit split off is chained to the rest
	 * of its write, so what is restored there is bio_chain_endio, which from
	 * Linux 7.0 is a BUG() that only bio_endio() steps around (it unrolls the
	 * chain itself).  Called directly it panicked a host on Proxmox's 7.0.14
	 * kernel on its first write over the chunk.  The second pass through
	 * bio_endio is the stacking drivers' own pattern (blk-crypto-fallback):
	 * a chain count already at zero has cleared its flag, and a bio on this
	 * bio-based device carries no QoS throttling or integrity state.
	 */
	bio_endio(bio);
}

/* Admit one bio of at most a chunk (or a bio that cannot be split). */
static int mxfs_ioq_admit_one(struct mxfs_ioq *q, struct bio *bio,
			      enum mxfs_ioq_class cls, unsigned int bytes)
{
	struct mxfs_ioq_waiter w;
	struct mxfs_ioq_hook *h;
	bool waited = false;
	unsigned long depth;
	u64 t0, ns = 0, n_wait = 0;

	spin_lock_irq(&q->lock);
	if (list_empty(&q->wait[MXFS_IOQ_META]) &&
	    (cls == MXFS_IOQ_META || list_empty(&q->wait[MXFS_IOQ_DATA])) &&
	    mxfs_ioq_fits(q, bytes)) {
		mxfs_ioq_take(q, bytes);
		depth = q->bytes;
		spin_unlock_irq(&q->lock);
	} else if (bio->bi_opf & REQ_NOWAIT) {
		spin_unlock_irq(&q->lock);
		return -EAGAIN;
	} else {
		w.task = current;
		w.bytes = bytes;
		w.go = false;
		list_add_tail(&w.node, &q->wait[cls]);
		t0 = ktime_get_ns();
		/* the semaphore's pattern: `go` is set and the task woken under
		 * q->lock, and read here only under it */
		while (!w.go) {
			__set_current_state(TASK_UNINTERRUPTIBLE);
			spin_unlock_irq(&q->lock);
			io_schedule();
			spin_lock_irq(&q->lock);
		}
		__set_current_state(TASK_RUNNING);
		ns = ktime_get_ns() - t0;
		q->n_wait++;
		q->wait_ns += ns;
		if (ns > q->wait_ns_max)
			q->wait_ns_max = ns;
		n_wait = q->n_wait;
		depth = w.depth;
		waited = true;
		spin_unlock_irq(&q->lock);
	}

	/*
	 * A REQ_NOWAIT submitter must not sleep here either: without a hook to
	 * hand it now, its share goes back and it is told to retry blocking.
	 * Otherwise the pool's reserve is refilled by the completions of the
	 * writes already in flight, so the wait ends.
	 */
	h = mempool_alloc(q->pool, (bio->bi_opf & REQ_NOWAIT) ? GFP_NOWAIT : GFP_NOIO);
	if (!h) {
		mxfs_ioq_put(q, bytes, 0, cls, 0);
		return -EAGAIN;
	}
	h->end_io = bio->bi_end_io;
	h->private = bio->bi_private;
	h->q = q;
	h->bytes = bytes;
	h->cls = cls;
	h->depth = depth;
	h->t_ns = ktime_get_ns();
	bio->bi_private = h;
	bio->bi_end_io = mxfs_ioq_end_io;

	if (!waited)
		return 0;
	if (!(n_wait % MXFS_IOQ_STATS_EVERY))
		mxfs_probe("mxfs: P-DRBD-IOQ-STATS minor=%u admitted=%llu waited=%llu wait_avg_us=%llu wait_max_ms=%llu peak_kib=%lu peak_reqs=%u last_wait_us=%llu win_kib=%lu cuts=%llu\n",
			   MINOR(q->devt), q->n_admit, q->n_wait,
			   q->wait_ns / q->n_wait / NSEC_PER_USEC,
			   q->wait_ns_max / NSEC_PER_MSEC, q->bytes_peak >> 10,
			   q->reqs_peak, ns / NSEC_PER_USEC, q->win >> 10,
			   q->n_cut);
	/*
	 * The writer asked the mount's authority question before it came here;
	 * the wait must not carry its write past the answer.  Hooked already:
	 * the caller completes the bio with an error, which returns its share.
	 */
	if (q->admitted && !q->admitted(q->ctx)) {
		spin_lock_irq(&q->lock);
		q->n_refused++;
		spin_unlock_irq(&q->lock);
		pr_err_ratelimited("mxfs: P-DRBD-IOQ-REFUSED minor=%u class=%s bytes=%u waited_ms=%llu comm=%s -- this node's authority closed while the write waited for room on the DRBD device; it is failed (-EIO), never submitted\n",
				   MINOR(q->devt), cls == MXFS_IOQ_META ? "meta" : "data",
				   bytes, ns / NSEC_PER_MSEC, current->comm);
		return -EIO;
	}
	return 0;
}

#ifdef REQ_ATOMIC
#define MXFS_IOQ_NOSPLIT	(REQ_NOWAIT | REQ_ATOMIC)
#else
#define MXFS_IOQ_NOSPLIT	REQ_NOWAIT
#endif

/*
 * The largest piece admitted as one write.  A bio is not bounded by its
 * count: writeback on large folios builds them by the hundred MiB (measured
 * on 6.17: one of 392 MiB, admitted alone because nothing else was in flight,
 * held the swaps behind it for a second on NVMe), and DRBD splits one only
 * after it has queued all of it.  So anything larger is split here, each piece
 * admitted on its own: a quarter of the byte bound, a multiple of 64 KiB (any
 * logical block size divides it), at most 1 MiB, DRBD 8.4's own largest bio.
 */
static unsigned int mxfs_ioq_chunk_sectors(void)
{
	unsigned int kb = READ_ONCE(mxfs_drbd_inflight_kb);
	unsigned int chunk_kb = kb ? max(64U, (kb / 4) & ~63U) : 1024U;

	return min(chunk_kb, 1024U) << 1;
}

int mxfs_pal_ioq_admit(struct mxfs_ioq *q, struct bio *bio,
		       enum mxfs_ioq_class cls, unsigned int ahead)
{
	unsigned int chunk;
	struct bio *split;
	int rc;

	if (!q || bio_op(bio) != REQ_OP_WRITE || !bio->bi_bdev ||
	    bio->bi_bdev->bd_dev != q->devt ||
	    (!READ_ONCE(mxfs_drbd_inflight_kb) && !READ_ONCE(mxfs_drbd_inflight_reqs)))
		return 0;
	/*
	 * A bio with no completion yet would have its submitter's default
	 * installed later, over the hook, and the share would never come back.
	 * Every caller admits after the completion is set; one that does not
	 * is a bug in the caller, and the write goes unbounded rather than
	 * leaking.
	 */
	if (WARN_ON_ONCE(!bio->bi_end_io))
		return 0;

	if (ahead) {
		u64 n;

		spin_lock_irq(&q->lock);
		n = ++q->n_ahead;
		q->ahead_bytes += ahead;
		if (ahead > q->ahead_max)
			q->ahead_max = ahead;
		spin_unlock_irq(&q->lock);
		if (n % 256 == 1)
			mxfs_probe("mxfs: P-DRBD-IOQ-UNBOUNDED minor=%u spans=%llu kib=%llu max_kib=%u this_kib=%u -- bytes its submitter sent before this span reached the bound; they were in flight outside it\n",
				   MINOR(q->devt), n, q->ahead_bytes >> 10,
				   q->ahead_max >> 10, ahead >> 10);
	}

	/*
	 * Split from the front, each piece chained to what is left so the
	 * caller's completion still runs once, after all of them; each piece is
	 * submitted as soon as it is admitted, so nothing admitted waits on this
	 * task.  A REQ_NOWAIT bio is not split (a refusal after a piece went
	 * out could not be retried whole) and neither is an atomic one; a
	 * direct write's bio is at most BIO_MAX_VECS pages anyway.
	 */
	chunk = mxfs_ioq_chunk_sectors();
	while (bio_sectors(bio) > chunk && !(bio->bi_opf & MXFS_IOQ_NOSPLIT)) {
		split = bio_split(bio, chunk, GFP_NOIO, &fs_bio_set);
		if (IS_ERR_OR_NULL(split))
			break;
		bio_chain(split, bio);
		spin_lock_irq(&q->lock);
		q->n_split++;
		spin_unlock_irq(&q->lock);
		rc = mxfs_ioq_admit_one(q, split, cls, split->bi_iter.bi_size + ahead);
		ahead = 0;
		if (rc) {
			/* refused: the authority closed (this bio may not wait, so
			 * never -EAGAIN); the error reaches the caller's completion
			 * through the chain, and the rest is refused with it */
			split->bi_status = BLK_STS_IOERR;
			bio_endio(split);
			return rc;
		}
		submit_bio(split);
	}
	return mxfs_ioq_admit_one(q, bio, cls,
				  min_t(u64, (u64)bio->bi_iter.bi_size + ahead, UINT_MAX));
}
EXPORT_SYMBOL_GPL(mxfs_pal_ioq_admit);

void mxfs_pal_ioq_submit(struct mxfs_ioq *q, struct bio *bio,
			 enum mxfs_ioq_class cls)
{
	int rc = mxfs_pal_ioq_admit(q, bio, cls, 0);

	if (!rc) {
		submit_bio(bio);
		return;
	}
	bio->bi_status = rc == -EAGAIN ? BLK_STS_AGAIN : BLK_STS_IOERR;
	bio_endio(bio);
}
EXPORT_SYMBOL_GPL(mxfs_pal_ioq_submit);

struct mxfs_ioq *mxfs_pal_ioq_create(struct block_device *bdev,
				     bool (*admitted)(void *ctx), void *ctx)
{
	struct mxfs_ioq *q;
	bool drbd;
	int c;

	if (!bdev)
		return NULL;
	mutex_lock(&mxfs_drbd_cas_list_lock);
	drbd = mxfs_drbd_cas_find(bdev->bd_dev) != NULL;
	mutex_unlock(&mxfs_drbd_cas_list_lock);
	if (!drbd)
		return NULL;

	q = kzalloc(sizeof(*q), GFP_KERNEL);
	if (q)
		q->pool = mempool_create_kmalloc_pool(MXFS_IOQ_POOL_MIN,
						      sizeof(struct mxfs_ioq_hook));
	if (!q || !q->pool) {
		kfree(q);
		pr_err("mxfs: P-DRBD-IOQ-NOMEM minor=%u -- this mount's writes on the DRBD device are not bounded, so under heavy writes its coordination writes can queue behind them\n",
		       MINOR(bdev->bd_dev));
		return NULL;
	}
	spin_lock_init(&q->lock);
	for (c = 0; c < MXFS_IOQ_NCLASS; c++)
		INIT_LIST_HEAD(&q->wait[c]);
	q->devt = bdev->bd_dev;
	q->admitted = admitted;
	q->ctx = ctx;
	q->win = (unsigned long)READ_ONCE(mxfs_drbd_inflight_kb) << 10;
	pr_info("mxfs: P-DRBD-IOQ-ARMED minor=%u inflight_kib=%u inflight_reqs=%u max_kib=%u target_ms=%u -- this mount's data and metadata writes on the DRBD device are held to that much in flight, the window growing toward max_kib while they complete within target_ms, so its coordination writes never queue behind more\n",
		MINOR(q->devt), READ_ONCE(mxfs_drbd_inflight_kb),
		READ_ONCE(mxfs_drbd_inflight_reqs),
		READ_ONCE(mxfs_drbd_inflight_max_kb),
		READ_ONCE(mxfs_drbd_inflight_target_ms));
	return q;
}
EXPORT_SYMBOL_GPL(mxfs_pal_ioq_create);

void mxfs_pal_ioq_destroy(struct mxfs_ioq *q)
{
	bool idle;
	int c;

	if (!q)
		return;
	spin_lock_irq(&q->lock);
	for (c = 0; c < MXFS_IOQ_NCLASS; c++)
		WARN_ON_ONCE(!list_empty(&q->wait[c]));
	q->dead = true;
	idle = !q->reqs;
	if (!idle)
		pr_warn("mxfs: P-DRBD-IOQ-LATE minor=%u reqs=%u kib=%lu -- writes still in flight as the mount is freed; the last of them frees the bound\n",
			MINOR(q->devt), q->reqs, q->bytes >> 10);
	spin_unlock_irq(&q->lock);
	if (idle)
		mxfs_ioq_free(q);
}
EXPORT_SYMBOL_GPL(mxfs_pal_ioq_destroy);

/*
 * The peer is FENCED: a certificate (kind 25) proves it can no longer write.
 * A flag it died holding would make every later swap wait it out and fail,
 * so its register is cleared — the one write to a register its owner did not
 * make, and safe only because that owner provably cannot write any more —
 * and our own register publishes the advanced membership generation.  When
 * the peer returns it attaches afresh and writes its register itself.
 */
void mxfs_pal_drbd_cas_peer_fenced(mxfs_bdev_t *dev)
{
	struct block_device *bdev = dev ? mxfs_pal_bdev_get_bdev(dev) : NULL;
	struct mxfs_drbd_cas *e;
	struct mxfs_drbd_reg *r;
	int rc;

	if (!bdev)
		return;
	mutex_lock(&mxfs_drbd_cas_list_lock);
	e = mxfs_drbd_cas_find(bdev->bd_dev);
	mutex_unlock(&mxfs_drbd_cas_list_lock);
	if (!e)
		return;
	r = kzalloc(512, GFP_KERNEL);
	if (!r)
		return;
	mutex_lock(&e->lock);
	/* no other write of our register may be in flight beside this one */
	mxfs_drbd_rel_wait(e);
	e->membership_gen++;
	rc = mxfs_drbd_sec_write(e, e->area_lba + 1 + (1 - e->index), r);
	if (!rc)
		rc = mxfs_drbd_reg_put(e, r, 0, 0);
	mutex_unlock(&e->lock);
	kfree(r);
	pr_warn("mxfs: P-DRBD-CAS-PEER-FENCED minor=%u index=%u membership_gen=%llu rc=%d -- the fenced peer's register is cleared\n",
		MINOR(e->devt), e->index, e->membership_gen, rc);
}
EXPORT_SYMBOL_GPL(mxfs_pal_drbd_cas_peer_fenced);

/* ═══════════════════════ the exclusion notice ═══════════════════════ */

/*
 * The pair's fence-peer handler excludes the peer as soon as DRBD loses it
 * (DRBD's own ping timeout, about ten seconds after a death), but MXFS learns
 * of the death from its lock manager's TCP link: a dead peer sends nothing,
 * so the socket times out at 25 s and the death then waits out the 40 s flap
 * grace.  Measured on the rig (0.90.57): exclusion at +10.9 s, death declared
 * at +65.6 s, and everything waiting on the dead node's grants waited that
 * long.  So the handler writes the DRBD minor here once its exclusion is
 * durable, and the mount on that minor takes the write as a cue, never as
 * evidence: it asks its own witness and declares the death only on the
 * judgment the fence leg certifies on (dlm/drbdfence.c).  A minor no mount
 * watches is accepted and ignored.
 */
#define MXFS_DRBDX_PROC_NAME	"fs/mxfs/drbd_excluded"

struct mxfs_drbd_excl_watch {
	struct list_head	list;
	dev_t			devt;
	void			(*fn)(void *data);	/* atomic context: a flag, no more */
	void			*data;
};
static LIST_HEAD(mxfs_drbd_excl_watches);
static DEFINE_SPINLOCK(mxfs_drbd_excl_lock);
static struct proc_dir_entry *mxfs_drbdx_pde;

static ssize_t mxfs_drbdx_write(struct file *file, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	struct mxfs_drbd_excl_watch *w;
	char buf[16];
	size_t n = min(count, sizeof(buf) - 1);
	unsigned int minor, mounts = 0;

	if (copy_from_user(buf, ubuf, n))
		return -EFAULT;
	buf[n] = '\0';
	if (kstrtouint(buf, 10, &minor))
		return -EINVAL;
	spin_lock(&mxfs_drbd_excl_lock);
	list_for_each_entry(w, &mxfs_drbd_excl_watches, list) {
		if (MAJOR(w->devt) == DRBD_MAJOR && MINOR(w->devt) == minor) {
			w->fn(w->data);
			mounts++;
		}
	}
	spin_unlock(&mxfs_drbd_excl_lock);
	pr_info("mxfs: P-DRBD-EXCL-NOTICE minor=%u mounts=%u -- the fence handler reports its peer excluded; a mount confirms with its own witness before it declares the death\n",
		minor, mounts);
	*ppos += count;
	return count;
}

static const struct proc_ops mxfs_drbdx_ops = {
	.proc_write	= mxfs_drbdx_write,
	.proc_lseek	= noop_llseek,
};

int mxfs_pal_drbd_exclusion_watch(mxfs_bdev_t *dev, void (*fn)(void *data),
				  void *data)
{
	struct block_device *bdev = dev ? mxfs_pal_bdev_get_bdev(dev) : NULL;
	struct mxfs_drbd_excl_watch *w, *n;

	if (!fn) {
		spin_lock(&mxfs_drbd_excl_lock);
		list_for_each_entry_safe(w, n, &mxfs_drbd_excl_watches, list) {
			if (w->data == data) {
				list_del(&w->list);
				kfree(w);
			}
		}
		spin_unlock(&mxfs_drbd_excl_lock);
		return 0;
	}
	if (!bdev)
		return -EINVAL;
	w = kzalloc(sizeof(*w), GFP_KERNEL);
	if (!w)
		return -ENOMEM;
	w->devt = bdev->bd_dev;
	w->fn = fn;
	w->data = data;
	spin_lock(&mxfs_drbd_excl_lock);
	list_add(&w->list, &mxfs_drbd_excl_watches);
	spin_unlock(&mxfs_drbd_excl_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(mxfs_pal_drbd_exclusion_watch);

/* ═══════════════════════════ lifetime ═══════════════════════════ */

int mxfs_pal_drbd_init(void)
{
	init_completion(&mxfs_drbdw_slot.done);
	mxfs_drbd_rel_wq = alloc_workqueue("mxfs_drbd_rel", WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
	if (!mxfs_drbd_rel_wq)
		return -ENOMEM;
	mxfs_drbdw_pde = proc_create(MXFS_DRBDW_PROC_NAME, 0200, NULL,
				     &mxfs_drbdw_report_ops);
	if (!mxfs_drbdw_pde) {
		pr_err("mxfs: P-DRBDW-NOCHAN could not create %s -- a DRBD device cannot be admitted or fenced\n",
		       MXFS_DRBDW_PROC_PATH);
		destroy_workqueue(mxfs_drbd_rel_wq);
		mxfs_drbd_rel_wq = NULL;
		return -ENOMEM;
	}
	/* Without it a death is still declared, by the TCP link's timeout and
	 * grace; the notice only shortens that. */
	mxfs_drbdx_pde = proc_create(MXFS_DRBDX_PROC_NAME, 0200, NULL,
				     &mxfs_drbdx_ops);
	if (!mxfs_drbdx_pde)
		pr_warn("mxfs: P-DRBDX-NOCHAN could not create /proc/%s -- a DRBD peer's death waits out the TCP link's timeout and grace\n",
			MXFS_DRBDX_PROC_NAME);
	return 0;
}

void mxfs_pal_drbd_exit(void)
{
	struct mxfs_drbd_excl_watch *w, *n;

	if (mxfs_drbdx_pde) {
		proc_remove(mxfs_drbdx_pde);
		mxfs_drbdx_pde = NULL;
	}
	spin_lock(&mxfs_drbd_excl_lock);
	list_for_each_entry_safe(w, n, &mxfs_drbd_excl_watches, list) {
		list_del(&w->list);
		kfree(w);
	}
	spin_unlock(&mxfs_drbd_excl_lock);
	if (mxfs_drbdw_pde) {
		proc_remove(mxfs_drbdw_pde);
		mxfs_drbdw_pde = NULL;
	}
	/* every attachment flushed its release at detach */
	if (mxfs_drbd_rel_wq) {
		destroy_workqueue(mxfs_drbd_rel_wq);
		mxfs_drbd_rel_wq = NULL;
	}
}
