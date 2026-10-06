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
 * two-party Lamport bakery lock built on the device itself.  Each participant
 * writes only its own register sector, and DRBD protocol C completes a write
 * only once both disks hold it, which is the order the bakery needs.  The
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
		mxfs_probe("mxfs: P-DRBDW-STALE a report naming nonce=%s arrived while another invocation is outstanding — discarded\n",
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
		pr_err("mxfs: P-DRBDW-NOEXEC helper='%s' mode=%s rc=%d — no report, no evidence\n",
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
#define MXFS_DRBD_REG_MAGIC	0x4b42584du	/* "MXBK": a bakery register */
#define MXFS_DRBD_CAS_VERSION	1
#define MXFS_DRBD_EP_LEN	48
/* Tickets reset to 0 at every release, so they grow only while both nodes
 * contend without a pause; a bound far below the field's range turns the
 * impossible into a refusal instead of a wrap. */
#define MXFS_DRBD_TICKET_MAX	(1ULL << 48)

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

/* Sectors 1 and 2: one bakery register per participant, written only by it. */
struct mxfs_drbd_reg {
	__le32	magic;
	__le16	version;
	__le16	index;
	u8	fs_uuid[16];
	__le64	boot_nonce;	/* this attachment's incarnation on that node */
	__le64	membership_gen;	/* advanced only when a fenced peer's register is cleared */
	__le32	choosing;
	__le32	pad;
	__le64	number;
	char	endpoint[MXFS_DRBD_EP_LEN];
	u8	reserved[512 - 56 - MXFS_DRBD_EP_LEN - 4];
	__le32	crc;
} __packed;

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
	u64			membership_gen;	/* advanced each time a fenced peer's ticket is cleared */
	struct mutex		lock;		/* one local participant at a time */
	spinlock_t		qlock;		/* guards queue */
	struct list_head	queue;		/* swaps waiting for the next leader */
	int			refs;
	u64			ops, contended, miscompares;
	/*
	 * Where a swap's time goes, in ns, summed since the last stats line:
	 * waiting for this node's other swaps (lock), the doorway's two register
	 * writes and one read (door), waiting on the peer's ticket (bakery),
	 * the target's read-compare-write (crit), the register clear (rel).
	 * Read under `lock`; printed every MXFS_DRBD_STATS_EVERY swaps.
	 */
	u64			st_n, st_batches, st_lock, st_door, st_bakery, st_crit, st_rel, st_max;
	/*
	 * The exclusion judgment the mount supplies (dlm/drbdfence.c
	 * mxfs_drbd_judge_excluded): stateless, so it outlives any one mount.
	 * excl_next paces the witness while a swap waits on the peer's ticket.
	 */
	int			(*judge_excluded)(const struct mxfs_pal_drbd_report *r,
						  char *why, size_t whylen);
	unsigned long		excl_next;
	/*
	 * A PEER REGISTER SET ASIDE.  After both nodes crash, the peer's
	 * register keeps whatever its dead attachment last wrote — a ticket,
	 * or a doorway half done — until the peer mounts again, and every swap
	 * here would wait on it and fail.  A peer that is Secondary on a
	 * Connected link (judge_quiescent, kind 27's judgment) has no attachment
	 * at all: DRBD refuses a Secondary every write open, and a Primary
	 * cannot demote while a mount holds it open.  So a register read before
	 * such a report, while our own ticket was already published, was
	 * written by an attachment that is gone, and its exact 512 bytes are
	 * recorded here and read as idle for as long as the sector still holds
	 * them.  The register is never written: a later attachment of the peer
	 * first rewrites it under a fresh random boot_nonce, so its content
	 * differs from these bytes from its first write on, and its doorway
	 * reads our published ticket and takes a larger one.  Zeroing it
	 * instead could erase the live ticket of a peer that attached between
	 * the report and the write.  Any read that differs ends the setting
	 * aside for good.
	 */
	int			(*judge_quiescent)(const struct mxfs_pal_drbd_report *r,
						   char *why, size_t whylen);
	bool			void_set;
	u8			void_img[512];
};
#define MXFS_DRBD_STATS_EVERY	512

static LIST_HEAD(mxfs_drbd_cas_list);
static DEFINE_MUTEX(mxfs_drbd_cas_list_lock);

/*
 * THE WAIT BOUND.  A critical section is one sector read and one replicated
 * write: milliseconds.  A peer that holds its ticket for longer than this is
 * not in a critical section — it died holding it, or its I/O is frozen.  The
 * swap then FAILS (-EIO, the caller's I/O-error path) rather than proceeding:
 * a dead participant's ticket may be set aside only once that participant is
 * fenced, which is the fence path's decision, never a timeout's.
 */
static unsigned int mxfs_drbd_cas_wait_ms = 10000;
module_param_named(drbd_cas_wait_ms, mxfs_drbd_cas_wait_ms, uint, 0644);
MODULE_PARM_DESC(drbd_cas_wait_ms,
		 "longest a DRBD compare-and-swap waits for the peer's ticket before it fails");

/* DEBUG one-shot: the next swap on this node holds its ticket this long inside
 * the critical section, so a test can kill the node while it holds the lock
 * (scripts/drbd_rig.sh death-test DEATH_HOLD_TICKET=1).  Never in production. */
static int mxfs_dbg_drbd_cas_hold_ms;
module_param_named(dbg_drbd_cas_hold_ms, mxfs_dbg_drbd_cas_hold_ms, int, 0644);
MODULE_PARM_DESC(dbg_drbd_cas_hold_ms,
		 "DEBUG one-shot: the next DRBD compare-and-swap holds its ticket this many ms. Never enable in production.");

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

/* Write this node's register: {choosing, number}. */
static int mxfs_drbd_reg_put(struct mxfs_drbd_cas *e, struct mxfs_drbd_reg *r,
			     u32 choosing, u64 number)
{
	memset(r, 0, sizeof(*r));
	r->magic = cpu_to_le32(MXFS_DRBD_REG_MAGIC);
	r->version = cpu_to_le16(MXFS_DRBD_CAS_VERSION);
	r->index = cpu_to_le16(e->index);
	memcpy(r->fs_uuid, e->fs_uuid, 16);
	r->boot_nonce = cpu_to_le64(e->boot_nonce);
	r->membership_gen = cpu_to_le64(e->membership_gen);
	r->choosing = cpu_to_le32(choosing);
	r->number = cpu_to_le64(number);
	strscpy(r->endpoint, e->endpoint, sizeof(r->endpoint));
	r->crc = cpu_to_le32(mxfs_drbd_crc(r));
	/*
	 * Without FUA.  A register excludes only live participants: what the
	 * bakery needs is that the peer's next read sees it, and protocol C
	 * completes a write only once both disks have accepted it, which is
	 * what the peer's read of its own disk returns.  Stable media adds
	 * nothing across a crash (a participant's register is rewritten when it
	 * attaches, and a fenced one's is cleared by its survivor) and costs a
	 * cache flush on both disks for each of the three register writes of a
	 * swap.  Measured: a departure's ~6,600 serial swaps at 10-15 ms each
	 * held two unmounts for 98 s.  The target's own write keeps FUA.
	 */
	return mxfs_pal_bio_write_sync_bdev(e->bdev, e->area_lba + 1 + e->index, r, 512);
}

/*
 * Read the peer's register.  Never written (all zero) reads as idle, and so
 * do the exact bytes set aside under void_img.  Any other content must be a
 * valid register of THIS filesystem, of the peer's index, from the peer's
 * endpoint.  Anything else — a sector torn by a power cut, corruption, a
 * misconfigured pair — reads as BUSY, never as idle: the swap waits on it
 * and fails at the wait bound unless the peer is proven excluded (the
 * register is cleared) or without an attachment (it is set aside).
 */
static int mxfs_drbd_reg_get_peer(struct mxfs_drbd_cas *e, struct mxfs_drbd_reg *r,
				  u32 *choosing, u64 *number)
{
	unsigned int peer = 1 - e->index;
	int rc = mxfs_drbd_sec_read(e, e->area_lba + 1 + peer, r);

	if (rc)
		return rc;
	if (e->void_set) {
		if (!memcmp(r, e->void_img, 512)) {
			*choosing = 0;
			*number = 0;
			return 0;
		}
		e->void_set = false;
		pr_warn("mxfs: P-DRBD-CAS-PEER-SET-ASIDE-ENDED minor=%u index=%u — the peer's register changed (an attachment of the peer wrote it); its ticket counts again\n",
			MINOR(e->devt), e->index);
	}
	if (mxfs_drbd_all_zero(r)) {
		*choosing = 0;
		*number = 0;
		return 0;
	}
	if (le32_to_cpu(r->magic) != MXFS_DRBD_REG_MAGIC ||
	    le16_to_cpu(r->version) != MXFS_DRBD_CAS_VERSION ||
	    le32_to_cpu(r->crc) != mxfs_drbd_crc(r) ||
	    le16_to_cpu(r->index) != peer ||
	    memcmp(r->fs_uuid, e->fs_uuid, 16) ||
	    strncmp(r->endpoint, e->peer_endpoint, sizeof(r->endpoint))) {
		pr_err_ratelimited("mxfs: P-DRBD-CAS-PEER-REG-INVALID minor=%u peer_index=%u magic=0x%x crc_ok=%d index=%u endpoint='%.48s' want='%s' — read as busy: the swap waits on it\n",
				   MINOR(e->devt), peer, le32_to_cpu(r->magic),
				   le32_to_cpu(r->crc) == mxfs_drbd_crc(r),
				   le16_to_cpu(r->index), r->endpoint, e->peer_endpoint);
		*choosing = 1;
		*number = 0;
		return 0;
	}
	*choosing = le32_to_cpu(r->choosing);
	*number = le64_to_cpu(r->number);
	if (*number >= MXFS_DRBD_TICKET_MAX)
		return -EOVERFLOW;
	return 0;
}

/*
 * Called with e->lock held from a swap waiting on the peer's ticket, our own
 * ticket `mine` already published.  `reg` holds the peer's register as last
 * read.  The witness is taken for the attachment's minor; if the judgment
 * says the peer is excluded, its register is cleared, the membership
 * generation advanced and our own register (still holding `mine`)
 * re-published under it.  If instead the peer is Secondary on a Connected
 * link, the register as read BEFORE the witness ran is set aside (void_img).
 * 1 = cleared or set aside: the caller reads the peer's register again.
 */
static int mxfs_drbd_peer_excluded_locked(struct mxfs_drbd_cas *e,
					  struct mxfs_drbd_reg *reg, u64 mine)
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
		pr_warn("mxfs: P-DRBD-CAS-PEER-SET-ASIDE minor=%u index=%u ticket=%llu peer_choosing=%u peer_ticket=%llu peer_nonce=%016llx — the peer is Secondary on a Connected link, so no attachment of it is alive; the register its dead attachment left is read as idle while unchanged, and never written\n",
			MINOR(e->devt), e->index, mine,
			le32_to_cpu(((struct mxfs_drbd_reg *)img)->choosing),
			(unsigned long long)le64_to_cpu(((struct mxfs_drbd_reg *)img)->number),
			(unsigned long long)le64_to_cpu(((struct mxfs_drbd_reg *)img)->boot_nonce));
		kfree(r);
		kfree(zero);
		return 1;
	}
	if (rc) {
		pr_warn_ratelimited("mxfs: P-DRBD-CAS-PEER-NOT-EXCLUDED minor=%u index=%u why='%s' quiescent='%s' — the peer's ticket stands\n",
				    MINOR(e->devt), e->index, why, whyq);
		kfree(r);
		kfree(zero);
		return 0;
	}
	e->membership_gen++;
	rc = mxfs_drbd_sec_write(e, e->area_lba + 1 + (1 - e->index), zero);
	if (!rc)
		rc = mxfs_drbd_reg_put(e, reg, 0, mine);
	pr_warn("mxfs: P-DRBD-CAS-PEER-EXCLUDED minor=%u index=%u peer=%s episode=%s membership_gen=%llu rc=%d — the peer is excluded (kind-25 evidence); its ticket is cleared\n",
		MINOR(e->devt), e->index, r->peer_host, r->receipt_episode,
		e->membership_gen, rc);
	kfree(r);
	kfree(zero);
	return rc == 0;
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
	u64			tq;		/* when it was queued */
	int			rc;
	bool			done;
};

/* A leader serves at most this many swaps under one bakery acquisition, so the
 * peer's wait for the lock stays bounded by a few dozen sector writes. */
#define MXFS_DRBD_CAS_BATCH	32

/*
 * The swap: bakery acquire, read-compare-write the target, release.  The
 * release is ordered after the target write has completed with FUA, so the
 * peer can never hold the lock while our write is still in flight.
 *
 * GROUP COMMIT.  Every swap on this node is serialised by e->lock, and each
 * acquisition costs a doorway (two replicated register writes and a read) and
 * a release (one more write) on top of the target's read-compare-write.
 * Measured on the 2-node rig: ~3 ms doorway, ~1 ms release, ~1-2 ms target,
 * and swaps queued behind e->lock for 130 ms on average under a directory
 * workload, which pushed lock handoffs past the 1 s acquire wait.  So swaps
 * queue, and whoever takes e->lock serves every queued swap (up to
 * MXFS_DRBD_CAS_BATCH) inside one acquisition, each one's read-compare-write in
 * queue order — a later swap of the same sector reads the earlier one's write —
 * and releases once, after every target write has completed.  Mutual exclusion
 * with the peer and the release ordering are those of a single swap.
 */
static void mxfs_drbd_cas_serve(struct mxfs_drbd_cas *e)
{
	struct mxfs_drbd_cas_req *batch[MXFS_DRBD_CAS_BATCH];
	struct mxfs_drbd_cas_req *r, *tmp;
	struct mxfs_drbd_reg *reg;
	u8 *cur, *bounce;
	u32 pch;
	u64 pnum, mine;
	unsigned long deadline;
	unsigned int sleep_us = 100;
	int n = 0, i, rc, rrc;
	u64 t1, t2, t3, t4, t5;

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

	reg = kmalloc(1536, GFP_KERNEL);
	if (!reg) {
		for (i = 0; i < n; i++) {
			batch[i]->rc = -ENOMEM;
			batch[i]->done = true;
		}
		return;
	}
	cur = (u8 *)reg + 512;
	/*
	 * The target image is written from here, never from the caller's
	 * buffer: COMPARE AND WRITE copies its data into a page of its own, so
	 * callers hand it stack images (mxfs_bootstrap_claim's `want`), and a
	 * bio cannot be built on a vmalloc'd kernel stack.  Measured: the
	 * bootstrap claim on /dev/drbd0 failed -EINVAL after a pair outage.
	 */
	bounce = (u8 *)reg + 1024;

	t1 = ktime_get_ns();
	t2 = t3 = t4 = t1;
	e->ops += n;
	/* doorway: announce, take a ticket above the peer's, publish it */
	rc = mxfs_drbd_reg_put(e, reg, 1, 0);
	if (!rc)
		rc = mxfs_drbd_reg_get_peer(e, reg, &pch, &pnum);
	if (rc)
		goto release;
	mine = pnum + 1;
	rc = mxfs_drbd_reg_put(e, reg, 0, mine);
	t2 = t3 = t4 = ktime_get_ns();
	if (rc)
		goto release;

	deadline = jiffies + msecs_to_jiffies(mxfs_drbd_cas_wait_ms);
	for (;;) {
		rc = mxfs_drbd_reg_get_peer(e, reg, &pch, &pnum);
		if (rc)
			goto release;
		if (!pch && (pnum == 0 || mine < pnum ||
			     (mine == pnum && e->index < 1 - e->index)))
			break;
		if (sleep_us == 100)
			e->contended++;
		/*
		 * A peer that died holding a ticket keeps it for ever, and the
		 * certificate that would clear it (mxfs_pal_drbd_cas_peer_fenced)
		 * needs swaps to be written: measured, every swap on the survivor
		 * then failed after 10 s and it withdrew itself.  So once a swap
		 * has waited a second, ask the witness whether the peer is
		 * excluded by the evidence kind 25 or 26 is built from (link
		 * disconnected, peer Outdated, a receipt, the authority holding
		 * it off under that episode).  If it is, its ticket is cleared
		 * and the membership generation advanced exactly as the
		 * certificate path does.  If the peer is instead Secondary on a
		 * Connected link (both nodes restarted after a pair outage), the
		 * register its dead attachment left is set aside unwritten
		 * (void_img).  Never on age alone.
		 */
		if ((e->judge_excluded || e->judge_quiescent) &&
		    time_after(jiffies, deadline - msecs_to_jiffies(mxfs_drbd_cas_wait_ms) + HZ) &&
		    time_after_eq(jiffies, e->excl_next)) {
			e->excl_next = jiffies + 2 * HZ;
			if (mxfs_drbd_peer_excluded_locked(e, reg, mine)) {
				sleep_us = 100;
				continue;
			}
		}
		if (time_after(jiffies, deadline)) {
			pr_err("mxfs: P-DRBD-CAS-WAIT-TIMEOUT minor=%u index=%u ticket=%llu peer_choosing=%u peer_ticket=%llu waited_ms=%u — the peer holds its ticket past any critical section; failing the swap\n",
			       MINOR(e->devt), e->index, mine, pch, pnum,
			       mxfs_drbd_cas_wait_ms);
			rc = -EIO;
			goto release;
		}
		usleep_range(sleep_us, sleep_us * 2);
		if (sleep_us < 5000)
			sleep_us *= 2;
	}

	/* critical section: every queued swap, in order */
	t3 = ktime_get_ns();
	{
		int hold = READ_ONCE(mxfs_dbg_drbd_cas_hold_ms);

		if (unlikely(hold > 0) && xchg(&mxfs_dbg_drbd_cas_hold_ms, 0) == hold) {
			pr_warn("mxfs: P-DBG-DRBD-CAS-HOLD minor=%u index=%u ticket=%llu hold_ms=%d — holding the lock (test)\n",
				MINOR(e->devt), e->index, mine, hold);
			msleep(hold);
		}
	}
	for (i = 0; i < n; i++) {
		r = batch[i];
		r->rc = mxfs_drbd_sec_read(e, r->lba, cur);
		if (!r->rc) {
			if (memcmp(cur, r->compare_buf, 512)) {
				e->miscompares++;
				r->rc = -EAGAIN;
			} else {
				memcpy(bounce, r->write_buf, 512);
				r->rc = mxfs_drbd_sec_write(e, r->lba, bounce);
			}
		}
	}
	t4 = ktime_get_ns();
release:
	rrc = mxfs_drbd_reg_put(e, reg, 0, 0);
	t5 = ktime_get_ns();
	if (rrc)
		/* A ticket that could not be cleared stays visible to the peer,
		 * which then waits and fails its own swaps: never a correctness
		 * loss, but loud. */
		pr_err("mxfs: P-DRBD-CAS-RELEASE-FAILED minor=%u index=%u rc=%d\n",
		       MINOR(e->devt), e->index, rrc);
	for (i = 0; i < n; i++) {
		r = batch[i];
		if (rc)			/* never reached the critical section */
			r->rc = rc;
		else if (rrc && !r->rc)
			r->rc = rrc;
		r->done = true;
	}

	e->st_n += n;
	e->st_batches++;
	for (i = 0; i < n; i++)
		e->st_lock += t1 - batch[i]->tq;
	e->st_door += t2 - t1;
	e->st_bakery += t3 - t2;
	e->st_crit += t4 - t3;
	e->st_rel += t5 - t4;
	if (t5 - batch[0]->tq > e->st_max)
		e->st_max = t5 - batch[0]->tq;
	if (e->st_n >= MXFS_DRBD_STATS_EVERY) {
		/* per swap: lock (its own wait); per batch: the rest */
		mxfs_probe("mxfs: P-DRBD-CAS-STATS minor=%u swaps=%llu batches=%llu avg_us lock/swap=%llu door/batch=%llu bakery/batch=%llu crit/batch=%llu rel/batch=%llu max_us=%llu ops=%llu contended=%llu miscompares=%llu\n",
			   MINOR(e->devt), e->st_n, e->st_batches,
			   e->st_lock / e->st_n / 1000,
			   e->st_door / e->st_batches / 1000,
			   e->st_bakery / e->st_batches / 1000,
			   e->st_crit / e->st_batches / 1000,
			   e->st_rel / e->st_batches / 1000, e->st_max / 1000,
			   e->ops, e->contended, e->miscompares);
		e->st_n = e->st_batches = e->st_lock = e->st_door = 0;
		e->st_bakery = e->st_crit = e->st_rel = e->st_max = 0;
	}
	kfree(reg);
}

static int mxfs_drbd_cas_run(struct mxfs_drbd_cas *e, u64 lba,
			     const void *compare_buf, const void *write_buf)
{
	struct mxfs_drbd_cas_req req = {
		.lba = lba, .compare_buf = compare_buf, .write_buf = write_buf,
		.tq = ktime_get_ns(),
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

/* Called by mxfs_pal_bdev_compare_and_write for a device with no SCSI underneath. */
int mxfs_pal_drbd_cas_emulate(mxfs_bdev_t *dev, uint64_t offset,
			      const void *compare_buf, const void *write_buf)
{
	struct block_device *bdev = mxfs_pal_bdev_get_bdev(dev);
	struct mxfs_drbd_cas *e;
	u64 abs;

	if (!bdev)
		return -EINVAL;
	mutex_lock(&mxfs_drbd_cas_list_lock);
	e = mxfs_drbd_cas_find(bdev->bd_dev);
	mutex_unlock(&mxfs_drbd_cas_list_lock);
	if (!e)
		return -EOPNOTSUPP;
	abs = offset + mxfs_pal_bdev_get_base_offset(dev);
	if (abs & 511)
		return -EINVAL;
	/* The lock's own sectors are never a swap target. */
	if (abs / 512 >= e->area_lba && abs / 512 < e->area_lba + 3)
		return -EINVAL;
	return mxfs_drbd_cas_run(e, abs / 512, compare_buf, write_buf);
}

/*
 * The pair's enrollment: participant 0's and 1's endpoints, bound to the
 * filesystem.  Written by whichever node arrives first; both nodes, if they
 * agree, write the same bytes.  A node that finds an enrollment naming a
 * different pair — or that reads back something other than what it wrote —
 * refuses: two nodes that disagree about who is participant 0 must never both
 * run the bakery.
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
	want->version = cpu_to_le16(MXFS_DRBD_CAS_VERSION);
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
		pr_err("mxfs: P-DRBD-CAS-ENROLL-MISMATCH minor=%u this node: index=%u endpoints=[%s,%s]; on disk: magic=0x%x endpoints=[%.48s,%.48s] — refusing: the pair disagrees about who is participant 0\n",
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
	if (!e || !r) {
		kfree(e);
		kfree(r);
		return -ENOMEM;
	}
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
		pr_err("mxfs: P-DRBD-CAS-OWN-REG-FOREIGN minor=%u index=%u register names endpoint='%.48s' crc_ok=%d — another node holds this index; refusing\n",
		       MINOR(e->devt), index, r->endpoint,
		       le32_to_cpu(r->crc) == mxfs_drbd_crc(r));
		rc = -EIO;
	}
	if (!rc)
		rc = mxfs_drbd_reg_put(e, r, 0, 0);
	kfree(r);
	if (rc) {
		kfree(e);
		return rc;
	}

	mutex_lock(&mxfs_drbd_cas_list_lock);
	have = mxfs_drbd_cas_find(bdev->bd_dev);
	if (have) {
		/* A concurrent attach on this node won: use it. */
		have->refs++;
		mutex_unlock(&mxfs_drbd_cas_list_lock);
		kfree(e);
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
	pr_info("mxfs: P-DRBD-CAS-DETACH minor=%u index=%u ops=%llu contended=%llu miscompares=%llu\n",
		MINOR(e->devt), e->index, e->ops, e->contended, e->miscompares);
	kfree(e);
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
};

/* A writer waiting for its share; lives on its own stack until `go`. */
struct mxfs_ioq_waiter {
	struct list_head	node;
	struct task_struct	*task;
	unsigned int		bytes;
	bool			go;
};

/* What an admitted bio's completion gives back, and to whom. */
struct mxfs_ioq_hook {
	bio_end_io_t		*end_io;
	void			*private;
	struct mxfs_ioq		*q;
	unsigned int		bytes;
};

#define MXFS_IOQ_POOL_MIN	64
#define MXFS_IOQ_STATS_EVERY	1024	/* waits between P-DRBD-IOQ-STATS lines */

static bool mxfs_ioq_fits(struct mxfs_ioq *q, unsigned int bytes)
{
	unsigned long max_bytes = (unsigned long)READ_ONCE(mxfs_drbd_inflight_kb) << 10;
	unsigned int max_reqs = READ_ONCE(mxfs_drbd_inflight_reqs);

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
			w->go = true;
			wake_up_process(w->task);
		}
	}
}

static void mxfs_ioq_free(struct mxfs_ioq *q)
{
	pr_info("mxfs: P-DRBD-IOQ-DONE minor=%u admitted=%llu split=%llu waited=%llu refused=%llu wait_avg_ms=%llu wait_max_ms=%llu peak_kib=%lu peak_reqs=%u\n",
		MINOR(q->devt), q->n_admit, q->n_split, q->n_wait, q->n_refused,
		q->n_wait ? q->wait_ns / q->n_wait / NSEC_PER_MSEC : 0,
		q->wait_ns_max / NSEC_PER_MSEC, q->bytes_peak >> 10, q->reqs_peak);
	mempool_destroy(q->pool);
	kfree(q);
}

/* Give a share back and hand it on; the last one back after the mount is gone
 * frees the bound.  Any context: completions call it. */
static void mxfs_ioq_put(struct mxfs_ioq *q, unsigned int bytes)
{
	unsigned long flags;
	bool gone;

	spin_lock_irqsave(&q->lock, flags);
	q->bytes -= bytes;
	q->reqs--;
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

	bio->bi_end_io = h->end_io;
	bio->bi_private = h->private;
	/* the hook goes back first: q is alive while this share is held */
	mempool_free(h, q->pool);
	mxfs_ioq_put(q, bytes);
	bio->bi_end_io(bio);
}

/* Admit one bio of at most a chunk (or a bio that cannot be split). */
static int mxfs_ioq_admit_one(struct mxfs_ioq *q, struct bio *bio,
			      enum mxfs_ioq_class cls, unsigned int bytes)
{
	struct mxfs_ioq_waiter w;
	struct mxfs_ioq_hook *h;
	bool waited = false;
	u64 t0, ns = 0, n_wait = 0;

	spin_lock_irq(&q->lock);
	if (list_empty(&q->wait[MXFS_IOQ_META]) &&
	    (cls == MXFS_IOQ_META || list_empty(&q->wait[MXFS_IOQ_DATA])) &&
	    mxfs_ioq_fits(q, bytes)) {
		mxfs_ioq_take(q, bytes);
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
		mxfs_ioq_put(q, bytes);
		return -EAGAIN;
	}
	h->end_io = bio->bi_end_io;
	h->private = bio->bi_private;
	h->q = q;
	h->bytes = bytes;
	bio->bi_private = h;
	bio->bi_end_io = mxfs_ioq_end_io;

	if (!waited)
		return 0;
	if (!(n_wait % MXFS_IOQ_STATS_EVERY))
		mxfs_probe("mxfs: P-DRBD-IOQ-STATS minor=%u admitted=%llu waited=%llu wait_avg_us=%llu wait_max_ms=%llu peak_kib=%lu peak_reqs=%u last_wait_us=%llu\n",
			   MINOR(q->devt), q->n_admit, q->n_wait,
			   q->wait_ns / q->n_wait / NSEC_PER_USEC,
			   q->wait_ns_max / NSEC_PER_MSEC, q->bytes_peak >> 10,
			   q->reqs_peak, ns / NSEC_PER_USEC);
	/*
	 * The writer asked the mount's authority question before it came here;
	 * the wait must not carry its write past the answer.  Hooked already:
	 * the caller completes the bio with an error, which returns its share.
	 */
	if (q->admitted && !q->admitted(q->ctx)) {
		spin_lock_irq(&q->lock);
		q->n_refused++;
		spin_unlock_irq(&q->lock);
		pr_err_ratelimited("mxfs: P-DRBD-IOQ-REFUSED minor=%u class=%s bytes=%u waited_ms=%llu comm=%s — this node's authority closed while the write waited for room on the DRBD device; it is failed (-EIO), never submitted\n",
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
		pr_err("mxfs: P-DRBD-IOQ-NOMEM minor=%u — this mount's writes on the DRBD device are not bounded, so under heavy writes its coordination writes can queue behind them\n",
		       MINOR(bdev->bd_dev));
		return NULL;
	}
	spin_lock_init(&q->lock);
	for (c = 0; c < MXFS_IOQ_NCLASS; c++)
		INIT_LIST_HEAD(&q->wait[c]);
	q->devt = bdev->bd_dev;
	q->admitted = admitted;
	q->ctx = ctx;
	pr_info("mxfs: P-DRBD-IOQ-ARMED minor=%u inflight_kib=%u inflight_reqs=%u — this mount's data and metadata writes on the DRBD device are held to that much in flight, so its coordination writes never queue behind more\n",
		MINOR(q->devt), READ_ONCE(mxfs_drbd_inflight_kb),
		READ_ONCE(mxfs_drbd_inflight_reqs));
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
		pr_warn("mxfs: P-DRBD-IOQ-LATE minor=%u reqs=%u kib=%lu — writes still in flight as the mount is freed; the last of them frees the bound\n",
			MINOR(q->devt), q->reqs, q->bytes >> 10);
	spin_unlock_irq(&q->lock);
	if (idle)
		mxfs_ioq_free(q);
}
EXPORT_SYMBOL_GPL(mxfs_pal_ioq_destroy);

/*
 * The peer is FENCED: a certificate (kind 25) proves it can no longer write.
 * A ticket it died holding would make every later swap wait it out and fail,
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
	e->membership_gen++;
	rc = mxfs_drbd_sec_write(e, e->area_lba + 1 + (1 - e->index), r);
	if (!rc)
		rc = mxfs_drbd_reg_put(e, r, 0, 0);
	mutex_unlock(&e->lock);
	kfree(r);
	pr_warn("mxfs: P-DRBD-CAS-PEER-FENCED minor=%u index=%u membership_gen=%llu rc=%d — the fenced peer's ticket is cleared\n",
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
	pr_info("mxfs: P-DRBD-EXCL-NOTICE minor=%u mounts=%u — the fence handler reports its peer excluded; a mount confirms with its own witness before it declares the death\n",
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
	mxfs_drbdw_pde = proc_create(MXFS_DRBDW_PROC_NAME, 0200, NULL,
				     &mxfs_drbdw_report_ops);
	if (!mxfs_drbdw_pde) {
		pr_err("mxfs: P-DRBDW-NOCHAN could not create %s — a DRBD device cannot be admitted or fenced\n",
		       MXFS_DRBDW_PROC_PATH);
		return -ENOMEM;
	}
	/* Without it a death is still declared, by the TCP link's timeout and
	 * grace; the notice only shortens that. */
	mxfs_drbdx_pde = proc_create(MXFS_DRBDX_PROC_NAME, 0200, NULL,
				     &mxfs_drbdx_ops);
	if (!mxfs_drbdx_pde)
		pr_warn("mxfs: P-DRBDX-NOCHAN could not create /proc/%s — a DRBD peer's death waits out the TCP link's timeout and grace\n",
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
}
