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

#include "../pal.h"

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
 * Read the peer's register.  Never written (all zero) reads as idle.  Any
 * other content must be a valid register of THIS filesystem, of the peer's
 * index, from the peer's endpoint: anything else is corruption or a
 * misconfigured pair, and the swap fails closed.
 */
static int mxfs_drbd_reg_get_peer(struct mxfs_drbd_cas *e, struct mxfs_drbd_reg *r,
				  u32 *choosing, u64 *number)
{
	unsigned int peer = 1 - e->index;
	int rc = mxfs_drbd_sec_read(e, e->area_lba + 1 + peer, r);

	if (rc)
		return rc;
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
		pr_err("mxfs: P-DRBD-CAS-PEER-REG-INVALID minor=%u peer_index=%u magic=0x%x crc_ok=%d index=%u endpoint='%.48s' want='%s' — refusing the swap\n",
		       MINOR(e->devt), peer, le32_to_cpu(r->magic),
		       le32_to_cpu(r->crc) == mxfs_drbd_crc(r),
		       le16_to_cpu(r->index), r->endpoint, e->peer_endpoint);
		return -EIO;
	}
	*choosing = le32_to_cpu(r->choosing);
	*number = le64_to_cpu(r->number);
	if (*number >= MXFS_DRBD_TICKET_MAX)
		return -EOVERFLOW;
	return 0;
}

/*
 * Called with e->lock held from a swap waiting on the peer's ticket.  The
 * witness is taken for the attachment's minor; if the judgment says the peer
 * is excluded, its register is cleared, the membership generation advanced and
 * our own register (still holding `mine`) re-published under it.  1 = cleared.
 */
static int mxfs_drbd_peer_excluded_locked(struct mxfs_drbd_cas *e,
					  struct mxfs_drbd_reg *reg, u64 mine)
{
	struct mxfs_pal_drbd_report *r;
	char why[160] = "";
	u8 *zero;
	int rc;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	zero = kzalloc(512, GFP_KERNEL);
	if (!r || !zero) {
		kfree(r);
		kfree(zero);
		return 0;
	}
	rc = mxfs_drbdw_run(MINOR(e->devt), MXFS_PAL_DRBD_RECHECK, r);
	if (rc == 0)
		rc = e->judge_excluded(r, why, sizeof(why));
	if (rc) {
		pr_warn_ratelimited("mxfs: P-DRBD-CAS-PEER-NOT-EXCLUDED minor=%u index=%u why='%s' — the peer's ticket stands\n",
				    MINOR(e->devt), e->index, why);
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

/* Register the mount's exclusion judgment on the attachment of `dev`. */
void mxfs_pal_drbd_cas_set_judge(mxfs_bdev_t *dev,
				 int (*judge)(const struct mxfs_pal_drbd_report *r,
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
	e->judge_excluded = judge;
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
		 * excluded by the evidence kind 25 is built from (link
		 * disconnected, peer Outdated, a STONITHED receipt, the authority
		 * holding it off under that episode).  If it is, its ticket is
		 * cleared and the membership generation advanced exactly as the
		 * certificate path does; never on age alone.
		 */
		if (e->judge_excluded &&
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
	return 0;
}

void mxfs_pal_drbd_exit(void)
{
	if (mxfs_drbdw_pde) {
		proc_remove(mxfs_drbdw_pde);
		mxfs_drbdw_pde = NULL;
	}
}
