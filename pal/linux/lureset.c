/*
 * MXFS — Multinode XFS
 * Platform Abstraction Layer — Linux: the witnessed LOGICAL UNIT RESET.
 *
 * WHY THIS EXISTS.  When a node dies, MXFS may replay its journal slice only
 * once it can state that the work the target had already ACCEPTED from that
 * node can no longer execute.  A PERSISTENT RESERVE OUT / PREEMPT AND ABORT
 * states it, but only while the victim's registration is still in the target's
 * table — and a target that purges a registration together with its iSCSI
 * session (the shipping LUN does, ~32 s after a power cut, while MXFS does not
 * declare the node dead for ~63 s) has destroyed that evidence before the
 * first fence attempt is made.  A LOGICAL UNIT RESET has no such dependency:
 * its scope is the logical unit, not one registration, so it reaches work
 * whose originating session is gone.
 *
 * WHY IT RUNS IN USERSPACE.  Issuing a task-management function from a module
 * needs either a fabricated scsi_cmnd handed to a low-level error handler —
 * whose locking, recovery state and calling-context assumptions are not ours
 * to assume — or the ioctl the SCSI midlayer already exports for exactly this,
 * SG_SCSI_RESET.  That ioctl reads its argument from user memory and there is
 * no in-kernel caller for it, so the operation is performed by a helper
 * program this module executes and whose report it checks.  The helper owns no
 * decision: this module chooses the logical unit, generates the nonce, and
 * decides what the report is worth.
 *
 * THE CHANNEL IS A WRITE INTO THIS MODULE, NEVER A FILE.  The helper writes
 * its report to /proc/fs/mxfs/lu_reset_report, which exists only while an
 * invocation is outstanding and accepts one report per nonce.  A file on disk
 * would be stale, substitutable and replayable; a fresh 64-bit nonce carried
 * through argv and required back in the report binds the answer to the
 * question that was asked.
 *
 * WHAT THIS MODULE WILL AND WILL NOT CONCLUDE.  A verdict of WITNESSED means:
 * the helper executed, resolved the logical unit by the designator this module
 * named, issued exactly one LOGICAL UNIT RESET with escalation forbidden, the
 * ioctl returned success, and the transport incarnation it ran on was
 * unchanged across the call.  Anything else is REFUSED (nothing was issued) or
 * INDETERMINATE (it may have been issued and the outcome is unknown), and an
 * INDETERMINATE is never downgraded to "no reset happened" — killing the
 * helper does not cancel an ioctl already executing.
 *
 * Copyright (c) 2026
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/random.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>

#include "../pal.h"

#define MXFS_LURESET_PROC_NAME	"fs/mxfs/lu_reset_report"
#define MXFS_LURESET_PROC_PATH	"/proc/" MXFS_LURESET_PROC_NAME
#define MXFS_LURESET_END_MARK	"MXFS-LURW-END"

/*
 * THE HELPER MUST BE NODE-LOCAL.  The default is an installed path and not a
 * path inside the source tree: on the test fleet the tree is an NFS mount from
 * the build host, and a fence that upcalls into NFS has made the survival of
 * one node's storage recovery depend on a third machine's file server.  The
 * deployment sets this; a path that does not exist produces NOT_RUN, which is
 * a refusal, so a mis-set path costs availability and never integrity.
 */
static char *mxfs_lu_reset_helper = "/usr/local/sbin/mxfs_lu_reset_witness.py";
module_param_named(lu_reset_helper, mxfs_lu_reset_helper, charp, 0644);
MODULE_PARM_DESC(lu_reset_helper,
		 "absolute path to the node-local LOGICAL UNIT RESET witness helper");

/*
 * THE BOUND ON ONE UPCALL, derived and not chosen for roundness.  The ioctl
 * itself is bounded by the session's own LU reset task-management timeout,
 * which libiscsi defaults to 30 s; the helper's remaining work is process
 * startup, a handful of sysfs reads and two short iscsiadm invocations, all of
 * which together measured well under 1 s on this fleet, and 15 s is a very
 * wide multiple of that.  Exceeding it yields INDETERMINATE, never a witness
 * and never "nothing happened".
 */
static unsigned int mxfs_lu_reset_timeout_ms = 45000;
module_param_named(lu_reset_timeout_ms, mxfs_lu_reset_timeout_ms, uint, 0644);
MODULE_PARM_DESC(lu_reset_timeout_ms,
		 "bound on one LOGICAL UNIT RESET upcall; exceeding it is INDETERMINATE");

/*
 * A STANDALONE TRIGGER, OFF BY DEFAULT.  With this set, writing
 * "<designator> <epoch> <victim-tag>" to /proc/fs/mxfs/lu_reset_probe runs the
 * real upcall against the named logical unit and logs the verdict.  It runs
 * the production path rather than a copy of it, which is the only reason it is
 * worth having; it is also a way to reset a logical unit from a shell, so it
 * is not reachable unless a deployment asks for it.
 */
static bool mxfs_lu_reset_probe_enable;
module_param_named(lu_reset_probe_enable, mxfs_lu_reset_probe_enable, bool, 0644);
MODULE_PARM_DESC(lu_reset_probe_enable,
		 "expose /proc/fs/mxfs/lu_reset_probe, which issues a real LU RESET");

/*
 * ONE INVOCATION AT A TIME, AND THE SLOT IS THE CHANNEL.  Serialising is not
 * an optimisation: the report arrives through a write with no caller identity
 * attached, so two outstanding invocations would be two reports with no way to
 * say which belongs to which beyond the nonce — and having only one outstanding
 * removes the question instead of answering it.
 */
static DEFINE_MUTEX(mxfs_lureset_invoke_lock);

static struct {
	spinlock_t		lock;
	bool			armed;
	bool			complete;
	u64			nonce;
	char			nonce_str[17];
	size_t			len;
	struct completion	done;
	char			buf[MXFS_PAL_LURESET_REPORT_MAX];
} mxfs_lureset_slot = {
	.lock = __SPIN_LOCK_UNLOCKED(mxfs_lureset_slot.lock),
};

static struct proc_dir_entry *mxfs_lureset_report_pde;
static struct proc_dir_entry *mxfs_lureset_probe_pde;

/* ───────────────────────── report parsing ───────────────────────── */

/*
 * The value of one `KEY=value` line in the report, copied out NUL-terminated.
 * The report is framed text from a program this module executed, and it is
 * parsed as DATA: no line is trusted to exist, to be terminated, or to fit.
 * Returns false when the key is absent, which every caller treats as a missing
 * fact rather than as an empty one.
 */
static bool mxfs_lureset_field(const char *rep, size_t replen, const char *key,
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
			/* A trailing CR would silently fail every comparison
			 * below while printing identically in the log. */
			while (vlen > 0 && (out[vlen - 1] == '\r' ||
					    out[vlen - 1] == ' '))
				out[--vlen] = '\0';
			return true;
		}
		i = eol + 1;
	}
	return false;
}

/*
 * Compare two logical-unit designators by content.  The kernel's
 * scsi_vpd_lun_id() and sysfs's device/wwid print the same identifier with
 * different prefixes and, on some targets, different case, so the two
 * spellings of one logical unit must compare equal or the helper would refuse
 * the very device it was sent to.  Everything that is not a hexadecimal digit
 * after the prefix is dropped from both sides.
 */
static void mxfs_lureset_normwwid(const char *in, char *out, size_t outsz)
{
	size_t o = 0;
	const char *p = in;

	if (!out || outsz == 0)
		return;
	out[0] = '\0';
	if (!in)
		return;
	while (*p == ' ' || *p == '\t')
		p++;
	if (!strncasecmp(p, "naa.", 4) || !strncasecmp(p, "eui.", 4) ||
	    !strncasecmp(p, "t10.", 4))
		p += 4;
	else if (!strncasecmp(p, "0x", 2))
		p += 2;
	for (; *p && o < outsz - 1; p++) {
		char c = *p;

		if (c >= 'A' && c <= 'Z')
			c = c - 'A' + 'a';
		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z'))
			out[o++] = c;
	}
	out[o] = '\0';
}

/* ───────────────────────── the report channel ───────────────────────── */

static ssize_t mxfs_lureset_report_write(struct file *file,
					 const char __user *ubuf,
					 size_t count, loff_t *ppos)
{
	char *stage;
	char nonce_seen[24];
	size_t take;
	ssize_t ret;
	bool finished = false;

	if (count == 0)
		return 0;
	/*
	 * Refuse when nothing is outstanding.  This is the whole reason the
	 * channel is a write into the module: a report that nobody asked for
	 * is not evidence, and accepting it into a buffer that a later
	 * invocation might read would make a replay possible.
	 */
	spin_lock(&mxfs_lureset_slot.lock);
	if (!mxfs_lureset_slot.armed || mxfs_lureset_slot.complete) {
		spin_unlock(&mxfs_lureset_slot.lock);
		return -EPERM;
	}
	spin_unlock(&mxfs_lureset_slot.lock);

	take = count;
	if (take > MXFS_PAL_LURESET_REPORT_MAX)
		take = MXFS_PAL_LURESET_REPORT_MAX;
	stage = kmalloc(take, GFP_KERNEL);
	if (!stage)
		return -ENOMEM;
	if (copy_from_user(stage, ubuf, take)) {
		kfree(stage);
		return -EFAULT;
	}

	spin_lock(&mxfs_lureset_slot.lock);
	if (!mxfs_lureset_slot.armed || mxfs_lureset_slot.complete) {
		spin_unlock(&mxfs_lureset_slot.lock);
		kfree(stage);
		return -EPERM;
	}
	if (mxfs_lureset_slot.len + take > MXFS_PAL_LURESET_REPORT_MAX - 1)
		take = MXFS_PAL_LURESET_REPORT_MAX - 1 - mxfs_lureset_slot.len;
	if (take) {
		memcpy(mxfs_lureset_slot.buf + mxfs_lureset_slot.len, stage, take);
		mxfs_lureset_slot.len += take;
		mxfs_lureset_slot.buf[mxfs_lureset_slot.len] = '\0';
	}
	/*
	 * A REPORT THAT NAMES ANOTHER INVOCATION IS DISCARDED HERE, not judged
	 * afterwards.  An earlier helper that outlived the bound its caller
	 * waited under is still running and will still write; buffering that
	 * write would end the CURRENT wait, so the live question would have
	 * been consumed by a dead one.  Judging the nonce later makes that safe
	 * but not useful.  Rejecting it leaves the channel armed for the report
	 * that was actually asked for.
	 */
	if (mxfs_lureset_field(mxfs_lureset_slot.buf, mxfs_lureset_slot.len,
			       "NONCE", nonce_seen, sizeof(nonce_seen)) &&
	    strcasecmp(nonce_seen, mxfs_lureset_slot.nonce_str)) {
		mxfs_lureset_slot.len = 0;
		mxfs_lureset_slot.buf[0] = '\0';
		spin_unlock(&mxfs_lureset_slot.lock);
		kfree(stage);
		pr_warn("mxfs: P305-LURESET-STALE a report naming nonce=%s arrived while another invocation is outstanding — discarded; the channel stays armed for the report that was asked for\n",
			nonce_seen);
		return -EPERM;
	}
	/*
	 * The report is complete at its own end marker, not at the end of a
	 * write(): a truncated report must stay incomplete so the waiter times
	 * out into INDETERMINATE rather than reading a half-report as a
	 * verdict.
	 */
	if (strstr(mxfs_lureset_slot.buf, MXFS_LURESET_END_MARK)) {
		mxfs_lureset_slot.complete = true;
		finished = true;
	}
	spin_unlock(&mxfs_lureset_slot.lock);
	kfree(stage);
	if (finished)
		complete(&mxfs_lureset_slot.done);
	/* Report the full count as consumed even when the tail was dropped:
	 * the helper must not block or retry, and what was dropped is visible
	 * as a report with no end marker. */
	ret = count;
	*ppos += ret;
	return ret;
}

static const struct proc_ops mxfs_lureset_report_ops = {
	.proc_write	= mxfs_lureset_report_write,
	.proc_lseek	= noop_llseek,
};

/* ───────────────────────── the upcall ───────────────────────── */

static const char *mxfs_lureset_verdict_name(int v)
{
	switch (v) {
	case MXFS_PAL_LURESET_REFUSED:		return "REFUSED";
	case MXFS_PAL_LURESET_WITNESSED:	return "WITNESSED";
	case MXFS_PAL_LURESET_INDETERMINATE:	return "INDETERMINATE";
	default:				return "NOT_RUN";
	}
}
const char *mxfs_pal_lu_reset_verdict_name(int v)
{
	return mxfs_lureset_verdict_name(v);
}
EXPORT_SYMBOL_GPL(mxfs_pal_lu_reset_verdict_name);

/*
 * Everything a report must say before this module will call it a witness.
 * Each check names what it rejected, because a fence that refuses has to be
 * able to say which fact was missing — "no witness" with no reason is
 * indistinguishable from a bug in this code.
 */
static void mxfs_lureset_judge(struct mxfs_pal_lu_reset_result *out,
			       const struct mxfs_pal_lu_reset_req *req)
{
	char val[80];
	char want[80];
	char got[80];

	/* The nonce first: without it, nothing else in the report is known to
	 * belong to this invocation. */
	if (!mxfs_lureset_field(out->report, out->report_len, "NONCE", val,
				sizeof(val))) {
		out->verdict = MXFS_PAL_LURESET_INDETERMINATE;
		strscpy(out->reason, "report-has-no-nonce", sizeof(out->reason));
		return;
	}
	snprintf(want, sizeof(want), "%016llx", (unsigned long long)out->nonce);
	if (strcasecmp(val, want)) {
		out->verdict = MXFS_PAL_LURESET_INDETERMINATE;
		snprintf(out->reason, sizeof(out->reason),
			 "nonce-mismatch-want-%s-got-%s", want, val);
		return;
	}

	/* Which logical unit the helper actually acted on.  WWID_SEEN is the
	 * designator it read from the device it opened, so it is the one that
	 * matters; WWID_REQ only says the argument arrived intact. */
	mxfs_lureset_normwwid(req->lun_id, want, sizeof(want));
	if (mxfs_lureset_field(out->report, out->report_len, "WWID_REQ", val,
			       sizeof(val))) {
		mxfs_lureset_normwwid(val, got, sizeof(got));
		if (strcmp(want, got)) {
			out->verdict = MXFS_PAL_LURESET_INDETERMINATE;
			snprintf(out->reason, sizeof(out->reason),
				 "wwid-req-mismatch-%s", got);
			return;
		}
	}

	if (mxfs_lureset_field(out->report, out->report_len, "KREL", val,
			       sizeof(val)))
		strscpy(out->krel, val, sizeof(out->krel));

	if (mxfs_lureset_field(out->report, out->report_len, "RESET_ISSUED",
			       val, sizeof(val)) && !strcmp(val, "1"))
		out->issued = true;
	if (mxfs_lureset_field(out->report, out->report_len, "RESET_RC", val,
			       sizeof(val)) && kstrtoint(val, 10, &out->reset_rc)) {
		/* A result code that will not parse is not a zero.  Zero is
		 * the one value that would let the witness stand, so an
		 * unreadable one has to stop it here rather than default into
		 * the success it cannot be read as. */
		out->verdict = MXFS_PAL_LURESET_INDETERMINATE;
		snprintf(out->reason, sizeof(out->reason),
			 "reset-rc-unparsable-%s", val);
		return;
	}
	if (mxfs_lureset_field(out->report, out->report_len, "RESET_WALL_MS",
			       val, sizeof(val)) &&
	    kstrtouint(val, 10, &out->reset_wall_ms))
		out->reset_wall_ms = 0;	/* reported time only; never a verdict */
	if (mxfs_lureset_field(out->report, out->report_len, "REASON", val,
			       sizeof(val)))
		strscpy(out->reason, val, sizeof(out->reason));

	if (!mxfs_lureset_field(out->report, out->report_len, "WITNESSED", val,
				sizeof(val))) {
		/* The helper writes WITNESSED on every exit path, so its
		 * absence means the report was cut short — and a report cut
		 * short after the reset was issued is not "no reset". */
		out->verdict = out->issued ? MXFS_PAL_LURESET_INDETERMINATE
					   : MXFS_PAL_LURESET_NOT_RUN;
		strscpy(out->reason, "report-has-no-verdict",
			sizeof(out->reason));
		return;
	}
	if (strcmp(val, "1")) {
		/* The helper declined.  Which side of the command boundary it
		 * declined on is the only thing that decides whether anything
		 * may have reached the target. */
		out->verdict = out->issued ? MXFS_PAL_LURESET_INDETERMINATE
					   : MXFS_PAL_LURESET_REFUSED;
		if (out->reason[0] == '\0')
			strscpy(out->reason, "helper-declined",
				sizeof(out->reason));
		return;
	}
	if (!out->issued) {
		out->verdict = MXFS_PAL_LURESET_INDETERMINATE;
		strscpy(out->reason, "witnessed-without-reset-issued",
			sizeof(out->reason));
		return;
	}
	if (out->reset_rc != 0) {
		out->verdict = MXFS_PAL_LURESET_INDETERMINATE;
		snprintf(out->reason, sizeof(out->reason),
			 "witnessed-with-reset-rc-%d", out->reset_rc);
		return;
	}
	out->verdict = MXFS_PAL_LURESET_WITNESSED;
	strscpy(out->reason, "lu-reset-completed-on-unmoved-incarnation",
		sizeof(out->reason));
}

int mxfs_pal_lu_reset_witness(const struct mxfs_pal_lu_reset_req *req,
			      struct mxfs_pal_lu_reset_result *out)
{
	char nonce_str[17];
	char epoch_str[24];
	char helper[192];
	char *argv[7];
	static char *envp[] = {
		"HOME=/",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin",
		NULL
	};
	ktime_t t0;
	unsigned long left;
	int rc;

	if (!req || !out || !req->lun_id || !req->lun_id[0])
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	out->verdict = MXFS_PAL_LURESET_NOT_RUN;

	if (!mxfs_lureset_report_pde) {
		strscpy(out->reason, "no-report-channel", sizeof(out->reason));
		return -ENODEV;
	}
	/*
	 * 0.89.34 — TRIM THE PATH BEFORE ANYTHING LOOKS IT UP.
	 *
	 * This parameter is how a deployment names the helper, and the way a
	 * path is written into a sysfs file is `echo /path > .../lu_reset_helper`
	 * — which stores the newline too, because a charp store keeps the bytes
	 * that were written.  Nothing would then exist at the stored path, every
	 * upcall would return NOT_RUN, and on a target that purges a dead node's
	 * registration NOT_RUN is the difference between a recoverable death and
	 * a journal slice nobody can ever replay.  The refusal would name the
	 * helper, and the name it printed would look correct.
	 *
	 * A path may not begin or end with whitespace here, so trimming can only
	 * recover the path that was meant.  The copy is also what argv and the
	 * log lines use, so the value that ran and the value that was reported
	 * cannot drift apart if the parameter is rewritten mid-call.
	 */
	{
		const char *hp = mxfs_lu_reset_helper ? mxfs_lu_reset_helper : "";
		size_t hn;

		while (*hp == ' ' || *hp == '\t' || *hp == '\n' || *hp == '\r')
			hp++;
		hn = strlen(hp);
		while (hn && (hp[hn - 1] == ' ' || hp[hn - 1] == '\t' ||
			      hp[hn - 1] == '\n' || hp[hn - 1] == '\r'))
			hn--;
		if (hn >= sizeof(helper)) {
			strscpy(out->reason, "helper-path-too-long",
				sizeof(out->reason));
			return -ENAMETOOLONG;
		}
		memcpy(helper, hp, hn);
		helper[hn] = '\0';
	}
	if (!helper[0] || helper[0] != '/') {
		strscpy(out->reason, "helper-path-unset", sizeof(out->reason));
		return -ENOENT;
	}

	mutex_lock(&mxfs_lureset_invoke_lock);

	out->nonce = get_random_u64();
	/* A zero nonce would compare equal to an uninitialised slot. */
	if (!out->nonce)
		out->nonce = 1;
	snprintf(nonce_str, sizeof(nonce_str), "%016llx",
		 (unsigned long long)out->nonce);
	snprintf(epoch_str, sizeof(epoch_str), "%llu",
		 (unsigned long long)req->epoch);

	spin_lock(&mxfs_lureset_slot.lock);
	mxfs_lureset_slot.nonce = out->nonce;
	strscpy(mxfs_lureset_slot.nonce_str, nonce_str,
		sizeof(mxfs_lureset_slot.nonce_str));
	mxfs_lureset_slot.len = 0;
	mxfs_lureset_slot.buf[0] = '\0';
	mxfs_lureset_slot.complete = false;
	mxfs_lureset_slot.armed = true;
	spin_unlock(&mxfs_lureset_slot.lock);
	init_completion(&mxfs_lureset_slot.done);

	argv[0] = helper;
	argv[1] = nonce_str;
	argv[2] = (char *)req->lun_id;
	argv[3] = epoch_str;
	argv[4] = (char *)(req->victim && req->victim[0] ? req->victim : "-");
	argv[5] = (char *)MXFS_LURESET_PROC_PATH;
	argv[6] = NULL;

	pr_warn("mxfs: P305-LURESET-ISSUE lun=%s epoch=%llu victim=%s nonce=%s helper=%s bound_ms=%u — issuing ONE LOGICAL UNIT RESET, escalation forbidden\n",
		req->lun_id, (unsigned long long)req->epoch, argv[4], nonce_str,
		helper, mxfs_lu_reset_timeout_ms);

	t0 = ktime_get();
	/*
	 * UMH_WAIT_EXEC and not UMH_WAIT_PROC.  Waiting for the process gives
	 * an exit status but no bound: a helper that never exits would park
	 * the fence thread forever, and refusing by hanging is not refusing.
	 * Waiting for the REPORT instead is bounded, and the report says
	 * everything the exit status would have.  An exec that fails returns
	 * here with an error and nothing has been issued.
	 */
	rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	if (rc) {
		/*
		 * The helper was never entered, so nothing reached the target
		 * and this attempt is retryable.  It still falls through to
		 * the verdict line: a reader looking for what one attempt
		 * concluded must find exactly one such line per attempt,
		 * whatever the attempt did.
		 */
		spin_lock(&mxfs_lureset_slot.lock);
		mxfs_lureset_slot.armed = false;
		spin_unlock(&mxfs_lureset_slot.lock);
		out->verdict = MXFS_PAL_LURESET_NOT_RUN;
		snprintf(out->reason, sizeof(out->reason), "exec-failed-%d", rc);
		out->upcall_wall_ms = ktime_to_ms(ktime_sub(ktime_get(), t0));
		pr_err("mxfs: P305-LURESET-NOEXEC helper='%s' rc=%d — NOTHING was issued; this attempt is retryable\n",
		       helper, rc);
		goto verdict;
	}

	left = wait_for_completion_timeout(
		&mxfs_lureset_slot.done,
		msecs_to_jiffies(mxfs_lu_reset_timeout_ms));
	out->upcall_wall_ms = ktime_to_ms(ktime_sub(ktime_get(), t0));

	spin_lock(&mxfs_lureset_slot.lock);
	mxfs_lureset_slot.armed = false;
	out->report_len = mxfs_lureset_slot.len;
	if (out->report_len > sizeof(out->report) - 1)
		out->report_len = sizeof(out->report) - 1;
	memcpy(out->report, mxfs_lureset_slot.buf, out->report_len);
	out->report[out->report_len] = '\0';
	spin_unlock(&mxfs_lureset_slot.lock);

	if (!left && out->report_len == 0) {
		/*
		 * The helper execed and then said nothing within the bound.
		 * It may have been anywhere: before opening the device, or
		 * inside the ioctl.  That is INDETERMINATE and never "no reset
		 * happened" — killing or outrunning the helper does not cancel
		 * an ioctl the kernel is already executing.
		 */
		out->verdict = MXFS_PAL_LURESET_INDETERMINATE;
		strscpy(out->reason, "no-report-within-bound",
			sizeof(out->reason));
	} else if (!left) {
		out->verdict = MXFS_PAL_LURESET_INDETERMINATE;
		strscpy(out->reason, "report-truncated-at-bound",
			sizeof(out->reason));
	} else {
		mxfs_lureset_judge(out, req);
	}

verdict:
	pr_warn("mxfs: P305-LURESET-VERDICT lun=%s epoch=%llu nonce=%s verdict=%s issued=%d reset_rc=%d reset_ms=%u upcall_ms=%u krel=%s reason=%s\n",
		req->lun_id, (unsigned long long)req->epoch, nonce_str,
		mxfs_lureset_verdict_name(out->verdict), out->issued,
		out->reset_rc, out->reset_wall_ms, out->upcall_wall_ms,
		out->krel[0] ? out->krel : "?", out->reason);
	if (out->report_len)
		pr_warn("mxfs: P305-LURESET-REPORT nonce=%s bytes=%zu <<%s>>\n",
			nonce_str, out->report_len, out->report);

	mutex_unlock(&mxfs_lureset_invoke_lock);
	/* rc carries the exec failure and is 0 on every path that got as far
	 * as running the helper; the VERDICT is what a caller acts on. */
	return rc;
}
EXPORT_SYMBOL_GPL(mxfs_pal_lu_reset_witness);

/* ───────────────────────── the standalone trigger ───────────────────────── */

static ssize_t mxfs_lureset_probe_write(struct file *file,
					const char __user *ubuf,
					size_t count, loff_t *ppos)
{
	struct mxfs_pal_lu_reset_req req;
	struct mxfs_pal_lu_reset_result *res;
	char line[160];
	char *p, *lun, *epoch_tok, *victim;
	size_t take = count;
	int rc;

	if (!mxfs_lu_reset_probe_enable)
		return -EPERM;
	if (take == 0)
		return 0;
	if (take > sizeof(line) - 1)
		take = sizeof(line) - 1;
	if (copy_from_user(line, ubuf, take))
		return -EFAULT;
	line[take] = '\0';
	p = strchr(line, '\n');
	if (p)
		*p = '\0';

	p = line;
	lun = strsep(&p, " \t");
	epoch_tok = strsep(&p, " \t");
	victim = p;
	if (!lun || !lun[0])
		return -EINVAL;

	memset(&req, 0, sizeof(req));
	req.lun_id = lun;
	req.victim = (victim && victim[0]) ? victim : "probe";
	if (epoch_tok && epoch_tok[0] && kstrtoull(epoch_tok, 10, &req.epoch))
		return -EINVAL;

	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;
	rc = mxfs_pal_lu_reset_witness(&req, res);
	kfree(res);
	if (rc)
		return rc;
	*ppos += count;
	return count;
}

static const struct proc_ops mxfs_lureset_probe_ops = {
	.proc_write	= mxfs_lureset_probe_write,
	.proc_lseek	= noop_llseek,
};

/* ───────────────────────── lifetime ───────────────────────── */

int mxfs_pal_lu_reset_init(void)
{
	init_completion(&mxfs_lureset_slot.done);
	mxfs_lureset_report_pde = proc_create(MXFS_LURESET_PROC_NAME, 0200,
					      NULL, &mxfs_lureset_report_ops);
	if (!mxfs_lureset_report_pde) {
		pr_err("mxfs: P305-LURESET-NOCHAN could not create %s — the witnessed LOGICAL UNIT RESET has no report channel and every attempt will refuse\n",
		       MXFS_LURESET_PROC_PATH);
		return -ENOMEM;
	}
	mxfs_lureset_probe_pde = proc_create("fs/mxfs/lu_reset_probe", 0200,
					     NULL, &mxfs_lureset_probe_ops);
	return 0;
}

void mxfs_pal_lu_reset_exit(void)
{
	if (mxfs_lureset_probe_pde) {
		proc_remove(mxfs_lureset_probe_pde);
		mxfs_lureset_probe_pde = NULL;
	}
	if (mxfs_lureset_report_pde) {
		proc_remove(mxfs_lureset_report_pde);
		mxfs_lureset_report_pde = NULL;
	}
}
