// SPDX-License-Identifier: GPL-2.0
/*
 * inode_dio_release — perform the inode_dio_end() that a GPF-killed task never
 * ran, returning a proven-leaked i_dio_count token so the legitimate waiter
 * can resume.
 *
 * WHY (mxfs sess145).  sess136/137's general protection fault in
 * dma_direct_map_sg() killed a loop worker inside __iomap_dio_rw() on
 * /var/lib/mxfs-fence/fio-backing.img.  make_task_dead() does not unwind
 * iomap's accounting, so the backing inode's i_dio_count stayed at 1 forever
 * (measured by scripts/inode_dio_probe across sess141..145).  The replacement
 * loop worker then parks in ext4_dio_write_checks() -> inode_dio_wait() and
 * its serial cmd_list wedges everything queued behind it: a dd, a blk-mq
 * flush_rq, a jbd2 PREFLUSH superblock write parked in the flush state
 * machine, two ext4 mounts, and — via buffer_migrate_folio_norefs hitting the
 * locked jbd2 buffer during THP compaction — an unrelated user process
 * holding its mmap_lock in D, khugepaged queued as a writer behind it, and
 * every /proc/<pid>/cmdline reader (hundreds of pgrep/ps) queued behind that.
 *
 * WHY A LATE LEGITIMATE inode_dio_end() CANNOT RACE THIS REPAIR.  iomap
 * returns the token only in iomap_dio_complete(), which runs when dio->ref
 * hits zero.  The submitter's initial reference is dropped only at the tail
 * of __iomap_dio_rw() — which the dead task never reached — so dio->ref can
 * never reach zero and the normal release path is permanently unreachable.
 * All bios of that dio have long completed (nvme inflight 0 0).
 *
 * THE INTERLOCK.  atomic_cmpxchg(&i_dio_count, 1, 0), one attempt only.  Any
 * live DIO holds its own token, so the count being exactly 1 at swap time
 * proves the swapped-out token is the leaked one; a concurrent
 * inode_dio_begin() makes the count 2 and the swap refuses.  cmpxchg is fully
 * ordered.  Underflow is impossible by construction.
 *
 * THE WAKE KEY IS KERNEL-VERSION-SPECIFIC.  On this 6.8 kernel,
 * inode_dio_end() is an inline in fs.h doing
 * wake_up_bit(&inode->i_state, __I_DIO_WAKEUP) — the waiter sleeps on the
 * bit waitqueue of i_state, NOT on wait_var_event(&i_dio_count) (that
 * conversion landed in later kernels; /src/linux 7.1-rc7 uses the var key).
 * The first act=1 run of this module used only wake_up_var and woke nothing.
 * We now issue BOTH wakes — each is idempotent, and the waiter re-checks the
 * count in its wait loop, so a spurious wake is harmless.
 *
 * act=2 exists for exactly that partial state: count already swapped to 0 by
 * a prior act=1 whose wake missed, waiter still parked.  It requires
 * i_dio_count==0 plus the full identity match and only issues the wakes.
 *
 * Identity is enforced before any action: expected inode number, expected
 * st_dev major:minor, EXT4 superblock magic, regular file, expected size.
 * Additionally verify from userspace, immediately before act=1, that
 * /sys/block/loop0/loop/backing_file still names this exact path.
 *
 * Usage:
 *   sudo insmod inode_dio_release.ko path=/var/lib/mxfs-fence/fio-backing.img \
 *        expect_ino=62527935 expect_major=259 expect_minor=2 \
 *        expect_size=2147483648              # probe only (act=0)
 *   sudo rmmod inode_dio_release
 *   ... same with act=1 to release the token.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/magic.h>
#include <linux/rwsem.h>
#include <linux/wait_bit.h>
#include <linux/sched/signal.h>
#include <linux/rcupdate.h>

static char *path;
module_param(path, charp, 0444);
MODULE_PARM_DESC(path, "file whose inode holds the leaked i_dio_count token");

static unsigned long expect_ino;
module_param(expect_ino, ulong, 0444);
MODULE_PARM_DESC(expect_ino, "required inode number; mismatch refuses");

static uint expect_major;
module_param(expect_major, uint, 0444);
MODULE_PARM_DESC(expect_major, "required major of the filesystem's s_dev");

static uint expect_minor;
module_param(expect_minor, uint, 0444);
MODULE_PARM_DESC(expect_minor, "required minor of the filesystem's s_dev");

static unsigned long long expect_size;
module_param(expect_size, ullong, 0444);
MODULE_PARM_DESC(expect_size, "required i_size of the file; mismatch refuses");

static int act;
module_param(act, int, 0444);
MODULE_PARM_DESC(act, "0 = probe only (default), 1 = cmpxchg the count 1->0 and wake, 2 = wake only (count must already be 0), 3 = up_read the leaked reader hold (guarded)");

/* 6.8 rwsem word layout (kernel/locking/rwsem.c) */
#define RWSEM68_WRITER_LOCKED	(1UL << 0)
#define RWSEM68_FLAG_WAITERS	(1UL << 1)
#define RWSEM68_FLAG_HANDOFF	(1UL << 2)
#define RWSEM68_READER_SHIFT	8
#define RWSEM68_READER_BIAS	(1UL << RWSEM68_READER_SHIFT)
#define RWSEM68_OWNER_READER	(1UL << 0)
#define RWSEM68_OWNER_FLAGS	(3UL)

/*
 * The ONLY count value act=3 will act on: exactly one reader bias plus the
 * waiters flag — writer clear, handoff clear, no other bits (READFAIL
 * included).  Anything else means the world changed; refuse.
 */
#define RWSEM68_LEAKED_STATE	(RWSEM68_READER_BIAS | RWSEM68_FLAG_WAITERS)

/*
 * Is the task_struct address recorded in the rwsem owner word a LIVE task?
 * Pointer comparison only under RCU — the stale pointer is never
 * dereferenced.  Returns the live task's pid, or -1 if no live task matches
 * (i.e. the recorded owner is dead and the hold is provably leaked).
 */
static long owner_task_live_pid(unsigned long ownraw)
{
	struct task_struct *g, *t;
	void *ownptr = (void *)(ownraw & ~RWSEM68_OWNER_FLAGS);
	long pid = -1;

	rcu_read_lock();
	for_each_process_thread(g, t) {
		if ((void *)t == ownptr) {
			pid = t->pid;
			break;
		}
	}
	rcu_read_unlock();
	return pid;
}

/*
 * Both wake halves an inode_dio_end() could owe, by kernel version: the
 * 6.8 bit-waitqueue key on i_state and the newer var key on i_dio_count.
 * Idempotent; waiters re-check the count, so extra wakes are harmless.
 */
static void wake_dio_waiters(struct inode *inode)
{
	wake_up_bit(&inode->i_state, __I_DIO_WAKEUP);
	wake_up_var(&inode->i_dio_count);
}

static int __init inode_dio_release_init(void)
{
	struct path p;
	struct inode *inode;
	int dio, old, rc = 0;

	if (!path || !*path || !expect_ino || !expect_size) {
		pr_err("inode_dio_release: path=, expect_ino= and expect_size= are required\n");
		return -EINVAL;
	}

	rc = kern_path(path, LOOKUP_FOLLOW, &p);
	if (rc) {
		pr_err("inode_dio_release: cannot resolve %s: %d\n", path, rc);
		return rc;
	}

	inode = d_backing_inode(p.dentry);
	dio = atomic_read(&inode->i_dio_count);

	pr_info("inode_dio_release: %s ino=%lu dev=%u:%u magic=%#lx mode=%#o size=%lld gen=%u i_dio_count=%d i_count=%d i_writecount=%d i_rwsem locked=%d contended=%d act=%d\n",
		path, inode->i_ino,
		MAJOR(inode->i_sb->s_dev), MINOR(inode->i_sb->s_dev),
		inode->i_sb->s_magic, inode->i_mode, i_size_read(inode),
		inode->i_generation, dio,
		atomic_read(&inode->i_count),
		atomic_read(&inode->i_writecount),
		rwsem_is_locked(&inode->i_rwsem),
		rwsem_is_contended(&inode->i_rwsem), act);

	/*
	 * Raw rwsem state (6.8 layout): count bit0=WRITER_LOCKED,
	 * bit1=WAITERS, bit2=HANDOFF, readers counted from bit 8; owner low 2
	 * bits are READER_OWNED/NONSPINNABLE flags over a (possibly stale,
	 * never dereferenced) task pointer.
	 */
	{
		unsigned long cnt = atomic_long_read(&inode->i_rwsem.count);
		unsigned long own = atomic_long_read(&inode->i_rwsem.owner);
		long live = rwsem_is_locked(&inode->i_rwsem) ?
			owner_task_live_pid(own) : -2;

		pr_info("inode_dio_release: i_rwsem count=%#lx owner=%#lx (writer=%ld waiters=%ld handoff=%ld readers=%ld owner_flags=%#lx) owner_live_pid=%ld\n",
			cnt, own,
			(long)(cnt & RWSEM68_WRITER_LOCKED),
			(long)!!(cnt & RWSEM68_FLAG_WAITERS),
			(long)!!(cnt & RWSEM68_FLAG_HANDOFF),
			(long)(cnt >> RWSEM68_READER_SHIFT),
			own & RWSEM68_OWNER_FLAGS, live);
	}

	if (inode->i_ino != expect_ino ||
	    MAJOR(inode->i_sb->s_dev) != expect_major ||
	    MINOR(inode->i_sb->s_dev) != expect_minor ||
	    inode->i_sb->s_magic != EXT4_SUPER_MAGIC ||
	    !S_ISREG(inode->i_mode) ||
	    i_size_read(inode) != expect_size) {
		pr_err("inode_dio_release: IDENTITY MISMATCH (want ino=%lu dev=%u:%u ext4 regular size=%llu) — refusing\n",
		       expect_ino, expect_major, expect_minor, expect_size);
		rc = -ENXIO;
		goto out;
	}

	if (!act) {
		pr_info("inode_dio_release: act=0 — probe only, nothing was changed\n");
		goto out;
	}

	if (act == 2) {
		if (dio != 0) {
			pr_err("inode_dio_release: act=2 but i_dio_count=%d, not 0 — refusing\n",
			       dio);
			rc = -EBUSY;
			goto out;
		}
		wake_dio_waiters(inode);
		pr_info("inode_dio_release: act=2 — woke i_dio_count waiters (bit + var keys), count untouched (=0)\n");
		goto out;
	}

	/*
	 * act=3: perform the dead reader's missing up_read().  Reader
	 * releases are not owner-enforced, and __up_read()'s own wake path
	 * (rwsem_wake) grants the queued writer with correct handoff
	 * semantics — never hand-roll the count arithmetic (GPT RULE-5
	 * ruling, sess146).  up_read_non_owner() is the intent-correct
	 * primitive; on this CONFIG_DEBUG_LOCK_ALLOC=n kernel the header
	 * maps it to plain up_read(), whose lockdep/debug bookkeeping is
	 * all compiled out.
	 *
	 * Guards: i_dio_count still 0 (a live DIO would hold a token), and
	 * the count word re-read immediately before the call must be
	 * EXACTLY the leaked state 0x102, plus owner carrying READER_OWNED.
	 * The owner TASK POINTER is deliberately not a guard: for
	 * reader-owned rwsems it is best-effort — every down_read stamps
	 * it and (without CONFIG_DEBUG_RWSEMS) nothing clears it on
	 * up_read, so it names the LAST reader (here the parked kworker's
	 * own released pre-upgrade hold), not the current holder.
	 *
	 * One attempt only.  Whatever the post-state, never a second
	 * decrement and never a supplementary wake (both ruled hazardous).
	 */
	if (act == 3) {
		unsigned long cnt, own;

		dio = atomic_read(&inode->i_dio_count);
		if (dio != 0) {
			pr_err("inode_dio_release: act=3 but i_dio_count=%d (live DIO?) — refusing\n",
			       dio);
			rc = -EBUSY;
			goto out;
		}

		own = atomic_long_read(&inode->i_rwsem.owner);
		if (!(own & RWSEM68_OWNER_READER)) {
			pr_err("inode_dio_release: act=3 owner=%#lx lacks READER_OWNED — refusing\n",
			       own);
			rc = -EBUSY;
			goto out;
		}

		cnt = atomic_long_read(&inode->i_rwsem.count);
		if (cnt != RWSEM68_LEAKED_STATE) {
			pr_err("inode_dio_release: act=3 count=%#lx != expected %#lx — refusing\n",
			       cnt, RWSEM68_LEAKED_STATE);
			rc = -EBUSY;
			goto out;
		}

		up_read_non_owner(&inode->i_rwsem);

		pr_info("inode_dio_release: act=3 — released the dead reader's i_rwsem hold (pre count=%#lx); count now=%#lx owner=%#lx\n",
			cnt,
			(unsigned long)atomic_long_read(&inode->i_rwsem.count),
			(unsigned long)atomic_long_read(&inode->i_rwsem.owner));
		goto out;
	}

	if (dio != 1) {
		pr_err("inode_dio_release: i_dio_count=%d, not the single leaked token — refusing\n",
		       dio);
		rc = -EBUSY;
		goto out;
	}

	/*
	 * One attempt, no retry.  Success proves the count was exactly 1 at
	 * the instant of the swap, i.e. the removed token is the leaked one.
	 */
	old = atomic_cmpxchg(&inode->i_dio_count, 1, 0);
	if (old != 1) {
		pr_err("inode_dio_release: cmpxchg found %d (a DIO began since the probe) — refusing, nothing was changed\n",
		       old);
		rc = -EBUSY;
		goto out;
	}

	wake_dio_waiters(inode);
	pr_info("inode_dio_release: RELEASED the leaked token (1 -> 0) and woke i_dio_count waiters (bit + var keys); i_dio_count now=%d\n",
		atomic_read(&inode->i_dio_count));

out:
	path_put(&p);
	return rc;
}

static void __exit inode_dio_release_exit(void)
{
}

module_init(inode_dio_release_init);
module_exit(inode_dio_release_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("perform a dead task's missing inode_dio_end() under an exact-value interlock");
