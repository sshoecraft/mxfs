// SPDX-License-Identifier: GPL-2.0
/*
 * inode_dio_probe — read the in-core direct-I/O state of one file's inode.
 *
 * WHY (mxfs sess141).  The fence harness's stage-(ii) stack wedged with its
 * loop worker parked in ext4_dio_write_checks() on the loop BACKING FILE while
 * O_DIRECT READS of the same loop device still completed.  A read takes
 * i_rwsem shared, so a leaked exclusive i_rwsem is ruled out by construction;
 * what remains inside that function and can block forever is
 *
 *	inode_dio_wait(inode);	 -> wait_var_event(&inode->i_dio_count, ...)
 *
 * i_dio_count is raised by inode_dio_begin() at the head of every
 * iomap_dio_rw() and dropped by inode_dio_end() at its completion.  A task
 * that dies *inside* the DIO (sess136/137: a general protection fault in
 * dma_direct_map_sg() killed the loop worker inside __iomap_dio_rw()) never
 * runs the matching inode_dio_end(), so the count is stuck above zero for the
 * lifetime of the in-core inode.  Every later write that needs the exclusive
 * path then blocks forever, while reads keep working — exactly what was
 * observed.
 *
 * This module reports the counter so the diagnosis is a measurement rather
 * than an inference.  Read-only: it takes a reference on the path, prints, and
 * puts it back.
 *
 * Usage:
 *   sudo insmod inode_dio_probe.ko path=/var/lib/mxfs-fence/fio-backing.img
 *   sudo rmmod inode_dio_probe
 *   dmesg | grep inode_dio_probe
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/rwsem.h>

static char *path;
module_param(path, charp, 0444);
MODULE_PARM_DESC(path, "file whose inode DIO state to report");

static int __init inode_dio_probe_init(void)
{
	struct path p;
	struct inode *inode;
	int dio, rc;

	if (!path || !*path) {
		pr_err("inode_dio_probe: path= is required\n");
		return -EINVAL;
	}

	rc = kern_path(path, LOOKUP_FOLLOW, &p);
	if (rc) {
		pr_err("inode_dio_probe: cannot resolve %s: %d\n", path, rc);
		return rc;
	}

	inode = d_backing_inode(p.dentry);
	dio = atomic_read(&inode->i_dio_count);

	pr_info("inode_dio_probe: %s ino=%lu dev=%u:%u size=%lld i_dio_count=%d i_count=%d i_writecount=%d\n",
		path, inode->i_ino,
		MAJOR(inode->i_sb->s_dev), MINOR(inode->i_sb->s_dev),
		i_size_read(inode), dio,
		atomic_read(&inode->i_count),
		atomic_read(&inode->i_writecount));

	/*
	 * rwsem_is_locked() is a plain read of the owner/count word — safe to
	 * evaluate, and it distinguishes "nobody holds i_rwsem" (the state a
	 * working inode is in between operations) from a leaked hold.
	 */
	pr_info("inode_dio_probe: %s i_rwsem locked=%d contended=%d  VERDICT: %s\n",
		path,
		rwsem_is_locked(&inode->i_rwsem),
		rwsem_is_contended(&inode->i_rwsem),
		dio > 0 ?
			"i_dio_count LEAKED — every exclusive-path DIO write to this inode blocks forever in inode_dio_wait()" :
			"i_dio_count clean");

	path_put(&p);
	return 0;
}

static void __exit inode_dio_probe_exit(void)
{
}

module_init(inode_dio_probe_init);
module_exit(inode_dio_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("report in-core i_dio_count / i_rwsem state for one path");
