// SPDX-License-Identifier: GPL-2.0
/*
 * scst_unwedge — break an SCST SCSI-atomicity blocker deadlock cycle.
 *
 * Targets the wedge diagnosed in mxfs sess43 (see
 * scripts/scst_atomic_wedge_diag.py): a COMPARE AND WRITE and an
 * overlapping READ each registered the other as its scsi_atomic blocker
 * (A blocks B, B blocks A), so neither ever runs, every later overlapping
 * command piles up behind the CAW, scst_suspend_activity() waits forever
 * and `scst stop` wedges all teardown threads in D-state.
 *
 * scst_unblock_aborted_cmds() cannot rescue them: it only walks
 * blocked_cmd_list and deferred_cmd_list, and atomic-blocked commands are
 * parked on neither.
 *
 * This module removes ONE edge of the cycle exactly the way SCST's own
 * scst_check_unblock_scsi_atomic_cmds() would if the READ had completed:
 * it forgets the READ's blocked-cmds registration, drops the CAW's
 * blocker count to zero and requeues the CAW onto its cmd_threads'
 * active_cmd_list.  Normal SCST processing then executes and completes
 * the CAW, whose completion unblocks every parked reader through the
 * stock code path, draining the device and releasing the wedged stop.
 *
 * Usage (addresses from scst_atomic_wedge_diag.py):
 *   sudo insmod scst_unwedge.ko blocker=0x<READ#1 addr> blocked=0x<CAW addr>
 *   sudo rmmod scst_unwedge
 *
 * The init function verifies the diagnosed topology under dev->dev_lock
 * before touching anything and bails with -EBUSY on any mismatch.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/slab.h>

#include <scst.h>

static unsigned long blocker;	/* cmd holding the edge to remove (READ#1) */
module_param(blocker, ulong, 0444);
MODULE_PARM_DESC(blocker, "address of the scst_cmd whose blocked list holds the cycle edge");

static unsigned long blocked;	/* cmd parked on that edge (the CAW) */
module_param(blocked, ulong, 0444);
MODULE_PARM_DESC(blocked, "address of the scst_cmd to release and requeue");

static int __init scst_unwedge_init(void)
{
	struct scst_cmd *br = (struct scst_cmd *)blocker;
	struct scst_cmd *bd = (struct scst_cmd *)blocked;
	struct scst_device *dev;
	struct scst_cmd_threads *th;

	if (!br || !bd) {
		pr_err("scst_unwedge: blocker= and blocked= are required\n");
		return -EINVAL;
	}

	dev = br->dev;
	if (!dev || bd->dev != dev) {
		pr_err("scst_unwedge: cmds not on the same device (%p vs %p)\n",
		       br->dev, bd->dev);
		return -EINVAL;
	}

	spin_lock_bh(&dev->dev_lock);

	{
		int i, idx = -1, cnt = br->scsi_atomic_blocked_cmds_count;

		for (i = 0; i < cnt; i++) {
			if (br->scsi_atomic_blocked_cmds &&
			    br->scsi_atomic_blocked_cmds[i] == bd) {
				idx = i;
				break;
			}
		}

		if (idx < 0 || bd->scsi_atomic_blockers < 1) {
			spin_unlock_bh(&dev->dev_lock);
			pr_err("scst_unwedge: topology mismatch: blocker count=%d list=%p, blocked not in array or blockers=%d — not touching\n",
			       cnt, br->scsi_atomic_blocked_cmds,
			       bd->scsi_atomic_blockers);
			return -EBUSY;
		}

		/* Remove the one edge: compact the array in place. */
		for (i = idx; i < cnt - 1; i++)
			br->scsi_atomic_blocked_cmds[i] =
				br->scsi_atomic_blocked_cmds[i + 1];
		br->scsi_atomic_blocked_cmds_count = cnt - 1;
		if (br->scsi_atomic_blocked_cmds_count == 0) {
			kfree(br->scsi_atomic_blocked_cmds);
			br->scsi_atomic_blocked_cmds = NULL;
		}

		bd->scsi_atomic_blockers--;
	}

	if (bd->scsi_atomic_blockers == 0) {
		th = bd->cmd_threads;
		spin_lock_irq(&th->cmd_list_lock);
		if (bd->queue_type == SCST_CMD_QUEUE_HEAD_OF_QUEUE)
			list_add(&bd->cmd_list_entry, &th->active_cmd_list);
		else
			list_add_tail(&bd->cmd_list_entry, &th->active_cmd_list);
		wake_up(&th->cmd_list_waitQ);
		spin_unlock_irq(&th->cmd_list_lock);

		spin_unlock_bh(&dev->dev_lock);
		pr_info("scst_unwedge: edge %p->%p removed, cmd %p requeued on %p\n",
			br, bd, bd, th);
	} else {
		spin_unlock_bh(&dev->dev_lock);
		pr_info("scst_unwedge: edge %p->%p removed, cmd %p still has %d blockers\n",
			br, bd, bd, bd->scsi_atomic_blockers);
	}

	return 0;
}

static void __exit scst_unwedge_exit(void)
{
}

module_init(scst_unwedge_init);
module_exit(scst_unwedge_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("one-shot breaker for SCST scsi_atomic blocker deadlock cycles");
