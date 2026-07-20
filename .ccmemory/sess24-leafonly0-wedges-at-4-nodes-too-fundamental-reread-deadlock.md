---
name: sess24-leafonly0-wedges-at-4-nodes-too-fundamental-reread-deadlock
description: sess24: leaf_only=0 wedges even at 4 nodes (test2-4 network-dark) on pristine keeper, while 4/tcp PASSES at default leaf_only=1. So the dir-DATA-bloc…
metadata:
  type: project
---

## sess24 — leaf_only=0 deadlock is fundamental (wedges at 4 nodes too)

Extends [[sess24-CONFIRMED-leafonly0-wedges-pristine-keeper-need-serial-console]].

### Test (pristine keeper EF6000F0, clean 4-node boot)
`dir_postread_reread=1 dir_postread_leaf_only=0`, `./run.sh 4 tcp dir_reuse_coherency` -> FAIL 0/4, **test2,3,4 network-DOWN (wedged)**, test1 up. Compare: 4/tcp dir_reuse at DEFAULT (leaf_only=1) PASSES 4/4. So enabling the dir-DATA-block FUA re-read (postread hook, xfs_da_btree.c ~3821-3906) DEADLOCKS even at 4 nodes — it is NOT a contention-volume problem that more batching would fix. The re-read site itself (xfs_buf_relse + xfs_trans_read_buf_map of a dir DATA buffer from WITHIN xfs_da_read_buf, while the caller holds the dir ILOCK and is mid-dir-btree-walk) creates a lock cycle under concurrent peer BAST/drain.

### Implication for the fix
- The corruption fix REQUIRES a coherent data-block RMW base (leaf_only=0 proves uf=0/hole=0).
- But re-reading data blocks IN the postread hook deadlocks.
- => Move the re-read OUT of the postread hook to a CLEANER call site: in xfs_dir2_node_addname_int AFTER xfs_dir3_data_read returns the buffer locked+held by the transaction, BEFORE xfs_dir2_data_use_free (Patch 5). At that point the dir-btree walk is done; only dbp is held. A single targeted re-read there MAY avoid the lock cycle. UNPROVEN — needs the wedge stack to confirm the cycle, then verify Patch 5 breaks it.
- Risk: clearing XBF_DONE / re-reading a TRANSACTION-attached buffer mid-transaction is delicate (can trip AIL/log-item asserts). May need xfs_trans_brelse + a fresh xfs_dir3_data_read, or an explicit invalidate primitive.

### REQUIRED next-session setup to crack it: capture the wedge stack
Nodes go fully network-dark on wedge; SSH/dmesg polling cannot catch it. Kernel console is not on serial (no console=ttyS0). Do:
1. guest: add `console=ttyS0,115200` to GRUB_CMDLINE_LINUX in /etc/default/grub, `update-grub`, reboot.
2. libvirt: `virsh edit testN` -> serial `<source>` to `type='file'` logging to /var/log/.../testN-serial.log (or add `<log file=.../>` to the pty serial).
3. enable `echo 1 >/proc/sys/kernel/hardlockup_panic` off, but `nmi_watchdog=1` + hung_task; re-run 4/tcp leaf_only=0; read the serial log for the blocked-task / hardlockup backtrace = the exact lock cycle to break.

Keeper unchanged EF6000F0 (all sess24 code reverted; tree == sess23 keeper byte-identical).
</body>
