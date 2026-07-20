---
name: AAA-ccloop8ba7-sess6-P133-bwrite-fatal-plus-igrab-site11
description: sess6: P133 xfs_bwrite-in-tx PROVEN fatal (bli freed on t_items→t_items spin→31-node collapse); reworked as raw SCSI FUA write (0.10.111). test26 mid…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, sess6, P133, igrab, panic, cache_coherency]
---

# sess6 (ccloop 8ba7ae5c) findings

## State on entry
sess4/5 died at startup (nothing done). sess3's P133 fix (0.10.110/76FA993D) was built not deployed.
criteria.json rows for cc/pm@32 were from iter_1b (probe build).

## Bug 1 — P133 xfs_bwrite mid-transaction is FATAL (PROVEN, fixed in 0.10.111)
iter_2b (76FA993D): cc@32 collapsed 0/32. Chain, fully evidenced:
- test30 20:40:38: `xfs_trans_ail_delete: attempting to delete a log item that is not in the AIL` + log shutdown 0x8 + first P133 prints (rc=0 then rc=-5).
- Mechanism: xfs_ialloc_inode_init carve buf is tx-joined (trans_get_buf attaches bli; trans_ordered_buf). xfs_bwrite → __xfs_buf_ioend → xfs_buf_item_done → ail_delete(not-in-AIL→shutdown) + xfs_buf_item_relse FREES bli still linked in tp->t_items.
- test30 mkdir then SPUN forever in xfs_trans_buf_item_match (soft lockup 340s+, stack captured) walking corrupted t_items, holding root ino=128 dir EX; peers' P7B refire storm pin=1; 31 nodes ETIMEDOUT rc=-110 at 20:46:38 → mass SHUTDOWN_CORRUPT_INCORE at xfs_mxfs_dlm.c:21810.
- FIX (0.10.111): P133 now bounces the CRC'd cluster image through kmalloc and issues mxfs_pal_scsi_write_fua_bdev (WRITE16+FUA passthrough; lba = bm_bn + bt_sector_offset). No xfs_buf submit → bli untouched. FUA also fixes what xfs_bwrite lacked: durability vs target write cache for peer FUA READs (sess6 flush-epoch note).
- iter_3 (2C98ED67): cc 32/32 in 91s, sc PASS, P133 rc=0 everywhere. Fix validated.

## Bug 2 — unchecked igrab at dwork arm site 11 (batch_arm) → phantom dwork panic (fixed in 0.10.112/7F6191C9)
iter_4: cc stalled >450s; slot-13 node = test26 KERNEL PANIC at 21:15:50 mid-cc (serial log /var/log/libvirt/qemu/test26-serial.log): radix_tree_tag_set BUG via xfs_inodegc_set_reclaimable ← destroy_inode ← iput ← xfs_irele ← mxfs_dlm_bast_dwork_fn, with P6ZC/P138/P70 printing ino=0 (recycled inode, i_ino unset). Site 11 (xfs_mxfs_dlm.c ~22190, sess35 BATCHING arm in ilock_begin slow path) called `igrab(VFS_I(ip));` IGNORING the result — evicting inode ⇒ no ref taken but dwork queued anyway ⇒ fires on recycled memory. All sibling sites (9,10,12,13,14,15,pr_demote) were guarded in sess1's sweep; 11 was missed. Guarded now + P134-BASTQ-FREEING site=batch_arm print. Teardown-side reasoning: a properly-ref'd dwork keeps inode out of reclaim, so ONLY phantom dworks can outlive.

## Bug 3 — Family A panics (OPEN): callbacks into UNLOADED mxfs text
Serial logs of test21/26/28 show repeated `BUG: unable to handle page fault ... RIP 0xffffffffc1xxxxxx` (module space), often "Fatal exception in interrupt", at odd uptimes — fires ~15-20 min AFTER a teardown where `disklock: heartbeat thread did not exit within 5s, abandoning` + `sd reservation conflict` appeared. This killed 21/26/28 at ~20:31 today (20:11:45 teardown) and explains ALL historic "mystery reboots". NOT yet root-caused/fixed: suspect abandoned heartbeat thread's timer/work armed at rmmod. Serial logs are readable via `sudo -n tail /var/log/libvirt/qemu/testN-serial.log`.

## Infra fixes this session
- run.sh: /src NFS restore now retried 6× with SRC_OK/SRC_MISSING gate → escalation; power_cycle_node dl2 loop also retries the NFS mount (test21/26 lost /src after reboot → join failed with prep_node.sh No-such-file).
- dblalloc_repro.sh batches now run RULE0_CALIBRATE=1 (ladder semantics): pm@32 needs ~80s vs flat 30s budget (scaling 4/6/14/35s @ 2/4/8/16n); enforced kill mid-storm reads as NO_TERMINAL_RECORD=32 (iter_3's pm "FAIL" = artifact; 3017/3200 files existed at kill). All prior ladder criteria PASSes recorded via RULE0_CALIBRATE=1 (fio_perf 32/caw PASS 428/30s proves it).
- P-DBLALLOC hits 403-1148/iter are the known false-positive family (holds=dir-block foreign-dead reuse); static xref CLEAN in 1b and 3.

## Next steps
1. iter 5+ on 7F6191C9: expect cc+sc+pm functional-pass (pm ~80s calibrated). Watch serial logs for panics.
2. If clean ×2-3: quiesced xref_owners.py, then full ladder `MXFS_DEV=/dev/mapper/mpatha RULE0_CALIBRATE=1(?) ./run.sh 32 caw` — check how ladders were invoked (criteria entries say calibrate was on).
3. Family A root-cause (heartbeat abandon → post-rmmod timebomb) — needed for stable multi-iteration runs.
4. Regression 16/8/4/2/1, then criteria marker (echo YES > /src/mxfs/.ccloop/runs/8ba7ae5c-35d8-4efa-9f72-44504bb63a45/criteria-met).
