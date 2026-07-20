---
name: AAA-ccloop8ba7-sess1-three-kernel-fixes-ladder-progress
description: sess1: harness unmount bug SOLVED+validated; 3 kernel fixes (ino-cluster CRC retry 106, dirty-data reload guard 107, 4x igrab conversions 108). Ladde…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, ladder, caw, multipath, igrab, panic]
---

# ccloop 8ba7ae5c sess1 — progress ledger (2026-07-16)

Criteria: 1/2/4/8/16/32-node CAW **multipath** (`MXFS_DEV=/dev/mapper/mpatha`) 100%.
Method per rung: `scripts/caw_preflight.sh N` → `env MXFS_DEV=/dev/mapper/mpatha
[RULE0_CALIBRATE=1] ./run.sh N caw` (calibrate only on first measurement at 16/32).
nohup + foreground waiter chunks ≤290s (Bash sleep-chain is blocked; until-loops OK).

## Landed fixes (chronological)
1. **Harness** (VERSION 0.10.105, no kernel change): dlm_lock_correctness unmount
   bug = the old "idle dir_reuse" mystery — see AAA-idle-dirreuse-bug-SOLVED-harness-unmount.
   Validated: fixed 2/caw 19/19 + solo dir_reuse PASS immediately AND after 600s idle
   (runs 20260716T142731Z/143537Z/145045Z, build 67AB53E622F5450D5BC8692).
2. **0.10.106** (4345AC8DB3D5CFE875C842D): xfs_inode_buf_ops added to
   mxfs_buf_is_multinode_dir_meta → bounded coherent re-read retry now covers INODE
   CLUSTER transient torn cold-reads. Proven need: fence@4 test4 shutdown via
   xfs_ifree EUCLEAN on dinodes 0x484531/32 (CRC-bad at read); raw O_DIRECT platter
   dump minutes later = ALL CRC-VALID (transient). NOTE: XFS di_crc is LE on disk —
   a BE unpack shows byte-swapped "mismatch" that actually proves validity.
3. **0.10.107** (E547133892296683AA7AB5C): P34F-RELOAD-DIRTYDATA-SKIP in
   mxfs_dlm_reload_inode — refuse fork destroy/rebuild for S_ISREG with
   i_delayed_blks or dirty/writeback mapping. Proven need: fence@8 test3 own-file
   f6 (ino 4196680) durable md5 mismatch: BAST-drain flushed page 1 (disk size=4096),
   head's tail stayed delalloc+dirty-page-only (ili_fields=0, changecount equal →
   P34E and P3 guards blind), reload adopted disk + destroyed delalloc + reverted
   i_size → beyond-EOF dirty tail silently discarded at writeback.
4. **0.10.108** (in build): 4 remaining raw ihold() BAST-arm sites → igrab()+skip
   (P134-BASTQ-FREEING; sites orphan_rearm/rel_stale_defer/demwait_redrive/pr_demote,
   pr_demote also unwinds bast_pending). Proven need: 32/caw test4 KERNEL PANIC
   during cache_coherency: ASSERT !XFS_ALL_IRECLAIM_FLAGS (xfs_icache.c:3347) +
   radix_tree_tag_set BUG, Workqueue mxfs-ino-bast bast_work_fn→xfs_irele→evict —
   concurrent SECOND eviction (P-DBLRECLAIM check passed clean nanoseconds before
   assert saw flags set = two racing evicts). Same BUG3 family (cc87fed3 sess5).
   Panic trace source: /var/log/libvirt/qemu/test4-serial.log on clyde (VMs also
   run mxfs-netconsole → clyde:6666). kernel.panic=25 → VMs auto-reboot after panic;
   journald on nodes is volatile (crashed boot's log GONE — use serial log).

## Ladder state (criteria.json cells, mixed builds until final sweep)
- 1/caw 29/29 (133658Z, build 67AB...), 2/caw 19/19 post-harness-fix (142731Z, 67AB...)
- 4/caw 19/19 (151841Z, build 106); 8/caw 19/19 (build 107); 16/caw 19/19 CALIBRATE
  (build 107) — first-ever 16-node full green (dir_reuse 1251s/2240; old 16:FAIL wall gone)
- 32/caw: attempt 1 on 107 died = test4 panic (fix #4). RERUN pending on 108.
- FINAL: whole ladder 1..32 must re-run on ONE build (the final one) before marker.
- Budget-scale notes for tightening: fio_perf@32=576s (flat 30s budget absurd at N;
  one shared LUN serializes), posix_multi@16=35s, dlm_fairness@16=33s, fio_perf@16=48s.
- Converge flake seen once at 4/caw attempt 1 (test3 active_count=3 vs 4, 110s gate) —
  retry converged; watch frequency.
- prep at 32 power-cycles slow-teardown nodes (test16 et al) — normal, self-heals.

## Env notes
- run.sh solo/filtered needs marker match; my runs: rm -f /tmp/mxfs_run.lock first.
- fence_during_write flakes ~1-in-2 pre-fixes at 4/8; both shapes (EUCLEAN shutdown,
  own-md5 mismatch) now have root-cause fixes; NEITHER guard has fired live yet
  (P34F=0, DIRCRC=0 at 4/8/16) — watch dmesg each rung for engagement evidence.
