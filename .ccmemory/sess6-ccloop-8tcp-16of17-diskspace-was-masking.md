---
name: sess6-ccloop-8tcp-16of17-diskspace-was-masking
description: sess6(run6614): 8/tcp = 16/17 after fixing test5-8 disk-space env (masked cache_coherency/posix/mmap/zsl/etc). dir_reuse_coherency (0/8) is the SOLE…
metadata:
  type: project
---

## sess6 (run 6614) — 8/tcp now 16/17; disk-space env was masking 5+ tests

### ROOT of most 8/tcp failures = DISK SPACE on test5-8 (NOT mxfs bugs):
- test5-8 have SMALL 6.1G root disks (test1-4 = 26G) and mxfs's heavy always-on kernel logging (P15-REL-ABORT, P28E, P-BLKWR, P64 etc. via pr_warn) → rsyslog fills /var/log/{syslog,kern.log} → root 100% full → /tmp writes fail.
- The cwr (cross_write_read) failures (node5 file=4096, node7=8192, node8=0) were `dd if=/dev/urandom of=/tmp/src` writing SHORT because /tmp full, then `cp` copying the short source. NOT a coherency bug. PROVEN: strace showed `read(3=/tmp/src)=0` (empty source); dd to /mnt/shared (50G) worked fine.
- FIX (applied all 8 nodes): `systemctl stop rsyslog; systemctl mask rsyslog` + journald Storage=volatile RuntimeMaxUse=50M + truncate logs. dmesg kernel ring (for debugging) is unaffected. **test5-8 refill fast — the NEXT session must ensure rsyslog stays masked / disks have room before trusting an 8/tcp result.** (test3 also wedged mid-run; recovered via virsh destroy+start.)

### 8/tcp RESULT after fix (build 9AA569A0): 16/17 PASS.
- PASS (8/8): precond, cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency, fence_during_write, fault_netpartition, soak, tcp_dlm_scaling.
- **FAIL: dir_reuse_coherency (0/8)** — the SOLE remaining blocker for the whole criterion (1/2/4 tcp already 100%; 8/tcp now only dir_reuse).

### CRITERION now = fix dir_reuse_coherency at 8 nodes ONLY.
8-node dir_reuse face (needs fresh re-capture with clean disks): earlier = P-IFLUSH-GAP-DETECT / DABUF_MAP_HOLE torn extent map (divergent grow) + residual single-dirent losses. My gg_refresh+leaf_flush got 4/tcp to 12/12; 8-node contention exposes more. Next: capture 8-node dir_reuse failrounds + shutdown face on clean disks; extend the fix (e.g. dinode/extent-map durability before EX release; the sess49b TORN-DISK RELOAD GATE is EXTENTS+same-incarnation only — may miss BTREE or the local-grow tear).
See [[sess6-ccloop-HANDOFF-3of4-columns-100pct-8tcp-divergent-grow]] [[sess6-ccloop-FIX-COMPLETE-gg-refresh-plus-leaf-flush-12of12]]</body>
