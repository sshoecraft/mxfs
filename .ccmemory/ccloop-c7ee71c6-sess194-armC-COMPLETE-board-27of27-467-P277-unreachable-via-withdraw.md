---
name: ccloop-c7ee71c6-sess194-armC-COMPLETE-board-27of27-467-P277-unreachable-via-withdraw
description: sess194: 467 fleet-wide, FULL BOARD 27/27 + vergate mixed_build PASS; dirty repro 3/3 — dirty umount takes WITHDRAW path, P277 needs mid-unmountfs sh…
metadata:
  type: project
---

# sess194 — Arm C verification complete on 0.11.467

## Done
- Uniform fleet deploy 0.11.467 (sv 45C15DFCBE7578D9258D801) to all 32 nodes, prep 74s, converged.
- FULL BOARD 27/27 PASS at 32/caw (run in 3 chunks under the 10-min foreground cap: P0-P5 / P6-P7 / P6b-P9). open_defects FAIL by RULE 6 policy only (28 open).
- vergate mixed_build arm PASS on 467 (gen 3->4 refused with EPROTONOSUPPORT before any recovery, dirty log replayed after gen restore).
- tests/dirty_slice_release_repro.sh test32 all: 3/3 arms PASS (race, delay, remount; marker B4-dirty-slice survived fence+replay).

## Key finding — P277 reachability
Forced shutdown (GOINGDOWN) BEFORE umount routes teardown through the WITHDRAW path: depart_clean=false, so mxfs_v5_dlm_shutdown destroys the disklock itself (slot stays WITHDRAWN on disk) and never hands the deferred slot out. slot_release_commit then logs "P278-LATE-RELEASE no deferred slot to commit (late=1 disklock=0)" — EXPECTED, not a failure.
P277-SLOT-RETAINED-UNMOUNT-DIRTY fires only in the narrower window: DLM teardown completed CLEAN (depart_clean && late handout, dlm/v5_mount.c:4543) and the log then shut down INSIDE xfs_unmountfs before the unmount record hit the platter (unmount_clean = !xfs_is_shutdown(mp) at pal/linux/xfs_super.c:1663/3303). Its action is omitting release_slot — the dangerous action is not performed. Clean path proven sess193 (ftrace caller chain + P278 rc=0); dirty withdraw disposition proven this session (slot retained, P274-CLAIM-WITHDRAWN-SKIP, fence, P238-FENCE-SINGLENODE cert, replay, marker survived).

## Board chunking recipe (reusable)
run.sh subsets in manifest order, cluster already prepped:
1. precond_readiness fio_perf fio_perf_vs_xfs cache_coherency strong_consistency posix_multi mmap_coherency zero_silent_loss dlm_fairness dlm_membership dlm_lock_correctness scaling_curve dlm_scaling rsync_paired (~2.5min)
2. fault_enospc crash_consistency dir_reuse_coherency fence_during_write fault_netpartition soak (~4.5min)
3. dirent_durability node_responsive kernel_health dirent_publish_integrity dirent_type_integrity ag_strand_repair sustained_load open_defects (~3min)
(fault_enospc/posix_single/fsx/fio_verify/integrity_filetypes are max_nodes=1, absent at N=32.)

## Rig state at session point
test32 left by repro: module reloaded, /mnt/shared unmounted, loop7 on /tmp/vergate_loop.img — marker stale for test32; MXFS_FORCE_PREP=1 full prep required before next rig measurement.
