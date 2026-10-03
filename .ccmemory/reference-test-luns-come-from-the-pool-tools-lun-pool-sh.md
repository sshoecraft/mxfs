---
name: reference-test-luns-come-from-the-pool-tools-lun-pool-sh
description: Since 2026-10-01 every clyde test LUN is borrowed from tools/lun_pool.sh (11 x 20G dense since 2026-10-02); size it to every concurrent user, within the host's 88% gate.
metadata:
  type: reference
---

The fixed LUNs (~/disks/disk.img :shared, disk-grp-<g> :grp-<g>, disk-plat-<p> :plat-<p>) and scripts/rig_groups.sh + scripts/scst_platform_targets.sh were deleted 2026-10-01 at the user's direction.

tools/lun_pool.sh: images ~/disks/pool/lunNN.img (fallocate, fixed size), SCST device mxfspoolNN, target iqn.2026-05.local.mxfs:pool-NN, LUN 0 only in ini_group `alloc` = the allocated nodes. Allocation owned by a pid; after the owner exits it is KEPT bound and adopted by the next alloc of exactly that node set (0.08 s, cluster stays mounted); released when a new alloc overlaps its nodes, or oldest-first when no LUN is free. `up` after a host reboot. `snapshot <id> <label>` copies a platter to ~/disks/snapshots before the next holder formats it. `create <count> <size>` adds LUNs.

POOL SIZE: 12 x 20G from 2026-10-01 (lun01-12); 11 since 2026-10-02 (lun12 destroyed: the host's / had crept to the preflight's 88% gate and every release board aborted; a release run needs 10 bound plus a yardstick capture only when the yardstick is missing, and a full pool evicts the oldest kept allocation). It was 8, and a release run needed more: 6 board groups keep their LUNs bound after their boards, plus 4 platform sets, plus the yardstick capture on test1. With 8, debian13's platform round got "no pool LUN for its verification set" and never ran. The user's reaction to that: "MAKE ONE". When the pool is short, add LUNs (`tools/lun_pool.sh create N 20G`, within the preflight's 120 GB free / 88% used floor on /); do not route around it.

run.sh: every direct run and every --group run borrows one after taking its locks; exports MXFS_LUN_WWID / MXFS_HOST_IMAGE_PATH / MXFS_POOL_LUN; MXFS_LOG_SLICES defaults to 2N (<=8 nodes, 20G), 32 on 80G (<=16), 32 on 144G beyond. MEASURED: 20G at -n 32 = only 9 AGs; at -n 16 = 19. The AG cap comes from the log slice count, not the AG size.

Groups g2/g4/g8 + g2b/g4b/g8b (test15-28). tests/full_verify.sh runs the matrix suites side by side on g<N>, g<N>b and writes lab.<platform> from a pool alloc; tests/board_4node_chain.sh takes cfg@group args and runs them side by side. mpath/pass attachments have no LUN now. data/rigs.json scst-fio has "pool": true and no lun_wwid.
