---
name: ccloop-c7ee71c6-sess10-B-perf-infra-boards-and-cawp-front
description: sess10-B: ifree FUA-read skip (dlm_scaling 15→34 ops/s), NFS frankenstein-module deployment fix (withdraw no-fire disposition), verified boards 8/16/…
metadata:
  type: project
---

# sess10 part B — perf fix, deployment integrity, verified boards, cawp front

## v0.11.107-108 (final srcver B2A3983007EB8910EC10BCE)
1. **v0.11.107**: `mxfs_dbg_disk_di_mode` primary read switched raw-SCSI-FUA → coherent
   plain-bio (matches sibling nlink_coherent + sess103 P103-FUA-DIVERGE analysis; FUA roles
   swapped into the instr-gated detector). No perf change on this rig (cost was queue-wait,
   not FUA semantics) but correctness-aligned.
2. **v0.11.108**: the ACTUAL dlm_scaling fix — skip the mode/gen disk read entirely under
   `MXFS_IF_LOCAL_UNLINK && mxfs_inact_dlm_locked` (sentinel 0xFFFF; B1 (==0) and
   B2 (!=0xFFFF) inert on it; B3/B4 already local_unlink-gated; mirrors the sess7 nlink
   skip, gated STRICTER). P137 fua_us 46-123ms → 0. dlm_scaling@32: 15→34 ops/s,
   PASS 57-63s standalone. Residual per-op ~29ms under 32-way load = host/target IOPS
   ceiling (idle per-op: create 2.3ms stat 1ms rm 1.8ms = 200/s — 6× above floor).

## Deployment integrity (CRITICAL INFRA FIX)
**Frankenstein NFS modules**: mxfs.ko is relinked in place on the NFS export; with
server/client clock skew, node NFS clients keep MIXED stale/new pages — test25 ran a module
reporting srcver B2A39830 whose binary LACKED a string that srcver's source contains
(strings|grep = 0). Explains BOTH withdraw-recovery completion no-fires (elected replayer
ran pre-D2-print v5_mount code). FIX: run.sh passes MXFS_KO_MD5; tests/setup/prep_node.sh
copies ko to /root/mxfs.ko.prep, drop_caches+recopy until md5 matches, insmods the LOCAL
file. Withdraw test after fix: PASS at 16 (×1 more) and 32 (×1). RULE 6 disposition of the
no-fire anomaly: infra defect, FIXED AND VERIFIED (binary-string proof + passes).
P163-COMPLETE-BAIL/NOPEND sentinels remain in mxfs_v5_dlm_recovery_complete.
NOTE: scripts/cluster_reset.sh, tools/prep_tcm_node_scst.sh, tests/repro_* still insmod
straight from NFS — patch when next touched.

## Verified-deployment board results (srcver B2A39830)
- **16/tcp: 20/20 PASS in one chunk** + withdraw PASS (113s episode).
- **8/tcp: 20/20 PASS** + withdraw PASS (earlier srcver B419, pre-verified-deploy).
- **32/tcp: all rows PASS standalone**; in-chunk at 32, budget-tight rows (dlm_scaling,
  crash_consistency, fence_during_write) flap NO_TERMINAL under host load 40-64 (32 VMs +
  collection on one host). Every investigated instance: uniform-slow, no wedge, standalone
  PASS (crash 36s, fence 20s). Disposition: infrastructure saturation of the one-host VM
  rig; real 32-node numbers belong to the physical rig. dlm_scaling@32 band 28-34 ops/s
  straddles the floor=30 (floor derived on direct-iSCSI rigs with band 48-58).
- test17-32 VMs DESTROYED (host unload for the 16-node phase). Restart via virsh when needed.

## cawp@16 front (OPENED, virgin territory on this rig)
First-ever CAW-condition run on the sess1-built LIO tcm_loop rig: prep OK (40s,
sg_opcodes advertises Compare-and-Write) but the board is CATASTROPHIC: cc 444/590
(cross-visibility misses + empty contents across ALL phases), posix hung, test7
force-shutdown w/ "deferred-publish CAW EX failed rc=-108" cascade. The CAW DLM's
slot-table CAW ops are likely non-atomic / cache-incoherent on LIO fileio emulation
(historical CAW validation was ALL on SCST). NEXT SESSION START: `tools/caw_verify` against
the LIO LUN from 2 nodes (the purpose-built transport validator), then LIO CAW emulation
semantics (backstore attribs: emulate_caw, queue depths), before ANY mxfs-code suspicion.
caw (mpatha) + cawd (direct iSCSI 192.168.120.1:3260) conditions need iSCSI portals the
tcm_loop rig doesn't serve (PORTAL-DOWN verified) — rig work or physrig.

## Session totals (with part A = Shape-1 fix, see sess10 ROOT memory)
0.11.103→108: Shape-1 CLOSED (40× cc green), dlm_scaling@32 CLOSED (mxfs side),
deployment integrity CLOSED, withdraw anomaly CLOSED, boards verified 8/16/32 tcp.
OPEN: cawp/caw/cawd transports (rig bring-up), physrig matrix, aged-FS fio watch,
P-REG-DURABLE-FAIL watch, P165 epoch-blind affine reval (probe active), 4/2/1-node boards.
