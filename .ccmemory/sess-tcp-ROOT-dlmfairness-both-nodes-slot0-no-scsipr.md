---
name: sess-tcp-ROOT-dlmfairness-both-nodes-slot0-no-scsipr
description: ROOT of dlm_fairness wedge (2-node tcp): TCP path skipped SCSI PR register → disklock slot-claim CAW rejected (sense 0x5/0x24 INVALID FIELD) → node_s…
metadata:
  type: project
---

## PROVEN ROOT of the dlm_fairness FS-shutdown wedge (2-node tcp, build F22321→C44D5CF3)

dlm_fairness PASSes ~4-6× then WEDGES: iter5/6 stale-readdir (got=1), iters7+ hard wedge
(both nodes 0 rounds, ~6s fast-fail). dmesg = real FS SHUTDOWN: test1 `inobt record
corruption in AG 0 ... freemask 0x7fffffff80 ... xfs_difree_inobt -117`; test2
`xfs_remove → xfs_trans_cancel dirty → Corruption of in-memory data shutdown` + unrecovered
unlinked inodes. Classic concurrent same-AG inode alloc/free inobt corruption.

### Why both nodes hit AG 0 (the actual root, found via P90-PICK tracer mxfs.dirwr=1):
P90-PICK histogram showed `slot=0` on BOTH test1 AND test2 → AG affinity (node_slot %
agcount, xfs_dialloc_pick_ag in xfs/libxfs/xfs_ialloc.c) sent EVERY node's inode allocs into
AG 0. So both nodes hammer AG0's inobt → freemask divergence → corruption.

### Why node_slot=0 on both:
dmesg: `mxfs: disklock: claim_slot failed: -5` (-EIO) on each TCP node. When claim fails,
ctx->node_slot stays at its 0 default (dlm/v5_mount.c TCP branch ~L670). claim_slot
(dlm/disklock.c:1259) does a SCSI COMPARE_AND_WRITE (opcode 0x89) to atomically claim a slot.
With mxfs.dirwr=1 the P51-INSTR sense was: `ret=1026 sense_key=0x5 asc=0x24 ascq=0x0` =
ILLEGAL REQUEST / INVALID FIELD IN CDB. The SCST target SUPPORTS CAW (sg_opcodes shows
`89 ... Compare and write`) but REJECTS it here.

### Why the CAW is rejected in TCP but works in CAW-transport mode:
The CAW-transport init path (v5_mount.c ~L731-743) does `mxfs_scsipr_register` +
`mxfs_scsipr_reserve` (PR type 5 WRITE-EXCLUSIVE REGISTRANTS-ONLY) BEFORE claim_slot, and
makes claim failure FATAL — so CAW clusters mount only because the slot-claim CAW succeeds.
The TCP path returned (L722) BEFORE the SCSI PR block, so it NEVER registered PR. SCSI PR
registration is the prerequisite the SCST target needs to accept COMPARE AND WRITE.

### FIX (dlm/v5_mount.c, build C44D5CF3):
1. In the TCP branch, before the disklock block: create+register+reserve SCSI PR (mirror the
   CAW path) so the slot-claim CAW is accepted.
2. Defense-in-depth: if claim_slot still returns <0, derive node_slot = node_id %
   MXFS_DISKLOCK_HB_SLOTS instead of defaulting to 0 (never collide all nodes on slot 0/AG0).

### Verify next: each node logs a UNIQUE `disklock: claimed heartbeat slot N` / distinct
P90-PICK slot=, dlm_fairness loop 15× stays PASS with NO inobt shutdown. This was THE last
2/tcp blocker besides porting the 8 PENDING test scripts (dlm_membership, scaling_curve,
dlm_scaling, rsync_paired, crash_consistency, fence_during_write, fault_netpartition,
tcp_dlm_scaling). See [[sess-tcp-dlmfairness-degrades-node2-wedge-on-churn]].
