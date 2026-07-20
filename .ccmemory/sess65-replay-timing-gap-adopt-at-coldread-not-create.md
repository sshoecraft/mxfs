---
name: sess65-replay-timing-gap-adopt-at-coldread-not-create
description: sess65: epoch-adopt+pending-replay built but REPLAY fires ~0x — timing gap: losing node (rank1) adopts winning block0 only at COLD-READ reload (no tx…
metadata:
  type: project
---

## sess65 — why epoch-adopt + pending-dirent-replay did NOT fix node1_f1

### What was built (build 0676923D, ON DISK)
1. **Pending-dirent list** (xfs_inode.h i_dlm_dir_pending[_bytes/_incarn]; xfs_mxfs_dlm.c mxfs_dir_pending_add/replay; wired in xfs_create after merge + after create success; resblks headroom; freed in xfs_icache.c). Tracks this node's local reg-file creates per incarnation; on each create, re-adds (xfs_dir_createname) up to 4 pending names that lookup ENOENT, in the create's own tx. Idempotent, incarnation-cleared.
2. **Epoch-adopt** (xfs_mxfs_dlm.c ~6880): on post_release reload with dir_grant_epoch > valid_epoch, set genuine_handoff=true (force disk-extent-map adopt) for ALL formats. P65-EPOCH-ADOPT log.
3. **Truncate staleness guard** (xfs_iops.c xfs_setattr_size, P65-STALE-TRUNC): FUA dinode header check (gen/mode/nextents/size) before extent free — INERT, fires 0x (staleness is in bmbt CONTENTS not header). Defensive only.

### RESULT: still 0/4, node1_f1 lost every round. EPOCH-ADOPT fired 2-18x/node but REPLAY fired ~0-1x.

### THE TIMING GAP (key new finding)
node1_f1 loss is dir-inode EXTENT-MAP DIVERGENCE, NOT a missing in-core dirent: rank1 holds dir EX through its whole 50-file dd loop, builds block0@daddr=120 (node1_f1 visible in-core; lookup SUCCEEDS so replay SKIPS). A peer's block0 (diff AG) wins the dir inode's on-disk extent[0] (last iflush wins). rank1 only ADOPTS the peer's winning block0 at the **cold-read drop_caches reload** (verify phase) — where there is NO transaction to replay into. So replay (which only runs inside xfs_create) never gets the chance. By the time rank1 sees the peer's block0 (cold read), creates are done.

### WHY epoch-adopt alone regresses / can't elect a winner
The split is SYMMETRIC at round start: rank1 mkdir's, barrier, all 4 nodes create concurrently from fresh shortform. Each node's first modify converts sf->block allocating its OWN block0 (node-affine AG). The epoch advances from every node's modify, so ALL nodes see "epoch advanced" — there's no clean FIRST converter to elect as winner. Forcing adopt on all (LOCAL-only, sess65 earlier) made node1_f1 lost EVERY round (rank1 adopts a peer's node1_f1-less block0 before/instead of its own conversion winning).

### IMPLICATION for next step
The fix must be WRITE-SIDE (ensure exactly one block0 daddr wins AND it accumulates all nodes' entries), OR make the conversion itself serialize to one block0, OR make the cold-read reload trigger a DEFERRED replay (flag dir; next modify or a worker re-adds dropped local entries into the winning block0). The create-time replay alone can't fix it because the losing node never modifies the dir after it observes the loss.
Candidate: dir-inode-fork FLUSH FENCE (sess-tcp-FIX-entrypoints-inode-flush-fence, xfs_iflush ~4298) — don't let a node's iflush publish a dir extent[0] that orphans a peer's already-durable block0; instead union the dir blocks. OR a deterministic per-incarnation conversion owner.
See [[sess65-GPT-design-pending-dirent-replay-fixes-node1f1]] [[sess64-DECISIVE-ROOT-node1f1-orphaned-in-double-allocated-block0]].</body>
