---
name: sess68-check5-result-unlink-base-staleness
description: sess68 Check-5 REFUTED (unlock publishes AFTER fence+flush in bast_process). unlink_visibility loss = acquire-side dir-block BASE staleness under fua…
metadata:
  type: project
---

# sess68 — Check-5 result for unlink_visibility (read-only verification, no code change)

Builds on [[sess68-baseline-evidence-bnobt-fua-gap]] + [[sess97_lessons]]. Stay on v5 symmetric.

## unlink_visibility test (tests/cluster/test_unlink_visibility.sh), exact shape
4 nodes, ONE shared dir, each node creates node{ID}_file{1..30} (120 entries, BLOCK/LEAF format),
barrier, each node `rm`s its OWN 30, sync, barrier uv_delete, sleep 2, all nodes verify 0 remain.
FAIL = 1-2 entries durably survive on ALL nodes = hot-shared-dir lost-update.

## GPT Check-5 ("does unlock publish BEFORE the fence worker completes?") = REFUTED.
Read mxfs_dlm_bast_process (xfs/xfs_mxfs_dlm.c L743-1744). For a dir inode the ORDER is:
1. set i_dlm_mode=NL (L1228) — local fast-path gate only, not the on-disk publish.
2. RELEASE durability fence (L1265-1349): unbounded loop xfs_log_force(SYNC)+ail_push+
   mxfs_dir_flush_data_blocks (xfs_bwrite each DATA block, waits unpin, sync write) until
   mxfs_dir_data_durable; 15000-iter backstop → xfs_force_shutdown.
3. mxfs_dir_evict_data_blocks (L1444) — drop durable cached blocks so next read refetches.
4. inode-cluster quiesce barrier (L1504-1523).
5. blkdev_issue_flush (L1707, sess35 H26) — pre-unlock device flush.
6. mxfs_dlm_publish_unpublished (L1724).
7. **mxfs_v5_dlm_inode_unlock (L1732)** ← on-disk DLM publish, genuinely AFTER all flushing.
So the releasing node DOES land its own dir blocks before publishing unlock. Early-unlock is NOT
the bug. (Deferred BAST runs this via mxfs_dlm_bast_work_fn on system_wq; immediate path same fn.)

## SHARPENED HYPOTHESIS (next): acquire-side dir-block BASE staleness under fua_disable=1
Since the releasing node flushes correctly, the surviving entry must come from a node that applied
its own `rm` to a dir-block image that PREDATES a peer's committed removal of a DIFFERENT entry,
then flushed that stale-base image → resurrects the peer's removed entry. The dir is BLOCK/LEAF
(120 entries), all 4 nodes mutate it concurrently. The gap is on ACQUIRE: after a node re-acquires
EX, its cached dir DATA block is NOT refreshed to the peer's latest committed state before it
applies its removal. fua_disable=1 (sess94, deliberate — FUA reads = 45x slow + corruption) means
no FUA-fresh read on acquire; v5 relies on evict+reread, and the inline note at L1424-1434 +
L1448-1484 says "the evict+reread coherency premise is BROKEN under fua_disable=1 (the reread does
NOT reliably pull a peer's just-committed dir block from the SCST target)".
TENSION to resolve: sess97 claimed "PROVEN NOT read/acquire (DIR-STALE-SKIP=0)". Check-5 pushes
back toward acquire-side base-staleness. NEXT SESSION must reconcile: instrument the ACQUIRE path
for the surviving entry's dir block — does the re-acquiring node read a block missing the peer's
removal? Add a trace at dir EX-acquire: (ino, daddr, block gen/lsn, entry-count, whether a FUA/
disk reread happened, vs the peer's last-committed image). Identify the last writer of the
surviving block AND whether that writer's base image already lacked the peer's removal.

## mxfs.1 BLUEPRINT (why mxfs.1 passes this): its dir_cache re-parses the dir under EX from a
DLM-coherent block_cache that is dropped on BAST and re-read fresh; every modify flushes
immediately under EX. v5's equivalent would be: on dir EX (re)acquire, GUARANTEE the cached dir
DATA blocks reflect the latest durable peer state (a reliable fresh read), THEN apply the local
dirent op. The hard part under fua_disable=1 = making "fresh read after BAST-evict" actually pull
the peer's committed block off SCST (plain read may serve initiator cache). Options for next
session: (a) a targeted FUA read ONLY for dir DATA blocks on acquire (narrow, avoids the broad
fua slowness sess94 hit); (b) verify the evict at L1444 actually invalidates so the post-acquire
read is a real disk fetch; (c) GPT/Gemini consult with this Check-5 refutation + base-staleness
framing (RULE 5).

## Cluster left CLEAN: all 4 (test1-4) mounted on EC07F422. Next: clean reboot → reset4 → fix → cache_coherency.sh (only trustworthy test) → need 4/4 → verify_ship.sh.</body>
