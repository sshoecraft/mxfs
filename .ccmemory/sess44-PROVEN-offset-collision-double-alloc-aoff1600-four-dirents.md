---
name: sess44-PROVEN-offset-collision-double-alloc-aoff1600-four-dirents
description: sess44 DECISIVE (P13 offset trace, clean reboot repro): dir_reuse 8/tcp loss is cross-node INTRA-BLOCK offset double-allocation — round19 daddr=14652…
metadata:
  type: project
---

## sess44 (ccloop 4cb2d0a2) — PROVEN: the 8/tcp dir_reuse single-entry loss is cross-node INTRA-BLOCK dir-data freespace DOUBLE-ALLOCATION

### Clean repro (build 5F0C1457, after full virsh destroy+start of test1-8)
`./run.sh 8 tcp dir_reuse_coherency` (default NFILES=50 ROUNDS=24, DRC_STREAM=1 dirland=1) → FAIL nodes_pass=0/8. Round 5 first failed (all ranks readdir=799), round 19 victim = **node8_f31.md5** (created by rank8), LOOKUP_ENOENT REREAD_MISS on ALL 8 nodes = durable single-entry loss, dir ino=131 (reused every round).

### DECISIVE EVIDENCE — P13-NADD/LADD offset trace (per-rank round-19 create windows via DRCph PHASE markers; P13 ts is per-node uptime, NOT synced — must window per rank):
In round 19, the shared dir DATA block **daddr=14652648** received FOUR distinct dirents all placed at the SAME physical offset **aoff=1600**:
- rank3 → node3_f47.md5
- rank6 → node6_f47.md5  AND  node6_f20.md5 (two bursts)
- rank8 → node8_f31.md5  ← THE VICTIM

Massive offset-range OVERLAP across nodes in the same block (rank8 1600-2368, rank6 832-1696, rank3 128-896, rank2 352-1152...). Many nodes compute OVERLAPPING free offsets in the same block → last durable writer wins, the rest are clobbered. Only 1 entry net-lost (799/800) because the EX handoff + cold-read reconciles MOST collisions; node8_f31.md5 was the one added-then-clobbered-after-the-last-correcting-read.

### dland write-completion ring (sorted by realns t=, wall-clock synced): daddr=14652648 round-19 incarnation i=116546476 count is MONOTONIC 1→131, final writer = rank6 (n=131). Chain rank8→rank7→rank2→rank6, count continuous (rank6 picked up rank2's count 121→131). **Count rising MASKS the loss** (sess42 was right; sess41 "no count regression ⇒ never durably added" was the wrong discriminator). The NAME-LEVEL offset trace is decisive where the count ring is blind.

### "TWO BURSTS per rank" pattern (e.g. rank8 added node8_f31.md5 at aoff=1760 THEN aoff=1600): each node's addname runs TWICE for the same names within one round → the create transaction is RE-RUN after an EX handoff/BAST, with a FRESH (or stale) base the second time. Strong signal: a BAST revokes EX mid-create-wave and the node re-acquires + re-addname; if the re-acquire base is stale, the re-run collides.

### ROOT (proven): the EX-acquiring node runs xfs_dir2_*_addname against a base that does NOT reflect a peer's just-committed add at that offset → bestfree/freespace shows the offset free → it places its own dirent there → clobbers the peer's. The staleness is the node's OWN pinned/dirty buffer (sess43: acquire-evict found evicted=0) OR a not-durably-flushed peer image.

### NEXT (RULE 4): find whether a BAST can revoke the dir-inode EX MID-addname (modification under a lost grant — sess42 holders>0 / MHT-batch window), and whether EX release truly checkpoints+cleans the dir DATA buffer so re-acquire cold-reads. The fix must make addname's read-find-write-commit atomic w.r.t. the EX grant: either (a) EX cannot be revoked until the in-flight addname trans commits AND its buffer is checkpointed durable+clean, or (b) on EX re-acquire, force-invalidate the node's own stale dir-data buffer (checkpoint-first) so addname re-reads the peer's image. Tooling: P13-NADD/LADD offset trace + per-rank DRCph windows is the decisive name-level instrument (count ring is blind). [[sess44-...]] supersedes the count-ring ambiguity of [[sess41-DEFINITIVE-loss-is-insert-time-not-writeback-ring-proven]] and [[sess42-PROVEN-799-is-stalebase-clobber-not-insert-loss-gpt-tenure-fence-plan]]; confirms [[sess11run-ROOTCAUSE-PROVEN-cross-node-dirblock-freeslot-double-allocation]].</body>
