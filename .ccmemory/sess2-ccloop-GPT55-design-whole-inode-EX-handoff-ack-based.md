---
name: sess2-ccloop-GPT55-design-whole-inode-EX-handoff-ack-based
description: sess2(ccloop) GPT-5.5 architectural design for 8/tcp dir_reuse: coherency unit = WHOLE dir inode (data+leaf+node+free+fork), ACK-based EX handoff, fu…
metadata:
  type: project
---

## sess2 — GPT-5.5 consult (RULE 5): correct architecture for concurrent same-dir creates over TCP DLM

GPT CONFIRMED the diagnosis (write-side lost-update + phantom-EX + leaf/data divergence) and that ALL prior single-sided fixes are expected to fail. The correct fix is a COMBINATION (no single piece suffices):

### Core invariants (all 4 required):
1. **Single-writer**: ≤1 node runs XFS dir2-modifying transactions on a dir inode at a time.
2. **Handoff visibility**: before EX moves A→B, every dir-metadata change A committed is on the LUN.
3. **No stale writeback**: after A releases/downconverts, A has NO dirty/pinned/delwri/async-writeable dir buffers that can later overwrite B.
4. **Whole-inode coherency UNIT**: the unit is the ENTIRE dir inode — data fork extent map + dir DATA + LEAF + NODE + FREE blocks + inode core + bmap-btree fork blocks. **NOT one dir data block.** (mxfs's per-block epoch/gen selective evict violates this — THE root of the partial handoff.)

### (b) Phantom-EX IS a protocol bug — master must be ACK-based:
```
A owns EX epoch E; B requests EX → master QUEUES B, sends RECALL/BAST to A, A stays owner.
A finishes bounded batch → freezes new mutations → drains active txns → checkpoints ALL dir metadata to LUN → invalidates entire dir inode → sends DOWNCONVERT_ACK(E).
master receives ACK → epoch=E+1 → grants EX to B. B invalidates whole inode → rereads from LUN.
```
RULES: A may keep modifying after BAST ONLY while master still regards A as owner (no grant to B yet). A must NOT modify after ACK. B must NOT modify before GRANT(E+1). **Local mirror (mxfs_dlm_held_mode / i_dlm_mode) is DIAGNOSTIC ONLY — gate modify on an explicit per-lock grant epoch/token (mode==EX && epoch==current_ex_epoch && !draining && !released), NOT on i_dlm_mode==EX or mirror-held.**

### (c) Merge-at-bio-submit (dir_write_merge) is FUNDAMENTALLY WRONG (explains my use_free corruption + leaf holes): XFS dir2 create couples data-block bytes + free tags + bestfree[] + leaf hash entry + leaf stale counts + node/free blocks + inode size/extent map + bmap btree + log ordering. Grafting name bytes at writeback leaves bestfree/leaf/free-index inconsistent → readdir sees name, lookup fails. A "correct merge" = replaying CREATE/REMOVE/RENAME through XFS dir2 code under EX = just serialization. So: DON'T merge dir blocks at writeback; serialize via EX and let XFS dir2 be the only writer of metadata.

### Make it FAST (RULE 0): EX delegation/LEASE — owner keeps EX for a bounded batch (max_ops≈128 or max_time≈5-20ms); peers queue at master; ~8 handoffs/round (one per node burst), NOT 800. Native XFS also serializes same-dir creates; the win is amortizing cluster handoff cost. mht-batching already exists but is layered on a broken (non-ACK, mirror-trusting, selective-evict) handoff.

### Concrete impl sketch: per-dir mxfs_dir_coh{epoch,state(NL/EX_VALID/RECALL_PENDING/DRAINING/RELEASED),active_writers,dirty_dir_buffers}. mxfs_dir_write_enter/exit around every dir2-modifying txn (enter validates epoch token + ++active_writers; blocks if draining). Recall handler: mark_recall→batch-window→mark_draining→stop new writers→wait active_writers==0→checkpoint WHOLE dir to LUN (log_force SYNC + AIL push/wait + writeback+wait data&leaf&node&free&core&bmap + blkdev_flush + assert no dirty/pinned remain)→invalidate WHOLE inode→ACK. Acquire: new epoch→invalidate whole inode→reread→EX_VALID. Add assert at dir-modify chokepoint: epoch token valid EX else shutdown; and at dir-buffer bio-submit: buffer_epoch==current_owned_epoch else it's a stale-after-release write = bug, fail loud (don't merge).

### NEXT (RULE 4) — verify the GAPS in the current code, fix incrementally, test each:
1. Does the release fence flush LEAF/NODE/FREE (not just DATA)? (write_merge left leaf holes ⇒ likely NO.) → extend to whole-inode flush.
2. Does the acquire evict drop the WHOLE inode (incl leaf/node/free), or selective+keep-guarded? → make genuine-handoff a full whole-inode invalidate (drained-durable at release ⇒ safe to drop all).
3. Is the master ACK-based, or does it grant before the holder's drain completes / before the unlock msg? → ensure unlock/ACK sent only AFTER drain completes.
4. Gate dir modify on explicit EX epoch token, not i_dlm_mode/mirror.
See [[sess2-ccloop-write-merge-removes-dabuf-but-corrupts-use-free-leafhash-holes]] [[sess2-ccloop-EA485CE6-still-fails-rank1-rm-leaf-vs-data-and-p13collide-garbage]] [[sess52-NEXT-probe-find-local-dlm-downgrade-without-bastprocess]]
