<!-- sess432 RULE-5 ruling D-0353: explicit GAUTH_SINGLE_NODE provenance (transition-serialized), P131 -> two-pass preflight + shutdown (never log-force t… -->
# sess432 RULE-5 ruling — D-SINGLENODE-FALSE-FRESH-DISCARDS-PINNED-AGMETA-DOUBLE-ALLOC-0353

Chain (measured on the LUN, tests/lone_mount_create.sh): caw_lock single-node fast path -> non-proving grant (epoch 0) -> sess291 epochless-hint drop (xfs_mxfs_dlm.c:40088) on every acquire -> P130 false-fresh -> invalidate_ag_meta stales PINNED AGI/inobt/finobt (P131) -> platter re-read -> mkdir's inode allocated twice -> shutdown.

## Q1 trigger (B)
- Exempting single-node from the epochless drop is sound ONLY if the single->multi transition is a serialization boundary (TOCTOU: acquire returns single-node result, join flips mode, XFS publishes epoch-0 after). Do NOT key on an unlocked live single_node read.
- Preferred: distinct provenance GAUTH_SINGLE_NODE = cached reuse valid within the same single-node generation; NOT an authority proof for replay; must never survive the join barrier.
- Join ordering required: JOINING state; block new single-node acquires + new dirtying; drain in-flight acquires (finish-and-drain or detect generation change and retry multi); commit txns; log_force SYNC; ail_push_all_sync (error = transition failure); VERIFY no AG meta pinned/CIL/AIL/dirty/delwri/under-writeback; end all single-node lineages via normal release bookkeeping; invalidate cached views + clear provenance/epoch; enable multi CAW; admit peer. The flush is insufficient if new single-node txns can start between flush and mode switch.

## Q2 loss mechanism (A)
- Option (ii) (log_force+AIL push at the fresh acquire) UNSAFE: may clobber a peer's newer platter state. Land local state BEFORE yielding authority, never after reacquiring.
- Option (i) (skip when lineage open) only if continuity is independently proven by slot state, not by the in-memory boolean.
- Shape: classify acquisition (continuous vs fresh) after the CAW slot is taken, before invalidating; fresh + lineage open -> reclassify continuous only if slot state proves uninterrupted local ownership, else force shutdown (P130 becomes an enforced invariant). Fresh: exclude local AG-meta users, stabilize the buffer set, COMPLETE preflight pass first; any buffer pinned / CIL item / unlanded in AIL / dirty / delwri / under writeback -> force shutdown, stale NOTHING (two-pass, all-or-nothing). Only if all clean -> second pass xfs_buf_stale. No log_force / AIL push in that error path.
- Complementary release-path invariant: local committed metadata landed successfully before the CAW authority is yielded.

## Q3
Yes: the join barrier must run the normal end-of-lineage bookkeeping (clear lineage_open, cached hint, provenance, grant_epoch, invalidate view) via the common release helper, while acquires are blocked; on flush/push/verify failure do not clear and do not admit the peer.

## Q4 additional stop-ship
Lone node commits epoch-0 txns, crashes before landing, another node mounts and must replay the slice under token enforcement -> refused. Needs durable proof: persistent single-node authority incarnation in tokens, or a durable epoch minted in single-node mode without the old EX-bit promotion OR-bug, or narrowly permit epoch-0 replay only when durable membership/incarnation state proves an uninterrupted exclusive single-node era. "Current mount sees no peers" is not enough. Crash cuts at every join stage must be tested.

## Disposition order
1 provenance/exemption, 2 P130 enforce, 3 P131 preflight+shutdown, 4 join barrier lineage end, 5 block join if not landed, 6 directed tests (repeated single-node reacquire; acquire racing join; pinned at fresh invalidation; slot-loss/open lineage; lone crash + foreign replay; crash injection through the join), 7 full 32-node board.
