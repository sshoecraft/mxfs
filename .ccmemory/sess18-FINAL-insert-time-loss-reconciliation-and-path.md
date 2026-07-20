---
name: sess18-FINAL-insert-time-loss-reconciliation-and-path
description: sess18 FINAL: the 2/tcp durable loss is at INSERT time (node1_f1 absent on BOTH nodes' earliest block image per prior P35E-DIRWR), NOT stale post-han…
metadata:
  type: project
---

## sess18 (ccloop 8ddb16a2) FINAL synthesis + reconciliation. Cluster left HEALTHY at baseline (build F13B9FB0, dir_merge=0 force_block=0; both mounted RW_OK). Marker NOT written — durable dir-entry loss reproduced live today (cc_blockdir_probe, multiple runs, unrecoverable).

## THE EVIDENCE THAT REFRAMES EVERYTHING (from prior [[sess17-detector-refutes-enforce-and-cc-flaky-pass]], P35E-DIRWR dirwr=1 on the actual failing iter): the lost entry was node1_f1 (the FIRST file), and it was ABSENT FROM THE EARLIEST captured image of the dir block on BOTH nodes. => the dirent is lost AT INSERT TIME (shortform / sf->block-conversion / concurrent-RMW), NOT a stale xfsaild/kworker re-flush over a good image. ZERO nl=1 (NL-released) dir-block writes in the trace. So:
- My sess18 "stale-writeback clobber" framing AND GPT's "epoch-checked write-submission guard" target a vector that the evidence says is NOT firing here (no NL-released stale reflush). The tenure-mismatch write-skip can't be enforced (fires only on legit tenure=0 fresh/conversion blocks → enforcing corrupts, [[sess23-ccloop-suppression-was-corruptor-3of4]]).

## THE ACTUAL VECTOR (best synthesis): a CONCURRENT INSERT lost-update during the shortform / shortform→block phase. node1 inserts node1_f1 (lives INLINE in the shortform dinode). node2 concurrently acquires EX with a shortform base MISSING node1_f1 (either node1_f1 not durable at node1's release — shortform dirents are INLINE in the dinode, and the sess97 data-block release fence flushes DATA blocks but a shortform dir HAS NONE; the dinode-cluster durability is a separate path that can lag — OR node2 keeps its own stale shortform via a keep-guard), node2 adds node2_f1 and CONVERTS sf->block, writing a block image WITHOUT node1_f1 → node1_f1 durably lost; node1's later reload of that block drops its own entry. This is the shortform concurrent-insert lost-update family (sess9/sess13/sess14) — supposedly fixed before, but still reproduces.

## WHAT THIS SESSION DEFINITIVELY ESTABLISHED (don't re-try):
- Merge family (v1/v2 extra-DLM-acquire → crash; fold-into-tp I/O-under-grant → wedge): DEAD. Also GPT: union-merge of stale XFS buffers is architecturally unsafe (not a CRDT; old committed log items persist). 
- Read-side FUA: no effect (loss still durable).
- force_block (block format from mkdir): NO effect (loses iter 2) — sf→block transition was a RED HERRING; pre-grown 0/30 was MULTI-BLOCK SPREAD. [[sess18-CORRECTION-transition-redherring-sameblock-rmw-is-root]]
- Epoch write-guard enforce: refuted (would suppress legit fresh-block writes).

## PATH FORWARD (next iterations):
1. DETERMINISTIC 4-node repro (user guidance) + dirwr=2/instr to CAPTURE the node1_f1-style loss lifecycle: is node1_f1 (a) never durable at node1's release (shortform dinode durability gap — check mxfs_dlm_dir_inode_durable / mxfs_inode_cluster_durable actually lands the dinode on the platter before release), or (b) node2 reloads/keeps a stale shortform missing it (shortform keep-guard / reload), or (c) the sf->block conversion (xfs_dir2_sf_to_block) reads a stale base? P35E said absent on BOTH nodes' EARLIEST block image → favors (a) or (b): node2 converted a base that never had node1_f1.
2. FIX locus candidates: (a) shortform RELEASE durability — ensure the dinode (inline dirents) is platter-durable before dir-EX handoff for SHORTFORM dirs (the data-block fence is a no-op for shortform); (b) shortform ACQUIRE coherency — node2 must adopt node1's durable shortform (incl node1_f1) before RMW/convert (sess14 sf_merge may not cover the concurrent in-flight case).
3. GPT's architectural frame still valuable for the GENERAL coherency (DLM grant = buffer-cache ownership; checkpoint-on-revoke completeness; directory-owner DELEGATION/op-forwarding for hot dirs to satisfy RULE-0 perf) — see [[sess18-GPT-architecture-epoch-ownership-checkpoint-on-revoke]].

## All sess18 memories: merge-v2-refuted, readside-ruled-out, merge-perf-doomed, ROOT-NARROWED (corrected), FIX-LOCUS-reload-selfskip, candidate-fixes-ranked, CORRECTION-transition-redherring, GPT-architecture, this. [[sess18-readside-ruled-out-writeside-clobber-confirmed]]
