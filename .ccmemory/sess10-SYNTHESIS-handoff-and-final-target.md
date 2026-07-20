---
name: sess10-SYNTHESIS-handoff-and-final-target
description: sess10 FINAL SYNTHESIS (read first): coherency model is DLM PR/EX-acquire-forces-BAST-drain; eviction-ring is only an eviction optimization. Bug = a…
metadata:
  type: project
---

## sess10 FINAL SYNTHESIS — read FIRST next session. Supersedes the earlier "lossy eviction-ring is the primary signal" framing.

## THE COHERENCY MODEL (proven from code comment, mxfs_dlm_dir_durable_signal xfs_mxfs_dlm.c:9984-10001):
Dir coherency is DLM-BASED, NOT heartbeat-based:
- "A peer that READS the dir coordinates through the DLM; its PR acquire forces OUR BAST release drain (invariant #1), which makes these blocks durable BEFORE the peer can read them."
- The eviction-ring (note_dir_modified / DIR_MODIFY heartbeat) "only EVICTs caches; their subsequent re-read coordinates as above" — it is an OPTIMIZATION, not the primary coherency mechanism.
So the intended flow IS reliable: peer acquires PR/EX -> BASTs holder -> holder drains+demotes (i_dlm_mode=NL, blocks durable) -> peer acquires + reloads fresh.

## SOLID FACTS (verified, don't re-investigate):
- TCP dir modify takes a REAL per-inode DLM EX (mxfs_v5_dlm_inode_lock -> mxfs_dlm_lock on ctx->dlm).
- Release/bast_process sets i_dlm_mode=NL before unlock (2869/3545/8346/8369).
- mxfs_dlm_reload_inode is reliable when reached (stale cluster buf + clear XBF_DONE -> FUA re-read).
- Master double-grant fixed (gen-token 404BC55C in-tree).
- mxfs_v5_dlm_inode_held = NO-OP on TCP (returns 1) -> P106/P108 detectors dead on TCP.

## THE BUG (necessarily): a node's CACHED-lock FAST PATH bypasses the DLM coordination. The failing node (rank1's `ls`, or a modifier) holds the dir cached (PR/EX from its own earlier churn) and FAST-PATHs its read/modify WITHOUT a fresh DLM acquire -> it never BASTs the peer / never re-coordinates -> serves its STALE in-core dir. For its cache to be stale, the peer modified the dir after this node cached it; that REQUIRES the peer to have acquired EX, which should have BAST'd+demoted this node. So the ROOT is a BAST that did NOT demote this node (deferred and never honored, or a dropped/reordered TCP BAST), leaving this node with a stale cached grant the fast path trusts.

## WHERE TO LOOK NEXT (pinpoint the failed-demote / stale-cache window):
1. Can a node hold a cached dir grant whose on-disk/DLM grant the peer ALSO holds (the cache outliving a demote that didn't fire)? Trace the BAST path end-to-end on TCP: process_remote_request (peer EX) -> send BAST to holder -> holder mxfs_dlm_bast_notify -> branch chosen (ACQUIRING/pinned/MHT-defer/immediate/active-holders) -> is the demote ALWAYS eventually run? Suspect: a branch that sets state but whose honor-point (ilock_end/unpin/MHT-dwork) can be MISSED so i_dlm_mode stays EX/PR cached forever.
2. The MHT-defer keeps state==CACHED + arms i_dlm_bast_dwork. If the dwork's "already consumed" early-out (mxfs_dlm_bast_dwork_fn ~4370: `if(!i_dlm_bast_pending) return`) fires wrongly, or the dwork is cancelled by a re-acquire, the BAST is DROPPED -> stale cache persists. CHECK THIS PATH CLOSELY.
3. Eviction-ring reliability matters only as the backup that ALSO failed.

## FIX once root found: ensure EVERY BAST reliably reaches a demote (i_dlm_mode->NL) bounded by MHT; OR force a real DLM re-acquire for a shared-dir read/modify when the cached grant may be stale. NOT the di_changecount/local-gen/refresh-while-holding dead-ends (all refuted, see other sess10-* memories). Validate FULL `./run.sh 2 tcp` x3 FOREGROUND. Baseline 5EC1F0BF. [[sess10-gpt-verdict-serialize-tenure-not-epoch]] [[sess10-CORRECTION-local-grantgen-insufficient]] [[feedback-never-background-wait-poll]].
