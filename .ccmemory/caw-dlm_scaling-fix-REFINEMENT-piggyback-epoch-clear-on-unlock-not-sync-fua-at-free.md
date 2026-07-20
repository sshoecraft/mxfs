---
name: caw-dlm_scaling-fix-REFINEMENT-piggyback-epoch-clear-on-unlock-not-sync-fua-at-free
description: CRITICAL refinement to the dlm_scaling dealloc-invalidate fix: do NOT add a synchronous per-free FUA CAW op (slow + sess70 heartbeat-cascade risk) NO…
metadata:
  type: project
---

## dlm_scaling fix — CRITICAL implementation refinement (ccloop 0d6e174d sess2, code-grounded)

Refines [[caw-dlm_scaling-fix-BEST-approach-invalidate-caw-epoch-at-inode-dealloc-GFS2-pattern]]. AVOID two
traps the naive version hits.

### TRAP 1 — synchronous per-free FUA CAW op is SLOW + can cascade-crash the cluster:
`mxfs_dlm_caw_purge_node` (dlm_caw.c:3501) header (sess70) PROVES: per-slot FUA read_slot+CAS on a sensitive
thread blocked the disklock HEARTBEAT → peers fenced this node (SCSI PR preempt) → reservation-conflict → log
I/O error → FS shutdown → whole-cluster eviction-cascade collapse. `mxfs_v5_dlm_note_inode_freed` (v5_mount.c
:1592) is explicitly NON-BLOCKING (stages into the eviction ring). dlm_scaling does 2000 inode FREES/node →
adding a synchronous find_slot(FUA read)+CAS(FUA write) there = ~4000 extra FUA round-trips/node ON THE FREE
PATH → SLOWER dlm_scaling (defeats the fix) + heartbeat-blocking cascade risk. DO NOT do a sync FUA op at free.

### TRAP 2 — pure-async (stage in eviction ring, clear later) has a CORRECTNESS WINDOW:
The stale epoch must be cleared BEFORE the ino is REALLOCATED (else the realloc inherits it → the bug). Under
dlm_scaling's fast create+unlink churn, a peer can realloc the freed ino within ms — before an async clear
lands. So a purely deferred clear can miss the window.

### BEST RESOLUTION — piggyback the epoch-clear on the UNLOCK CAS that ALREADY happens during the free:
When an inode is FREED, its DLM lock is released (an unlock → caw_tombstone_slot preserves epoch/last_ex_slot,
dlm_caw.c:694 — THAT preservation is the bug for a free). The unlock ALREADY does find_slot + a CAS. So:
- Distinguish "unlock because the inode is being FREED" from "unlock because idle/BAST release". On a FREE
  unlock, write the tombstone with dir_epoch=0/last_ex_slot=NONE (fresh) INSTEAD of preserving them. On an
  idle release, preserve (keep the idle-gap coherence — load-bearing per the caw_tombstone_slot comment).
- Zero extra I/O (reuses the unlock's existing CAS), synchronous (clears before the ino can be reused —
  the free's inobt update, which gates realloc, is ordered after the release).
- Plumb the "freeing" signal: xfs_ifree/xfs_inactive already calls mxfs_v5_dlm_note_inode_freed(ctx,ino,gen);
  set a per-inode "being freed" flag (or pass a free-reason into the unlock) that caw_tombstone_slot/the
  release path checks. Since the free hook has {ino,gen,ctx}, and the unlock has the slot, wire the signal
  between them (e.g. i_dlm flag, or a mxfs_dlm_caw_mark_freeing(ctx, ino) that the next unlock consults).

### Param-gate caw_epoch_free_reset (default 0). Validate as before (dlm_scaling_diag.sh 32 + no regression on
dir_reuse/cache_coherency which rely on the idle-gap epoch inheritance for GENUINE releases). Model the slot
CAS on mxfs_dlm_caw_purge_dead_nodes (dlm_caw.c:3546, batched clear+CAS). CAW ctx = ctx->dlm_caw. This is the
implementation the next session should build + TEST — NOT the sync-FUA-at-free naive version.
