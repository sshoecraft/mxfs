---
name: ccloop-c7ee71c6-sess14-D-gpt-consult-designs-d2-tickets-d5-queue-d3-poison
description: sess14 GPT consult (RULE 5): D2 = deadline visibility-tickets design; D5 = queue-reload+serve-stale-once; D3 fences → permanent write-poison + tenure…
metadata:
  type: project
tags: [gpt-consult, design, d2, d3, d5, write-poison, visibility-tickets]
---

# sess14-D: GPT-5.6 consult — designs for D2/D5 + D3 fence hardening

## D2 (per-dirop barrier) — RECOMMENDED DESIGN: deadline-bounded coalesced destage
- Per dirty parent (or per inode cluster) a "visibility ticket": {incarnation, dir epoch,
  dirty generation, target LSN}. First dirtying op arms a ~2ms deadline (do NOT extend on
  later ops — track FIRST-dirty age); later ops coalesce (raise target gen/LSN).
- One log_force covers all queued parents ≤ LSN; batch cluster+dir-block writes; one flush.
- PIN the dir's EX (no down-convert/unlock) until its ticket lands; BAST expedites the
  ticket inside the existing release drain. Hard backpressure at ~5ms (mutators help/wait).
  Dedicated high-prio workqueue. Tune to device p99.
- DROP the per-op device-read + 512B FUA readback verify from the normal path (keep as
  sampled diagnostics / mount-time qualification only).
- Cluster-write caveat: per-inode EX doesn't protect NEIGHBOR slots in the cluster buffer —
  need cluster-level serialization / CAW-version / rebuild-from-fresh-read+patch-authorized-
  slots (mxfs's P13-SLOTPATCH is this third option — keep).
- 13-item failure-test list (crash points around force/write/flush; BAST at each stage;
  continuous-mutation deadline starvation; SF<->block conversions; 2-parent rename order;
  unlink/reuse with stale ticket; neighbor slots; IO-error must NOT release grant; fencing
  during drain must not transfer authority).
- Durability semantics note: plain create need not survive power loss (Linux semantics) —
  ticket-queued return is fine; if MXFS promises durable-on-return, group commit still
  amortizes.

## D5 (readdir reload livelock) — RECOMMENDED: option (i), no lock games
- Readdir path: NEVER down_write_trylock from under own read lock. Set RELOAD_QUEUED bit +
  igrab, queue dedicated reload worker, serve current snapshot for this invocation.
- Worker: normal down_write (no spin), recheck stale/epoch after acquiring, build
  replacement state in temps, install under lock, requeue if epoch moved, clear bit, iput.
- ALSO queue the worker at stale-MARKING time (BAST/invalidate) so readdir rarely sees stale.
- Rejected: drop/retake i_rwsem inside iterate_shared (VFS contract risk); RCU fork swap
  (invasive; cursor consistency unsolved); -EAGAIN to VFS (userspace readdir not uniform).
- Serve-stale-once is POSIX-acceptable for concurrent-modification readdir semantics.

## D3 fences (P146D/P32D marker + P32E epoch fence) — verdict: keep, harden
1. Dead-incarnation marker → make it a permanent WRITE-POISON: once dirent-validated corpse,
   REFUSE all core relog/iflush/dirtying regardless of gen equality (di_gen ABA-fragile;
   keep the gen only as diagnostics). Clear ONLY via fully-serialized successful adoption
   (or in-core destruction). [APPLIED in v0.11.123: guards fire on marker alone.]
2. Epoch fence: correct, but the DEEP invariant is "EX cannot transfer until prior holder's
   committed changes landed or recovery owns them" — a failed release drain must fence/
   recover, never silently hand off. Phantom-retire must NEVER override the epoch fence
   (after epoch advance, old-node unlanded changes = protocol violation → recovery event).
3. AIL: skipping flush forever tail-pins — need explicit SUPERSEDED retirement (complete the
   item WITHOUT a cluster write once supersession is proven durable). Current P32F/P32E
   idiom (write buffer unmodified) is acceptable interim but carries neighbor-slot risk on
   stale cached buffers (same risk class as all cluster writes; P13-SLOTPATCH mitigates).
4. Target invariant (structural, future): flush requires {grant==EX, item incarnation ==
   in-core == disk, item tenure epoch == current validated tenure, not poisoned} — i.e.
   tag dirty items with {incarnation cookie, write-tenure epoch, dirty gen}; background AIL
   writeback after EX release should not exist (land-before-release or recovery-owned).

## Priority notes
Next implementation order: (1) write-poison hardening [DONE .123]; (2) D5 queue-reload
(contained, kills the livelock storms + drc pace contributor); (3) D2 ticket design (bigger);
(4) structural tenure-tagged flush authority (the D3-family end-state).
