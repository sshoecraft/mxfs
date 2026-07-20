---
name: sess123-caw-ex-starvation-gemini-fairness-design
description: sess123: Gemini's 3-part design for the CAW inode-EX starvation (post-tenure-fix blocker): strict allowed_next ticket handoff + in-core bast_pending…
metadata:
  type: project
---

## sess123 — CAW inode-EX handoff starvation: Gemini RULE-5 fairness design

### Problem (post tenure-fix; see [[sess123-tenure-id-FIXED-agi-corruption-now-starvation]])
unlink_visibility content is 100% correct now, but 4 nodes unlinking 30 files each in a SHARED dir all contend EX on the parent-dir inode (ino=135). Per-node wall: min=6.3s, max=123.2s — ONE node starves ~123s, crosses MXFS_CAW_WAIT_TIMEOUT_MS=120000 → -ETIMEDOUT → force-shutdown at mxfs_dlm_ilock_begin (xfs_mxfs_dlm.c:4356) → barrier EIO → FAIL. The 6s-vs-123s spread = UNFAIRNESS (one node shut out), not uniform slowness.

### Root (Gemini bet, matches evidence): CAS-race unfairness + cached-EX monopolization
- CAW slot has a `waiters` bitmap + `yield_to` priority hint but NO ORDER among waiters → free-for-all CAS with backoff; the just-released hot node (backoff timer at 0) re-wins instantly and shuts out a node deep in backoff sleep.
- Inode CACHED-EX fast-path (xfs_mxfs_dlm.c ~4020-4144) re-grants LOCALLY without touching the disk slot, so a holder runs many unlinks before any peer BAST forces a yield.

### Gemini's 3-part fix (concrete; full pseudocode in this session's Gemini call)
1. **Strict handoff (FIFO ticket)** — add `allowed_next` (bitmap) + `allowed_epoch` to the CAW slot. RELEASE picks ONE next EX waiter round-robin (first set bit after releaser's node id), sets allowed_next; only that node may acquire next. Readers batch-grant (allowed_next = waiters_pr). Dead-node skip: if allowed_next set but slot.generation unchanged >~2000ms, any waiter CAS-clears allowed_next (one free-for-all round). Bounds wait to O(N) handoffs. [Higher risk: ON-DISK SLOT FORMAT CHANGE + core CAW protocol; deadlock-prone — implement only if MHT insufficient.]
2. **In-core bast_pending** — atomic_t on the incore inode; set by the peer-BAST signal. Fast-path checks `if (atomic_read(&bast_pending)) { drop_cached_lock(); acquire_disk_lock(EX); }` = zero-I/O fast path, forces holder onto the fair disk queue when a peer waits. Needs #1 to stop instant re-acquire.
3. **Minimum Hold Time (MHT) batching** — the LOW-RISK, HIGH-LEVERAGE first fix. On fresh inode-EX acquire, record acquired-time. In bast_notify, if time-held < ~50ms, DEFER bast_process via queue_delayed_work for the remainder instead of releasing immediately. The holder stays on the fast path during the window and chews through many unlinks → converts ~120 serialized handoffs into ~8 → storm finishes <1s → starvation moot. (GFS2/OCFS2 "minimum hold time" / glock min-hold pattern.) No on-disk or CAW-protocol change.

### Diagnostic to confirm dominant mode (Gemini)
Poll ino=135 slot every 50ms, log Time|Gen|Holders_EX|Waiters:
- Gen churns 50+/sec, Holders_EX changes constantly → pure CAS-race unfairness (#1).
- Gen ~1/sec, Holders_EX SAME for seconds → cached-EX monopolization (#2).
- Gen ~1/sec, Holders_EX changes every tick → per-handoff drain cost inherently too high (#3/MHT).

### Plan (RULE 4): implement MHT (#3) first — lowest risk, collapses the storm. Measure unlink_visibility. If unfairness persists, add strict-handoff (#1) + bast_pending (#2).
NOTE: an "adaptive yield quantum" (MXFS_BAST_YIELD_QUANTUM) already exists for AG locks (xfs_mxfs_dlm.c ~7063) — INODE locks lack the equivalent; MHT is that gap. bast_notify inode branches at xfs_mxfs_dlm.c ~2606-2666 (immediate/deferred/pinned).

Related: [[sess123-tenure-id-FIXED-agi-corruption-now-starvation]] [[sess50_lessons]] [[sess49_lessons]] [[feedback_timing_is_first_class]]
