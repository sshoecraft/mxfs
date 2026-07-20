---
name: sess96_gpt_fix_design
description: sess96 GPT(gpt-5.5) definitive fix for shared-dir lost-update: DLM demote=checkpoint fence + acquire=invalidation fence; DIR-STALE-SKIP→fatal.
metadata:
  type: project
---

# sess96 — GPT-5.5 definitive design for the shared-dir durable lost-update

Consulted GPT after 2 Gemini consults (RULE 5 escalation). GPT confirmed the
architecture and explained WHY both my tried fixes failed. This is the design the
NEXT session should implement. Full context in [[sess96_lessons]].

## Core invariant set (GPT)
**Inv 1 — DLM EX demotion/release MUST be a real XFS metadata CHECKPOINT FENCE.**
Before releasing/demoting a dir DLM EX lock, for EVERY local xfs_buf protected by it:
not pinned, not dirty, no committed-but-uncheckpointed AIL obligation, and (if modified
this tenure) its contents have REACHED THE SHARED TARGET (home-block written). NOT just
log_force; NOT just wait_unpin; NOT a 200ms bounded best-effort. No timeout, no
best-effort, DLM not demoted until complete. If writeback fails → xfs_force_shutdown
(don't hand off the lock).

**Inv 2 — slow-path EX ACQUIRE is an INVALIDATION FENCE.** After grant, before the first
modifying read: bump i_dlm_dir_gen; for each cached dir buf — if clean+unpinned, mark
stale/clear-DONE so the next plain read re-fetches from the target; if pinned/dirty/in-AIL
from a prior tenure → PROTOCOL VIOLATION (should be impossible after Inv 1) → wait only for
this node's own in-progress demote drain, else shutdown. NEVER write a stale buf on acquire
(that clobbers the peer = Fix B's flaw).

**Inv 3 — the DIR-STALE-SKIP "keep stale and continue" branch must become FATAL.** Once
Inv 1+2 hold it can never fire; if it does, xfs_force_shutdown(SHUTDOWN_CORRUPT_INCORE),
NEVER silently reuse / force-write / discard. There is NO correct local merge once two
divergent committed physical versions of a dir block exist.

## WHY my sess96 fixes failed (GPT)
- **Fix A (release xfs_bwrite)**: xfs_bwrite is NOT wrong — it writes the current buffer
  image. It failed because the buffer's ACQUIRE BASE was ALREADY stale (the node had earlier
  reused a stale pinned buf), so xfs_bwrite PUBLISHED a divergent image → deterministic
  stale-writer-wins → 2→24 fails. Release writeback is correct ONLY as part of a protocol
  that ALSO guarantees acquire-side freshness + forbids dirty/pinned leftovers from a prior
  tenure. (Any residual bounded/timeout release behavior also still violates Inv 1.)
- **Fix B (read-time wait_unpin+reread)**: at DIR-STALE-SKIP the node is ALREADY in an
  impossible state (local pinned buf diverged from the peer's newer target version). Forcing
  the pin out publishes the stale image (clobbers peer); the reread then returns the node's
  OWN just-forced clobber. The read path must NEVER resolve a stale pinned buffer — it must
  refuse (shutdown).

## Q3 deep XFS point (GPT) — do NOT evict/reread a logged-but-unwritten metadata buffer
XFS has NO semantic merge for metadata buffers. The log holds physical redo records; the
AIL item is tied to the in-core buffer/log item; checkpoint writeback writes the buffer's
CURRENT in-core contents to the home block. If you evict+reread a peer version while a prior
logged-but-unwritten change to that block is outstanding, you get: lost prior change, or a
later AIL push writing wrong contents, or crash-recovery replaying old byte ranges onto a
diverged block. So: a prior-tenure logged change MUST be fully checkpointed to the target +
buffer clean/non-AIL/non-pinned BEFORE any release OR invalidation/reread.

## Implementation plan (GPT, deadlock-safe)
1. **Track protected buffers explicitly** per DLM lock domain (dir inode lock): a
   `dirty_bufs` list of xfs_buf's dirtied while the lock was held (dir data/leaf/node/
   freespace/dabtree blocks). Attach+ref when a dir metadata buf is committed under the EX
   lock. Do NOT rely only on i_dlm_dir_gen to FIND dirty buffers — need a deterministic list.
2. **BAST = quiesce + queue, do NOT release in callback.** BAST marks revoke_pending, blocks
   new local ops under this lock, queues a blocking demote worker, returns WITHOUT unlocking.
   Local dir ops wrap in begin/end that increments active_users and waits if revoke_pending.
3. **Demote worker (blocking WQ, NOT BAST thread, NO inode ilock / txn / buf locks held):**
   wait active_users==0 → xfs_log_force(SYNC) → per tracked buf: xfs_buf_lock +
   xfs_buf_wait_unpin + (if needs checkpoint) xfs_bwrite (fail→shutdown) → assert
   !pinned&&!dirty&&!in_AIL → mark clean-stale → ONLY THEN dlm_unlock/demote.
4. **Read path:** if dir buf gen-stale: if pinned||dirty||in_AIL → shutdown (fatal, not
   reuse); else clear XBF_DONE + plain reread + restamp gen.
5. **Slow EX acquire:** bump gen; assert no dirty/pinned/AIL prior-tenure dir bufs; mark
   clean dir bufs stale.

## Caveats for implementer
- `xfs_buf_wait_unpin` is STATIC in pal/linux/xfs_buf.c:1020 → need to de-static + extern
  decl, or add an exported wrapper, to call from xfs_mxfs_dlm.c.
- The "track dirty bufs per lock" is the big new piece — current code re-derives dir blocks
  from i_df extents (mxfs_dir_data_durable/flush/evict all walk for_each_xfs_iext). That walk
  may MISS leaf/freespace/dabtree blocks and cross-AG blocks. An explicit tracked list is
  more robust but a bigger change. A pragmatic first cut: keep the i_df-extent walk but make
  the release drain UNBOUNDED + synchronous (wait_unpin + bwrite + verify-clean, no msleep
  giveup) and move it off the bast thread if it's currently on the CAW poll thread; AND make
  DIR-STALE-SKIP fatal so any residual violation is loud, not silent.
- Verify execution context: is mxfs_dlm_bast_process on a workqueue or the CAW poll/notify
  thread? GPT requires the heavy drain OFF the DLM callback/poll thread (else deadlock vs
  log force / writeback / DLM rx). Check before making the drain unbounded.
- fua_disable=1 stays (FUA-on DISPROVEN this session). Keep typeflip fix (build FB9573F7).
- After implementing: reset4 (fua_disable=1 default) + run cache_coherency; rename 2→0 AND
  stays fast (~9s, NOT 370s). Also watch the intermittent bnobt double-free
  (ltbno+ltlen>bno) — GPT's same fence design applies to AG locks (AGF/AGI/AGFL/bnobt bufs).
