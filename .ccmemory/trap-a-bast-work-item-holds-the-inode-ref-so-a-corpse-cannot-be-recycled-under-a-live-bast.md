---
name: trap-a-bast-work-item-holds-the-inode-ref-so-a-corpse-cannot-be-recycled-under-a-live-bast
description: INVARIANT (D-0532 item c, 0.87.10): a delivered BAST is owned by a work item holding an igrab ref, so the inode cannot be inactivated/freed/recycled…
metadata:
  type: feedback
---

# A BAST work item pins the inode: no recycle can meet a live BAST

## What was asked (design consult, Astra 2026-09-18, D-0532 item c)
`xfs_iget_recycle` clears `i_dlm_bast_pending` and resets state BAST unconditionally.
The consult ruled the incarnation argument insufficient: a cached EX that survives a
deferred free is the SAME DLM grant the new incarnation is served from, so a peer's
BAST delivered to the corpse before its drain ran is an obligation on the grant and
may not be discarded. It asked for a directed schedule: real BAST in-core, grant live,
drain delayed, then free + recycle.

## What the schedule showed (tests/d0532_pending_bast_recycle.sh, 9/9 laps)
The shape is unreachable, and the reason is the invariant:
- The BAST work item (immediate `i_dlm_bast_work` or delayed `i_dlm_bast_dwork`) is
  armed under an `igrab` reference and holds it until after `mxfs_dlm_bast_process`
  (`/* queued: work fn owns the ref */`, `/* dwork owns the iget ref */`).
- So while a delivered BAST is outstanding the inode's last iput cannot happen: no
  evict, no inactivation, no ifree, never IRECLAIMABLE, never recycled.
- Trace: `rm F; sync` completed ~50 ms into a 700 ms park (`dbg_bast_defer_ino`), the
  corpse still read `nlink=0 imode=0100644` at `P-BAST-DEFER-END`, the drain released
  4 ms later, `P-INACT-CERT`/`P128-INACT-DEFER` followed 10 ms after that, the create
  got a fresh number every lap.
- All 14 `i_dlm_bast_pending = true` sites audited: each arms a work under igrab,
  parks the signal on a live holder whose `mxfs_dlm_ilock_end` arms it, or sets it on
  an inode already being evicted (I_FREEING: igrab refuses, teardown releases the slot).

## Consequences for future work
- The recycle only ever meets the STALE form (grant already NL, release ran). The
  clear exists for that; 0.87.10 classifies it (`recycle_bast_stale`) and keeps a live
  signal as a fail-safe (`recycle_bast_kept`, `P-RECYCLE-BAST-KEEP`). `recycle_bast_kept`
  non-zero anywhere = the invariant broke; investigate, do not accept.
- The immediate work path marks a delivered BAST as state BAST with the pending flag
  CLEAR (`P-BAST-DEFER who=BWORK pending=0 state=3`); the flag is the deferred form.
  Any rule about "a pending BAST" must key on either signal.
- A knob that parks a BAST work item cannot be used to build "BAST pending, inode
  freed" states: the park itself pins the inode. Parking the drain AFTER it has set
  mode NL (`dbg_bast_pause_ino`) is the other window and it is the stale one.
