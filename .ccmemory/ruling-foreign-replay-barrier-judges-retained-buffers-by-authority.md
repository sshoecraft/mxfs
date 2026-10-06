---
name: ruling-foreign-replay-barrier-judges-retained-buffers-by-authority
description: Consult (0.90.58): the barrier around a dead peer's slice replay must not wait for an empty AIL; judge retained buffers by authority, fail closed on…
metadata:
  type: project
tags: [recovery, foreign-replay, drbd, consult, ruling]
---

Design consult (GPT, 0.90.58) on mxfs_dlm_peer_joined_flush used as the barrier before/after a foreign slice replay on a live survivor.

Measured: DRBD rig, 4 VM-like O_DIRECT loads on the survivor; each barrier round ~35 s in xfs_ail_push_all_sync (inode timestamp items relogged every write), invalidation -EBUSY ("2 AG(s) retained 2 buffer(s)"); the replay started only when the loads ended (105.7 s after election). With VMs that never stop, never.

Ruling:
- An empty AIL is NOT part of the pre-replay predicate. Every image the replay APPLIES is under a grant the dead node held at death (token enforcement); those grants stay frozen; nothing the survivor logged can be under one. A sampled-LSN "bounded push" would not prove "pre-sample content on disk" anyway (relogging moves items) -- do not present it as such.
- Retained buffers are judged by AUTHORITY, not provenance. "Has a BLI / in AIL / pinned / delwri" is a hint, not proof. Supported merge: inode clusters (slot-granular: partial writer mask, b_mxfs_recov_slots, platter slot refresh before first patch, canonical cached buffer under lock). AG meta with local un-landed content is ours only while this node holds the AG grant -- otherwise fail closed. Anything unclassifiable fails closed.
- Post-replay: every replayed unit must complete a write containing its final bytes before the dead slice is retired/grants released. The tree already does this: the replay pass's delwri_submit waits, and a durable flush precedes IMAGES_REPLAYED.
- freeze_super is the wrong tool: a local writer blocked inside sb_start_write on a dead node's grant would deadlock the freeze against the recovery that releases it.
- Keep the full destage for the join (both sides must be clean) and the intent engine's home write (its own transactions must land).

Implemented as mxfs_dlm_foreign_replay_barrier (xfs/xfs_mxfs_recovery.c) + census classes in mxfs_dlm_invalidate_cached_views_census (xfs/xfs_mxfs_buf.c). Oracle line: P232-FREPLAY-BARRIER slot= when=pre|post rc= rounds= ms= retained{...}.
