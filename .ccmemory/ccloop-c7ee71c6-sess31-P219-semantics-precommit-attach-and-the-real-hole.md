---
name: ccloop-c7ee71c6-sess31-P219-semantics-precommit-attach-and-the-real-hole
description: KEY: b_li_list items attach at PRECOMMIT (not flush) and survive iodone when re-logged. P219 stale=1 = submit writes bytes last copied under a dead t…
metadata:
  type: project
---

# sess31 — P219 semantics decoded: the attach is at PRECOMMIT, and stale=1 describes the BYTES

## The architectural fact that unlocks everything
`xfs_inode_item_precommit` (xfs_inode_item.c:158-192) attaches the inode log
item to the cluster buffer (`li_buf` + `b_li_list`) at TRANSACTION PRECOMMIT —
NOT at flush. `xfs_buf_inode_iodone` detaches only items that were NOT
re-logged (ili_fields empty); a re-dirtied inode's item stays attached across
iodone. `xfs_iflush` (the byte copy into the buffer + the
i_mxfs_pub_stage_epoch stamp, xfs_inode.c:7297) runs from xfsaild's push via
xfs_iflush_cluster just before submit — and SKIPS inodes it cannot trylock,
whose slots then submit with the bytes of their LAST successful flush.

## Therefore
- P219 `staged=1` = "a committed change pins this buffer", not "freshly staged".
- The stamp accurately describes the bytes about to hit the wire (last copy-in).
- `stale=1` (stamp_epoch != live epoch) at submit = the wire receives an image
  copied under a DEAD tenure. This is REAL for class X, not an artifact.
- The epoch_flushing=0 "contradiction" dissolves: the tenure ended AFTER
  iodone#1 cleared XFS_IFLUSHING (re-logged item still attached), so no bump
  ever ran with IFLUSHING set. XFS_IFLUSHING is the wrong predicate for the
  obligation — the obligation is "attached item + committed-not-yet-republished
  change", which survives IFLUSHING clearing. (GPT: use an explicit obligation
  counter under the DLM state lock, not IFLUSHING inference.)

## The two measured classes (13 events, one PASSING dirent_durability run)
- Class X (REAL HOLE): dlm_mode=0(NL) stage_mode=5 img_nl=0 — xfsaild submits,
  at NL, a freed-inode image last copied under dead EX epoch 2 (now 3). If a
  peer reused the ino meanwhile, this write REVERTS it (sess29 corruption
  class, logged-slot variant). Confirmed on the true bio path
  (mxfs_submit_partial_inode_write is called from xfs_buf_submit_bio:5609).
- Class Y (torn stamp): stage_mode=0 with stage_epoch=2: mxfs_dlm sets mode=NL
  (xfs_mxfs_dlm.c:14514) then epoch++ (14516) under i_dlm_lock, but the stamp
  reads both LOCKLESSLY → interleaved read. Fix: snapshot {epoch,mode} under
  i_dlm_lock at xfs_iflush entry, stamp from the snapshot.

## GPT fix ranking for the hole (consult sess31)
D (prevent: tenure must not end while publication obligations outstanding; for
INVOLUNTARY loss the answer is fencing/no-more-home-writes, not late drain)
> C (reacquire EX + reload/adopt current home + REstage under new tenure —
never byte-merge, never blind-republish) > B (fresh iflush restage — only as
C's final step) > A (quarantine/hold — fail-closed containment; AIL-pileup
hazard). Never silently write the dead-tenure image.

## Next concrete steps
1. Snapshot-stamp fix (kills class Y noise) + P219 adds: bp->b_flags (XBF_STALE
   =(1<<1)? print raw), per-submission flush-round marker (did THIS round's
   iflush_cluster copy this slot, or is it carrying old bytes), img di_gen.
2. Then the containment/fix per D/C — behavior change, knob-gated, A/B.
3. dirent_durability is the producer; 13 events/run is plenty of signal.
