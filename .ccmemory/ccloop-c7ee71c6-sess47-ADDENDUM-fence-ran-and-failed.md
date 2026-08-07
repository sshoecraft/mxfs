---
name: ccloop-c7ee71c6-sess47-ADDENDUM-fence-ran-and-failed
description: sess47 addendum: fence RAN during the P53 wave (60 COLDREAD fence=1 interleaved, same AG) — flush didn't help ⇒ write never submitted; new top arm =…
metadata:
  type: project
---

# sess47 addendum — the discriminator that reorders the arms

test10 wave window (t=18340.8-18342.6): 60× P-INOCL-COLDREAD fence=1 (agno 15, repeated daddr 31406008) INTERLEAVED with the P53-IUNLINK-MISMATCH events (inos 0x1e01dxx = agno 15). The fence executed and issued device flushes BETWEEN fossil observations — and fossils kept coming.

## Implication
A device flush cannot help if the iunlink NULL-clear was never SUBMITTED to the device. ⇒ For this wave the stale image is on the MEDIA (or the buffer refill path serves a pre-write image regardless of flush). Target-write-cache time-travel is NOT the operative arm here.

## New top hypothesis (RULE-4 target #1 for next session)
**Re-read over a clean-bli delwri-pending buffer**: iunlink write → CIL → checkpoint completes → bli goes CLEAN (li_dirty cleared, unpinned) → buffer sits on delwri queue awaiting writeback home → an mxfs invalidation/coherency re-read (coherent re-read path / evict-ring / DONE-clear) refills b_addr from stale media → delta silently gone. NO existing tripwire covers this window: P-PINNED-REREAD requires li_dirty||pinned (both false post-checkpoint); P-BUF-FREE-WITH-ITEMS requires attached items (detached at clean). Instrument: probe any DONE-clear/re-read/refill of an xfs_inode_buf_ops buffer while (_XBF_DELWRI_Q set || b_mxfs uncheckpointed ledger) — print daddr+delwri+lsn; correlate with next P53 on same chunk.
Secondary: the raw coherent re-read path (mxfs_buf_is_multinode_dir_meta incl. clusters) is still the likely REFILL vector — instrument it regardless.

## Note
The repeated SAME daddr 31406008 cold-in-window reads (60×!) say cluster buffers are being evicted/re-read at high frequency under churn — the refill machinery, not memory pressure, is the driver. Find who clears DONE / evicts cluster buffers in the DLM release path (P70-BP pipeline) — that's where the delta dies.
