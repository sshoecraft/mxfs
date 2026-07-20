---
name: sess18run-REFUTED-dir-acq-lockwait-does-not-fix-low-mht-loss
description: sess18(ccloop) REFUTED: increasing dir_acq_lockwait (60→250, the drain_evict TRYLOCK-skip bounded wait) does NOT fix the mht=250 dir-data loss (got 4…
metadata:
  type: project
---

## sess18 (ccloop) REFUTED lead — dir_acq_lockwait is NOT the low-mht loss root

Tested `inode_mht_ms=250 dir_acq_lockwait=250` (5× the default 120ms wait for momentarily-LOCKED dir blocks in mxfs_dir_drain_evict_data_blocks): result = **40 failrounds (5/node)** — MORE loss than default, not less. So the residual dir-data free-slot lost-update at low mht is NOT caused by the drain_evict TRYLOCK-skip (the sess52 bounded-wait mechanism). Increasing the evict wait does not help and is not the fix.

Therefore the reload-reliability gap that forces high mht is elsewhere:
- Either the cross-node handoff SIGNAL (grant_gen handoff bit / dir_epoch level) occasionally fails to fire on a genuine re-acquire (so the comprehensive reload at xfs_mxfs_dlm.c:11597 mxfs_dlm_reload_inode(post_release=dir_ex_handoff) + drain_evict is skipped entirely), OR
- The RMW/free-slot selection in xfs_dir2 addname reads a stale free-space view in a window the gen-bump doesn't cover (a TOCTOU between the gen bump in ilock_begin and the addname's block/bests read).

Speed note: mht=250 completes ~283s (test) vs mht=275 ~300s — mht is the dominant speed knob (~17s per 25ms mht over 24 rounds), but mht=275 is the hard correctness floor (250 lossy). So fast+correct requires fixing the reload signal/timing, not the evict wait.

Next-session focus (see [[sess18run-HANDOFF-correctness-solved-speed-floor-reload-reliability-lead]]): instrument WHICH acquires lose (is dir_ex_handoff false on the losing re-acquire? does the epoch advance? is the addname reading a pre-bump block?). Add an always-on probe in the dir-EX fast path logging handoff/epoch/dir_gen vs the round, correlate with the RDMISS round. The build 58360875 (4 speed fixes + correctness at mht=275) is KEEP.
