---
name: sess52-NEXT-probe-find-local-dlm-downgrade-without-bastprocess
description: sess52(ccloop) NEXT probe target. RULED OUT: partial-grant (P52 0x), mxfs_dlm_lock_convert (dead code - dlm_convert_fn never called), dlm.c:3276 (upg…
metadata:
  type: project
---

## sess52 — next-probe target + ruled-out downgrade candidates

### PROVEN root (recap): the dir_reuse readdir=799 loss == a dir modify under i_dlm_mode=EX while mxfs_dlm_held_mode(local TCP DLM entry) < EX (held=0). P51-PHANTOM modifies correlate 1:1 with lost dirents (1 phantom/1 loss default MHT; 13 phantoms/9 losses at mht=0). Full proof: [[sess52-ROOT-PROVEN-phantom-EX-bast-during-acq-modify-without-grant]].

### RULED OUT this session (do NOT re-check):
- **Partial grant at acquire**: P52-PARTIAL-GRANT (v5_mount.c:1284, logs rc==0 && granted<requested) fired 0× → mxfs_dlm_lock always grants the requested mode when rc=0.
- **mxfs_dlm_lock_convert downgrade** (dlm.c:1814, sess44's stale-base-RMW flag): its only entry point `dlm_convert_fn`/`dlm_convert_tcp_wrapper` is NEVER CALLED (grep: 0 call sites). Dead code. Not the downgrade.
- **dlm.c:3276** (`if (mode > lk->mode) lk->mode = mode`): UPGRADE-only for local_node entries. Not a downgrade.
- **dlm.c:2998** (`lk->mode = mode` after other->GRANTED check): master grant-promote context, not a downgrade of our entry.
- **bast_process** (xfs_mxfs_dlm.c:8436): couples local unlock with i_dlm_mode=NL @9358, re-checks ex_holders @9345 atomically. Not the uncoupled path.
- **promote_waiters**: BLOCKS conflicting waiters; never force-revokes a GRANTED holder.

### REMAINING candidates for held<EX while i_dlm_mode=EX:
1. **Entry REMOVAL** (mxfs_dlm_held_mode returns NL when no GRANTED local entry exists): find every site that removes/frees our GRANTED inode entry from ctx->buckets — membership recovery (fail_all_pending @444/2048/2334), master-message handlers that lock_remove our entry, lease/disklock teardown. One of these removes our entry while i_dlm_mode stays EX.
2. **Re-acquire transient (state=1 ACQUIRING phantoms)**: during a slow-path re-acquire the old entry is gone (held=0) and the new grant not yet recorded, while i_dlm_mode is still EX (cached) and the SAME create thread proceeds to addname. Check ilock_begin: after a release (mode=NL), a re-acquire sets state=ACQUIRING; does i_dlm_mode get restored to EX BEFORE mxfs_dlm_lock confirms GRANTED? If the create reads i_dlm_mode=EX (stale) during ACQUIRING and the dir fast-path/demoter-belt serves it, it modifies with held=0.

### NEXT PROBE: instrument the read of mxfs_dlm_held_mode at the P51-PHANTOM site to also log the local entry's state (GRANTED/BLOCKED/absent), AND add a log at every ctx->buckets entry-remove/free for an inode resource owned by local_node (ino + caller + i_dlm-side state). Correlate with a phantom modify's realns. Then fix: ensure i_dlm_mode is demoted to NL atomically with ANY local-entry removal/downgrade, OR gate the dir modify on mxfs_dlm_held_mode>=EX (DLM = source of truth) + block entry removal while ex_holders>0.

Build DDC54A0E = baseline + gated P51 probes + P52-PARTIAL-GRANT (0-vol). Marker NOT written.
