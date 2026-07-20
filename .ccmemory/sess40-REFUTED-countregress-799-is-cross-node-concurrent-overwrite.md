---
name: sess40-REFUTED-countregress-799-is-cross-node-concurrent-overwrite
description: sess40: P-COUNTREGRESS detector (per-buffer dir-data count high-water) did NOT fire on the 799 loss → it's a CROSS-NODE concurrent overwrite (each no…
metadata:
  type: project
---

## sess40 (ccloop) — REFUTED the per-node count-regression theory for readdir=799.

### What was added (build `B17141DA` = `A985424B` + detector; instrumentation only, default-on, no behavior change)
`P-COUNTREGRESS` at `xfs_buf_submit_bio` (pal/linux/xfs_buf.c): for a multi-node dir DATA/block WRITE, compute the active-dirent count via `mxfs_dir3_data_fingerprint` and compare to `bp->b_mxfs_dir_wrcnt_max` (new xfs_buf field = high-water count this buffer has ever written; reset on `xfs_buf_stale`). Fires when a write's count is BELOW the buffer's own high-water = this node destaged a block image that LOST entries it previously held (a stale-base RMW), which dataclobber's disk-superset compare misses. Logs comm/real_mode/in_txn/in_ail.

### RESULT: P-COUNTREGRESS did NOT fire on a failing 8/tcp iter (round 20, readdir=785, all nodes agree, NO flap, NO dataclobber, NO relverify). 
So the loss is NOT a per-node count regression — each node's dir-data buffer is internally consistent (monotonic count). The lost entry was added by a PEER and this node's buffer simply NEVER held it; this node writes its own (consistent) block image and overwrites the peer's entry. This is a **CROSS-NODE concurrent / overlapping dir-block write**: two nodes write the same data block, each consistent with disk-at-its-own-submit, net loses one entry. dataclobber is blind (at each submit, disk also lacked the other's entry — the writes interleave). The only ways two nodes write the same dir block:
1. **DOUBLE-GRANT** (both hold EX simultaneously) — but membership is stable (no flap) so the single-master `mxfs_dlm_audit_double_grant` (dlm.c:601, logs `MX-DOUBLEGRANT`) should catch it IF the master granted two conflicting holders. Cross-master double-grant (divergent active_nodes) would NOT be caught by the single-master audit.
2. **Async-writeback overlap across the EX handoff**: node A releases EX with a dir-data block write still queued/in-flight in xfsaild (the release fence's `mxfs_dir_buf_is_undestaged` lseq==wseq check is unreliable, OR the acquire-evict SKIPS a block locked by in-flight I/O); B acquires, cold-reads (misses A's entry), writes; A's late write and B's write interleave → one entry lost. No double-grant, serialization "correct" at the lock layer but writeback crosses the boundary.

### DECISIVE NEXT CAPTURE (running): drc_cap8 with `MX-DOUBLEGRANT` + `P-STALEMASTER-GRANT` in the grep.
- If MX-DOUBLEGRANT or P-STALEMASTER fires at the 799 loss → master/mastership serialization break → fix the grant/promote path (promote_waiters dlm.c:659, or the membership/master computation).
- If BOTH silent → serialization is intact → the loss is async-writeback overlap (release-drain gap). Then attack: (a) make `mxfs_dir_buf_is_undestaged` reliable / the release fence wait for actual bio completion of dir-data blocks (NOT the refuted mount-wide `dir_wr_barrier` — needs per-dir-inode in-flight tracking so it actually has something to wait for), and (b) the acquire-evict-skip (mxfs_dir_drain_evict_data_blocks LOCKED-SKIP) — abort/wait the in-flight write before evict.

Refutes/supersedes the per-buffer angle. Builds on [[sess40-CORRECTION-799-is-concurrent-add-not-flap-bmbt-extent-fork]]. Keeper still `A985424B`; B17141DA adds only the (harmless) detector.
