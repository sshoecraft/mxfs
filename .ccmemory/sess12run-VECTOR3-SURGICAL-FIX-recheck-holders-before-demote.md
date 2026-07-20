---
name: sess12run-VECTOR3-SURGICAL-FIX-recheck-holders-before-demote
description: sess12(ccloop) vector-3 SURGICAL FIX: BAST checks i_dlm_ex_holders once at start, then drains+demotes without re-checking; a create acquires (holders…
metadata:
  type: project
---

## sess12 (ccloop) — vector-3 SURGICAL FIX (start here next session)

### The exact race (now fully pinned down)
- The create's `xfs_ilock(dp, ILOCK_EXCL)` goes through `mxfs_dlm_ilock_begin`, which on the cached fast-path does `ip->i_dlm_ex_holders++` (xfs_mxfs_dlm.c:10712-10713). So a dir modify DOES register as a holder.
- The peer-BAST defer-on-holders mechanism EXISTS: `i_dlm_ex_holders/pr_holders/i_dlm_pin_count > 0` → re-arm `i_dlm_bast_dwork` (msecs 4) and return WITHOUT releasing (xfs_mxfs_dlm.c:7194-7206, in the MHT dwork path; proven safe, "peer NOT stranded", bounded re-arm).
- BUG: the inode-BAST processing reads holders ONCE near the start, then runs the WHOLE drain loop + `mxfs_dlm_dir_inode_durable` (6431) + `mxfs_v5_dlm_inode_unlock` (7079) WITHOUT re-checking. The drain releases `ip->i_lock` (6372) between/after blocks. So a create that acquires the dir lock AFTER the BAST's initial holder-check but DURING the drain (PROVEN trace: BAST FLUSH-UNCACHED daddr=112 @433.579, create addname f15.md5→112 @433.580905) bumps holders too late to be seen → the BAST demotes EX out from under the in-flight create → the create's committed dirent is lost.

### SURGICAL FIX
In the inode-BAST processing function (the one ending at the 7079 `mxfs_v5_dlm_inode_unlock`), RIGHT BEFORE the final unlock/demote, RE-CHECK under `i_dlm_lock`: if `i_dlm_ex_holders > 0 || i_dlm_pr_holders > 0 || i_dlm_pin_count > 0`, a writer/holder raced in during the drain → DEFER: re-arm `i_dlm_bast_dwork` (reuse the 7200-style `queue_delayed_work(..., msecs_to_jiffies(4)+1)`) and RETURN WITHOUT unlocking (keep state CACHED + `i_dlm_bast_pending=true`). The drain already ran (harmless — it's a flush, idempotent); only the EX handoff is deferred until the create's `mxfs_dlm_ilock_end` drops holders to 0, at which point ilock_end / the dwork re-fires the BAST and finds holders==0 → demotes cleanly.

### Why safe (bounded, no deadlock, no resurrection)
- Bounded: the create completes in µs–ms; the re-arm polls every ~4ms. If a create is genuinely stuck (e.g. blocked on a peer AG = AG↔dir ABBA), the existing re-arm just keeps polling — to hard-bound it, cap consecutive re-arms (e.g. 250 ≈ 1s) and then proceed (today's behavior) so a pathological case can't strand the peer forever.
- No resurrection: the drain is a FLUSH (in-core→platter), not an evict (sess96 evict-on-release was refuted; this keeps the flush, only defers the unlock).
- This reuses the PROVEN sess124 MHT defer/re-arm infrastructure — low risk.

### Verify: `./run.sh 4 tcp` (esp. dir_reuse_coherency 0/4 → 4/4) + watch dmesg for DLM rc=-110 (peer stranded) and tcp_dlm_scaling (the EX-handoff-latency-sensitive test) for regressions. Confirm the create-side `mxfs_dlm_ilock_end` re-kicks the deferred BAST (grep where i_dlm_bast_pending is honored on holder-drop, ~xfs_inode.c:387 "decrement holders, process deferred BAST if last").

Build at relay = 40AC2A0C (2 backstop fixes, no regression). Criterion NOT met. See [[sess12run-BREAKTHROUGH-vector3-BAST-release-races-active-create]] [[sess12run-VECTOR3-precise-gap-ilock-released-before-flush-demote]].
</body>
