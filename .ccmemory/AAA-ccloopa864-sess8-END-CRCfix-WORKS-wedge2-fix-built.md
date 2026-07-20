---
name: AAA-ccloopa864-sess8-END-CRCfix-WORKS-wedge2-fix-built
description: sess8 END: 0.10.57 CRC-reread-retry fix WORKS (round5 shutdown→RETRY-OK, 0 shutdowns). Then hit pre-existing wedge#2 (rm lost-wakeup) at round7. Fixe…
metadata:
  type: project
---

## sess8 (ccloop a864) END — dir_reuse@32/caw: CRC fix VALIDATED, wedge#2 fix built, needs test

### PROGRESS THIS SESSION (two layered bugs, both now addressed):

**BUG 1 (round-5 shutdown) — FIXED & VALIDATED (0.10.57, build 78970C3C):** transient torn coherent-read of a rapidly-rewritten shared dir bmbt/dir3 block across a fast EX handoff (multipath/SCST cache lag). Reader cold-reads before the image settles → EFSBADCRC → xfs_trans_cancel → shutdown. FIX = bounded coherent re-read retry in `_xfs_buf_read` (pal/linux/xfs_buf.c) for multi-node dir metadata that fails read-verify CRC (`mxfs_buf_is_multinode_dir_meta` + `mxfs_buf_coherent_reread_verify`; params dir_read_crc_retries=8, dir_read_crc_retry_us=4000). **PROVEN WORKING**: test at round5 logged `P-DIRCRC-RETRY try=1 err=0` → `P-DIRCRC-RETRY-OK (transient torn read settled)`, **0 shutdowns, 0 xfs_trans_cancel** — the round that shut the FS down in 0.10.56 now passes. Test progressed r1→r7 cleanly. KEEP this fix.

**BUG 2 (wedge#2, surfaced at round-7 once BUG1 unblocked progress) — FIX BUILT, UNTESTED (0.10.58):** rank1 `rm` hangs D-state in `xfs_buf_iowait` under `mxfs_dir_data_owner_scan → xfs_bwrite` (per-unlink durable-signal flush of a dir3_data block). PRE-EXISTING lost-wakeup (sess5/sess6 wedge#2). P-IOWAIT-STUCK showed **sync_wait=0 ioend_seen=2 done=0**: a lock-free XBF_ASYNC set (buf-item unpin on another CPU) lands between `xfs_bwrite` clearing XBF_ASYNC and `xfs_buf_submit`'s `b_mxfs_sync_wait = !(XBF_ASYNC)` snapshot (line ~5667) → snapshot latches 0 → completion takes the async/relse branch (xfs_buf_ioend 1920) → never `complete(&b_iowait)` → sync bwrite waiter hangs forever. sess6's override (xfs_buf_ioend 1909: `XBF_ASYNC && b_mxfs_sync_wait → complete()`) can't fire because sync_wait=0. FIX (0.10.58) = new field `b_mxfs_force_sync` (xfs/xfs_buf.h ~257): sync submitters (`xfs_bwrite`, `_xfs_buf_read`) set it under b_sema BEFORE xfs_buf_submit (immune to the XBF_ASYNC race); xfs_buf_submit ORs it into b_mxfs_sync_wait, consumes it, and gates the completion reinit on the result. 4 edits: xfs_buf.h field, xfs_bwrite, _xfs_buf_read, xfs_buf_submit snapshot.

### NEXT SESSION (do this):
1. Confirm build58 OK: `tail /tmp/.../scratchpad/build58.log` (BUILD_EXIT=0 + new srcversion). If not built, `cd /src/mxfs && make modules`.
2. Ensure cluster clean (run=0, lock GONE): `pkill -9 -f 'run[.]sh 32 caw'; fuser -k -9 /tmp/mxfs_run.lock; rm -f /tmp/mxfs_run.lock`.
3. TEST: `env MXFS_DEV=/dev/mapper/mpatha MXFS_TEST_ENV='DRC_STREAM=1' timeout 1800 ./run.sh 32 caw dir_reuse_coherency`. Streams → tests/tcp/drc_cap/stream_rank${R}.log (persistent). Watch: `P-DIRCRC-RETRY-OK` (BUG1 fix recovering, expected+good), NO `P-IOWAIT-STUCK` (BUG2 fixed), NO `Shutting down`, run completes 32/32. Failure was deterministic ~round5-7; prep≈110s + ~65s/round → ~25min full 24-round run. WALL-CLOCK realns is truth (per-node dmesg clocks unsynchronized!).
4. If wedge#2 persists (P-IOWAIT-STUCK still): the force_sync latch missed a path — consider a bounded-wait ESCAPE in xfs_buf_iowait (break when ioend_seen>0 = I/O done, wakeup lost) BUT beware double-relse (async branch already relse'd); or find the other XBF_ASYNC setter.
5. On clean PASS: run 2-3 MORE times (race-condition fixes need repetition to claim 100%), confirm criteria.json dir_reuse_coherency 32/caw = PASS, then the caw matrix is 100% (all other 1/2/4/8/16/32 caw cells already PASS; tcp_dlm_scaling caw n/a). THEN write YES.

### Builds: 0.10.57=78970C3C (BUG1 fix, KEEP), 0.10.58=BUG2 fix (building). All diagnostic probes KEEP.
