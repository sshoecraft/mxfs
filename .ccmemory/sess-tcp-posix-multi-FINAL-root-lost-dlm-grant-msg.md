---
name: sess-tcp-posix-multi-FINAL-root-lost-dlm-grant-msg
description: FINAL ROOT (proven, frozen stacks): posix_multi/cache_coherency 2-node TCP stall = intermittent LOST DLM grant/release msg on contended dir-EX → requ…
metadata:
  type: project
---

## FINAL ROOT (build 23E19A81, RULE 4, frozen-stack proven) — supersedes ifree-drain theory
The 2-node TCP posix_multi / cache_coherency failure is a ~60s stall on a SINGLE create
(per-create timing: test1 all 100 creates <5ms; test2 create#1 or #9 = 62-63s, rest fast).
Frozen capture (tests/catch_create_stall.sh) at the stall:
- REQUESTER (test2): blocked in `pending_wait` -> dlm_lock_impl -> mxfs_dlm_lock ->
  mxfs_v5_dlm_inode_lock -> mxfs_dlm_ilock_begin -> xfs_ilock -> xfs_create. Waiting for the
  DIR inode EX (mode=5).
- HOLDER (test1): COMPLETELY IDLE — no blocked task, no bast_work kworker, nothing logged.
  Burst finished in ~590ms. Holds dir-EX cached, does NOT hand it off for ~60s.
- Always-on `P-DIRBAST` (added this session) shows the holder DOES receive the BAST
  (state=1 CACHED, mode=5, ex=0 pr=0 pin=0 -> "immediate" branch -> queue bast_work) and DOES
  release (later P-DIRBAST state=4 mode=0). So the BAST is delivered and the holder releases.
=> The lost link is the GRANT/RELEASE NOTIFICATION back to the waiter. dlm.c send_grant
   "retries once after 10ms on failure; if the retry also fails, the requesting node's
   pending_wait will timeout and retry" (dlm.c:566). An intermittently dropped/delayed TCP
   grant or release message leaves the waiter's pending entry unsignaled for the full 60s
   MXFS_LOCK_WAIT_TIMEOUT_MS (include/mxfs/mxfs_dlm.h:235). Intermittent => most handoffs fast,
   occasional one drops => the flaky 60s stall -> barrier desync -> posix_multi/cache_coherency FAIL.

## KEY GAP: mxfs_dlm_lock does NOT retry on -ETIMEDOUT (dlm.c:1163-1188)
The retry loop re-requests only on MXFS_DLM_RETRY and -ENOTCONN/-EPIPE/-ECONNRESET. On
-ETIMEDOUT it returns the error (-> "DLM inode lock failed rc=-110" -> create fails / upper
layer re-attempts at ~60s). So a lost grant is NOT promptly recovered by the DLM layer.

## CANDIDATE FIXES (next session — pick, implement, verify with tests/repro_burst_timed.sh:
   test2 create#N must drop from ~62s to <1-2s, then posix_multi PASS 2/2)
1. RECOVERY (lower risk): a master-side WATCHDOG / re-drive — periodically (every ~1-2s)
   re-run promote_waiters + re-send_grant / re-fire BAST for pending entries older than a few
   seconds, so a lost grant/release is recovered in ~1-2s instead of 60s. This is the robust
   fix for unreliable msg delivery without masking.
2. CHEAPER: add -ETIMEDOUT to the mxfs_dlm_lock retry set AND cut MXFS_LOCK_WAIT_TIMEOUT_MS
   from 60000 to ~15-20s (healthy handoff <1s; release-fence drain cap is 30s so don't go too
   low). A fresh post-timeout request re-fires the BAST and recovers the lost grant. Band-aid
   (RULE 0 / user dislikes timeout widening) but turns 60s -> ~15s; combine with #1 ideally.
3. BEST: find why the grant/release TCP msg drops — instrument send_grant / the LOCK_GRANT &
   LOCK_RELEASE send+recv paths (mxfs_peer_recv_fn / dlm message handlers) for the dir resource;
   add seq/ack or a resend. Check master assignment for ino=132 (which node is master changes
   the grant path: local-master promote_waiters+pending_signal vs remote-master send_grant).

## CODE CHANGES MADE THIS SESSION (build 23E19A81, deployed both nodes — SAFE, INSUFFICIENT alone)
- xfs_mxfs_dlm.c: bounded the xfs_ifree inactivation drain (new mxfs_ail_drain_inode_sync_bounded
  + module param `ifree_drain_ms`=200, used at xfs_inode.c ifree site). Stops the 62s ifree-drain
  AG-holder starvation in the CONTAMINATED (rm-rf recycled inodes) case. Cross-node dinode
  durability still guaranteed by the BAST drain pipeline. Was chasing a contamination artifact;
  fresh-format stall has NO ifree -> this alone doesn't fix posix_multi. KEEP (correct).
- xfs_mxfs_dlm.c bast_notify: NONE_mode_held branch now releases idle cached holders
  (ex=0/pr=0/pin=0) via DEMOTING+bast_work instead of dead-deferring (was "no holders to fire
  it!"). Real bug fix but NOT the dir path (dir hits state=1 CACHED immediate branch). KEEP.
- xfs_mxfs_dlm.c: always-on `P-DIRBAST` diagnostic (S_ISDIR BAST state/mode/holders) +
  `P-NONE-HELD-IDLE-RELEASE`/`P-NONE-HELD-DEFER` logs. Keep for next session's tracing.
- mht=3000 REFUTED (reset to 50). ifree-drain bound REFUTED for fresh case.

## Tooling (tests/): repro_burst_timed.sh (per-create ms — THE decisive tool), catch_create_stall.sh
(freeze stacks+dmesg mid-stall), catch_hang.sh, repro_pm_timed.sh, repro_pm_loop.sh, stall_catch.sh.
Reset: tests/setup/reset2_tcp.sh. A wedge can D-state umount in xfs_buftarg_drain -> virsh
destroy+start ([[reference-node-power-control]]). Current build src 23E19A81 on test1+test2.
Criterion NOT met. See [[sess-tcp-posix-multi-root-ifree-drain-wedge-holds-AG]] (earlier, partial).
</body>
