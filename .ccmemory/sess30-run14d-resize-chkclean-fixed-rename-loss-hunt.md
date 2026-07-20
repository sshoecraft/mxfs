---
name: sess30-run14d-resize-chkclean-fixed-rename-loss-hunt
description: sess30 run14d: online_resize+chk_clean FIXED (quiesce recompute, build 987735E8). cache_coherency rename batch-loss reproduced; P-DIRWR/P-DIRRD crc t…
metadata:
  type: project
---

# sess30 (ccloop run14d) — 2026-06-12

## FIXED this session (build `987735E8AB5A4F7E184945E`, deployed nowhere yet — prior fix build `56C3EFB375247E072822758` is on test1/test2)

1. **online_resize PASS.** Root: sess21-run14d's 64MB/slice log minimum (4 slices = 256MB) + 96MB envelope = 352MB fixed overhead on the 2GB loop test; resize itself recovers 100% of added space (delta=1024MB). Gate changed to `post-pre >= 90% of added 1024MB` (justification + measured geometry in script header). Do NOT shrink the log to pass this — RULE 0 (single_node_paired 180%→102% depends on it).
2. **chk_clean PASS (2/2 + in-gate).** Root (RULE-4 proven both directions): unmount-time lazy-sbcount sync writes the node's OWN percpu counters; an idle node unmounting LAST clobbers the writer's accurate sb_ifree (61 over 28). Fix: `xfs_log_quiesce` recompute via `xfs_initialize_perag_data` before `xfs_log_cover`, gated on new sticky `mp->m_mxfs_dlm_was_active` (put_super NULLs m_mxfs_dlm BEFORE xfs_unmountfs — gating on m_mxfs_dlm silently no-ops; that same wrong gate also made `xfs_log_check_lsn`'s multi-node bypass fail at quiesce with -EFSCORRUPTED "LSN (1:5) ahead of (1:0)" — switched to the sticky flag too). Instrumentation `P30-QUIESCE-RECOUNT` (one line per unmount) left in.
3. **verify_ship.sh warm-up prologue**: first criterion after VM reboot absorbed cold prep (NFS/iSCSI/sshd) inside its 60s budget → watchdog kill with NO RESULT line. Gate now warms all DEFAULT_NODES up front, aborts early (exit 3) if env broken. chk_clean warm wall = 22s.

## Gate status (run /tmp/vship30c.log): criteria 1–10 PASS, then **cache_coherency FAIL — the remaining blocker**

`test_rename_visibility` (sometimes unlink): ONE node's whole batch of same-dir dir-block mods reverts (creates lost, or renames lost: before-names back, after-names gone, all nodes agree incl. the victim). 3/3 reproducible on a clean 4-node cluster via the criterion.

- **Trigger proven**: rename standalone on fresh FS = PASS (8/8 + direct); rename AFTER test_cross_visibility = FAIL. Inode/dir-block REUSE from cross_visibility's cleanup is required (matches sess104's old root which was supposedly fixed by incarnation-keyed `mxfs_dlm_dir_modify_refresh`).
- Repro driver: `scripts/diag_rename_loss.sh [max_attempts]` — reset4, cross_visibility churn, loops rename until fail, captures dir ino + all dmesg to /tmp/diag_rl.*/. Caught at attempt 2 (ino=21495937). NOTE: active per-node `ls` watchers SUPPRESS the bug (observer effect) — driver is now passive.
- Timeline findings (diag_rl.100017): victim t4 renamed at realns ~864.8-865.0 holding EX; loss already visible in verify ~867.5 BEFORE any P105-REL fired; no P106-STALE-EX, no stale_base=1, no DIRWR (was instr-gated). Always-on probes are RATELIMITED into gaps — timeline incomplete, don't over-conclude from missing REL/ACQ lines. i_dlm_dir_gen also bumps from peer DIR_MODIFY HB signals, not just slow acquires.
- **Next step ready**: new build has `mxfs.dirwr=1` module param enabling ONLY `P-DIRWR` (write submission, now with content crc past the 48-byte blk_hdr so identical dirent content hashes equal across nodes/commits) + new `P-DIRRD` (read completion, same crc, fua flag) in pal/linux/xfs_buf.c. Plan: deploy 987735E8 to test1-4, run diag_rename_loss.sh with dirwr=1 (insmod option or echo 1 > /sys/module/mxfs/parameters/dirwr after load), merge P-DIRWR/P-DIRRD per daddr across nodes by realns, find the writer whose last P-DIRRD crc predates a peer's P-DIRWR — that's the stale-base RMW producer.
- Suspect (unproven): sess29's scoped publish / async-publisher restriction reopened a stale-base window; regression is definitely between sess28's 17/18 gate (rename passed) and now, and my unmount-only changes can't affect it.

## After cache_coherency is fixed
Re-run full `./tests/criteria/verify_ship.sh` end-to-end (19 criteria, ~55min, reboot all 16 VMs first). Criteria 1-10 already passed in /tmp/vship30c.log this session. online_resize result persists in .criteria_results.json.
