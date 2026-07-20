---
name: AAA-ccloopa864-sess4-orphan-fix-WORKS-then-AIL-flush-deadlock
description: sess4: mode=NL orphan wedge FIXED (wall-clock strand escape, build E5F760E6, KEEP) — validated, got r4-wedge→r8/r9. NEW deeper wedge: AIL flush deadl…
metadata:
  type: project
---

# sess4 (ccloop a864) — dir_reuse@32/caw: orphan wedge FIXED; deeper AIL-flush-deadlock exposed

## CRITERIA: only gap = dir_reuse_coherency@32/caw. criteria.json confirms 1/2/4/8/16 caw = 17 PASS each; 32/caw = 16 PASS (dir_reuse absent). Fix dir_reuse@32/caw → record PASS → DONE.

## FIX #1 (KEEP — validated, IN TREE build E5F760E6, VERSION 0.10.50)
**Root (PROVEN, RULE-4): the orphan_live 280-strike stranded-release escape NEVER converges on CAW.** `p_rel_gen = mxfs_v5_dlm_inode_grant_gen` → on CAW returns `mxfs_dlm_caw_grant_seq32` (v5_mount.c:1558), a LOCAL per-node counter bumped on every acquire/promote → churns under contention → the reset `orphan_gg != p_rel_gen` (xfs_mxfs_dlm.c ~11908) zeroes the strike counter every ~26ms dwork re-arm → 280 never reached. EVIDENCE: backoff logs = 0 P15H-STRANDED-RELEASE across 1748 P-ACQ-STUCK; node17 held dir ino131 EX on-disk while idle (ex=pr=pin=0), bast_process re-entered 2352x mode=NL/DEMOTING, single peer stalled 119.3s.
**Fix:** added WALL-CLOCK strand escape in the orphan_live block (xfs_mxfs_dlm.c ~11957), CAW-only (gated `mxfs_v5_dlm_transport_caw`; TCP keeps 280-strike since its grant_gen is a real per-episode token + TCP has a legit 6s unconsumed window). New field `i_dlm_orphan_since_ns` (xfs_inode.h:133, init at ~22373). New param `mxfs_caw_orphan_force_ms` default 3000 (xfs_mxfs_dlm.c ~10202). Reset since_ns on genuine consumption (ACQUIRING/mode!=NL) NOT gen churn. Fire → orphan_live=false + p15h_reap=true. Also added `!p15h_reap` to the gen_moved abort term (~11983) so the stranded release bypasses gen_moved (unlock_gen -ESTALE is the real double-EX guard). New probe P15H-STRAND-TIMEOUT.
**VALIDATED in repro (build E5F760E6, default modargs, /dev/mapper/mpatha):** P15H-STRAND-TIMEOUT fired 15+/node, P-ACQ-STUCK dropped from 1748/119s → few/≤55s early, **fail=0 (no readdir/leaf-hash loss)**, test progressed r1→r9 (previously wedged r4-r18 on the orphan). Fix WORKS for its target.

## FIX #2 NEEDED (the NEW wedge that stopped the r9 progress)
**AIL FLUSH DEADLOCK in rank1's rm-rf per-unlink durable signal.** At r8/r9, rank1 (`rm -rf .dir_reuse_coherency`, pid stuck D-state 302s) wedges the cluster. Peers starve (P-ACQ-STUCK el_ms→119s, hex=1=test1 holds EX, wex=0 all want PR for verify).
**Exact stuck stack (test1 rm):**
```
xfs_buf_iowait  <- inflight=0 (NOT transport; bio not in-flight / lost-wakeup or not-submitted)
xfs_bwrite
mxfs_dir_data_owner_scan+0x39d  (xfs_mxfs_dlm.c:1042, flush=true path)
mxfs_dir_flush_data_blocks+0xa5
mxfs_dlm_dir_durable_signal+0x136   <- per-unlink durability signal in xfs_remove
xfs_remove+0x416 → xfs_vn_unlink → do_unlinkat
```
**Corroborating:** ALL mxfs-ino-bast kworkers stuck D-state in `xfs_ail_push_upto_sync_b` (sync AIL push). `P91-BAST-PROTECT` firing repeatedly for a CONTIGUOUS inode range (0x1c0078f..0x1c00796) all sharing inode-cluster buffer blkno=0x1bf30b0 flags=0x20(XBF_DONE) pin=0 li_empty=0 — "keeping in-core authoritative cluster buffer (would-be iflush-strand averted)". So the inode-cluster buffer of the files being rm'd is stuck in the AIL (FLUSHING, never destaged), and the rm's sync dir-data bwrite + all bast AIL-pushes wait on it forever. = the CLAUDE.md `_XBF_DELWRI_Q` collision / IFLUSHING-in-AIL design tension. NOT in prior backoff logs (0 dir_data_owner_scan hangs) — my orphan fix EXPOSED it by progressing past the orphan wedge.

## NEXT SESSION PLAN (RULE 4)
1. Cluster left wedged (test1 rm D-state, bast kworkers D-state) — run.sh prep power-cycles them, no manual reset needed. Lock free.
2. Read mxfs_dir_data_owner_scan (xfs_mxfs_dlm.c:1042) + mxfs_dir_flush_data_blocks + mxfs_dlm_dir_durable_signal. The xfs_bwrite at owner_scan+0x39d hangs with inflight=0 → the buffer is likely already _XBF_DELWRI_Q-owned by xfsaild (collision) OR completion woke the wrong waiter. Check how owner_scan handles a buffer already in delwri/AIL — likely must NOT sync-bwrite a delwri-queued buf (let xfsaild destage) or must force the inode-cluster buffer out of FLUSHING.
3. Related prior fixes: sess40 "dir-block ABA writeback skip" (build B9F9326E), P38-POSTREL-ZOMBIE, P91-BAST-PROTECT. The P91 guard keeps the cluster buf authoritative but nothing forces its eventual destage → AIL jam. May need: force-destage the protected cluster buffer after N strikes, OR make the per-unlink durable signal not sync-bwrite under this condition.
4. Consider: is the per-unlink durable signal (mxfs_dlm_dir_durable_signal on EVERY unlink) necessary, or can rm-rf batch it? 800 sync flushes/rm-rf under 32-node contention is the trigger.
5. Build, redeploy, rerun: nohup MXFS_DEV=/dev/mapper/mpatha ./run.sh 32 caw dir_reuse_coherency. Watch tests/drc_progress_watch.sh (new this sess, OUT=scratchpad/progress.log): tracks round + P15H-STRAND-TIMEOUT + P-ACQ-STUCK el_ms per 60s across 6 sample nodes. PASS = 24 rounds, fail=0, no barrier >120s.

## Diagnostic assets (new this sess): tests/drc_progress_watch.sh. Repro log scratchpad/repro.log. Orphan-fix evidence in scratchpad/progress.log (r1-r9, strand firing).
