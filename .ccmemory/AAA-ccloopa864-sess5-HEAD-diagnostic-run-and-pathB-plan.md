---
name: AAA-ccloopa864-sess5-HEAD-diagnostic-run-and-pathB-plan
description: sess5 HEAD: only criteria gap=dir_reuse@32/caw. Diagnostic run (durable_caw=0+fair_handoff=1) LIVE. Real fix=Path B (fair_handoff=1 default + fix AIL…
metadata:
  type: project
---

# sess5 (ccloop a864) HEAD — dir_reuse@32/caw: diagnostic run live, Path-B plan mapped

## CRITERIA STATE (verified this sess via criteria.json)
Full caw matrix 1/2/4/8/16/32 is PASS **except one cell**: `dir_reuse_coherency @ 32/caw` (absent = never passed). Everything else passes. Fix that ONE cell (in the DEFAULT build, legitimately) → criteria met.
- jq matrix confirmed: dir_reuse PASS at 2/4/8/16 caw; 32/caw has no entry.
- Build in tree: E5F760E6 (VERSION 0.10.50) = orphan wall-clock strand escape (wedge#1 fix). KEEP.
- Device = /dev/mapper/mpatha (the "multipath" in the criteria; 2 paths sda+sdb). MUST pass MXFS_DEV=/dev/mapper/mpatha (run.sh defaults /dev/sda).
- Per-test budget: dir_reuse@caw = 140*N = **4480s** at 32 (run.sh ~line 395). A timeout=FAIL.

## LIVE DIAGNOSTIC RUN (this sess)
`MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS='dirop_durable_caw=0 caw_fair_handoff=1' ./run.sh 32 caw dir_reuse_coherency`
(nohup, timeout 5600, log scratchpad/run_combined.log; monitor scratchpad/progress_combined.log). Prep OK all 32 @ E5F760E6. Cleared stale dmesg on 6 sample nodes (test1/8/16/17/24/32) so round/el_ms readings are real-run-only. Progressing r1→r2, stalls 0-23s. Monitor task b9mdl0721 emits per-round + terminal.

## THREE WEDGES (from sess4, all RULE-4 proven)
1. mode=NL orphan — FIXED in E5F760E6 (KEEP).
2. **durable-signal AIL-flush HANG** (wedge#2): rank1 rm-rf → per-unlink mxfs_dlm_dir_durable_signal (xfs_inode.c:2195) → mxfs_dir_flush_data_blocks → mxfs_dir_data_owner_scan(ip,true) → **xfs_bwrite(dir-data bp) HANGS** (xfs_mxfs_dlm.c:1135, inflight=0). Root: the inode-cluster buffer of the rm'd files is stuck FLUSHING-in-AIL because **P91-BAST-PROTECT** (xfs_mxfs_dlm.c:11550) SKIPS staling it when mxfs_buf_has_uncheckpointed_mods (xfs_mxfs_dlm.c:22515) — keeps it in-core authoritative but nothing destages it → AIL jam → log can't unpin → the async xfs_log_force(mp,0) at line 1134 never completes → bwrite waits forever. bast kworkers stuck in xfs_ail_push_upto_sync_b. = CLAUDE.md _XBF_DELWRI_Q collision (buf has _XBF_DELWRI_Q but not _XBF_MXFS_ALLOC_QUEUED → xfsaild delwri-queue returns false → items XFS_ITEM_FLUSHING forever).
3. acquire STARVATION (wedge#3): EX waiter starves under free-for-all CAS. Fix = caw_fair_handoff=1 (dlm_caw.c:1655/3129, inode-only, honors yield_to ticket, 5s stale-clear safety valve). Defaults OFF (dlm_caw.c:88).

## THE REAL FIX = Path B (safe, RULE-4, keeps coherency)
Do NOT ship durable_caw=0 default: run.sh budget comment documents durable_caw=0 durably LOST a dirent at r17/8-node (per-op FUA platter publish is load-bearing for CAW coherency). The diagnostic run only confirms fair_handoff fixes #3 and the durable signal causes #2.
1. **caw_fair_handoff=1 DEFAULT** (dlm_caw.c:88 `int mxfs_caw_fair_handoff;` → `= 1`). Needed regardless. Safe (stale-clear valve).
2. **Fix the AIL-jam** so the per-unlink durable signal doesn't hang, KEEPING durable_caw=1. Per RULE 4: INSTRUMENT first (pre-bwrite probe at owner_scan ~1135: daddr, b_flags, pin, bli li_flags incl FLUSHING, _XBF_MXFS_ALLOC_QUEUED; + why P91-protected cluster buf never destages). Candidate fixes: force-destage the P91-protected cluster buffer after N strikes / via mxfs drain pipeline; OR SYNC log force before the bwrite; OR make owner_scan skip the sync-bwrite when the buf is jammed and let the release-drain handle it. Pick after instrumented proof.
3. Rebuild (rev VERSION), plain `./run.sh 32 caw dir_reuse_coherency` (NO modargs) → must PASS. Then spot-check dir_reuse at 2/4/8/16 caw (esp. 8 for the r17 loss) + a coherency-sensitive test, to confirm no regression from the new defaults.

## Run mechanics / gotchas
- NEVER rebuild mxfs.ko while a run is active (mid-run node reboot re-insmods → contaminates). 
- After a kill: fuser /tmp/mxfs_run.lock; pkill run.sh + per-node dir_reuse_coherency; SSH-dead nodes recover via virsh destroy+start (iscsi+mpath auto-up ~12-18s).
- Monitor stale-dmesg trap: drc_progress_watch reads dmesg `tail -1`; prep power-cycles only SOME nodes so others carry prior-run DRCph/el_ms → clear dmesg on sample nodes after prep for clean readings.
- 32 nodes all alive at sess start.
