---
name: AAA-ccloop46ef-sess1-FOUR-FIXES-scoreboard
description: sess1(46efd8b6) END: build 30E6BF7F (sliding-grace floor) UNTESTED. cache_coh+crash_cons@32 PASSed on earlier builds; floor@300ms strands slots — det…
metadata:
  type: project
---

# ccloop 46efd8b6 sess1 END-OF-SESSION STATE (v0.10.1)

## BUILD LADDER (srcversions)
- 87E860C4: evict_ring_monotonic + iread_pr.
- DDB9E83B: + dscan_gen_gate → **cache_coherency@32 PASS 32/32** (run 20260710T003324Z).
- 0BD98E9E: + dir_ex_tenure_floor(300ms window) → **crash_consistency@32 PASS 32/32** (run 20260710T010044Z) BUT **REGRESSED cache_coherency@32 + dlm_scaling@32 to 0/32** (run 20260710T011521Z).
- **30E6BF7F (current, BUILT, NOT DEPLOYED/TESTED)**: floor converted to SLIDING GRACE — mxfs_dir_ex_batch_grace_ms=25: each op-end keeps the dir-EX only min(25ms, window-remaining); back-to-back writers batch, one-op-then-barrier phases hand off in ~25ms.

## WHY 0BD98E9E REGRESSED (RULE-4 measured)
Full-window floor let 31 waiters pile on the hot slot per tenure → grant/abort churn → PRE-EXISTING orphan-live release-abort loop (P15-REL-ABORT held_mode=0 orph=1, 27-52/node) → terminal STRANDED on-disk EX: slot ino=39846021 (= .cache_coherency/rename_visibility subdir; winner test4 P127-EEXIST-LOSER on others) showed gm=5 holder-bit 25 (likely test26) with NO in-core holder (all nodes P-DIRBAST state=0 mode=0) → every node mode=5 rc=-110 in 120s waves ×3 → both tests ate their budgets. test26 had P141-UNLK-EXCLR SUCCESS at 01:17:57 then re-grant ~gen 494 stranded. The orphan-strike escalation (sess15 FIX-H2) did NOT terminate the strand.

## NEXT SESSION — IMMEDIATE STEPS
1. Fresh prep + run trio on 30E6BF7F: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="caw_fair_handoff=1" timeout 945 ./run.sh 32 caw cache_coherency crash_consistency dlm_scaling` (foreground; NO `| tail` if you want interim output). Expect all 3 PASS if grace bounds the waiter churn.
2. If strand recurs (P15 orph=1 loops + rc=-110 waves on one ino): root-fix the orphan/strand: bast_process abort path for orph=1 must eventually FORCE-CLEAR our slot holder bit (in-core NL + disk-held is OUR bit to clear; bounded strikes exist: i_dlm_orphan_gg/strikes, sess15 FIX-H2 comment near xfs_mxfs_dlm.c:11290; P141-UNLK machinery does the CAS). Alternative fallback: dir_ex_tenure_floor=0 (loses crash_consistency batching — then crash_consistency needs another approach).
3. Then dir_reuse@16 (budget auto 140*16=2240s) + dir_reuse@32 (4480s) — bash timeout must exceed (use run_in_background, watch output file WITHOUT tail-pipe).
4. Then FULL-LADDER on the FINAL build: all criteria.json PASSes for 32/caw + 16/caw + spot 1/2/4/8 were recorded on OLDER builds — for an honest 100% re-run FULL suites per node count on the final build: `./run.sh N caw` (no test args = all applicable). ~17 tests each.
5. All green → echo YES > /src/mxfs/.ccloop/runs/46efd8b6-3dd3-477c-b004-14362c80d8e8/criteria-met

## FIX INVENTORY (all param-gated default-ON, in tree, uncommitted)
1. evict_ring_monotonic — dlm/disklock.c consume guard + evict_seen reset at fire_dead; param in dlm/v5_mount.c. Kills stale-HB DIR_MODIFY/INODE_FREE replay (was ~6 spurious dir_gen bumps+reloads/s during pure reads).
2. iread_pr — XFS_ILOCK_MXFS_PRIREAD (1u<<6, xfs_inode.h) set by xfs_ilock_data_map_shared/attr_map_shared; xfs_ilock/xfs_iunlock map it to cluster PR (local EXCL kept). Killed 12-node EX-starvation FS shutdowns in read-only verify.
3. dscan_gen_gate — i_mxfs_dscan_clean_key (~0 init in mxfs_dlm_inode_init; reset at real adopt in reload; stamped at P26-DSCAN-MISS tail). Was 459 read-IOs/112ms per neg lookup.
4. dir_ex_tenure_floor + dir_ex_batch_grace_ms=25 — mxfs_dlm_dir_tenure_keep_delay (all dir formats) called from ilock_end deferred-BAST gate (BAST-state arm reverts to CACHED+bpend + dwork) and mxfs_inode_unpin (both arms). Dwork protocol (mxfs_dlm_bast_dwork_fn) releases at first quiescent sample post-expiry, 4ms busy re-arm.

## KEY DIAG RECIPES
- Marker harvest: scripts/rv_marker_harvest.sh N "<UTC since>" [ino].
- Slot dump (fresh): ssh test1 'dd if=/dev/mapper/mpatha of=/tmp/s.bin bs=1M iflag=direct,skip_bytes skip=67149824 count=32; python3 /src/mxfs/scripts/caw_slot_dump.py /tmp/s.bin --offset 0 --ino INO'.
- P70-BP qsrc: 1=ilock_end_refire 3=notify_idle 5=notify_immediate 7=acq_selfbast 9=mht_arm 12=sf_tenure_arm 14=?(11290 site, check).
- P138-WAIT logs at WAITER w/ elapsed; mode 3=PR 5=EX. P15-REL-ABORT orph=1 = in-core NL + disk-held (abort loop).
- Test structure: cache_coherency = cv+cwr+rv+uv in tests/suite/cache_coherency.sh; rv dir = 640 files; budgets: run.sh TEST_TIMEOUT=300 default, dir_reuse caw=140*N.

## Scoreboard (criteria.json, runs on MIXED builds — needs final-build re-sweep)
1/2/4/8 caw 17/17 (old builds); 16 caw 16/17 (dir_reuse unrun); 32 caw: precond+cache_coh(DDB9E83B)+crash_cons(0BD98E9E)+13 others PASS on older builds; dlm_scaling FAIL(0BD98E9E strand)+dir_reuse unrun.
