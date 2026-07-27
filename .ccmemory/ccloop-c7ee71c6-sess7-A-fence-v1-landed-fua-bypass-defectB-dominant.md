---
name: ccloop-c7ee71c6-sess7-A-fence-v1-landed-fua-bypass-defectB-dominant
description: sess7: FENCE-V1 landed (P123 suppress works, platter fscks CLEAN after CC); FUA-bypass found+gated (b_mxfs_fence_skipped); CC FAIL now = Defect B rea…
metadata:
  type: project
tags: [fence, P123, dircrc, fua-bypass, defect-b, crash_consistency]
---

# sess7 part A — fence v1 landed, FUA bypass closed, Defect B now dominant

## Landed (v0.11.95→97, srcver F2386B015ACF3973B78E1D7)
1. **FENCE-V1** per sess6-D blueprint:
   - Task registry `mxfs_dirdrain_{enter,exit,set_mode}` + `mxfs_task_in_dir_drain()` in xfs_mxfs_dlm.c (~:11334, before bast_process). All 6 bast_process call sites bracketed; set_mode(p_held_mode) stamped at bast entry. **v1.1: sanction is ATTRIBUTION-ONLY** (in_drain never allows) — measured 0 in_drain=1 sub-EX events; P97 relfence loop orders publication before unlock, so sub-EX drain writes are definitionally republishes.
   - Submit fence in xfs_buf.c after the P122 block (~:8213): 6 dir ops (block/data/leaf1/leafn/free/danode), owner from block header → `mxfs_v5_dlm_inode_granted_mode` < EX → if no log obligation (!bli-dirty, !IN_AIL, !pinned) → **suppress**: stale+~DONE (bli-free only) + ioerror(0)+ioend+return (wseq stamps at ioend → data_durable converges). Obligated → allow + P-FENCE-AILLEAK census (0 hits so far). P123-DIRFENCE-SKIP print + capped 5 dump_stacks.
2. **FUA bypass closed**: `mxfs_dir_release_fua_write=1` (default ON) FUA-writes b_addr raw AFTER werr==0 — suppressed bios' stale bytes still hit the platter via SCSI passthrough (run-185647Z leaf1@290@PR "crime" landed THIS way; P21F fires on suppressed werr==0 too). Added `bp->b_mxfs_fence_skipped` (xfs_buf.h, cleared at fence pass, set at suppress) gating the FUA arm (xfs_mxfs_dlm.c:4122). Audited: only flush_one_daddr FUA-writes DIR blocks (8874=inode surgical, 8976=bmbt, ialloc=cluster-init).

## Measured (CC@8/tcp, fresh mkfs each run)
- sess6 baseline: 28-109 CRC/node, 5/8 shutdown cascade, LUN durably corrupted.
- v0.11.95 run 185647Z: 2 CRC (transient) + 18 EUCLEAN, 0 shutdowns, **quiesced LUN chk_mxfs CLEAN**. 135 P123.
- v0.11.96 run 190758Z: NO_TERMINAL_RECORD ×8 — NOT v1.1's delta (0 in_drain=1); nondeterministic handoff livelock mode, bounded suppress-loops re-driven by re-BASTs (leaf-rebuild republishes: lseq=0 done=0 has_bli=0, P21F pairs). Did not recur.
- v0.11.97 run 192304Z: 2 CRC (transient, da3 read verify @ split moment), 8 EUCLEAN(HOLE), no shutdowns. **checks=404 passed=304 failed=100 — ALL failures = node4+node8 names, START at 19:23:11 with DABUF-HOLE (ino 14680192 bno 8388608 br_startblock=-2) BEFORE the tear (:20)** → root = Defect B reader TOCTOU, not the write side.

## Defect B evidence (now the dominant CC failure)
- Readers walking dir mid leaf1→leafn→danode transition get XFS_DABUF_MAP_HOLE_OK internal error → EUCLEAN → md5sum/cat fail → cc checks fail for the hash range being split (deterministically node4/node8 names).
- POST-REMOUNT persistent variant on test4 (uptime 20728-20732): "DLM inode lock failed ino=<dir> mode=5 rc=-35 (EDEADLK)" loops + DABUF-HOLE on every walk — **EDEADLK acquire-failure fallback proceeds with stale extent state** (uncoordinated reader). FS later shut down (dirty trans cancel). Separate arm of B.
- Blueprint fix (e): grant-gen/fork-seq recheck-and-restart on HOLE/format mismatch, not fatal assert; plus the EDEADLK fallback must not walk stale.
- da3 read CRC at split moment: 4KB IO is page-atomic through SCST fileio → real interleave OR read-during-transition; revisit after B fix (may vanish).

## Env/harness notes
- kernlog_test* captures span WHOLE BOOT — always filter by wall-clock window of the run.
- `mountpoint -q` returns NOT-mounted on a shutdown FS; `mount | grep " type mxfs"` is the truth for mounted-ness.
- chk_mxfs on a LIVE mount reports icount/ifree drift (lazy sb counters) — not corruption; quiesce first.
- test4 20654 unmount: "BUG mxfs_inode: Objects remaining on kmem_cache_shutdown" + generic_shutdown_super WARN — inode leak at unmount after the EUCLEAN storm era (likely P142-BWORK-LASTREF deliberate leak); not yet triaged.
- LUN state after run 192304Z: NOT re-mkfs'd; cluster left mounted on v0.11.97.
