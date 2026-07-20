---
name: sess11run-REFUTED-dataclobber2-and-readside-gap-is-the-fix-target
description: sess11(ccloop) dataclobber=2 write-enforce REFUTED (corrupts dir, readdir=0; mis-classifies legit writes per sess23). The fix target is the READ side…
metadata:
  type: project
---

## sess11 (ccloop) — write-side enforce REFUTED; the fix must be a CONTENT-AWARE coherent READ on the modify path

### dataclobber=2 REFUTED (build C0290572, mxfs.dataclobber=2)
The existing write-side clobber-enforce (pal/linux/xfs_buf.c:2320 `if (mxfs_dataclobber>=2 && dc_stale) skip the write`) makes dir_reuse WORSE: drc4 FAIL round 1, dir readdir=0 (whole dir UNREADABLE/corrupt). Skipping a "clobbering" write mis-classifies legit writes and corrupts the dir (matches [[sess23-ccloop-suppression-was-corruptor-3of4]]: P122/P93 write-side suppression mis-classifies coalescing/legit writes). Do NOT use dataclobber>=1. Default 0 (param, build-safe).

### THE FIX TARGET (decisive): the modify-path READ serves a STALE cached dir block under EX
PROVEN: test2's acquire-evict (P106-MR-EVICT) did NOT process block 2093296 (no P68-EVDECIDE for it — the iext-walk evict missed it / it was cached+DONE+stale), so test2's xfs_dir2 addname read the STALE cached block 2093296 (XBF_DONE set, content missing the peer's node4_f4 at off=2768) and its bestfree free-slot search picked off=2768 (already occupied on disk) → double-allocation → durable loss.
- WHY not refreshed: xfs_da_read_buf's pre-read gen-invalidation is gated `!owned_ex` => SKIPPED on the modify path (under EX). And b_mxfs_dir_gen is lossy (stamped fresh over stale content — same reason FIX3's gen-gate is inert). So under EX-modify, the addname serves whatever is cached, stale.
- The acquire evict (mxfs_dir_evict_data_blocks) is supposed to clear XBF_DONE on stale clean blocks so the next read cold-fetches, but it MISSED block 2093296 this acquire (not in the iext walk / TRYLOCK / not-cached path). 

### FIX DIRECTION (for next session) — content-aware coherent read BEFORE addname, avoiding both prior failure modes
The signal must be CONTENT divergence (like the P29-DATAWRITE detector: dirent count + inumber sum/xor vs a COHERENT plain/FUA read of the same daddr), NOT the lossy b_mxfs_dir_gen (FIX3 over-fired and regressed) and NOT write-side suppression (dataclobber corrupts). Concretely: on the modify path (mxfs_dlm_dir_modify_refresh / before xfs_dir_createname's addname for a contended dir gen>0), for each dir DATA block, do a coherent plain-bdev read of the on-disk block; if its live-dirent set is a SUPERSET of (or diverges from) the in-core block AND the in-core block is NOT cluster-undestaged (logged==written, no own committed-unwritten work), invalidate+re-read so the addname's bestfree reflects the peer's entries. This is the READ-side analog of the P29 write detector, applied as prevention. Bound to dir data blocks of the storm dir; watch RULE-0 (one plain read per modify, like P56/P29 probes). The cluster-undestaged guard (mxfs_dir_buf_is_undestaged) prevents reverting own work (FIX3's failure).

### Full proven chain: [[sess11run-ROOTCAUSE-PROVEN-cross-node-dirblock-freeslot-double-allocation]] (two nodes same daddr+off) -> [[sess11run-DIRECTIONALITY-later-writer-stale-bestfree-loses-fix-coherent-refresh]] (later writer w/ stale bestfree loses) -> this (read serves stale under EX; write-enforce refuted). Tree C0290572 (clean baseline + inert FIX3 + SAFE dirwr-gated probes). Repro /tmp/...scratchpad/drc4_d1.sh (dirwr=1). Criterion NOT met.
