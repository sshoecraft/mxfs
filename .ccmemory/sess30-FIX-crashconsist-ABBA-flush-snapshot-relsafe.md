---
name: sess30-FIX-crashconsist-ABBA-flush-snapshot-relsafe
description: sess30(ccloop) FIX (build F449AACE): crash_consistency in-suite ABBA hang SOLVED — now PASSES 8/8 in full 8/tcp suite. Snapshot daddrs under i_lock,…
metadata:
  type: project
---

## sess30 FIX — crash_consistency in-suite ABBA hang SOLVED (build F449AACE)

### The fix (xfs/xfs_mxfs_dlm.c)
The sess21/sess29 PRIMARY 8/tcp wall — crash_consistency hung in-suite (two D-state threads, bast kworker + bash, both blocked in `xfs_buf_lock` under `mxfs_dir_flush_data_blocks`) — was an ABBA: the release loop held `dp->i_lock(read)` across `mxfs_dir_flush_data_blocks`, which does a BLOCKING `xfs_buf_incore(...,0,...)`. A journal-replay/peer-BAST context held the dir buffer while needing `i_lock(write)` → hard wedge.

**Structural fix (snapshot-then-act, mirrors `mxfs_dir_drain_evict_data_blocks`):**
1. Extracted the per-block flush body into `mxfs_dir_flush_one_daddr(ip, d, dir_blk_bb, startoff)` — i_lock-FREE (buffer cache is keyed by daddr, needs no i_lock). The 3 inner-loop `continue;` became `return;`.
2. `mxfs_dir_flush_data_blocks(ip)` unchanged contract (caller holds i_lock) — now just snapshots+loops one_daddr. Used by the 3 NON-ABBA callers (reclaim EXCL @ ~14098, etc.) byte-equivalently.
3. NEW `mxfs_dir_flush_data_blocks_relsafe(ip)`: caller holds i_lock(read); kmalloc-snapshots ALL dir-block daddrs+startoffs under i_lock (no fixed cap → Inv 1 safe), `up_read`, then flushes each via one_daddr WITHOUT i_lock. **Consumes the lock** (returns with it dropped).
4. The TWO release-loop ABBA sites (the P97 release fence ~7529 and the P35F stale-retry ~7866) now call `_relsafe(ip)` and DROP their own `up_read` (relsafe owns it).

### RESULT: full `./run.sh 8 tcp` (winning modargs) = crash_consistency PASS 8/8 IN-SUITE
Suite reached crash_consistency (was the 11/17 hang point) and it PASSED reliably. No regression: the other 10 prior-passing tests still pass.

### REMAINING 8/tcp walls (both pre-existing, == sess29 full8f): 11/17
- **zero_silent_loss FAIL 0/8** (isolated — tests after it pass).
- **dir_reuse_coherency FAIL 0/8 → CASCADE** (fence_during_write, fault_netpartition, soak, tcp_dlm_scaling all 0/8 after it). sess29 diagnosed = DABUF_MAP_HOLE extent-map staleness (fresh leaf walked vs stale in-core i_df). Lead: arm MXFS_IF_DIR_RELOAD when relinval_clean stales dir buffers.

Winning modargs (build F449AACE, levers still default-0): `dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_release_invalidate=1 dir_relinval_clean=1`. Run: `bash tests/tcp/full8.sh 8 "<modargs>"`. Backup of pre-fix dlm.c at xfs/xfs_mxfs_dlm.c.backup-sess30.
See [[sess29-full8tcp-11of17-crashconsist-insuite-hang-is-last-wall]] [[sess29-HEAD-handoff-dir_reuse-solved-standalone-fullsuite-env-blocked]].
