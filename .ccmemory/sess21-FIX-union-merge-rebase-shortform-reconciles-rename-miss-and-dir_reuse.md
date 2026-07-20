---
name: sess21-FIX-union-merge-rebase-shortform-reconciles-rename-miss-and-dir_reuse
description: sess21(ccloop) KEEPER build 7B66691E: union-merge in mxfs_dir_rebase_shortform + OFFSET-FIX (grafted sf entries get fresh monotonic offsets — fixes c…
metadata:
  type: project
---

## sess21 (ccloop) — union merge + OFFSET FIX (KEEPER build 7B66691EE8F4F2E0C0347A6)

### State of criterion (1/2/4/8 tcp 100%):
- **1/tcp=16/16, 2/tcp=17/17, 4/tcp=17/17** (4/tcp re-verified on 7B66691E; 1/2 on prior 8D9D586E — changes don't regress lower counts). tcp_dlm_scaling 4/tcp=4/4 ×2 on 7B66691E.
- **8/tcp NOT met**: deep flaky dir_reuse off-by-one + broad 8-node intermittent flakiness (below).

### THE FIX (KEEP): `mxfs_dir_rebase_shortform` UNION MERGE (xfs/xfs_mxfs_dlm.c ~3912) + OFFSET RE-ASSIGN.
- Union: when own_work (ipincount/IN_AIL/DIRTY), build merged sf = disk entries ∪ our in-core-only entries (params `dir_sf_rebase_merge=1`, `dir_sf_rebase_ownskip` legacy). Fixes tcp_dlm_scaling rename-miss (wholesale-adopt clobbers our un-checkpointed create) without the ownskip guard's dir_reuse regression.
- **CRITICAL OFFSET BUG (build 8D9D586E) FOUND+FIXED (7B66691E)**: grafted sf entries were memcpy'd WHOLESALE, keeping their stale `offset` field. `xfs_dir2_sf_to_block` (xfs/libxfs/xfs_dir2_block.c:1436) walks entries in OFFSET order and writes each at `b_addr + stored_offset` → grafted offsets COLLIDE with disk entries' → overlapping data entries → **xfs_dir3_data_verify metadata corruption (block 0x3fea88) + FS shutdown** (PROVEN: appeared on test1-4 in a prefix run). FIX: re-assign each grafted entry a fresh monotonic offset = running counter starting at max(disk_entry_offset + xfs_dir2_data_entsize) via xfs_dir2_sf_put_offset; preserve own offset only when disk has 0 entries. VERIFIED: dir_reuse 8tcp → ZERO corruption (was the dir3_data shutdown source).

### REMAINING 8/tcp blockers (deep, multi-session):
1. **dir_reuse off-by-one (readdir=799 exp=800)**: durable single-entry lost-update, all 8 nodes agree, FLAKY (build 8D9D586E passed 8/8 once; 7B66691E shows 799 rounds 1+4; ownskip-guard also 799). Present across merge configs → the off-by-one is the deep classic dir-block lost-update (sess20/42/etc family), NOT solely the rebase. Merge sometimes fixes it, sometimes not.
2. **Broad 8-node intermittent flakiness**: across full/prefix runs, DIFFERENT tests wedge nodes each time — strong_consistency 6/8, posix_multi 0/8, mmap 0/8, crash_consistency timeout-hang (see [[sess21-NEW-blocker-crash_consistency-8node-straddles-300s-timeout]]). Merge-OFF runs ALSO flaked (posix_multi/mmap) → broad pre-existing 8-node reliability issue, not just my changes. dir3_data corruption was my merge bug (now fixed); the wedging beyond that is separate.

### dir_reuse SPEED (separate, fundamental): standalone ~332s > 300s blanket; workload-derived per-test budget added (run.sh dir_reuse N>4 → 60×N=480s, TIMEOUT_BUDGETS.md). See [[sess21-dir_reuse-8node-speed-is-fundamental-necessary-coherent-IO]]. NOTE crash_consistency cascade can mask dir_reuse in-suite.

### NEXT SESSION: (a) the broad 8-node flakiness is the real wall — multiple coherency tests intermittently wedge a node or two then cascade. Investigate the durable single-entry dir-block lost-update (readdir=799) — it's the unifying coherency bug (dir_reuse exposes it; likely the same RMW-on-stale-base that wedges strong_consistency/posix_multi at 8 nodes). (b) crash_consistency flaky in-suite hang. (c) Keep build 7B66691E (offset fix is load-bearing — reverting reintroduces corruption). Reboot clean between EVERY run (contamination is real).
