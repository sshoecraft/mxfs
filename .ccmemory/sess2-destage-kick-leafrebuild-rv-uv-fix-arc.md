---
name: sess2-destage-kick-leafrebuild-rv-uv-fix-arc
description: sess2 part2 v0.11.82: leaf_rebuild=1 default (in-core-only, union was delete-unsafe), P34G incarn guard, destage-kick worker (10ms async). Build F029…
metadata:
  type: project
tags: [destage-kick, leaf-rebuild, rename-visibility, reuse-iget, ccloop-c7ee71c6]
---

# sess2 part 2 — the post-eager=0 residual arc (supersedes gaps in sess2-tcp-dlm-scaling memory)

State.md (2026-07-25 ~14:15 CDT checkpoint) has the full current picture. Key deltas after the first memory:

1. **Leaf-hash holes** (dir_reuse leaf-hash lookup_fail got=127, P21H-LEAFHOLE): `mxfs_dir_leaf_rebuild` default 0→1 (once-per-tenure rebuild). 1-in-5 fail → 0-in-3, same pace.
2. **Union rebuild is DELETE-UNSAFE** (cache_coherency rv "old gone" FAIL ×8 nodes, P26-REBUILD-OK comm=mv): "in-core free + disk live" is ambiguous (peer add vs our remove) — resurrection of renamed-away dirents. Rebuild now IN-CORE-ONLY (xfs_dir2_leaf.c; disk union behind leaf_rebuild=2). In healthy release-destage world the post-refresh in-core data already has every peer entry.
3. **uv-create 55s stall** (cache NO_TERMINAL ×8): reuse-iget convergence needs ms-scale destage of freed/created clusters; eager=0 left 30-55s gaps (P13-VISNUDGE spin, P-IGET-ENOENT mode=0 reclaimable shell, peers' nudged releases P146-RELDUR rerr=-11 wrote=0). Fix: **mxfs_destage_kick** — per-mount delayed_work (m_mxfs_destage_kick in xfs_mount.h, INIT in xfs_super.c setup, cancel_delayed_work_sync in put_super BEFORE unmountfs), queued (queue_delayed_work system_unbound_wq, 10ms debounce) from ifree (when !eager) and create-success; worker = async xfs_log_force(mp,0) + xfs_ail_push_all. NOT sync force (2ms+SYNC taxed ds node1 to 47/s vs floor 50 — builds F5BD8552 fail ×2).
4. Build F029104F (10ms+async) deployed to 8/tcp; **triad verification (cache/dlm_scaling/dir_reuse ×3) INTERRUPTED by user power-precaution — run it first on resume.**

Recovery-from-power-loss procedure + exact next steps: state.md.
