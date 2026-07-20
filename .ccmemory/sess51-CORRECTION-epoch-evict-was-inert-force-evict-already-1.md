---
name: sess51-CORRECTION-epoch-evict-was-inert-force-evict-already-1
description: sess51(ccloop) CORRECTION: the epoch-evict gate change was INERT (mxfs_dir_force_evict=1 default already bypasses the skip → whole-dir evict runs eve…
metadata:
  type: project
---

## sess51 (ccloop) — CORRECTION to [[sess51-FIX-epoch-triggered-wholedir-evict-build-AED21CF5]]

### The epoch-evict gate change was INERT — do not chase the "release-side durability" lead based on the repro7 regression.
`mxfs_dir_force_evict = 1` is the COMPILE-TIME DEFAULT (xfs_mxfs_dlm.c:3957, module_param). prep_node.sh loads `insmod mxfs.ko force_transport=1` with NO force_evict override → runtime value stays 1. The skip gate in mxfs_dlm_dir_modify_refresh is `if (!mxfs_dir_force_evict && !new_incarn && dir_gen==evicted_gen) return;` — with force_evict=1, `!force_evict`=false so the condition is ALWAYS false → it NEVER early-returns → mxfs_dir_evict_data_blocks ALREADY runs on EVERY modify in baseline. Adding `!epoch_advanced` to an already-false AND-chain is a NO-OP. So build AED21CF5 was behaviorally identical to baseline C69E3475 (and indeed compiled byte-identical after I reverted: same srcversion C69E3475).

### ⇒ repro7's mass loss (round7=722/800, round8/9=700/800) was NOT caused by my change. It is a FLAKY SECOND FAILURE MODE.
Mass loss (700-722) appeared in: loop1-iter1 (partial reboot), loop2-iter1 (full reboot, build B3957326), repro7 (full reboot, build AED21CF5-inert). NOT in repro1/4/5/6 (single-dirent losses). It spans multiple builds incl. baseline-equivalent → it's flaky, build-independent. Likely a node briefly wedging/slow under load → transient membership/coherency hiccup → en-masse divergence (related to the D-state mxfs-worker teardown wedge, or a slow node during the storm). The PRIMARY, reproducible failure is the SINGLE-dirent count-preserving divergent RMW.

### IMPORTANT IMPLICATION: the whole-dir clean-block evict ALREADY runs every modify (force_evict=1) and the single-dirent loss STILL happens. So "evict + cold re-read" does NOT prevent the divergent RMW. Either the cold re-read reads a stale/non-durable block (but content timeline showed NO backward-count writes, so the re-read isn't dropping counts), or the evict's per-block guards keep the stale block, or the divergence is in a window the evict doesn't cover. The existing eviction machinery is NOT the fix and may be load-bearing in unexpected ways.

### SOLID, uncorrupted facts to build on next session:
1. PROVEN (content-fingerprint timeline, repro6): loss = count-preserving block-level divergent RMW; NO write ever lowers a block's count; master handoff epoch monotonic; single stable master; zero master double-grants. See [[sess51-PROVEN-loss-is-count-preserving-divergent-RMW-phantom-cached-ex]].
2. GPT-5.5 full architectural design (epoch-fenced capability + acquirer-side whole-dir invalidate-on-grant + BAST quiesce with active_user refcount). The quiesce/active-ref part (mechanism d) is UNTRIED and is the most likely missing piece — the existing evict fires at MODIFY time, not atomically at GRANT before publishing, and has no active-user quiescence on BAST.
3. Tool: dirwr content fingerprints (MXFS_EXTRA_MODARGS=dirwr=1 + DRC_STREAM=1; analyze /src/mxfs/tests/tcp/drc_cap/stream_rank*.log P50-WR/RD by daddr+incarn+realns).

### STATE: tree = clean baseline C69E3475 (verified byte-identical srcversion); cluster rebooted clean; marker NOT written (criteria NOT met).
