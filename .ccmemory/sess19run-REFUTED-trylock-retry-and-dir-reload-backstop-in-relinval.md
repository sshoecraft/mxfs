---
name: sess19run-REFUTED-trylock-retry-and-dir-reload-backstop-in-relinval
description: sess19(ccloop) REFUTED: bounded-trylock-retry + MXFS_IF_DIR_RELOAD backstop in mxfs_dir_release_invalidate_data_blocks made mht=50 dir_reuse WORSE (2…
metadata:
  type: project
---

## sess19 (ccloop) — refuted the obvious fix for the residual single-dirent loss

### Context: `dir_release_invalidate=1` @ mht=50 leaves 2 residual single-dirent losses (see [[sess19run-PROGRESS-dir-release-levers-cut-lowmht-loss-18to4]]). I hypothesized the cause was the TRYLOCK-skip in `mxfs_dir_release_invalidate_data_blocks` (xfs_mxfs_dlm.c:3109) silently leaving a momentarily-locked dir block un-invalidated → survives handoff → clobber.

### REFUTED (RULE 4): added a bounded trylock-retry (30× msleep(1) on -EAGAIN) + `xfs_iflags_set(ip, MXFS_IF_DIR_RELOAD)` backstop when still locked → **failrounds 2 → 11 (WORSE)**. Reverted (build back to 15447D0C).
- Likely cause: **MXFS_IF_DIR_RELOAD arming forces a full dir reload on the next acquire, which CLOBBERS in-core committed-undrained work** — same failure mode as the REFUTED force_coherent=1 (24/24). Confirms [[sess19run-REFUTED-force-coherent-worse-reload-must-stay-handoff-gated]]: aggressive forced reload is the wrong direction; the reload must stay surgical.
- Also: msleep in the release path perturbs the concurrent-create timing.

### IMPORTANT — run-to-run VARIANCE is high: `dir_release_invalidate=1` @ mht=50 gave 2 failrounds one run, 11 another (with my refuted change). The residual single-dirent loss is a RACE with variable hit-rate; need multiple runs to judge any fix, and the "2" may itself be lucky. Treat <~5 failrounds as "much improved but not converged."

### STATE: build 15447D0C (KEEP: inode-skip fix; mht default 300; dir_release_invalidate default 0). The strong lead remains `dir_release_invalidate=1` (18→~2-11 @ mht=50) but it is (a) not yet 0-loss and (b) ~305s (>300s budget) due to cold-FUA re-reads. NEXT: the residual is NOT the release-side trylock-skip (refuted). Re-examine the ACQUIRE side — the surgical per-block gen-invalidation that DOESN'T clobber but DOES reliably catch the peer's add. Consider: make `dir_release_invalidate` also force-LAND (xfs_bwrite) a not-yet-durable block before invalidating it (instead of skipping), so no stale block survives, WITHOUT arming a force-reload. And separately solve the mht=50 FUA-read speed (the dir-block eviction/re-read thrash). See [[sess19run-FULL-8tcp-suite-13of17-mht-tradeoff-is-core-blocker]].
</body>
