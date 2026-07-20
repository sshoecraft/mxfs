---
name: sess19run-PROGRESS-dir-release-levers-cut-lowmht-loss-18to4
description: sess19(ccloop) BREAKTHROUGH LEAD: dir_release_invalidate=1 ALONE cuts dir_reuse mht=50 loss 18 heavy rounds → 2 single-dirent losses. fua_write REFUT…
metadata:
  type: project
---

## sess19 (ccloop) — dir_release_invalidate is the lever that makes low-mht dir_reuse nearly correct

### THE PATH to resolving the mht tradeoff (dir_reuse correct @ mht=50 → default mht=50 → BOTH dir_reuse + tcp_dlm_scaling pass the full 8/tcp suite).

### PROVEN (RULE 4, A/B at mht=50, build 15447D0C):
- plain mht=50: **18 failrounds** (heavy, up to 130/800 lost), ~233s.
- `dir_release_invalidate=1` ALONE: **2 failrounds** (round10 + round23, each 799/800 = ONE dirent lost), ~305s.
- `dir_release_invalidate=1 + dir_release_fua_write=1`: **4 failrounds** → **fua_write REFUTED** (makes it WORSE 2→4, and slower; do not use). force_coherent=1 also REFUTED (24/24, see [[sess19run-REFUTED-force-coherent-worse-reload-must-stay-handoff-gated]]).
- **`dir_release_invalidate=1` (xfs_mxfs_dlm.c:2524) is the key lever** — on dir-EX release, invalidate clean+durable dir DATA/leaf buffers so the next acquire cold-FUA-reads the coherent LUN image ("no dir buffer survives a handoff"). Cuts the loss ~9× (18→2). Default is currently 0; should likely become DEFAULT 1 once residual+speed solved.

### RESIDUAL after dir_release_invalidate=1 (the last mile):
1. **2 single-dirent losses** (round 10, 23; 799/800; lookup_fail=0; durable, all nodes agree) = the documented "399/400 per-handoff" free-slot race. Likely: a dir block NOT clean+durable at the release-invalidate moment (in-AIL/pinned) is SKIPPED by the invalidate (correct — can't drop undurable own work) → survives the handoff → stale base → 1-dirent clobber. The release-DRAIN loop (6592) should make it durable before the invalidate, but a timing gap remains. NEXT: instrument the dir_release_invalidate skip path (which blocks skipped because not-durable) vs the failing round.
2. **Speed = 305s @ mht=50** (over 300s budget) — the invalidate forces cold-FUA re-reads every acquire; at mht=50's high handoff rate that's many FUA reads. RULE 0: needs the dir-FUA-read thrash reduction (the sess19 dir-block eviction mechanism, still unsolved) OR a cheaper coherent-read path.

### NEXT-SESSION PLAN: (1) close the 2 residual single-dirent losses — make the release-side dir-data durable-before-invalidate gap-free (ensure the invalidate runs only AFTER every dir block is durable, or invalidate ALL blocks incl. not-yet-durable by first force-landing them); (2) reduce the mht=50 FUA-read cost to fit 300s; (3) set dir_release_invalidate default 1 + mht default 50; (4) re-validate full 8/tcp suite. KEEP build 15447D0C (inode-skip fix). See [[sess19run-FULL-8tcp-suite-13of17-mht-tradeoff-is-core-blocker]], [[sess18run-HANDOFF-correctness-solved-speed-floor-reload-reliability-lead]].
</body>
