---
name: sess20-4tcp-16of17-tcp_dlm_scaling-rename-revalidate-miss-at-low-sfmht
description: sess20(ccloop) 4/tcp build 4E047A49 = 16/17, tcp_dlm_scaling FAIL 3/4: test2 did 0 rounds (NOT a window issue - other 3 nodes fast 11-17s). Root = RE…
metadata:
  type: project
---

## sess20 (ccloop) — 4/tcp 16/17; tcp_dlm_scaling flaky via rename-revalidate-miss at low sf_mht

### FULL `./run.sh 4 tcp` build `4E047A49` = 16/17. ONLY tcp_dlm_scaling FAIL 3/4.
- NOT a window/timing fail: 3 nodes FAST (test1=16.8s, test3=11.0s, test4=16.1s, all 150 rounds — format-gate working). **test2 did 0 rounds (elapsed 1.34s, broke on round 1)**.
- ROOT: test2's `mv n2_r1 n2_r1.done` hit **RENAME-REVALIDATE-MISS** (xfs_inode.c:4320, sess8 guard): re-reads src name under held EX before rename; got `lookup_rc=-2 (ENOENT) cur_ino=0` → clean-abort → `mv` fails → loop breaks. n2_r1 is test2's PRIVATE file (no peer contention), so this is a FALSE abort: test2 created n2_r1 then its own rename's dir-lookup couldn't see it.
- WHY: at `dir_sf_mht_ms=100`, the shortform shared-dir handoff (peer BAST during test2's 100ms window → release+reload) left test2's rename reading a dir state MISSING its own just-created (should-be-durable) file. So sf_mht=100 reintroduces a SELF create-then-rename coherency race in the shortform dir. FLAKY: 8-node tcp_dlm_scaling passed 8/8 at sf_mht=100 (twice); 4-node test2 hit it. Premise "shortform dirs coherent at low mht" is only MOSTLY true — the rename-revalidate path has a low-mht gap.

### OVERALL 8/tcp + 4/tcp status (build 4E047A49, format-gated mht): each = 16/17, but the failing test DIFFERS per run/count — all are 8/4-node FLAKY coherency/timing residuals:
- tcp_dlm_scaling: rename-revalidate-miss at low sf_mht (4-node test2; flaky).
- dir_reuse: 8-node in-suite TIMEOUT (348s vs 300s; speed; passes at 420s & at 4 nodes).
- dlm_scaling: 8-node window flake (7/8 once, 8/8 once; passes 4/4).
- 1/tcp(16/16), 2/tcp(17/17) on PRE-gate build still need re-verify on 4E047A49.

### NEXT-SESSION OPTIONS (all to make the 16/17→17/17 reliable):
1. TUNE sf_mht: 100 is the floor for cache_coherency but flaky for tcp_dlm_scaling rename. Try 120-130 (reduce rename race; keep 8-node tcp_dlm_scaling <60s — at 100 it was 39s, slope ~0.2s/ms so ~47-50s at 130, still margin). Verify rename-miss gone AND cache_coherency still passes.
2. FIX the shortform rename-revalidate gap: ensure dir reload on EX re-acquire includes the node's own durable just-created dirent (check mxfs_dlm_dir_modify_refresh handles shortform inline-data reload; the guard at 4320 may read stale in-core shortform data). A re-read-fresh-before-abort in the guard could eliminate the FALSE abort.
3. dir_reuse 8-node speed: deep (per-handoff drain cost) — see [[sess20-8tcp-residuals-dir_reuse-348s-and-dlm_scaling-flaky]].
See [[sess20-BREAKTHROUGH-format-gated-mht-shortform-dirs-low-mht]] (the core win — keep it).
</body>
</invoke>
