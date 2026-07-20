---
name: sess50-ROOT-resurrection-is-fastpath-sfmerge-readd-FIX-B
description: sess50: FIX B (KEEP, build E67385C9) fixes the dirent RESURRECTION (fast-path sf-merge re-add). Validated full-suite 17/17 once. RESIDUAL now = tcp_d…
metadata:
  type: project
---

## sess50 (ccloop 8ddb16a2) — RESURRECTION root FOUND+FIXED (Fix B). New residual = handoff STALL.

### FIX B (KEEP, build E67385C9): fast-path sf-merge re-add eliminated.
ROOT (PROVEN, new `sfm_dbg` slow-path probe P-SFM-READD w/ state+gen): the durable dirent
resurrection (tcp_dlm_scaling/dlm_fairness "drained got>=1") is the **cached-EX FAST PATH**
(i_dlm_state==CACHED=1, peer_mod=0) sf 3-way merge re-adding the node's OWN async-destaged-then-
removed shortform dirent (theirs-loop "in theirs !ours !base"). NOT a DLM double-grant (P106-STALE-EX
fired 0; sess8 P-DOUBLEGRANT=0; request-path already re-affirms; purge_stale is DEAD CODE).
FIX: on a continuous-hold fast path the IN-CORE fork is AUTHORITATIVE (a peer modify needs EX which
BASTs us off CACHED) → do NOT adopt lagging disk. `xfs_mxfs_dlm.c` ~9018:
`if (sf_disk_check && mxfs_sf_fastpath_adopt) mxfs_dir_sf_refresh_if_disk_differs(ip);`
global `int mxfs_sf_fastpath_adopt;` default 0 (=fix). (NOTE: forgot the module_param_named for it —
add for runtime A/B; global default works.) VERIFIED: fast-path re-adds 0/0; full `./run.sh 2 tcp`
= **17/17 once**; node1-churn+node2-read clean (slow path drains, always was fine).

### RESIDUAL (criterion NOT met) = tcp_dlm_scaling intermittent SLOWNESS/STALL.
Reliability loop (`tests/tcp/reliability_loop.sh N`, reboots+reformats per run): RUN 1 FAILED
tcp_dlm_scaling nodes_pass=0/2: `test1 completed rounds exp=150 got=45` + both `within window`(>60s).
= a SINGLE dir-EX (or inode/AG) handoff STALLED ~60s then the op failed/broke (rounds 1-45 were
~110ms each = fine; round 46 ate the whole window). `mxfs_dlm_lock` retries **60× × 1000ms = 60s**
on -ETIMEDOUT (dlm.c:1389) — one unrecovered stall blows the window. This is the sess13/sess33
CROSS-RESOURCE **dir-inode-EX ↔ AG-DLM distributed deadlock** (cached AG inverts [inode,AG] order)
OR an unrecovered lost-message handoff. Worse IN-SUITE (tcp_dlm_scaling runs LAST; 16 prior tests
churn the LUN → more AGs/locks in play). Standalone (fresh LUN) passes. sess13 mitigation
`mxfs_dlm_yield_basted_cached_ags` (~8373) exists — verify it fires/suffices on TCP.

### NEXT SESSION:
1. Let the running reliability loop finish; read /tmp/relrun_{1,2,3}.log for the stall consistency.
2. REPRO the in-suite stall: run a few churny tests then tcp_dlm_scaling on ONE mount (no reformat),
   OR `./run.sh 2 tcp` watching tcp_dlm_scaling. Instrument: log any inode/AG DLM acquire that takes
   >2s (resource+state+holders) — it's SECONDS-scale = instrumentable (unlike the µs resurrection).
3. Identify: cross-resource deadlock (dir-EX held, AG-DLM stuck) vs lost-message. Fix root.
   Build E67385C9 deployed both nodes. Probes: sfm_dbg, sf_fastpath_adopt(global,default-fix).
Related: [[sess49-residual-tcp-doublegrant-dir-resurrection-complete-diagnosis]] [[sess34-6s-dir-handoff-is-LOCK_ACQUIRE_WAIT_MS-deferred-bast]] [[sess-tcp-15of16-tcp-dlm-scaling-stale-readdir-root]]
