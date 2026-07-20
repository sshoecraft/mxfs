---
name: sess43-KEY-loss-is-round1-pure-concurrent-create-not-reuse
description: sess43 KEY: 8/tcp dir_reuse loss reproduces at ROUND 1 (fresh dir, ZERO reuse) — pure concurrent-create coherency bug; reuse/incarnation framing REFU…
metadata:
  type: project
---

## sess43 (ccloop) — the framing-correcting finding. Read with [[sess43-TRIANGULATED-clobber-is-background-xfsaild-nonEX-write]] [[sess43-FIX-twosided-owner-scan-dir-blocks-map-independent]].

### THE loss reproduces at ROUND 1 (fresh dir, NO prior reuse)
New harness `tests/drc_trace.sh` (forwards DRC_STREAM=1 + DRC_ROUNDS via MXFS_TEST_ENV → rotation-immune per-node `dmesg --follow` to tests/tcp/drc_cap/stream_rank<R>.log) + P13-NADD/LADD made NON-ratelimited (capped 60000, build A8FCB6D0) caught a fail at **round=1**, victim=`node5_f1` (the FIRST data file). Round 1 = the dir was freshly mkdir'd this run; rank1's rm-rf reuse has NOT happened yet. So **the loss is NOT the rm-rf/daddr-reuse/incarnation-ABA stressor** (that framing — dominant in sessNN heads — is REFUTED for the core loss; reuse may add failure modes but is NOT necessary). It is a **pure concurrent same-dir create coherency bug**: 8 nodes grow one dir 0→800 entries concurrently and one early dirent is durably lost.

### What the round-1 stream shows for the victim's block (daddr=39771328, leaf use_block=3)
node5 (creator, comm=dd) adds node5_f1 via **P13-LADD daddr=39771328 aoff=352**. Then **rank1 (a PEER, NOT the creator) holding EX (dlm_mode=3)** processes daddr=39771328 during ITS OWN create wave (comm=bash): P38-DIRMAP bno=3 nextents=9 fmt=2; **P68-EVDECIDE flips undurable=0 (evict/force-reread, done=1) then repeatedly undurable=1 (KEEP, done=0)**; P-DE-BLK disp=SKIP. So the acquiring peer evicts+reloads the victim's block, then RMWs it (adding its own node1_f*). If rank1's reloaded base lacks node5_f1 (durability/ordering gap, or the undurable=1 KEEP serves a stale cached base), rank1's commit drops node5_f1 durably. Matches the dland-proven stale-base clobber.

### ⚠️ CAVEAT that invalidated my cross-node timing: **stream dmesg timestamps are PER-NODE BOOT-RELATIVE, NOT cross-node comparable** (each VM booted at a different wall time). t=75 on node5 ≠ t=75 on node1. Use the ROUND BARRIERS (PHASE=create-start/create-done/verify-done/rm-done markers, coord-synced) to bound cross-node ordering, or the dland ring's `t=` (ktime_get_real_ns, wall-clock, comparable) for fine ordering. Do NOT compare raw `[NNN.NNN]` dmesg ts across nodes.

### NEXT (decisive, RULE 4): re-run `tests/drc_trace.sh 6 24 50 dirland=1` (dirland adds per-write daddr+owner+incarn+COUNT+sum at I/O completion with comparable real-ns). For the round-1 victim: P13-LADD gives its daddr; then in the dland dump trace that daddr's content/count trajectory across nodes (real-ns ordered) → is the peer's clobbering write preceded by a coherent reload that HAD the victim (⇒ pure stale-base read despite evict), or did the creator's add never land durable before the peer read (⇒ durability/ordering)? Then fix at the proven point. The acquiring-peer evict (mxfs_dir_drain_evict_data_blocks / P68-EVDECIDE) IS firing (undurable=0) but interleaves with undurable=1 KEEPs — the KEEP path may be serving the stale base.

### Build: A8FCB6D0 = keeper-functional (dir_owner_scan default 0; only P13 made non-ratelimited + storm-dir-scoped → no 1/2/4 behavior change). Harness tests/drc_trace.sh (RULE 3, in-tree). Cluster clean.</body>
