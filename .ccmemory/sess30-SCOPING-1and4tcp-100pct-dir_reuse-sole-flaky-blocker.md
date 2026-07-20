---
name: sess30-SCOPING-1and4tcp-100pct-dir_reuse-sole-flaky-blocker
description: sess30(ccloop) SCOPING (build 04A615EE + winning modargs): 1/tcp=16/16 ✓, 4/tcp=17/17 ✓, 2/tcp=16/17, 8/tcp=11/17. SOLE blocker = dir_reuse_coherency…
metadata:
  type: project
---

## sess30 SCOPING — criteria reduced to ONE flaky test

Build **04A615EE** + modargs `dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_release_invalidate=1 dir_relinval_clean=1`:
- **1/tcp = 16/16 = 100% ✓** (single-node test set; no dir_reuse)
- **4/tcp = 17/17 = 100% ✓** (dir_reuse PASSED 4/4 — flaky pass)
- 2/tcp = 16/17 — ONLY dir_reuse_coherency 0/2
- 8/tcp = 11/17 — dir_reuse_coherency 0/8 (+ zero_silent_loss flaky, passed in prefix)

**The SOLE remaining criteria blocker is `dir_reuse_coherency`, and it is FLAKY** (passed 4-node, failed 2-node and 8-node in the same build/config). Every other multinode test (cache_coherency, strong_consistency, posix_multi, mmap, zsl, dlm_fairness/membership/scaling, scaling_curve, rsync_paired, crash_consistency, fence, fault, soak, tcp_dlm_scaling) passes reliably at 2/4/8.

### dir_reuse failure = the deep 130-session single-dirent durable lost-update (Face C)
CLEAN 2-node repro: `drc-RDMISS round=2 rank=1 readdir=199 missing_from_readdir=[node1_f10.md5]` (EXP=200 for 2 nodes). node1's OWN just-created dirent missing from rank1's readdir after sync+drop_caches+cold-read. Progression then degrades: round1=799/800-class, round7+ → readdir=0 (Face B dir-missing), and at 8 nodes the rm-rf mass-free can hit AGI-CRC shutdown (Face A). Root (sess22/29): an EX-holder RMW+destages a STALE-KEPT prior-tenure dir-DATA block (cross-node TOCTOU); release-side invalidation (the winning levers) can't fully close it; acquire-side evict (mxfs_dir_drain_evict_data_blocks) SKIPS pinned blocks (keeps stale) — candidate gap. Write-side merge (dir_write_merge) made cross-block duplicates; bail breaks Inv 1.

### FAST repro: 2/tcp fails at round 2 (~2 min in). `bash tests/tcp/full8.sh 2 "<modargs>"`. Per-round dmesg snapshots at /root/drc_fail_r${N}_rank${R}.dmesg on the nodes (BUT these accumulate across runs — interleaved round numbers from prior runs; trust the LATEST run's /root/drc_failround marker + the matching r-file timestamp).

### NEXT: RULE-4 the single-dirent loss with the 2-node round-2 repro (cleanest ever). Probes already in tree: P-DE-BLK (acquire evict disposition), DIR-STALE-SKIP, P21F-RELFLUSH-LEAF, P56-DIRWRITE. Determine: does node2's EX-tenure RMW a stale prior-tenure base (acquire-evict missed a pinned block)? Or does rank1's add not durably land before node2 takes EX?
Wins this session: [[sess30-FIX-crashconsist-ABBA-flush-snapshot-relsafe]] [[sess30-WIN-4tcp-17of17-soak-fixed-by-P30-ops-recover]].
