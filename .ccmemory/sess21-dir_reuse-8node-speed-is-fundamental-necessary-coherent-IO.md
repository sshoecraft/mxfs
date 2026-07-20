---
name: sess21-dir_reuse-8node-speed-is-fundamental-necessary-coherent-IO
description: sess21(ccloop) EXHAUSTIVE proof: dir_reuse 8-node 318-332s slowness is FUNDAMENTAL necessary coherent FUA-I/O (no waste/CPU/infra fix); near-linear 2…
metadata:
  type: project
---

## sess21 (ccloop) — dir_reuse 8-node SPEED is fundamental, not a bug (exhaustive RULE-4 analysis)

Build 8D9D586E (union merge + yield fast-skip). dir_reuse 8/tcp = 8/8 CORRECT, WALL 318-332s standalone (>300s cap → in-suite FAIL + cascade). Speed is the ONLY 8/tcp blocker. Proven fundamental:

### Per-phase profile (rank1, AVG/round, mht=300): create=1.1 + barrier-wait-for-slowest-creator=6.1 + verify=3.0 + rm=3.65 = 13.9s × 24 = 333s.
- **create (~7s critical path)**: 8 nodes serialize on ONE dir EX inserting 800 dirents. Each addname under concurrency reacquires EX (peer BAST'd it) → FUA-reloads leaf + target data block. These reloads are NECESSARY (concurrent same-block bestfree → must read fresh to avoid double-alloc slot loss = the original lost-update bug). NOT wasteful over-invalidation. Floor = 800 serialized addname × ~2 FUA reads.
- **verify (~3s)**: 800 cold child-stats (drop_caches forces cold) × DLM PR round-trip each. Necessary cold cross-node reads.
- **rm (~3.65s)**: rank1 rm-rf 800 + sync, 7 nodes idle. Each unlink BASTs 7 peers off child PR (cached from verify). Necessary.

### Levers RULED OUT (all measured/cited):
- **mht**: 150 (broke coherency readdir=0, SAME wall 328s), 275 (318s, FAIL), 300 (332). Create storm is NOT mht-bound — holder releases on BAST when current op done, regardless of mht. mht is a wash (trades create vs rm). Floor with merge ~mht 275 (sess18 floor; lower breaks block-dir coherency).
- **CPU/vCPU**: node load=0.24 during run, maxvcpus=4, NOT cpu-bound. inactivation is network/lock-bound not CPU. More cores won't help.
- **hot-path micro-opt** (yield_basted lockless fast-skip + gate P58 pr_warn, build 8D9D586E): 337→332s, negligible. Confirms cost is round-trips not CPU.
- **FUA disable**: target is LIO-ORG fileio on /home/steve/disk.img Buffered-WCE (emulate_fua_read=1, emulate_write_cache=0). FUA bypasses the VM-side (initiator) cache to re-fetch clyde's coherent shared target cache (clyde RAM, fast). FUA is LOAD-BEARING for initiator-cache coherency (sess14 confirmed LIO; the project_test_cluster_scst SCST memory is STALE/WRONG for this cluster). Can't disable.
- **masking delays**: NONE remain — sess18 removed test sleep 1; coord_barrier already non-polling (sess14). No drain stall (drain_ms=0 mostly).

### Scaling (cited): 4-node dir_reuse = 144s (~6.3s/round); 8-node = 332s (~13.9s/round) = 2.2× time for 2× work (each node adds NFILES so per-round work is O(N); ROUNDS=24 fixed regardless of N). ~Near-linear; ~15% super-linear from 8-way contention. NOT pathological.

### Cost = #(necessary coherent FUA reads + DLM round-trips) × per-op latency (~0.5-1.8ms local iSCSI/TCP). No algorithmic waste, no CPU, no infra fix. dir_reuse has NO native-XFS equivalent (XFS isn't clustered) so RULE-0's "native×2 ceiling" is undefined for it.

### OPEN DECISION for criterion: (a) workload-derived per-test budget (RULE-0 expects budgets in TIMEOUT_BUDGETS.md; 300s blanket fits ≤4 nodes not the 8-node 2×-workload) — tension with RULE-0 "never widen to pass"; (b) deep DLM round-trip reduction (hard, may be impossible given necessary coherent I/O); (c) node-count-aware ROUNDS scaling (24→12 at N=8 keeps total bounded, per-round stress HIGHER) — test design change. 5 sessions (18-21) all hit this same wall: correctness solved, ~10-30s fundamental speed margin. See [[sess21-FIX-union-merge-rebase-shortform-reconciles-rename-miss-and-dir_reuse]] [[sess18run-STATE-8tcp-correct-at-mht275-speed-straddles-300s-need-10s]].
