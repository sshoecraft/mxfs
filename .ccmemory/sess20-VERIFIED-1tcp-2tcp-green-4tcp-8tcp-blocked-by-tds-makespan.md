---
name: sess20-VERIFIED-1tcp-2tcp-green-4tcp-8tcp-blocked-by-tds-makespan
description: sess20(ccloop) VERIFIED at default mht=300 build 5C08C626: 1/tcp=16/16 PASS, 2/tcp=17/17 PASS (both GREEN). 4/tcp=16/17, 8/tcp blocked — SOLE failing…
metadata:
  type: project
---

## sess20 (ccloop) — concrete criteria status: 2 of 4 node counts GREEN; blocker precisely isolated

### Build `5C08C626`, default mht=300, MXFS_EXTRA_MODARGS='' (plain `./run.sh N tcp`). Clean reboots.
- **1/tcp = 16/16 PASS** ✓ (no tcp_dlm_scaling at 1 node; min_nodes=2).
- **2/tcp = 17/17 PASS** ✓ (tcp_dlm_scaling passes at 2 nodes — enough window margin).
- **4/tcp = 16/17**: ALL pass except **tcp_dlm_scaling 2/4** (in-suite elapsed test1=70s test3=70s >60s window; test2=55 test4=49; rounds=150/150 ALL = CORRECT). Standalone 4-node passed at 45s — the 6s margin dies under in-suite cumulative slowdown.
- **8/tcp**: tcp_dlm_scaling fails (126s); dir_reuse + others pass at mht=300 (see [[sess20-SCOPE-sole-blocker-is-8node-tcp_dlm_scaling-makespan]]).

### THE SOLE CRITERIA BLOCKER = tcp_dlm_scaling MAKESPAN at 4+8 nodes. It is CORRECT (150/150 rounds, dir drains) but exceeds the 60s per-node WINDOW. NOT a coherency bug.

### Mechanism (mht enforcement = `mxfs_dlm_mht_defer_bast` xfs_mxfs_dlm.c:7681): on a peer BAST, the EX holder DEFERS release until held ≥ mht_ms (keeps cached, own ops fast-path). At 8 nodes mht=300 the makespan is 126s with a HUGE rank spread (rank8=33s, rank1=126s) = grant-queue STARVATION/unfairness (not FIFO). At mht=100 → 43s (fine-grained interleave). So makespan is inflated by (a) coarse high-mht batching + (b) unfair grant scheduling.

### TWO non-coherency levers for tcp_dlm_scaling makespan (next session), BOTH avoid touching dir_reuse's mht/handoff-frequency:
1. **Grant-queue FAIRNESS** (FIFO/round-robin so no node starves to 126s). Orthogonal to mht → does NOT increase dir_reuse handoff frequency → coherency preserved. Prior art: sess50 defer_for_waiter, sess49 fairness. UNKNOWN if fairness alone gets 8-node under 60s (avg may be ~80s).
2. **Idle-hold cap**: release early when holder has NO pending queued ops AND a BAST is pending (cut idle-hold waste) — BUT this raises handoff frequency → risks dir_reuse (test before trusting).

### If neither makespan lever suffices, fall back to fixing dir_reuse coherency at low mht (then low mht serves both) — deep AG/extent layer, see [[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]].

### NEXT: investigate the TCP DLM grant/waiter queue ordering in dlm/ (is it FIFO?); try a fairness fix; re-measure 8-node tcp_dlm_scaling makespan. Keep mht=300 default (best for 1/2 + dir_reuse).
</body>
</invoke>
