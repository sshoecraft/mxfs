---
name: sess20-mht-tradeoff-no-single-value-coherency-fix-required
description: sess20(ccloop) QUANTIFIED mht tradeoff: NO single mht passes both. tcp_dlm_scaling=pure SPEED (correct 150/150 always, window 60s: mht300=126s FAIL,…
metadata:
  type: project
---

## sess20 (ccloop) — the mht tradeoff QUANTIFIED; single-value sweet spot does NOT exist

### Suite reality: `tests/tcp/tcp_dlm_scaling.sh` and `tests/suite/dir_reuse_coherency.sh` BOTH run on shared /dev/sda under the ONE suite mht (prep_node.sh insmod). NOTE: the SHIP-criterion `tests/criteria/tcp_dlm_scaling.sh` wraps `scripts/qnap_scale.sh` (separate /dev/sdb QNAP, reloads its OWN module) — that one IS decoupled, but /dev/sdb is ABSENT in this cluster so it is NOT what runs in `./run.sh N tcp`. The SUITE version is coupled.

### tcp_dlm_scaling = PURE SPEED test (correctness always fine):
- Each node: 150 rounds of `echo>f; mv f f.done; rm f.done` on a SHARED dir. PASS = all 150 rounds AND per-node elapsed ≤ 60s WINDOW AND dir drains to 0.
- Mechanism: high mht SERIALIZES (each node batch-holds the dir-EX ~16s, 8 nodes → last finishes ~126s). Low mht INTERLEAVES (round-robin, all finish ~together).
- MEASURED (build 5C08C626, 8/tcp): mht=300 → rounds=150/150 all nodes (CORRECT) but elapsed worst=126s (ranks 1/2/3 >60s) → 1/8 PASS. mht=100 → worst=43s → **8/8 PASS**. Extrapolated ceiling ≈ mht 130.

### dir_reuse = CORRECTNESS test, gradual cliff (higher mht = more rounds before bug fires):
- MEASURED: mht=300 → clean 24/24 → **8/8 PASS** (~270s). mht=100 → first loss rnd10, shutdown ~rnd22 → FAIL. mht=50 → loss rnd7 → FAIL. Floor to clear all 24 rounds ≈ 250+.
- High mht "passes" only by REDUCING handoff frequency so the coherency bug rarely fires — NOT a real fix.

### CONCLUSION: tcp_dlm_scaling ceiling (~130) < dir_reuse floor (~250). NO overlap. A single global mht CANNOT pass both. Per-test mht decoupling via test-set module params = GAMING (rejected — hides a real FS limitation). The ONLY honest path = fix dir_reuse handoff coherency so it is correct at LOW mht; then low mht serves BOTH. Root = [[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]] (stale leaf FIXED) + deeper stale-extent-map/AG-double-alloc (unsolved, sess38-47 family).

### Validated baselines this session (build 5C08C626): dir_reuse 8/8 @ mht=300 default; tcp_dlm_scaling 8/8 @ mht=100. Both standalone, clean reboot.
</body>
</invoke>
