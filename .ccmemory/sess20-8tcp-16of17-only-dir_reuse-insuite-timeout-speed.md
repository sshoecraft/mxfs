---
name: sess20-8tcp-16of17-only-dir_reuse-insuite-timeout-speed
description: sess20(ccloop) MILESTONE build 4E047A49: FULL 8/tcp = 16/17, ONLY dir_reuse_coherency FAIL (0/8 = 300s in-suite TIMEOUT, NOT shutdown - 4 tests passe…
metadata:
  type: project
---

## sess20 (ccloop) — FULL 8/tcp = 16/17; last blocker = dir_reuse SPEED (in-suite timeout)

### Build `4E047A49` (default inode_mht_ms=300, dir_sf_mht_ms=100). FULL `./run.sh 8 tcp` (plain default):
PASS (16): precond_readiness, cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency, fence_during_write, fault_netpartition, soak, **tcp_dlm_scaling** (8/8 — the format-gated mht fix WORKS, see [[sess20-BREAKTHROUGH-format-gated-mht-shortform-dirs-low-mht]]).
FAIL (1): **dir_reuse_coherency 0/8**.

### dir_reuse 0/8 = in-suite TIMEOUT, NOT shutdown/corruption:
- 4 tests ran AFTER dir_reuse and ALL passed → FS was NOT shut down (no cascade). dmesg: no 'Shutting down', mount alive.
- dir_reuse STANDALONE with sf_mht=100 = **PASS 8/8** (TEST_TIMEOUT=420; real wall 5m37=337s incl ~60s prep → ~277s test). So it is CORRECT; it just exceeds the default 300s TEST_TIMEOUT when run in-suite (cumulative state slows it ~30-40s past standalone).

### dir_reuse SPEED analysis (phase markers, mxfs-DRCph): per round ~10s × 24 = ~240s + ~37s infra.
Per-round breakdown: create=0.5s (FAST — batched in one EX tenure at high mht), **create-done→DIRID barrier wait = 4.5-9s** (serialized 8-node create contention — barrier waits for the SLOWEST node; round7 had a 9s straggler), verify=0.65s, **rm=3.6s**. Dominated by SERIALIZED dir-EX contention + barrier-wait variance.
- LOWER mht = FASTER (mht=300→277s, mht=600→314s — higher mht serializes MORE). But low mht breaks dir_reuse coherency (the deep bug).
- mht tuning 250-300 saves only ~6s (slope ~0.12s/ms) — NOT enough margin.
- The dir is leaf/btree → uses inode_mht_ms=300 (format gate gives sf_mht only to shortform).

### CONCLUSION: dir_reuse ~277s is near the intrinsic floor for CORRECT 8-node clustered dir contention at its mht. To fit in-suite (<300s) reliably needs ~240s. Paths: (1) the deep coherency fix → dir_reuse correct at LOW mht → fast (~like tcp_dlm_scaling's interleaved pipeline) [[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]]; (2) reduce barrier-wait variance via create-handoff FAIRNESS (coherency-safe — about WHICH waiter, not hold time); (3) reduce in-suite cumulative overhead. NOTE: 1/tcp(16/16) + 2/tcp(17/17) verified on PRE-gate build 5C08C626 — must RE-verify on 4E047A49 (sf_mht=100). 4/tcp must also be re-checked (tcp_dlm_scaling now fast; dir_reuse 4-node ~? in-suite).
</body>
</invoke>
