---
name: sess21-CRITICAL-mht-tradeoff-NOT-resolved-format-gate-broke-dir_reuse-correctness
description: sess21(ccloop) CRITICAL CORRECTION: sess20's format-gate (dir_sf_mht=100) did NOT resolve the mht tradeoff — it made tcp_dlm_scaling fast but BROKE d…
metadata:
  type: project
---

## sess21 (ccloop) — the mht tradeoff is NOT resolved (corrects sess20)

### PROVEN this session (build 7B66691E, clean reboots):
- **dir_sf_mht_ms=100** (sess20 format-gate default): tcp_dlm_scaling 4/tcp PASS (merge fixes rename-miss) BUT **dir_reuse 8/tcp = readdir=799 off-by-one CORRECTNESS FAIL** (durable, all 8 nodes agree, rounds 1+4; even at 600s timeout).
- **dir_sf_mht_ms=300** (sess18-like high): **dir_reuse 8/tcp = PASS 8/8** (correct!) BUT **tcp_dlm_scaling 8/tcp = FAIL 2/8** with reason "tds nodeN **within window**" (RENAME-MISS=0, shutdown=0 → pure SPEED/handoff-slowness failure, not correctness).

### So sess20's format-gated MHT (dir_sf_mht_ms=100 for shortform dirs) was a MISDIAGNOSIS: sess20 claimed it resolved the 19-session tradeoff and that dir_reuse failed ONLY on timeout. WRONG — dir_sf_mht=100 BROKE dir_reuse CORRECTNESS (the off-by-one). Both dir_reuse's growing-dir-shortform-window AND tcp_dlm_scaling's churn dir are SHORTFORM → they share dir_sf_mht_ms → the tradeoff is unescaped by the format gate.

### THE REAL TRADEOFF (unresolved):
- dir_reuse needs HIGH shortform mht (≥~275, sess18 floor) for CORRECTNESS — low mht's fast handoff causes a durable single-entry dir-block lost-update during the shortform→block growth/conversion under concurrent 8-node creates (sess68 write-side loss family: a node RMWs a stale dir block missing a peer's just-added entry and writes it back durably).
- tcp_dlm_scaling needs LOW shortform mht for SPEED — high mht's slow handoff makes nodes miss the "within window" op-count threshold.

### PATHS to truly resolve (pick one, next session):
1. **Fix dir_reuse off-by-one at LOW shortform mht** (keep dir_sf_mht=100, both pass): the deep write-side dir-block lost-update during shortform→block conversion under fast handoff. sess68 leads: P68-EVDECIDE=0 (mxfs_dir_evict_data_blocks never iterates → block0 not evicted before RMW); sess68 PROVED it's write-side (FUA-read enabled still fails). The union merge (sess21) handles the shortform REBASE clobber but NOT this conversion-time write-side loss. THIS is the highest-value fix — would also likely fix the broad 8-node flakiness (same RMW-on-stale-base wedges strong_consistency/posix_multi).
2. **Make tcp_dlm_scaling fast at HIGH mht** (keep dir_sf_mht=300, both pass): harder — high mht IS the slowness; would need to decouple correctness-hold from handoff-latency.
3. **Better discriminator than format**: dir_reuse's dir GROWS (converts to block); tcp_dlm_scaling's STAYS tiny shortform. Gate mht on dir-will-grow / entry-count / has-converted, not just current format.

### KEEP build 7B66691E (union merge + offset fix — offset fix removes a real corruption, load-bearing). Default dir_sf_mht_ms=100 currently → dir_reuse off-by-one. See [[sess21-FIX-union-merge-rebase-shortform-reconciles-rename-miss-and-dir_reuse]], [[sess68-LEAD-evict-data-blocks-never-runs-EVDECIDE0]], [[sess68-FUA-refutes-readside-loss-is-writeside-same-incarn]], [[sess18run-STATE-8tcp-correct-at-mht275-speed-straddles-300s-need-10s]].
