---
name: sess15run-MHT-tradeoff-tcpdlm-wants-low-dirreuse-wants-high
description: sess15(ccloop): inode_mht_ms is the 8/tcp speed/correctness knob with OPPOSITE needs: tcp_dlm_scaling PASSES 8/8 at mht=50; dir_reuse CORRUPTS at mht…
metadata:
  type: project
---

## sess15(ccloop) — inode_mht_ms is the 8/tcp speed/correctness knob (OPPOSITE needs)

After the P58 fix (build 48C6A95E, KEEP), BOTH remaining 8/tcp blockers are DLM-acquire SLOWNESS. `inode_mht_ms` (EX minimum-hold-time, default 300ms) is the dominant knob — but the two tests need OPPOSITE values:

### tcp_dlm_scaling (PASS criterion: per-node 150 rounds within WINDOW=60s)
- mht=300 (default): elapsed **73-119s/node**, P36-RETRY ~25-45/node → **FAIL 1/8** (only the fastest node ≤60s).
- mht=50: elapsed **5-22s/node**, P36-RETRY ~1-3/node, P58=0, no corruption → **PASS 8/8.** ✅
- So tcp_dlm_scaling wants LOW mht (less per-handoff defer → less acquire churn).

### dir_reuse_coherency (PASS criterion: readdir/lookup coherence over 24 rounds)
- mht=300 (default): CORRECT (PASS 8/8 at TEST_TIMEOUT=900) but SLOW (~630s).
- mht=50: fast (fits 300s, all 24 rounds) but **readdir=0/800 + Corruption-detected SHUTDOWN (sh=1, NOT P58)** → FAIL 0/8. Too-aggressive handoffs → dir-block coherency corruption.
- mht=150: also **FAIL 0/8** (failed ~round 8, sh=0 — content/coord).
- So dir_reuse wants HIGH mht (batch dir-EX modify, avoid stale-base RMW dir-block lost-update / the sess69 cross-node stale-read-cache class).

### Implication / NEXT
A single global mht can't satisfy both. Options for next session:
1. **Make dir handoffs fast AND correct** so low mht is safe — fix the underlying dir-block coherency (the corruption at low mht; sess69 cross-node stale-read-cache-hit RMW base poisoning is the known root, fix belongs on the READ/invalidation side). Then set mht low for everyone.
2. **Adaptive/scoped mht**: keep EX-hold high ONLY for dir DATA-modifying tenures (create/rename/remove that RMW dir blocks), low for everything else (esp. reads/the verify BAST-defer). mht only gates EX, but a dir read BASTs an EX-holding creator who defers mht — that defer is what slows dir_reuse verify AND is needed for create correctness.
3. Find a middle mht that's correct for dir_reuse AND <300s AND keeps tcp_dlm ≤60s — mht=150 already breaks dir_reuse, and mht=300 is too slow for tcp_dlm, so the window is narrow/empty → option 1 or 2 likely required.

Probe levers: `mxfs.inode_mht_ms=<N>` (MXFS_EXTRA_MODARGS). dir_reuse low-mht corruption is the SAME dir-coherency family the project has fought for ~90 sessions; the P58 fix removed ONE face (resurrection), this is another (stale-base dir-block RMW). See [[sess15run-FIX-P58-rel-abort-VERIFIED-tcpdlm-now-slowness-only]] [[sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base]].
