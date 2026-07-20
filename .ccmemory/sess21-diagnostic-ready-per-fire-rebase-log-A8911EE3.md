---
name: sess21-diagnostic-ready-per-fire-rebase-log-A8911EE3
description: sess21(ccloop) DIAGNOSTIC READY build A8911EE3: per-fire P21-RB rebase log (non-perturbing — rebase fires <256/test). Run dir_reuse 8tcp repeatedly u…
metadata:
  type: project
---

## sess21 (ccloop) — diagnostic build A8911EE3 ready for the dir_reuse shortform-phase race

### Build A8911EE3859F78F3CEAA409 = keeper 7B66691E (union merge + offset fix) + sess21 NON-PERTURBING diagnostics:
- **P21-RB** (per-fire, capped 4000): logs EVERY mxfs_dir_rebase_shortform fire with `ino own_work incore_cnt disk_cnt incore_bytes disk_sz comm`. Rebase fires RARELY (the dir is BLOCK format after ~8 entries; rebase only runs in the brief per-round SHORTFORM phase — PROVEN: 8tcp full dir_reuse produced <256 fires, the every-256 P21-RBSTAT never dumped). So per-fire pr_warn is LOW-FREQUENCY and does NOT perturb the race (unlike dirwr's hot-path flood which HID it).
- **P21-RBSTAT** (every 256 fires): aggregate genbail/cohskip/merged/adopted counts (rarely dumps — use P21-RB instead).

### KEY new findings this session:
1. **dir_reuse 8tcp is FLAKY**: with the counter build it PASSED 8/8 (failrounds=0); other runs it loses (readdir=799). The race fires ~half the runs. MUST run repeatedly (3-5×) to catch a loss.
2. **Rebase fires RARELY** (<256/whole test) → the loss is in the per-round SHORTFORM phase (first few entries after each rm-rf+recreate), governed by dir_sf_mht_ms. The union merge is largely IRRELEVANT to the steady-state block-format dir; it matters only in that shortform window.
3. The dir is block-format for the bulk of each round → the off-by-one entry is lost during the shortform→block growth window at fast (low-mht) handoff.

### NEXT SESSION — run the diagnostic:
1. Clean reboot 8. `MXFS_EXTRA_MODARGS='' TEST_TIMEOUT=600 ./run.sh 8 tcp dir_reuse_coherency` — repeat until a node logs `drc-FAIL readdir=799`. 
2. On the FAILING node, read `dmesg | grep P21-RB` around the failing round: does a rebase fire with **incore_cnt < disk_cnt** (node's base missing a peer's durable entry) followed by a path that does NOT pull it in? Or does the rebase NOT fire at all for that create (the loss is a BLOCK-format RMW with no shortform rebase)? Either answer pins the locus.
   - If P21-RB shows incore_cnt<disk_cnt but own_work=1 → merge should fix; check if merge actually ran (P21-RBSTAT merged count) or bailed (width/overflow).
   - If NO P21-RB near the loss → the loss is BLOCK-format (sess68 EVDECIDE=0 territory: mxfs_dir_evict_data_blocks never iterates → stale block0 RMW). Move instrumentation to the block-format modify path.
3. Keep build's offset fix (load-bearing). Remove P21 probes once root found.

### Constraints recap: dir_sf_mht MUST stay low (tcp_dlm_scaling 60s/150-round window, path-2 dead). So the fix is to make the shortform-phase (or block-conversion) coherent at LOW mht. See [[sess21-dir_reuse-lowmht-race-negatives-and-precise-localization]] [[sess21-CRITICAL-mht-tradeoff-NOT-resolved-format-gate-broke-dir_reuse-correctness]] [[sess68-LEAD-evict-data-blocks-never-runs-EVDECIDE0]].
