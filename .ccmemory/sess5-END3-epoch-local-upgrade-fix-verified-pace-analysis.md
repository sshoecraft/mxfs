---
name: sess5-END3-epoch-local-upgrade-fix-verified-pace-analysis
description: sess5 END3 (build E0915A1C): local-upgrade dg_grant_ex epoch hole FIXED+verified (dangerous-unest 95→34, runs 37-39 zero correctness failures). Sole…
metadata:
  type: project
---

# sess5 END3 — build `E0915A1C5A2E18EC3234E96` (deployed, in tree)

READ WITH [[sess5-THREE-ROOT-FIXES-p5f-p91bast-abba-plus-remaining]] [[sess5-END-abba-grow-stack-proven-design-next]] [[sess5-END2-run37-dirent-loss-epochplace-unestablished]].

## FIX 6 (this file's headline) — local-master upgrade epoch hole, dlm.c dlm_lock_impl conv_compat (~line 1305)
run38 wire census: 1336 EX grants rx'd for ino-131, only 2 with dir_epoch_rx=0 — yet 181 placements read master_ep=0 (P2-EPOCHPLACE unestablished=1). Split by danger (valid_ep>0): master node (test5) 61 dangerous, ALL from local PR→EX upgrades — the LOCAL conv_compat path was the only one of 4 grant/upgrade sites that never called dg_grant_ex (remote twin at ~3195 does), so the master's own mirror kept dir_epoch=0 → every epoch-gated dir coherence guard inert for the master's own tenures → stale-base RMW → the residual single-dirent loss (run34 r9 node3_f11.md5, run37 r18 node6_f30 — that one placed via P13-STALEREAD onto a near-empty stale image). FIX: stamp gen + dg_grant_ex (handoff/dir_epoch) exactly like the remote-upgrade twin.
**run39 (default): dangerous-unest 95→34 (master-side → 0), ZERO drc-FAIL/shutdown/-110 for 19 rounds.**
Remaining 34 dangerous-unest all on rank1 (test1) — mechanism unidentified (NOT the run-start fresh-epoch kind; those are the separate 86 harmless valid_ep=0). No loss observed from them in runs 38-39. Next: sample one (P2-EPOCHPLACE valid_ep>0 on test1) and trace its grant path — candidate: PR-grant messages always carry dir_epoch=0 (promote path stamps EX only) → PR-mirror fresh-insert after a drop leaves 0 until next EX rx; if rank1's EX comes via CACHED fast path (no message) the mirror keeps 0.

## Probes added: P51-SENDGRANT now CAPPED 60k (was ratelimited); P5H-GRANT-EPOCH-RX capped 60k (dlm.c process_remote_grant) — full per-grant epoch wire visibility for ino 131.

## Scoreboard after runs 37/38/39 (all default modargs, 595s cap):
- correctness: **three consecutive zero-failure runs** (no shutdowns, no -110, no dirent loss, no danglers) — every prior failure family closed.
- SOLE remaining blocker: pace. 26-27s/round → hits 480s cap at round 18-20 of 24.

## Pace anatomy (run39 r11, DRCph markers):
- create wave: rank1 0.7s; slowest rank ~10.5s (barrier waits for slowest). ≈100 creates/node × ~80-90ms effective.
- verify: ~5s. rm-rf (rank1, 800 files): **10.8s = 13.5ms/unlink** (cross-node ino-EX handoff from each file's creator ~10ms + bounded ifree drain 1-3ms).
- P36-RETRY 1.02s stalls: ~24/node/run ≈ 10/round cluster-wide (≈2-4s/round critical path). P37-GRANT-RECV matched=0 = ZERO (grants never late) ⇒ retries are promote-misses: original WAITING entry not promoted on holder release (find why — master-side promote path; check P37-RREL promoted=0 correlation with waiter timeouts).
- printk volume ~150k lines/node/run ≈ few seconds only — not the deficit.
- Healthy reference: 332s standalone (~14s/rd, sess21 build 4E047A49 "union-merge"). Current ≈1.9× that. Per-handoff latency breakdown via realns cross-node correlation (P138-BAST dur_us, P106-EXREL drain_ms, grant/release wire timestamps) is the next measurement.

## Next-session ladder
1. Pace: (a) fix promote-miss → kill 1s retries; (b) per-handoff latency breakdown → cut the ~10ms handoff (drain_ms? net? MHT 4ms sampling?); target ≤20s/rd. Do NOT widen budget (RULE 0).
2. rank1's 34 dangerous-unest (above).
3. 8/tcp ×5 consecutive clean PASS → 4/2/1 → full `./run.sh N tcp` suites N∈{1,2,4,8} → YES.
Cluster: 8 VMs up, build E0915A1C. Ledgers runs 29-39 in scratchpad.
