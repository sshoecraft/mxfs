---
name: ccloop-c7ee71c6-sess224-board-fail-attributed-28-ctxlock-fix-480-verified
description: sess224: 21:05Z board FAIL attributed to #28 fresh-fs create pace (cells PASS standalone, cc at 80s/90s!); #27 ctx->lock purge fix landed 0.11.480 sv…
metadata:
  type: project
---

# sess224 — board-FAIL diagnosis closed + #27 fixed and verified

## 1. 21:05Z board FAIL (rsync_paired + crash_consistency NO_TERMINAL_RECORD=32) — ATTRIBUTED
- Fleet sweep all 32: 0 real I/O errors (sess223's "132 on test1" = benign
  P144-EPOCH-FREE-RESET matching 'reset' — TRAP: exclude '] mxfs' lines).
- tests/shared_dir_pace.sh 32 50 on the SAME failing fresh fs, idle:
  C_contend wall p50=13.5s max=16.5s (per-create p50=10ms max=11064ms,
  bimodal tenure-rotation); D_private max 2.4s; nativeref 0.09s.
  Reproduced P34-ACQ-SLOW isdir=1 dur_ms=7305 idle (board had 11.7/12.4s).
- Isolation: fresh prep (73s) then standalone on 0.11.479:
  rsync_paired PASS 14s/60s (hostload 15.2!), crash_consistency PASS
  **80s/90s** (hostload 17.6 ≈ board's 18.45).
- CONCLUSION: crash_consistency on virgin fs rides ~90% of budget on
  .479; board lap tipped over by jitter => harness kill at 90s mid-verify
  => NO_TERMINAL_RECORD everywhere. This is ledger #28
  D-32NODE-SHARED-DIR-CREATE-PACE (open, major) manifesting, NOT infra,
  NOT a degraded node, NOT the build. Budgets stay AS-IS per RULE 0;
  fix routes through #28's "mount-global O(N) create term" root
  (next: tests/cc_stackprof.sh FOCUS re-rank on virgin-fs cc).

## 2. #27 D-RECOVERY-CTXLOCK-HOLD-HB-STARVATION — FIXED AND VERIFIED (31 open)
- Finished sess222's mid-edit per GPT ruling: purge_lock held across
  whole mxfs_disklock_purge_node (hb never takes it; order
  purge_lock->ctx->lock), ctx->lock per-I/O (phase-0 reads, scan reads,
  every purge_cas_zero, retry re-reads, HB-scan), phase 0 via
  purge_recov_gate + remembered gate_off, amortized ~2s mid-scan
  revalidation (-ENOENT => gate_found=0 continue; refusal =>
  P234-PURGE-REFROZE-MIDSCAN stop). Proof callers don't hold ctx->lock:
  old code took it at entry.
- 0.11.480 sv 567D9BDA19C009274B87A73. make clean wiped tools —
  needed make tools before prep (mkfs_mxfs missing broke prep once).
- Verify: incident474_load_kill.sh 32 test31 180 (kill 21:49:31Z):
  test1 owner P163-RECOVERY-COMPLETE 21:51:09Z, purge published,
  ZERO P-HB-SLOW fleet-wide (probe: cycle>2s incl lockwait OR hb later
  than 2x interval) vs 34978ms on .479. No P229/P234/P235. No withdraw
  stamp in window (facet vacuous; same mechanism removed).

## State at handoff
- Fleet: 0.11.480 deployed 32/caw, fs fresh-prepped 21:47Z + load474
  residue; test31 virsh-restarted but NOT rejoined (needs prep).
- criteria.json: rsync_paired + crash_consistency PASS cells recorded
  (21:35/21:36Z runs on .479); board otherwise stale.
- NEXT: full board on 0.11.480 cell-by-cell FOREGROUND (never background
  near relay) — serves #20 closure board. Then #28 root re-rank.
