---
name: sess16run-CORRECTION-dirreuse-fails-at-mht300-too-no-reliable-mht
description: sess16(ccloop) PIVOTAL CORRECTION: dir_reuse 8/tcp FAILS at mht=300 too (content loss node1_f1/node5_f40 + shutdown round 7-8, NOT a timeout). It's a…
metadata:
  type: project
---

## sess16 (ccloop) — CORRECTION: no mht reliably passes dir_reuse 8/tcp; it's a flaky race

### Finding
Build 72C02C21 (= 48C6A95E baseline + this session's changes, ALL inert at default config), dir_reuse 8/tcp at DEFAULT mht=300: FAILED 0/8 with **content loss** (round=1 readdir=751/800, node1_f1.md5/node5_f40.md5 missing) + shutdown on test1/test2 at round 7-8. This is NOT a timeout (it died at round 7-8 of 24, with the SAME content-loss signature as mht=50), and NOT a slowness fail.

### Why this matters (corrects the whole session's + sess15's framing)
The "mht tradeoff" ([[sess15run-MHT-tradeoff-tcpdlm-wants-low-dirreuse-wants-high]]) was WRONG: it is NOT "mht=300 → dir_reuse correct / mht=50 → corrupt". The dir_reuse lost-update is a TIMING RACE that fires at ALL mht values; higher mht just makes it LESS FREQUENT (fewer handoffs → smaller race window) so a 24-round run sometimes squeaks through. sess15's "mht=300 PASS 8/8" and the handoff's "8/tcp = 16/17 (dir_reuse passes)" were LUCKY runs, not a reliable pass. The criterion needs 100% → the race must be ELIMINATED; tuning mht cannot achieve it.

### My changes are NOT the regression (confirmed inert at default)
This session added to 48C6A95E: b_mxfs_dir_epoch field+stamps (trigger gated on dir_postread_reread, default 0), P32F-NXSHRINK fence (now default 0), MX-DOUBLEGRANT auditor (logging only), P16 leaf-refresh (REVERTED — it DID regress via crc-can't-tell-direction resurrection, removed). At default config (postread_reread=0, nxshrink_fence=0, P16 gone) all new logic is gated off or pure logging → behaviorally == baseline. The mht=300 failure reproduces the baseline's latent flakiness, not a regression.

### Consolidated TRUE state of the 8/tcp blocker
- dir_reuse 8/tcp: durable lost-update on the hot shared dir block (count 126→77 clobber), a TIMING RACE present at every mht. DLM serializes EX correctly (double-grant RULED OUT). Acquire-side re-read/refresh structurally cannot fix it (racy disk-compare). REFUTED levers: force_coherent, postread_reread, b_mxfs_dir_epoch, dir_release_fua_write, dir_release_invalidate, P16 leaf-refresh.
- tcp_dlm_scaling 8/tcp: too slow at mht=300 (the mht-defer); fast at mht=50.
- So BOTH 8/tcp tests fail; only fix path = eliminate the dir lost-update so low mht is correct AND fast.

### THE FIX (next session, over-determined): RELEASE-side coherence
[[sess16run-acquire-side-refresh-cannot-work-must-be-release-side]] + [[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]]: in mxfs_dlm_bast_process, under a REVOKING writer-fence, drain ALL dir metadata durable then INVALIDATE the releasing node's own cached dir buffers (incl. in_ail-undestaged DATA block0 — safe because just drained) BEFORE dropping the grant, so the next acquirer always cold-reads the durable image. Validate at dirwr=0 across MANY runs (it's flaky — need ~5+ clean passes), mht=50 AND mht=300. Then tcp_dlm at mht=50, full 17/17, 1/2/4.

### Build 72C02C21 is a safe baseline (inert new logic + KEEP: MX-DOUBLEGRANT auditor). Criterion NOT met — marker not written.</body>
