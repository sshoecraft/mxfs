---
name: sess41-NEXT-isolate-real-loss-write-detector-confound
description: sess41 BREAKTHROUGH: the 240 P-DATACLOBBER hits are BENIGN (a PASSING run had all 240, same-incarn growth transients). Real loss is SEPARATE+rare/fla…
metadata:
  type: project
---

## sess41 BREAKTHROUGH — the P-DATACLOBBER clobbers are BENIGN; the real bug is intermittent.

### DECISIVE: a PASSING run (build 7F15D2EA, dataclobber=1 detect) had ALL 240 P-DATACLOBBER hits.
- Run baf55ruip: `PASS dir_reuse_coherency (nodes_pass=2/2)`, criteria.json dir_reuse 2/tcp → PASS (2026-06-20T04:59:47Z). YET 240 data clobbers fired (disk_cnt=buf_cnt+1), ALL SAME-INCARN (incarn==bincarn, 24 distinct incarns = 24 rounds, mode=5).
- ⇒ The disk_cnt=buf_cnt+1 / daddr=120 / xfsaild clobbers are **BENIGN intra-round growth transients** (each xfsaild flush momentarily 1 behind the next during concurrent create growth; the final block-0 state is correct). They are NOT the durable loss. GPT interpretation (B) CONFIRMED. The "6 failed rounds" seen in logs were STALE dmesg ring-buffer entries from the PRIOR failing run (dmesg --follow dumps the whole ring buffer at stream start).
- ⇒ ALL sess41 fix attempts (write-side skip, evict-side refresh) targeted BENIGN transients = misdirected. The write-side skip REGRESSED precisely because it suppressed benign/fresh writes.

### CRITICAL CAVEAT: the PASS is FLAKY / possibly a HEISENBUG. NOT reliable. Marker NOT written.
- dataclobber=1 does a SYNC disk read PER dir write → perturbs timing → can HIDE the race (like instr=1, [[sess39_lessons]]). So baf55ruip's PASS may be a detect-mode artifact, OR plain flakiness (baseline fails ~2/3).
- criteria.json now shows ALL 17 2/tcp tests PASS, but the dir_reuse PASS is a SINGLE flaky/perturbed run. "100% successful" = RELIABLE passing. DO NOT trust criteria.json's PASS; re-validate at PRODUCTION (dataclobber=0, NO modargs, NO per-write disk read = baseline behavior).
- IN PROGRESS at relay boundary: `bash tests/drc_loop.sh 5` at production config (dataclobber=0), nohup, output → tests/_cap/loop_summary.txt + drcloop_prod.out. NEXT SESSION: read loop_summary.txt for the true production pass rate. If <5/5 → still flaky, criteria NOT met.

### NEXT STEPS (revised priority)
1. Read tests/_cap/loop_summary.txt (production batch result). Establish true pass rate at dataclobber=0.
2. To find the REAL durable loss (rare): instrument WITHOUT perturbing timing (no per-write sync disk read — that hides it). Options: target-side (SCST) write journal for daddr-120 (GPT rec, zero initiator perturbation); OR a LIGHTWEIGHT initiator detector that only records (no disk read) the block-0 buffer's dirent-name set per write into a ring buffer, dumped on the test's verify-fail. Compare a FAIL run vs a PASS run.
3. The real loss is node1_f1..f14 (block-0 first-wave), lookup_fail=0, intermittent. Per GPT it's a cross-tenure stale flush / release-not-atomic-with-downconvert ([[sess41-GPT-diagnosis-release-fence-not-atomic-with-downconvert]]); but FIRST confirm the mechanism on a FAIL run with non-perturbing instrumentation, since the benign-transient detector misled this session.

### Tree: build 7F15D2EA = baseline behavior + dormant detector (dataclobber=0, dirrefresh=0 defaults). No enforce (both refuted). drc_loop.sh counts P-DATACLOBBER-SKIP. See [[sess41-FIX-tenure-gated-dataclobber-guard-AF02E775]].
