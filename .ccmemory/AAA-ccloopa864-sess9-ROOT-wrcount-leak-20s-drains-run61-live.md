---
name: AAA-ccloopa864-sess9-ROOT-wrcount-leak-20s-drains-run61-live
description: sess9 ROOT UNIFIED: wedge#2 double-submit leaks m_mxfs_dir_wr_inflight → every dir release pays 2×10s barrier (P51-REL drain_ms=20s) → 32-node convoy…
metadata:
  type: project
---

# sess9 ROOT — the r10+ collapse chain fully unified (RULE-4 proven)

## The chain (each link evidenced)
1. A counted dir-metadata write's completion misses its decrement (wedge#2 mis-route family; exact origin path = watch P-WRCNT-RESUBMIT ring dumps).
2. `m_mxfs_dir_wr_inflight` leaks +N permanently (run58 stuck probe: dir_inflight=3; run60: rank1 stuck nonzero from ~r10).
3. EVERY subsequent dir EX/PR release pays the FULL wr-barrier bound at BOTH wait sites (xfs_mxfs_dlm.c 12385 + 13399, each `5000×msleep(2)`=10s) → **P51-REL drain_ms=20013/20022/20069/20235** (exact-20s signature, PR and EX legs both; rank1 run60 t=2128→2924 continuously).
4. Convoy: 31 EX waiters × 20s-per-handoff → gen/slot frozen 32+s (rank3 siege t=2151-2183 gen=647 hex=1=rank1) → waiters blow the 120s acquire budget → rc=-110 → shutdown; repeat each wave (run59: 27 nodes at r13; run60: 1 at r11 wave-1, 18 by r12 wave-2 — rank1 the leaker survived, kept freezing the convoy).
5. Post-shutdown zombie contention (defect A) amplified run59; FIXED in 0.10.60 (withdraw): run60 wave-1 rank3 fenced 12ms after shutdown, all 31 peers purged it, NO zombie EX, cluster continued — the fix works; it just can't save a run whose convoy keeps freezing.

## Fixes in 0.10.61 (srcver 65CA8C4E, run61 live 17:00:28Z)
- **Leak neutralizer** (pal/linux/xfs_buf.c, xfs_buf_submit_bio counter site): if `b_mxfs_dir_wr_counted` already true at submit (pending count never decremented — the double-submit shape; the old code RESET the flag then re-inc'd = permanent +1 leak), keep the single count, log `P-WRCNT-RESUBMIT` with the buffer's event ring (decode: scripts/decode_bufev.py).
- **P40-WRBARRIER-LONG** (xfs_mxfs_dlm.c 12389): always-on ratelimited print when the drain wr-barrier waits ≥1000ms — residual-leak visibility at default instr. (P3B site already prints on any wait.)
- Residual risk (known, deliberate): a leaked count on a buffer never resubmitted stays leaked (cached-read hits don't re-enter submit_bio). If P40-WRBARRIER-LONG still fires with inflight stuck >0 in run61 → add counter repair informed by the P-WRCNT-RESUBMIT ring evidence (origin path).

## Slot facts learned (defect-B side notes)
- CAW slot table NOT filling (159/65536 slots in use at r10 = 0.2%) — table-fill hypothesis REFUTED by live count.
- Healthy handoff rate ~13/s (~75ms) measured mid-run when convoy unfrozen; rotation drains waiters fairly when moving.
- Slot for ino131 gets RECREATED (gen reset 509→1, waiter bits wiped) when transiently holder+waiter-free — waiter registration is transient by design (nodes re-register per poll); benign when the convoy moves.
- Slot dump one-liner (from test1): python3 read /dev/mapper/mpatha @67149824+i*512; magic 0x4d584357; ino @+16; hex/hpw/hpr @40/48/56; waiters@80; gm/wm@88/89; wex@120; dir_epoch@128; last_ex_slot@132. disklock_offset=67117056 (chk_mxfs -v), lock region=+32768.

## Run61 watch list
- P51-REL drain_ms should stay ≪20000 ALL 24 rounds (the decisive metric).
- P-WRCNT-RESUBMIT fires = leak origin caught (decode ring!).
- P40-WRBARRIER-LONG = residual leak → needs repair pass.
- No rc=-110 / no shutdowns / drc-FAIL=0 → then rerun 2-3× for stability before recording PASS + YES.
- Pace: r1-r9 ~84-130s/round; degradation to ~5min/round = leak recurrence signal even before failures.

## Ops
- kill patterns MUST be self-match-safe: pkill -9 -f '[t]imeout 4480'; pkill -9 -f '[d]ir_reuse_coherency.sh'; pkill -9 -x sshpass; rm -f /tmp/mxfs_run.lock. (A plain 'timeout 4480' pattern killed MY OWN shell mid-command once.)
- criteria.json lifecycle now: PENDING={status PENDING, reason "running <id>"} only while live; EXIT-trap → FAIL on abort; fail_stale_pending() heals kill-9 leftovers at next run.sh start (user-requested fix, done this session).
