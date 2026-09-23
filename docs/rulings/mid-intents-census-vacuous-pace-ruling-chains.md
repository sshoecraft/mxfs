<!-- sess436 01:40Z: intents census proven VACUOUS (note inside the loop the ATOMIC-SKIP verdict returns before) -> pre-verdict pass in 0.41.8 (chain3 gat… -->
# sess436 mid-session state (01:40Z)

## Rig / chains
- Fleet on 0.41.7 sv 2BFBAF3D (dbg_efd_hold_ms knob, xfs/xfs_extfree_item.c). Chain 2 (tests/sess436_chain2_0417_intents_mht.sh, log tests/evidence/sess436_chain2_0417_intents_mht_s436b.log) running: burst arm done (rc=124, intents=0 — see below), then inode_mht_ms sweep 0/10/50/300 on crash_consistency with per-value P138 journal capture + tests/cc_tenure_modesplit.py reports in tests/evidence/sess436_chain2_0417_intents_mht_s436b/mht<N>/.
- Chain 3 (tests/sess436_chain3_0418_intents.sh, gated on chain 2 DONE): builds 0.41.8 (census pre-verdict pass), preps, burst lap, prep. Log tests/evidence/sess436_chain3_0418_intents_s436c.log.
- Tree VERSION 0.41.8 (unbuilt until chain 3).

## D-FOREIGN-SLICE-INTENTS-ABANDONED
- Old burst arm: 8-file rm = 1.35 s (destroy at 2 s always idle); 48 files still intents=0 (frees run in inactivation). Deterministic arm: dbg_efd_hold_ms=60000 on V, wait P-EFD-HOLD start, destroy → still intents=0.
- ROOT (proven, tests/evidence/20260829T012712Z_intents_burst/journal_test1.txt): window = 2 txns, both ATOMIC-SKIP whole; mxfs_icensus_note lived inside the item loop after the verdict early-return (xfs_log_recover.c ~4103). Fixed in 0.41.8: pre-pass notes intents/dones for every batch before the verdict.
- Harness: TERM trap now captures dmesg (timeout laps lost evidence).

## D-401 / D-32NODE-SHARED-DIR-CREATE-PACE
- Mode split anatomy (tests/evidence/sess436_tenure_modesplit/report.txt): EX one-at-a-time every 310 ms = inode_mht_ms=300 tenure; holder does ~13 serial O_SYNC creates (23 ms each) per tenure; release 9 ms; handoff 10 ms.
- All three MHT arm sites are grace-sliced (10 ms) and lastop is stamped at every ilock_end, yet tenures are full-window: suspect the dwork's busy gate (i_dlm_pin_count>0 during each file fsync / holders during the next open) never samples a >=10 ms quiet gap; the sweep discriminates (MHT=10 vs 300 vs 0).
- RULE-5 ruling banked: docs/rulings/shared-dir-create-pace-mht-delegation.md (short term: MHT as max useful quantum + direct baton + successor-only poll + aging; real fix: dir delegation/op combining or physical sharding). docs/perf.md updated.

## Other
- D-0359 step 2 (SNLOCAL_EXCLUSIVE) not started; UNGATED-IMAGES steps 7-10 not started.
