---
name: sess52-FINAL-serialization-hole-block0-contention-grant-ordering
description: sess52(ccloop) FINAL: confirms sess50 — dir_reuse loss is a DLM serialization/grant-ordering hole, NOT cache. P51-MOD shows all nodes funnel to block…
metadata:
  type: project
---

## sess52 (ccloop 4cb2d0a2) FINAL — confirms sess50: serialization hole, not cache

### Session arc (all evidence-backed)
1. **Refuted sess51 "breakthrough"** `dir_ex_revalidate=1`: fresh cold-reboot run → round-16 readdir=799 durable loss. repro9's 8/8 was a ~25% flaky fluke. Also refuted this session: `dir_write_merge=1` (WEDGES cluster ~round16), `dir_postread_reread=1 dir_postread_leaf_only=0` (P67 fired ~1×, blocks already coherent).
2. **GPT consult #1** (release-side EX-demotion barrier): ALREADY fully implemented+on (release fence xfs_mxfs_dlm.c:9557, unbounded data_durable loop + log_force SYNC + ail_push + FUA bwrite + blkdev_flush). Not the gap (sess44 whole-AIL push also refuted).
3. **GPT consult #2** (epoch-gate at da_read_buf, disable readahead, assertion-at-log-join, grant handshake): readahead already off (dir_no_reada=1); da_read_buf epoch gate exists (P67); the assertion led to the decisive probes.
4. **P28-PLATTER MATCH** (xfs_dir2_node.c:2074, FUA-compare in-core vs platter at addname): overwhelmingly MATCH (e.g. 564/2 per node); the clobbered block daddr=6279744 showed `b_epoch=378 valid=385 incore_vs_platter=MATCH` → **the DATA base is COHERENT at modify**. My P-STALEBASE-MODIFY probe (epoch<valid) is a FALSE POSITIVE (epoch-lag ≠ stale; block unchanged since 378 still MATCHes). This independently re-confirms **sess50: base always fresh → loss is a DLM serialization hole** (xfs_mxfs_dlm.c:19840 dir_relepoch_reread=0 INERT comment).

### DECISIVE NEW EVIDENCE — P51-MOD probe (build 34ED34B2, xfs_dir2_data.c:xfs_dir2_data_log_entry, gated dirwr=1)
Logs every storm-dir DATA modify with `dlm_mode, master_self, held, grant_gen, realns, comm`. FAIL run (node3_f43 lost, round 16). Findings:
- **ALL nodes funnel modifies into block 0 = daddr=120** (the dir's hot first data block); every node adds its `nodeN_f1`/`nodeN_fX` there in tight succession.
- **grant_gen (cluster-wide, master-assigned) churns ~1600 per round** (node3's consecutive block-0 modifies: gg=2588→4201→5844→...→18320) = the EX lock bounces ~1600×/round on block 0. Massive contention, correct single-master (audit `mxfs_dlm_audit_double_grant` = 0 double-grants).
- The loss correlates with rapid block-0 handoff: `node3[node3_f43] → node5[node5_f1]` modifies of daddr=120 ~6.9ms apart at the failing round; node5's RMW base lacked f43.
- `held=0` cases (7) are ALL benign: `master=1 gg=0 comm=mkdir` (master creating the dir, implicit hold). **No non-master phantom (held=0 master=0) seen.** So the phantom-EX = "stale local EX not demoted on revoke" was NOT observed; the hole is more likely **grant-before-drain ordering** (master grants node B's EX before node A's release-drain made A's add durable → B reads block 0 without A's entry → clobber).

### CAVEAT (must resolve next session)
Cross-node `realns` (ktime_get_real_ns wall clock) sync NOT verified — no chrony; ssh-dispatch latency ~450ms swamped a direct check. So the absolute dt (3-26ms) can't ALONE prove overlapping critical sections. Need a CLOCK-INDEPENDENT concurrent-modify proof.

### NEXT SESSION (RULE 4) — precise
1. **Clock-independent concurrent-modify proof**: implement the shared-disk OWNER-COOKIE (sess50 GPT): on EX acquire write {node,grant_gen} to a debug sector (FUA); at every block-0 modify read+verify it's us; on release clear. Overlapping cookies = two nodes hold EX = hole. OR add a master-side total-order check: at modify, the modifying node's grant_gen vs the master's current granted gen for the inode — a mismatch = modifying under a superseded grant.
2. **Verify grant-after-drain ordering in the TCP DLM**: trace the bast/release path — does node A send the DLM release/downgrade to the master BEFORE or AFTER its drain (xfs_mxfs_dlm.c:9557 data_durable loop) completes? If the master grants node B on release-MESSAGE receipt while A's drain is still in flight → grant-before-drain race → fix: master must not grant until A confirms drain-complete (GPT#2 handshake: request→holder drains+ACKs→master grants, with seq numbers). Check bast_process (dlm/dlm.c) + the MHT re-acquire window (P15-REL-ABORT sess15).
3. Build 34ED34B2 = baseline + gated probes (P51-MOD, P28-PLATTER via dir_addname_epoch_refresh, P-STALEBASE false-positive — dirwr off = baseline-equiv). Marker NOT written (criteria unmet).

See [[sess50-FINAL-all-coherency-refuted-prime-suspect-dlm-serialization-hole]] [[sess52-CORRECTION-datablocks-coherent-MATCH-loss-is-writeside-not-stale-read]] [[sess16run-DECISIVE-double-grant-RULED-OUT-bug-is-buffer-layer]] (note: sess16 ruled out master double-grant; the hole is grant-ordering/timing, not a static double-grant).
