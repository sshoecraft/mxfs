---
name: sess13run-P13-STALEREAD-mostly-normal-need-correlate-specific-lost-name-with-probes
description: sess13(ccloop) P13-STALEREAD (build B2FAE263) fires 150-200x/node = MOSTLY NORMAL (each round's fresh blocks fill from empty; dir freed/recreated eac…
metadata:
  type: project
---

## sess13 (ccloop) — probes show normal bulk activity; must correlate the SPECIFIC lost entry

### P13-STALEREAD result (build B2FAE263, leaf-addname placement trace)
Fires 150-200x/node with bf0len~3984 (block ~fully free) — but this is the NORMAL fill pattern: the storm dir is freed+recreated EVERY round (rank1), so each round's data blocks are fresh and fill from empty (each node's wave fills its own block sequentially: aoff 88,112,...). daddrs are REUSED across rounds (e.g. test3 & test4 both show daddr=6279752 — but in DIFFERENT rounds, not concurrent). So a "reused block read near-empty" is overwhelmingly legitimate fresh-round filling, NOT the loss. The 1 lost entry/round is a RARE race buried in ~750 normal placements/round.

### KEY METHODOLOGICAL LESSON for next session
Bulk probes (P11-DATALOG, P13-NADD, P13-COLLIDE, P13-STALEREAD) all show NORMAL high-volume dir activity and do NOT isolate the single loss. MUST correlate the SPECIFIC lost name:
1. Run winning config (no perturbing heavy probe — or accept the heisenbug); from a node's `/root/drc_failrounds.txt` + `drc-RDMISS round=N` get the EXACT lost name (e.g. node3_f19.md5) and round.
2. On EACH node, `dmesg | grep '<lostname>'` across P13-COLLIDE/P13-NADD/P13-STALEREAD/P11-DATALOG to reconstruct: which node placed it, at which (daddr,off), whether the block was read stale, and whether a peer wrote the SAME (daddr,off).
3. Cross-node correlate by (daddr,off): does ANOTHER node place a DIFFERENT name at the SAME (daddr,off) in the SAME round? That is the true double-alloc (vs the daddr-reuse-across-rounds false positive).
The probes are IN the build (B2FAE263, storm-dir scoped, always-on) — next session just needs to grep for the specific lost name, not re-instrument.

### Established this session (unchanged): winning config fua_disable=0 fua_always=1 dir_epoch_adopt=1 dir_epoch_convert_gate=1 → dir_reuse 4/tcp 399/400, ZERO corruption. Loss 1-26/round (contention-scaled). NOT cross-node-placement-onto-occupied (P13-COLLIDE clean), NOT master-double-grant, NOT fast-path-stale, NOT write-durability-to-platter (FUA-write inert). sess11run FINAL: entry vanishes from its own block in-transaction.
### 7 builds this session (final B2FAE263 = all probes + off-by-default levers; default behavior == 40AC2A0C). 2/tcp dir_reuse PASSES, 4/tcp fails = contention-scaled. 8/tcp unrun. Criterion NOT met.
See [[sess13run-FUAWRITE-inert-platter-hypo-weakened-next-is-intransaction-trace]] [[sess13run-WINNING-CONFIG-fua-plus-epoch-adopt-399of400]].</body>
</invoke>
