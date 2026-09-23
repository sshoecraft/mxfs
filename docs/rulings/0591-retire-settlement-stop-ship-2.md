<!-- sess451 RULE-5 ruling on 0.59.1 RETIRE_PENDING settlement: STOP-SHIP #2 — 5 blockers (non-coherent/cached absence proof, no-PR self-clear + key0=abse… -->
# sess451 RULE-5 ruling — 0.59.1 (sv 2529E66E) — STOP-SHIP #2

Criteria: 1 MET (reread on -EAGAIN; dead-confirm discards CHANGED), 2 MET (RETIRE_PENDING in barrier sweep, unresolved holds the gate), 3 PARTIAL, 4 PARTIAL, 5 UNMET, 6 PARTIAL, 7 UNMET, 8 PARTIAL, 9 MET, 10 UNMET.

## Blockers (ranked)
1. **Absence proof not coherent.** READ KEYS then READ RESERVATION then a 1 s cache: our registration can be preempted between the two commands (or during the cache TTL) and the snapshot still says own_present + resv_ok + victim absent => EMPTY without a valid proof. Required: bracketed KEYS A / RESV / KEYS B with equal PR generation, local key present and target absent in the final coherent view; invalidate the cache on EVERY local PR mutation (register/unregister/reserve/preempt) and on unit-attention / reservation-loss events; cache only PRESENT by time; establish ABSENT freshly at the destructive transition.
2. **Clustered no-PR still unsafe.** `retire_complete_self` on -EOPNOTSUPP self-clears; a valid record with pr_key==0 is treated ABSENT. A clustered incarnation must have a nonzero validated key; key 0 => UNKNOWN/invalid, never ABSENT; remove -EOPNOTSUPP -> EMPTY; require REGISTER/READ KEYS/READ RESERVATION/RESERVE/PREEMPT-AND-ABORT support before clustered admission.
3. **OWN too broad.** The generic callback maps local_key PRESENT -> OWN, so ANY monitor/barrier settlement can clear ANY pending record naming our key (stale/duplicate/colliding records), and PRESENT does not imply resv_ok. OWN must be a P305-only operation for one exact validated predecessor tuple (slot,node,epoch,boot_uuid) under the departure lock with FRESH proof of own registration + qualifying reservation; generic lookups see the key as PRESENT. P305 must enumerate ALL same-boot pending records and detect duplicates/conflicts.
4. **HB starvation.** READ KEYS/READ RESERVATION are synchronous on the shared heartbeat/monitor thread; a 1 s cache bounds count, not latency. Move PR discovery/settlement to a separate worker or make it async with strict time/work budgets so heartbeat deadlines cannot be missed.
5. **No enforced freeze before pending publish.** xfs_unmountfs + flush is evidence, not an enforced transition. Need: prohibit new FS I/O, drain I/O + workers, flush, publish RETIRE_PENDING, unregister — explicit and mechanically asserted in the shutdown state machine.

## High / medium
- Successful CAS must leave *rhb = committed image (0.59.1 DOES: `*rhb = *want` on rc==0 in both CAS branches — GPT could not see it).
- P305 must settle/refuse ALL matching records, not one recorded slot.
- Same-boot remount vs peer expiry CAS race is ACCEPTABLE iff: post-CAS classification from a fresh image, P305 treats observed WITHDRAWN as fatal, admission revalidates own key + reservation before writable I/O, error path unregisters + tears down before releasing serialization. Needs a deterministic race test both orderings.
- Deterministic UNKNOWN tests required: READ KEYS failure, truncation, READ RESERVATION failure, local key missing, wrong reservation type, generation change between commands, snapshot invalidation after preempt/unregister; plus slow/hung PR command while heartbeats keep flowing; plus no-PR clustered admission rejection; plus multiple same-boot pending records.

## Minimum for GO
(1) prohibit clustered no-PR; key0 never ABSENT; no -EOPNOTSUPP->EMPTY. (2) coherent bracketed absence proof, invalidation on PR mutations, no time-cached ABSENT for the destructive transition. (3) OWN restricted to P305 exact-tuple settle under the departure mutex with fresh proof; all same-boot records enumerated. (4) heartbeat progress separated from PR work. (5) enforced pre-publication quiescence, asserted. (6) fresh post-CAS classification (already done). (7) the deterministic tests above.
