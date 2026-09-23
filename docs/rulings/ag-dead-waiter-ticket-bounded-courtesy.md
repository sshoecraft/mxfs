<!-- sess404 RULE-5 ruling (D-DEAD-WAITER-AG-TICKET-CREATE-ETIMEDOUT-404): extend sess31 fix A/B to AG; NOQUEUE -> -EAGAIN at once; DEMAND overrides ticke… -->
# sess404 GPT ruling — AG courtesy ticket naming a DEAD registered waiter

## Defect (PROVEN, 0.24.1 P-CAWEXH-AG on kill5d, tests/evidence/sess404_v0241/)
AG co-owner V registers as EX waiter; C releases -> AG release builds batch ticket
`yield_to = waiters` (dlm_caw.c ~10399; INODE uses fair/direct handoff, AG does not);
V dies before claiming. Slot: holders=0 waiters=bit(V) yield_to=bit(V). sess299 rule:
ticket naming a registered waiter = live reservation, never age-cleared. sess31 fix A/B
(register + caw_fresh_yield_bound=16 then take the compatible claim) was INODE-only ->
every AG fresh acquire by C loops yield-backoff (3+node%10 ms) x100 -> -ETIMEDOUT
(~1.2 s each) until the dead slot's purge (~74 s = 62 s HB + fence + replay).
NOQUEUE was checked ONLY on the incompatible branch -> the allocator's "non-blocking"
AG probe slept 1.2 s and returned -ETIMEDOUT, which xfs_dialloc_try_ag treats as a hard
error (only -EAGAIN skips) -> open(O_TMPFILE) = ETIMEDOUT x55 on a FREE AG.
Census on the co-owner: `yield_bo=100 ea_claim=0 ea_compat=0 ea_regwait=0 last_hex=0
last_waiters=last_yt=bit(dead)` x57 (test17/AG2 bit 2; test31/AG3 bit 28 = 0x10000000).

## Ruling (gpt-5.6-sol)
- (i) ACCEPT A/B for AG: holder bitmaps + CAS generation are the exclusion authority;
  ticket is fairness metadata. Scope INODE + AG only (other classes unaudited = stop-ship
  if blanket-enabled). Properties: register once per acquire; count after registration;
  reset per acquire; NO waiter footprint on any timeout/error/NOQUEUE exit; force-claim
  via the normal full CAS; preserve foreign waiters + recompute waiter_mode atomically;
  preserve sticky revoke (claim path already does caw_revoke_consume); add counters.
- (ii) Ordinary NOQUEUE: return -EAGAIN immediately on a foreign live ticket, BEFORE
  registering (trace-free). NOT bounded sleeping (b/c). DEMAND|NOQUEUE must not spin until
  purge: escalate to bounded acquire or an EXPLICIT documented urgent bypass that takes
  the compatible claim (no holder to revoke). Chosen: DEMAND takes the claim directly
  (counted, P-CAW-TICKET-DEMAND-OVERRIDE). Do not translate repeated -EAGAIN into
  -ETIMEDOUT inside the DLM.
- (iii) 16 deferrals OK for the minimal patch (AG: 48-192 ms depending on node%10);
  longer term an elapsed budget 150-200 ms from registration; never tie to the 62 s HB.
  Telemetry: deferrals, overrides by class, elapsed before override, whether the ticket
  owner later claimed, BASTs right after an override.
- (iv) Release site: do NOT age-filter registered waiters (conflicts with sess299; cannot
  tell dead from slow/descheduled/partitioned-unfenced). Batch ticket itself is fine.
- (v) Do NOT block a free AG until purge — that elevates fairness metadata into ownership.

## Landed 0.24.2 sv 45CB1B5B316873A44731F38 (dlm/dlm_caw.c caw_lock_body)
NOQUEUE check moved ahead of registration in the compatible-yield branch; A/B for
INODE|AG; yreg_live + out: drop (property 4); counters caw_stat_ybound_ag/ino,
ticket_noq_eagain, ticket_demand_override printed on P221-YIELD-BOUND-AG / P-CAWEXH-AG.
Verification: kill5e auto:shared + kill4d auto:single (tests/evidence/sess404_v0242/).
