---
name: ccloop-c7ee71c6-sess363-GPT-ruling-caw-selective-purge-redo
description: sess363 RULE-5 ruling: CAW selective purge redo APPROVED w/ conditions — per-CAS leased gate, tri-state classifier, single victim; G1/G2 = demand-tri…
metadata:
  type: project
---

# sess363 RULE-5 ruling — CAW-layer selective purge redo (defect #3/#4 grant freeze)

Conditional approval. Mandatory items:

## A. Selective CAW purge (publisher path) — approved with:
- Per-destructive-CAS gate revalidation via fresh authoritative HB read (never
  amortized, never cached); crc+identity checked every read.
- Separate APIs `closure_gate_snapshot` / `closure_gate_revalidate(expected
  victim, mask)` — NO zero sentinel (node 0 valid).
- Phase 0 must compare HB image against the ALREADY IMPORTED canonical outcome
  (caller passes ocanon's victim+ag_mask); any mismatch -ESTALE. Same equality
  before every CAS.
- ONE victim per invocation (dead_mask == BIT(victim)); a victim's gate never
  authorizes stripping another node's bits (multi-victim slots: independent
  gate+classify per victim).
- Tri-state classifier contract: OUT_OF_CLOSURE / KEEP / negative-error→abort
  retry-required (never let an errno classify as "keep" silently).
- Gate failure (read err, crc, identity mismatch) → stop purge immediately,
  return retry-required; completed CASes stand.
- Reclassify after every authoritative reread/CAS conflict; slot reuse under
  CAS caught by generation, reclassify new resource.
- REUSE the full-purge mutation discipline (same field list, mode recompute,
  generation++, tombstone rules) — do not fork the strip logic.
- Counters: out_purged = successful mutations only; partial never → success.

## B. G1/G2: Shape 1 ONLY (Shape 2 import-scan REJECTED — 31 concurrent 64k
scans = HB/eviction risk). Must be GENERALIZED:
- Trigger on ANY victim-owned state blocking a live op: holder bits, waiter/
  waiters_ex/fairness, yield_to, open_holders, stale slot blocking allocation.
- Hook BOTH wait/defer paths AND slot-allocation/collision paths.
- Attempt repair well before timeout cascade (transient gate fail → backoff
  retry, but repair before -110).
- Same discipline as A: authoritative reread, classify from that image,
  fresh LEASELESS gate immediately before every CAS, strip only that victim,
  generation CAS, reread+reclassify+regate on contention. Racing waiters
  benign (first CAS wins).
- Leaseless sound IFF: terminal irreversible for {fs_gen,node,epoch,recov_gen};
  fresh-read crc/id checks; node slot CANNOT be re-adopted by new incarnation
  while quarantined-terminal descriptor stands (MUST VERIFY IN CODE + TEST);
  fresh live HB → fail closed. Separate leaseless gate fn — do NOT pass fake
  auth into the leased gate.
- G2 progress: none needed — on-disk bits are the state. Optional elected
  reconciler NOT required for ship.

## C. Publisher failure semantics: no retry loop, release lease regardless;
return must distinguish published_terminal (never rolled back) from
cleanup_complete/cleanup_rc (retry-required on any unread/gate/CAS failure);
caller must not log "purge complete" on partial.

## D. Strip ALL victim-owned state on out-of-closure slots (holders all modes,
waiters, waiters_ex, yield_to, open_holders), recompute modes, generation++,
wake live waiters, tombstone per canonical emptiness test.

## Hazards to close before ship
1. Node-slot incarnation reuse (biggest): prove claim path refuses a
   QUARANTINED slot while old CAW bits name it.
2. Terminal import must precede mount-time adopt of victim's retained grants;
   fail closed before v5 callbacks registered.
3. Confirm no salvage path uses out-of-closure ex_grant_epoch as replay
   authority before tombstoning (sess108: tombstone CARRIES ex_grant_epoch —
   likely moot, verify).
4. Successful scrub CAS must wake/re-evaluate waiters immediately.
5. Unknown/JOURNAL/SUPER/EXTENT/unmappable types stay frozen (already).
6. No CAW spinlock/mutex held across HB sector I/O in callbacks; pin like
   holders_alive_fn; audit unregistration at unmount.
7. Fault tests: G1/G2 at every CAS boundary, HB unreadable, crc fail, mask
   mismatch, tombstone/reuse race, racing waiters, multi-victim slot,
   waiter-only + open-holder-only slots, node 0, mount/adopt vs import race,
   CAS exhaustion partial reporting, publisher death post-publish.

Implementation target 0.14.3. sess361 disklock record-table purge DELETED.
