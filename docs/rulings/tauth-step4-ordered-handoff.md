<!-- sess423 RULE-5 ruling on tauth step 4 (ordered mastership handoff): volatile FROZEN insufficient — durable PREPARED->MOVED page transitions, nonce co… -->
# sess423 — RULE-5 ruling on step 4 (ordered mastership handoff) of docs/tcp-authority-ledger.md

## The hole (session finding, GPT concurred)
Step 3's page_write readback validates crc+seq only.  Old owner A (view lagging) and new owner B
both read page P at seq s, both target the same shadow copy, both write s+1; the loser's readback
finds the WINNER's valid image with seq s+1 and reports durable -> BOTH deliver.  Nothing detects
it later (each keeps its cached image).  Only the 20 s EX settle gate stands in the way; PR is ungated.

## Ruling (14 items, condensed; bottom line: my proposal P1-P6 is NOT complete as written)
1. Durable per-page transfer state, not a RAM freeze: ACTIVE(auth node,inc) -> TRANSFER_PREPARED
   (auth=A, target=B{node,inc}, config_id, nonce, prepared_seq; entries unchanged) -> ACTIVE(B) at
   prepared_seq+1 (the activation IS the durable MOVED).  A: close admission on P, drain/classify
   every txn+delivery, write PREPARED, exact readback, THEN send FROZEN naming {page, prepared_seq,
   target, config, nonce}.  A never transitions entries again while PREPARED is current.  B reads the
   exact PREPARED fresh (two-shadow read, not cache) before consuming.  A may not cancel/retarget a
   PREPARED while B can still execute it (only after proof B's incarnation can no longer write).
2. View-hash equality = live rendezvous check only, never an authority token.  Config id must cover
   member list + incarnations + a linearized transition number, compared in full; both sides recheck
   ledger_gen/config before the durable transition and before delivery.  M never adopting X's view
   = liveness failure: DEFER forever, never forced activation.  A bare bitmap FROZEN is rejected.
   B may complete an exact PREPARED after its own view changed, as a NON-SERVING relay (must not
   grant unless its current view names it owner; it hands the page onward).
3. Dead predecessor: lease-unregister-after-recovery is NOT enough — two live nodes with divergent
   views can both take over from dead M; readback does not stop SEQUENTIAL same-seq overwrite
   (X writes/verifies/delivers, then Y overwrites same seq/copy, verifies, delivers).  Need an ordered
   departure certificate / linearized recovery transition naming the unique immediate successor per
   page; only it may take over; later transitions hand off FROM it in order.  If the lease cannot
   issue it, the recovery coordinator durably serialises takeover before unregister.
4. Clean departure: GOODBYE proves M stopped but does not pick among successors under divergent
   views: M must durably PREPARE every owned page to the unique successor (or use the same ordered
   certificate) BEFORE GOODBYE; GOODBYE bound to node/inc + config transition; no I/O under that
   incarnation after it.
5. PR preempt-and-abort counts as a fence only as a VERIFIED certificate (all paths use the fenced
   key, P&A completed at target, queued commands aborted/conflict, multipath cannot re-register,
   array PR+FUA qualified, bound to LUN + old node/inc + key gen + config transition); else fail closed.
6. Freeze barrier covers transactions AND deliveries: stop all decisions on P (not just EX), take
   the page barrier, drain/classify (durable grant undelivered; release committed ACK undelivered;
   successors activated grants undelivered; uncertain write -> poison + reconcile), write PREPARED,
   then FROZEN.  New owner replays idempotent results by req_id / grant id after import.
7. Every timeout fails closed: parked request expiry (5 s) -> cancel + RETRY/REMASTER, no grant;
   DEFER 500 ms with jitter, expiry never authorises activation; freeze/drain timeout -> page
   non-serving, no FROZEN, reconcile/poison; lost FROZEN recovered by READING PREPARED, never by
   thawing; PREPARED never cleared on a timer.
8. Reads: full 4 KiB readback memcmp + a random/monotonic write_nonce (stamp_ms not unique);
   two shadows same highest seq but different valid content = conflicted -> poison, never pick one.
   Readback is not CAS and not the handoff exclusion.  Harness: X verifies+delivers before Y
   overwrites the same seq (shows P4 alone is insufficient).
9. Commit legal only when durable state ACTIVE, authority == self{node,inc}, local ownership still
   permits; only non-authority writes: named target consuming exact PREPARED, certified recovery
   successor doing a dead-target takeover.  Activation from a FRESH two-shadow read.  ledger_gen
   checked before prepare/write, after readback, right before delivery.
10. 20 s membership-settle is dampening only; step 4 must be safe with it disabled; refuse/park
    every decision (PR/shared/releases granting successors) while inactive/freezing/PREPARED/
    recovery/poisoned.
11. Matrix rows that belong in step 4 (not seal/shard): grant durable before freeze + delivery
    before/after barrier; delivery suppressed by gen; release committed ACK lost then transfer;
    successor delivery lost then transfer; freeze concurrent with grant/release write/readback/
    delivery; crash before/during/after PREPARED, after response, during/after MOVED; PREPARED
    target crashes/departs; authority crashes while PREPARED to a live target; A->B->A, A->B->C with
    stale requests/responses; two candidate successors after a dead owner; delayed old-view requester
    + delayed old-owner txn after MOVED; same node id new incarnation; equal-seq divergent shadows;
    corrupt/missing authority copy during transfer.
12. Harness: deterministic barriers at every durable write/readback; assert at most one node ever
    grants conflicting ownership, no delivery after freeze, every FROZEN maps to a readable exact
    PREPARED, every MOVED consumes a named PREPARED or certified recovery transition, stale nonces/
    configs rejected, no timeout changes authority, release retries get the same ACK after transfer,
    dead-owner activation has exactly one successor; fault-inject dropped/reordered RPC, restart
    with new inc, FUA uncertainty, shadow overwrite, sequential same-seq overwrite.
13. Eager PREPARE of all moved pages at the config transition (bounds the old-authority window,
    creates durable evidence); activate hot/requested pages immediately, the rest async with a
    bounded target; measure FUA latency; never fold several page authority transitions into one
    durability outcome.
14. Do not land step 4 without: durable PREPARED->MOVED; immutable transfer cookies + stale
    rejection; unique ordered successor for clean AND dead departures; precise freeze/drain/delivery
    barriers; fail-closed timeouts/uncertainty; the expanded matrix.

## Session mapping to existing MXFS mechanisms (decided sess423)
- Ordered successor for a DEAD owner = the victim's disklock recovery descriptor (single elected
  replayer with term + takeover on abandonment + fence certificate): the coordinator PREPAREs every
  page whose authority is the victim {node,inc} to successor(page) under its post-victim view,
  before the lease unregister; targets consume and relay if their view disagrees.
- UNOWNED pages (mkfs state, writer_node 0): only the lowest LIVE heartbeat slot may activate them
  (shared-disk arbitration, not local views); every other node obtains pages by live handoff.
- Clean departure: prepare all owned pages to successors, then GOODBYE.
- Config id = FNV over sorted (node, inc) + count; rendezvous only.
