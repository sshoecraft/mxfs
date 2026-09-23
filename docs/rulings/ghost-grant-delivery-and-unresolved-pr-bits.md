<!-- sess424 RULE-5 ruling: deliver every successful ledger commit (gen change after commit must not suppress); no release-on-send-failure; unresolved PR… -->
# sess424 — GHOST PR grants: root cause of the 0.34.0 32/tcp mount failures, and the ruling

## Measured (journal of test19/20/24/30 + usermode tests/tauth/formation_test)
mount's EX on ino=128 refused 125-208 s -> shutdown -> "Failed to read root inode 0x80, error 5" -> mount EIO
("can't read superblock").  Masters: P-TAUTH-DOUBLE-GRANT "req ... mode=5 vs record ex=0/0 holders=0x10000000".
Usermode (12-node join ramp, all hammering PR/EX on ino=128): P-TAUTH-GHOST "committed under a superseded
ownership generation; not delivered" x2 -> record holders=0x6 stuck -> imported as owner=UNKNOWN blocker ->
every EX times out (-110).  Mechanism: dlm_txn_finalize refuses delivery when ctx->ledger_gen != txn->gen
after a SUCCESSFUL durable commit, frees the table entry, answers REMASTER; the bit is never retired.

## Ruling (gpt-5.6-sol), prioritized
1. F1 ADOPT: a successful authority commit is deliverable regardless of a later ledger_gen change; gen is
   checked before commit and for routing only.  Keep the entry GRANTED; grant replies idempotent.
2. F1 cannot double-grant if the page-authority handoff holds (old frozen before new activates; new imports
   before granting).  Do not deliver to a fenced incarnation or a properly-cancelled request.
3. F2 REJECT: "send failed => compensating release" is unsafe (X may have received and be using the grant).
   After commit: retransmit the same idempotent grant / let X reconcile on retry / explicit rejection from X /
   fence.  After ownership moved, A cannot release with stale authority; forward intent to the current authority.
4. F3 REJECT the timeout+EMPTY-slot retirement: an unresolved PR bit stays fail-closed (blocks EX, allows
   compatible PR) until fencing/recovery proves the slot incarnation dead.  Re-asking the heartbeat table on
   every decision is fine.
5. Long-term: durable {node, incarnation} per shared holder (or non-reusable slot epoch / sidecar records);
   a slot-indexed bitmap cannot distinguish an old holder from a new occupant; hash identity only if
   collisions fail closed.
6. F4 cancellation needs a serialized protocol; volatile req_id is insufficient across remaster; one durable
   holder state per {resource,node,inc} reconciled/released rather than per request.  Beware multiple local
   PR references behind one bit.
7. Audit every uncertain-completion path (timeout after commit before reply, reply-ACK lost, release response
   lost, release to old owner, crash after commit, PR->EX conversion half-durable, slot reuse, purge/import
   losing identity).  Requesters must retain uncertain ops and retry to a definitive durable result.
