<!-- sess416 RULE-5 ruling D-0286: TCP wedge fix = Shape B strengthened — session-wide POISONED/dirty-departure state machine, no TCP pins; invariants + r… -->
# sess416 GPT ruling (gpt-5.6-sol) — D-TCP-WEDGE-PIN-NOOP-REPORTS-SUCCESS-0286 fix shape

## Ruling: Shape B, strengthened into a fail-closed dirty-departure protocol
NO per-resource TCP pins (volatile, would need replication/failover machinery = a second durable
lock mechanism). Instead WEDGED poisons the ENTIRE TCP DLM session/mount incarnation:
no NODE_LEAVE, no release_all, no reconnect/session migration, no unlock for the wedged resource;
connection loss classified as dirty death; grants not reassigned until fence + slice replay + cert.
State machine: ACTIVE -> QUIESCING -> CLEAN_LEAVE; any path -> POISONED/WEDGED -> DISCONNECTED ->
DEATH_RECOVERY. POISONED terminal per mount/session incarnation.

## Invariants (must all hold)
1. Wedge publication PRECEDES cleanup: publish per-resource WEDGED + session-wide POISONED (with
   barriers) BEFORE socket close/shutdown; every teardown/unlock/leave/reconnect/master-recovery
   path tests the session poison.
2. No clean protocol action after poison (leave/release_all/unlock/reconnect/advertise-clean/
   later ordinary unmount).
3. NODE_LEAVE needs a real linearization point: constructed+sent only after new activity stopped,
   ALL drains succeeded, no resource WEDGED, atomic QUIESCING->CLEAN_LEAVE transition; a concurrent
   wedge WINS. Suppressing future goodbyes is insufficient if one can already be queued.
4. Connection death != immediate reassignment: master keeps a node/session tombstone/recovery
   barrier — no purge/grant/promotion until PR fence confirmed + slice replayed + cert published,
   scoped to the exact session incarnation (ABA/slot-reuse). Fail closed on replay/fence failure.
5. Master failover preserves the obligation: new master must NOT infer "no lock record => free";
   census of uncleanly-absent sessions, fence+replay before conflicting grants; poisoned mount
   cannot reconnect.
6. Death dominates clean leave: a delayed NODE_LEAVE cannot downgrade a death classification;
   epoch/incarnation keys on all messages+certs.

## Shape-B hazards to design against
- Goodbye already queued/in flight when the wedge lands (cancellation cannot recall; ordering fix).
- Concurrent release_all walker: recheck poison before EACH wire-visible unlock; abort walk.
- Poison published after socket close (order), or poisoned-but-connected lingering (disconnect promptly).
- Master destroying connection-owned locks then GRANTING A FRESH REQUEST for the same resource
  (new-request bypass — must hit the dead-session barrier even with no old entry).
- Master failover at each phase (7-point matrix); stale goodbye/unlock buffered; auto-reconnect.

## Verification (when built)
Core wedge test on TCP (mirror of d512_t8_inject kinds 1/3) + deterministic race interleavings
(wedge vs release_all entry/each release/goodbye construct-queue-send-receive/socket close/
force-shutdown/unmount/module unload/HB timeout/reconnect) + receiver-side death-gate tests
(waiters not promoted; new requests blocked; fence/replay failure => blocked or cluster down;
delayed goodbye idempotent) + master-failover matrix + clean-unmount regression.

## Interim (-EOPNOTSUPP, landed 0.28.7) = containment only
Safe ONLY if force-shutdown already guarantees dirty death through the whole TCP teardown stack.
Audit list (each a potential hole): generic shutdown still runs release_all / still sends
NODE_LEAVE; wedge marked on inode but no session-wide poison; shutdown before sticky state
published; running release worker doesn't recheck; goodbye queued pre-wedge; auto-reconnect after
master failover; master grants recreated resource pre-recovery; error-unwind releases the grant on
pin failure; missed wedge call site.
