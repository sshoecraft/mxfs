<!-- sess426 RULE-5 ruling (D-0345): route UNOWNED-page FREEZE_REQ to the bootstrap node is correct; keep bootstrap-only claim (write+readback is not CAS)… -->
# sess426 GPT ruling — UNOWNED page routed to the bootstrap node (D-0345)

Proven root (usermode tests/tauth/unowned_page_test + rig s427): `dlm_page_acquire` UNOWNED branch at a non-bootstrap view-master parked forever (nobody to ask: auth_node=0).

Fix shape approved: `bootstrap_node_cb` (id+inc) → send FREEZE_REQ(page, target=self) to the bootstrap node; its handler's existing `bootstrap-for-request` path claims UNOWNED then PREPAREs to the sender. Landed 0.35.4.

## Ruling points
1. FREEZE_REQ validation: config_id==view AND owner(page)==sender is necessary; ALSO require target_node==sender (added), sender+inc live in that view, durable state re-read under the page lock and still exactly UNOWNED before claiming (activate(bootstrap=true) already refuses non-UNOWNED with -ESTALE), FROZEN carries the PREPARED seq (it does).
2. Bootstrap change between send/receipt → old bootstrap answers NOT_OWNER → re-route next interval: OK for liveness. SAFETY hazard (pre-existing, not introduced): two nodes each believing they are bootstrap (lowest-slot flips) could both claim — write+exact-readback is NOT an atomic CAS; bootstrap tenure must be exclusive/fenced (PR fence before another may claim) or claims serialized by an on-disk lease/epoch. Re-checking bootstrap before/after the write narrows but does not prove.
3. Do NOT let the mapped master claim UNOWNED directly — bootstrap-only rule is load-bearing while the storage has no compare-and-write.
4. Budget: 10 caller retries ≈1 s is small for 3 page writes + 2 msgs on a slow LUN; prefer parking/coalescing waiters woken on FROZEN with a durable-IO-derived timeout rather than burning REMASTER retries. Never block synchronously in the receive path (it would block the FROZEN that resolves it).
5. Ramp: don't require a stable view for the whole handoff; once PREPARED(target,inc,seq) is durable the named live target completes ACTIVE then hands onward; every message/write carries the ledger generation; the bootstrap may be live in the HB table but not yet in the DLM view → wait (dlm_node_in_view check does this); consider rate limits on the bootstrap's request queue during a 32-node ramp.
