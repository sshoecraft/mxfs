<!-- sess413 RULE-5 ruling D-532: (a) MANDATORY ordered mount-abort lease give-back (stop-submit→drain→durable CAS UNOWNED→then member release), (b) clean… -->
# sess413 GPT ruling: D-532 stranded recovery lease fix design

## Ruling (hierarchy)
1. **(a) MANDATORY**: crash-safe mount-abort give-back, strictly ordered: close recovery submission gate (serialize with every submit path) -> quiesce/join workers + drain all bios incl. SCSI-EH resolution + cache/order barrier -> DURABLE conditional CAS of every descriptor owned by (node,inc,term) back to UNOWNED preserving pending stage (anti-ABA rules) -> VERIFY none owned -> only then durably release own member slot -> only then discard incarnation/PR key.
2. **CRITICAL FAILURE RULE**: if quiesce/drain/give-back cannot be PROVEN (another IO error), DO NOT write the clean member-slot release — keep the incarnation fenceable; an owned descriptor with a fenceable owner is recoverable (HB expiry + fence), an unfenceable orphan owner is not.
3. **(b) backstop only**: clean-departure takeover proof requires member release upgraded to an incarnation-specific durable CLEAN-QUIESCE CERTIFICATE (release = IO-quiescence certificate, final step of enforced departure; bare RELEASED bit NEVER sufficient — late in-flight bios can land after the release write). Takeover rule: fenced-dead OR certified-clean-quiesced. Non-ABA incarnations; retirement record retains identity/key for forced fencing.
4. **No standalone TTL takeover** (expiry proves renewal stopped, not writes stopped); wedged-owner path = progress timeout -> declare unhealthy -> existing PR fence -> takeover.

## Crash-cut safety
- Crash before give-back: descriptor owned + member NOT cleanly released -> HB expiry + fence -> takeover (existing).
- Crash after give-back before member release: descriptor UNOWNED (safe — give-back was after quiesce); claimable immediately.
- Member-release-before-give-back: PROHIBITED under (a).

## Verification arms (map to tests/fr_mount_barrier_fail.sh --cold2 + new crash-cuts)
Primary: forced -EIO cold mount -> abort -> descriptor durably UNOWNED (pending stage kept) -> member released AFTER -> next mount claims immediately, replays, PASSES, no P238-RECOV-OWNED 30s abort.
Others: give-back-failure arm (member slot NOT released, stays fenceable), late-IO arm, certified-retirement negative set (bare released slot / newer-incarnation slot / unmatched record / no-cert release / PR-removal alone must NOT authorize), ABA slot-recycle arm.
