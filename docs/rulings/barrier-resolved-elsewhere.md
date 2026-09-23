<!-- sess424 RULE-5 ruling: mount barrier must accept a survivor's completion — proof = enumerated terminal sector state + armed->resolved lineage; never… -->
# sess424 — barrier "resolved elsewhere" ruling (D-MOUNT-WINDOW-PEER-DEATH-IMMEDIATE-PURGE window arm)

## Measured (s423 rerun, tests/evidence/20260828T090326Z_mwindow_window, module 0.34.0)
A mounting with the barrier hold; B dies; A records P233-MPHASE-DEATH slot=31; survivor test1 (lowest live
slot) completes B's recovery on the live path; A's monitor logs P163-RECOVERED slot=31 (marker cleared, but
clear_recovery_pending keeps pending_node); hold releases; barrier keeps bit 31 (nothing retires a bit
another node completed), recovery_acquire builds a claim from the stale tuple -> -ENOENT x4 rounds ->
"MXFS mount ABORTED: slot mask 0x80000000 still requires recovery" over a replay-complete slice.

## Ruling (gpt-5.6-sol)
P0 Completion proof must be POSITIVE and incarnation-bound: the fresh sector read may accept only (1) a valid
   recognized ZERO sector or (2) a valid ACTIVE successor of a DIFFERENT incarnation (activation protocol
   guarantees predecessor completion).  "Not holding the victim" is too weak (WITHDRAWN is not ACTIVE).
   Anything still bearing the victim (WITHDRAWN, claimed, executing, sub-complete, malformed) or unread/torn
   keeps the bit.  "Zero happens last" (replay -> publish -> purge/flush -> zero) is a core crash-consistency
   invariant; unauthorized zero sources (init/reformat, admin clear, successor provisioning, stale fenced
   writers, corruption) must be impossible online or force quarantine.
P0/P1 Require an armed->resolved lineage, not merely "marker not pending" (never tracked vs resolved vs reset
   are conflated).  Witness = this mount armed pending for {node,inc} and afterwards observed a valid
   terminal state for that identity (identity-matched P163-RECOVERED, or the barrier's own fresh validation
   recorded atomically).  Three-state marker UNSEEN/PENDING/RESOLVED preferred.  recovery_acquire -> -ENODATA
   on a non-pending marker is correct hygiene but not completion proof.
P1 Do NOT suppress survivor election for a death during a mount: "either path may resolve it; the barrier
   must accept durable completion by either".  The descriptor already serializes the single replayer.
   Harness: drop "nobody else raced"; assert at most one replayer per incarnation, admission never before
   durable completion, completion by either retires the cut bit, no loser publishes/purges/zeroes.
   P233-MPHASE-RESOLVED-ELSEWHERE must name the victim identity and the accepted terminal evidence.
