<!-- sess433 RULE-5 ruling D-0354: SHIP candidate A (single-node mode mints REAL durable epochs via the normal grant state machine; no memory-only authori… -->
# sess433 RULE-5 ruling — D-0354 lone-era epoch-0 images

Core invariant: no journal image requiring authority may be formatted until that authority is a durable, incarnation-bound, nonzero-epoch on-disk grant that recovery can place in the fence manifest. Caching an already-durable grant is fine; replacing it is not.

## Ship Candidate A (mint durable epochs in single-node mode)
- Enter the NORMAL grant state machine (full-word constructor/validator, compare complete old word incl. owner/incarnation/mode/epoch/gen; canonical successor word) with waiter/BAST suppressed only AFTER the grant is acquired. No separate single-node promotion (sess25 OR-bug class = ORing EX bit into an observed word, preserving stale owner/count bits). Never steal a stale grant because single_node=true; stale ownership goes through fence/incarnation recovery.
- Durable grant precedes token formatting; token immutable after format.
- Transition single->multi: gate new single-mode acquires; drain in-flight; verify every live token-bearing in-core grant has an identical durable grant; activate BAST/revocation on retained grants; force+land txns for surrendered grants; release only grants whose tokened txns are beyond replay; clear provenance; publish barrier ack; only then admit the peer. Do NOT release-and-remint retained grants (epoch change while old-epoch records exist).
- STOP-SHIP: joiner must not become filesystem-ACTIVE/writable until the incumbent acked the barrier OR was fenced+recovered (measured: B's mount returned and A kept writing single-mode for seconds).
- STOP-SHIP: inventory ALL lock classes protecting journaled state (AG, ICLUSTER, INODE, superblock/global, quota, rt, rmap/refcount, mixed-AG txns); a superblock-class image must not silently get epoch 0.
- Grant lifetime: a grant must not leave the durable held set while journal records bearing its token can still require replay (release needs log force/AIL proof or pin). Bounded cache: eviction/LRU/unmount/join release under that rule; 65536-slot table and manifest size must be bounded; slot exhaustion = hard error, never epoch-0 fallback.
- Own-slice adoption after own crash must use the same fence/incarnation/manifest enforcement as foreign replay.
- Mixed-version: a 0.40.0 memory-only-single-node peer must be rejected/fenced before a candidate-A peer admits.
- GAUTH_SINGLE_NODE may stay as diagnostic provenance but must not mean authority-without-epoch.

## Candidate B (automatic SNERA HB flag + kind16) REJECTED
Flag proves only 'no other ACTIVE member at claim'; measured overlap (peer active, incumbent still single-mode) is the counterexample; kind 16 proves fence-time exclusion, not historical exclusivity. SNLOCAL+kind17 stays as an explicit operator assertion; never generalize it.

## Q4 ex-victim remount into quarantined domain
Admitting the new incarnation after its old key was P&A'd is valid fail-closed IF quarantine is complete (EIO on the domain, no replay via another path, no auto-clear, survives churn/reboot, no allocation into the AG). Refuse the whole mount if the quarantined domain holds mount-critical metadata.

## Tests (beyond the obvious): EX-promotion legality + stale-word injection; stale lone lock table; 'no memory-only authority' assertions (tokened==total for every buffer class); grant lifetime vs log lifetime (evict then crash before checkpoint); capacity/manifest bounds; delayed convergence >9 s; contention on retained single-era grants after transition; recovery-chain crash cuts; own-slice adoption; epoch uniqueness/wrap; quarantine persistence; mixed-version join.
