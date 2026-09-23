<!-- sess432 RULE-5 ruling D-379(B)/D-0355: gate PR-key retirement on durable slot state + drain/flush (P1 OK); NO proving fence kind from WITHDRAWN+key-a… -->
# sess432 RULE-5 rulings on the lone-remount / dirty-departure key retirement

## Ruling A (shapes a/b/c)
- A PR registration belongs to an I_T nexus. A next incarnation on the SAME host/nexus cannot hold a second key while the stale one exists; REGISTER AND IGNORE EXISTING KEY only replaces it and is NOT a PREEMPT AND ABORT proof. Self-recovery on the same nexus needs a distinct nexus, a helper initiator, an independently verified transport reset, or fail-closed.
- Under WE-AR a stale registrant is an ACTIVE privilege; WE-AR does not prevent re-registration.
- Shape (c): keep the self-verified retirement for CLEAN departures; for DIRTY departures leave the key registered as a fence target — the incarnation stays unfenced until a verified P&A completes.
- Stamp/release write fails -> latch dirty/uncertain, do NOT unregister, do not report clean, no further FS writes, next incarnation blocked until a valid fence.
- Ordering: latch unmount_clean only after every cleanliness-affecting op; clean: durable slot release -> unregister -> READ KEYS verify; dirty: durable WITHDRAWN -> keep key. Slot release must not precede the last op that can dirty the departure.

## Ruling B (P1/P2)
- P1 (gate retirement on durable slot state) OK if ALSO gated on successful whole-stack quiesce/drain/final flush. Strengthens D-377 provided failures stay fail-safe; a same-host remount must never REGISTER-AND-IGNORE a still-present predecessor key.
- P2 (kind 18 = WITHDRAWN + key absent + WE-AR + complete view) REJECTED: absence causality unknowable (plain PREEMPT, CLEAR, target reset, PR loss, ambiguous unregister); SCSI tasks are not tagged by incarnation, so a same-nexus successor's registration re-authorizes surviving predecessor I/O. Only PREEMPT_ABORT_DONE (key present) or SINGLE_NODE_EXCLUSIVE prove exclusion.
- Fail-closed states: ACTIVE+key absent; WITHDRAWN+key absent; key present but P&A cannot complete/verify; ambiguous unregister; external key removal -> no replay, no purge, independent fence or operator action.
- 12 directed test families (departure boundaries, late I/O + multipath, external key removal, P&A fallback, incomplete PR views, slot/incarnation validation, reservation validation, same-nexus overlap, D-377 regressions, certificate/replay crash consistency).

## Loop-device publish -95 (scout)
xfs_mxfs_dlm.c:54108 abort <- v5_recovery_complete_ladder step 3 mxfs_disklock_purge_node <- purge_cas_zero (disklock.c:2894) returns -EOPNOTSUPP on non-CAW BY DESIGN (sess419 ruling, D-PURGE-NONATOMIC stop-ship 5). 8 of 9 disklock CAS sites fall back to write+FUA-verify; only the terminal publish zero refuses. A non-CAW device can never complete a recovery publication -> vergate MB3 on a loop device is not a valid replay proof; re-express as a byte-compare of the dirty slice across the refused mount.
