<!-- sess419 RULE-5 ruling D-PURGE-NONATOMIC-PUBLICATION test design: gate (P234) is the interlock, owner-side publish_refusal injectors for both refreeze… -->
# sess419 GPT ruling — D-PURGE-NONATOMIC-PUBLICATION verification

Context: live tree has only two purge call sites (elected owner post-GRANTS_RELEASED; slotless-victim
fallback on every survivor with nothing to zero). Takeover needs a PROVED-DEAD owner, so an alive
owner's descriptor cannot change under it except via false-death fencing.

## Rulings
1. Concurrent-purger test = option A: a one-shot trigger on a NON-owner invoking the normal
   mxfs_disklock_purge_node(V) while the owner is paused mid-scan. Expected: phase-0 refusal
   (-EBUSY) with P234-PURGE-FROZEN naming owner O, ZERO writes by the non-owner, no live grant/HB
   damaged, owner completes and publishes normally; a post-publication invocation performs no writes
   (may refuse -ENOENT). P235-PURGE-CONTENDED is NOT required (it only records retry exhaustion).
   Bypassing phase 0 (B) fabricates an impossible caller — not RULE-6 evidence; if CAS-collision is
   tested separately add a per-MISCOMPARE counter. Slotless fallback (C) exercises nothing destructive;
   add a regression assertion (0 victim records, no CAW zero, no HB zero).
2. Descriptor-change arms: no real false-fence needed. But "same gate function" is NOT sufficient —
   the wiring must be exercised through the full purge path with an OWNER-side one-shot injector that
   publishes a real transition via the normal publish_refusal (QUARANTINED) API, two modes:
   2A FIRST_MIDSCAN_REREAD -> -EPERM, P234-PURGE-REFROZE-MIDSCAN, scan stops, HB not zeroed, INCOMPLETE.
   2B PRE_FINAL_HB_GATE -> P235-PURGE-REFROZE on the exact HB image, no HB CAS, INCOMPLETE, descriptor
   keeps the quarantine. 2A alone is not a substitute for 2B (the second historical hole).
3. Soundness: 4-retry cap OK iff every exhaustion/error is fail-closed (it is: P229 INCOMPLETE).
   STOP-SHIP: the -EOPNOTSUPP plain-write fallback in purge_cas_zero recreates the defect if
   reachable on a shared LUN — CAW unavailable must make the purge INCOMPLETE / never publish.
   STOP-SHIP-TO-CONFIRM: record-zero CAWs must be durably ordered before the HB-zero publication
   (FUA on the CAW, or a flush between the record scan and the HB CAS).

## Minimal injector set
owner scan pause after phase 0; non-owner one-shot purge trigger; owner descriptor-transition hook
(modes midscan / pre-final-HB) through publish_refusal. Optional per-MISCOMPARE counter.

## Closure list
(1) P234 concurrent refusal + no non-owner writes; (2) 2A; (3) 2B; (4) all errors fail-closed;
(5) no reachable plain-write fallback; (6) record-zero durability ordered before HB zero.
