<!-- sess413 RULE-5 ruling D-526: APPROVE (a) monitor EMPTY clean-departure arm (exact-incarnation FUA+tokenized close), (b) latch clear, (c) tri-state st… -->
# sess413 GPT ruling: D-526 clean-departure fix design (APPROVED, conditions)

EMPTY must be treated as a durable TERMINAL state for ONE EXACT slot incarnation. Chain (already enforced, D-532 give-back included): durable clean-unmount record -> durable lease give-back -> exact-image CAS to EMPTY. A concurrent recovery/fence guard beats the CAS and the release is refused.

## (a) Monitor clean-departure arm — APPROVED WITH CONDITIONS
On monitored slot: valid record + FLAG_EMPTY + EXACT match (slot, node_id, epoch/incarnation, generation — !hb_gen_foreign only if it means exact binding match) -> FUA re-read confirm -> tokenized local close: under the state lock revalidate the monitor still binds THAT incarnation, then monitored=false live=false, reset equal_samples/dead-confirm/evict/fence state, clear per-victim pending contribution, cancel queued work (workers/callbacks must revalidate the incarnation token before declaring death/fencing/latching/claiming/electing). Slot-reuse: new ACTIVE -> normal join path; EMPTY of a DIFFERENT incarnation -> NOT proof for the old victim. ABA: close must be compare-and-close against the monitor binding.

## (b) Recovery-pending latch clear — APPROVED
Matching EMPTY (exact victim tuple + op token) closes the pending instance as CLEAN-DEPARTED; no unmount-record re-read needed (persistence ordering is a global invariant; no path may synthesize EMPTY without it). Death microseconds after EMPTY is post-departure — slice clean by construction. MUST also: invalidate queued election/replay work, block late fence completions from re-latching, remove from aggregate pending set + recompute global flag, stop retry timers/re-election, relinquish any phantom recovery descriptor via exact-owner CAS.

## (c) hb_still_dead_stamp — APPROVED, prefer tri/quad-state
STILL_DEAD / NOT_DEAD_OR_ADVANCED / CLEAN_DEPARTED / FOREIGN_OR_INVALID. Matching EMPTY = CLEAN_DEPARTED (never 'still dead'); same validation as (b).

## Fence path
At fence-intent: exact-incarnation FUA validation; matching EMPTY -> publish explicit CLEAN_DEPARTED / NO_FENCE_NEEDED disposition (distinct from FENCED — suppresses recovery, never authorizes replay), NO SCSI-PR issued, close pending + invalidate queued work. Never rely on NOINTENT-by-luck. No destructive PR op may dispatch after EMPTY observed; incarnation-specific keys, no reuse while an old fence can complete.

## Un-monitor durability
Node-local only, NO durable write; serialized tokenized transition + stale-callback suppression mandatory.

## Convergence (mass-unmount)
(a)+(b)+(c)+D-532 sufficient IF clean-close cancels ALL armed work. Closing assertion: no per-victim entries -> global_recovery_pending==false, no retry timer armed, no replay worker passes its generation token, no locally-owned phantom descriptor.

## Verify arm
tests/d513_lone_mount_torn.sh step-1 mass unmount (the trigger): assert ZERO 'no longer responding' for released slots, zero P163-RECOVERY-PENDING latches surviving, survivor stands down (assertion block above), board green after.
Build order: 0.27.7 = D-532 give-back (verify cold2 FIRST), then 0.27.8 = this.
