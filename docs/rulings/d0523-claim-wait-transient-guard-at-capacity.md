<!-- sess464 RULE-5 ruling on D-0523 (rejoin mount fails -28 during a transient sweep guard at capacity): in-kernel claim WAIT accepted; 8 STOP-SHIPs (rec… -->
# sess464 GPT ruling — D-REJOIN-CLAIM-ENOSPC-DURING-TRANSIENT-SWEEP-GUARD-AT-CAPACITY-0523

Defect: 32/32 volume, dead node reboots while a survivor holds the transient unclaimed-bucket sweep guard on its former slot -> mxfs_disklock_claim_slot pass 2 finds no slot -> -ENOSPC immediately -> mount aborts (chain 88 test2 07:22:57Z; remounted fine 6 s after the guard cleared). Evidence in the ledger record.

## Verdict
Fix belongs in the in-kernel claim/admission layer (dlm/disklock.c claim_slot or a claim_slot_wait() wrapper). REJECTED: restarting all DLM init from v5_mount per scan; returning -EAGAIN to systemd as the normal path; consuming MXFS_DISKLOCK_CLAIM_RETRIES=16 while waiting (those stay for CAW races on a FOUND slot). Exception: if all peers vanish during the wait -> return an internal "restart bootstrap phase" result to v5_mount (peerless cluster must re-run v5_bootstrap_run), never sleep hoping a nonexistent monitor acts.

## Liveness/progress
- "Progress by change" is sound ONLY for records contractually refreshed: sweep guards (GUARD_REFRESH_MS=1000 re-stamp), recovery leases with refreshed descriptor/guard, explicit phase transitions/slot release. Use hb_guard_abandoned()'s existing measured semantics for a frozen guard -> the established reclaim path, NOT reclassification as permanent; no unexplained "3x refresh" constant.
- NOT sound for WITHDRAWN / RETIRE_PENDING: they stay byte-identical while a peer fences/replays/retires. For those: wait for the MEASURED max wall of fence+replay / retirement while a capable OTHER member is live (resolver eligibility), or extend the protocol with an observable resolver lease {owner, op gen, phase, progress stamp}. Never reset a per-record stall timer on unrelated peer heartbeats.

## Absolute budget: REQUIRED
Progress-only can hang forever (refreshing-but-wedged guard, release/re-take churn, live-but-idle monitor). ONE monotonic absolute deadline for the claim wait, never reset by churn; derived from MEASURED end-to-end walls at 32 nodes: sweep, failure detection + PR fence, replay, PR-key retirement, monitor scheduling. On expiry return -ETIMEDOUT (transient) with P300-CLAIM-WAIT-GAVE-UP — never -ENOSPC (permanent). NOTE for the harness: a 180 s artificially held LIVE guard cannot both exceed a measured tens-of-seconds budget and be required to mount: shorten the success-arm hold below the budget, or make the 180 s arm assert the timeout path.

## STOP-SHIP #1 — recovery ordering (possible SEPARATE safety defect)
A joiner must not become operational on another slice while a required pre-join dirty-journal replay / writer-exclusion is incomplete. The rebooted node has a fresh random node_id, so "its own old slice" is not identifiable without a stable host identity -> the rule must be a GLOBAL recovery barrier (no new member ACTIVE/operational while any pre-join WITHDRAWN/recovery epoch is unresolved) or a stable predecessor identity + proof. If today's under-capacity claim of another free slot immediately implies normal membership with a WITHDRAWN predecessor slice unreplayed, THAT is a separate safety defect. RETIRE_PENDING needs the same audit: if it can mean an unfenced former writer, admission must block until retirement proof; if only delayed cleanup after proven exclusion, claiming another slice is fine. (sess464 action: check whether the pre-mountfs mount recovery barrier — 'MXFS mount recovery barrier complete: cohort=.. late=.. replayed=..' — already covers WITHDRAWN slices before xfs_mountfs; and the HB ident block (sess438, host/boot identity at offset 360) may give the stable identity.)

## Fail-fast set (unchanged)
QUARANTINED verdict, out-of-range member, unreadable/corrupt record, genuinely full (all live), single_node_exclusive=1 with any other live member, exclusive bootstrap unable to prove sole writer, no OTHER live member with unresolved WITHDRAWN/lease/RETIRE_PENDING, last peer lost during wait, bootstrap owner not provably abandoned, same-host successor cannot fence predecessor.

## Lock discipline
Dropping ctx->lock to sleep is required. Snapshot immutable diag data before unlock; monotonic deadline; relock + FULL reread/reclassify from disk; never act on a pre-sleep free/abandoned decision; exact-record CAW when claiming/clearing (guard released+re-taken between scans = ABA; only exact-image CAW prevents overwriting the new guard); handle signals/cancel/ctx lifetime; the joiner has NO heartbeat or monitor thread yet.

## Minimal shape
1 classify under lock {claimable | permanent | live-full | waitable guard/lease | peer-resolved WITHDRAWN/RETIRE_PENDING | bootstrap-required}; 2 permanent -> today's messages; 3 bootstrap-required -> internal phase result; 4 waitable -> deadline, per-slot {kind, owner/gen, timestamp, flags}, unlock, sleep measured scan interval, relock, reread; 5 refreshed guards: track identity+refresh, frozen -> abandonment/reclaim protocol; 6 WITHDRAWN/RETIRE_PENDING: resolver eligibility + measured op wall; 7 free slot -> exact CAW (conflict consumes one of the 16); 8 deadline/peer loss/signal/IO -> truthful rc; 9 rescan summary lines + exactly one DONE/GAVE-UP.

## Ranked STOP-SHIP
1 recovery ordering proof; 2 no change-progress for WITHDRAWN/RETIRE_PENDING; 3 absolute measured deadline; 4 peer-loss/bootstrap transition; 5 exact CAW/ABA; 6 preserve permanent fast-fails; 7 wait scans separate from the 16 retries; 8 -ETIMEDOUT vs -ENOSPC + logging.

## Required tests
holder dies mid-sweep; WITHDRAWN unchanged while peer replays (no false stall); wedged live monitor -> deadline fires; guard refreshing forever -> deadline fires; two joiners race one freed slot (exactly one CAW wins, loser reclassifies full); guard released+re-taken between scans; last peer dies mid-wait -> bootstrap; under-capacity dirty predecessor + free slice -> barrier verified; permanent cases immediate; peerless WITHDRAWN/RETIRE_PENDING + single_node_exclusive=1 no wait; deadline/abandonment boundary; CAW collision count independent of scans; interrupted mount / IO error leaves no claimed slot or leaked guard.
