<!-- sess463 RULE-5 ruling: D-FOREIGN-REPLAY-UNGATED-IMAGES stays OPEN (verification-blocked on the cc pace row): criterion (2) 'board clean' is literal;… -->
# sess463 GPT ruling — D-FOREIGN-REPLAY-UNGATED-IMAGES disposition question

Question: may the record close F&V with criterion (2) "32-node board clean apart from the policy cell" read as "no row fails for a cause attributable to this record", given crash_consistency fails only as a RULE-0 timeout (all checks pass) attributed to the separately-open D-32NODE-SHARED-DIR-CREATE-PACE / D-CRASH-CONSISTENCY-401?

## Ruling: DO NOT CLOSE.
- (2) is an OUTCOME criterion, not an attribution criterion; a board with a red crash_consistency row is not clean. Reinterpreting after failure = the prohibited precedent. Separate ledgering explains WHY verification is blocked; it does not satisfy (2).
- Operational label allowed: "FIX IMPLEMENTED; VERIFICATION INCOMPLETE — blocked on D-401 / D-PACE". Status stays OPEN.
- Masking evidence (all checks failed=0, zero mxfs-cc-FAIL, per-node artifacts, kernel_health + zero_silent_loss PASS on the same board, NDR PASS with override telemetry, failure located at the fleet barrier) supports causality documentation only; it cannot prove an early timeout never masks a later replay fault.
- Criterion (3): the 10 pre-fix laps do NOT count. A code change addressing the defect resets the streak: 10 consecutive PASS on the FINAL fixed build under production defaults, no intervening relevant change, buflsn_skips=0 + expected OVERRIDE telemetry retained. Chain 87's 6 laps = laps 1-6 of that streak ONLY if no relevant build change follows (any later relevant build restarts the count).
- Closure path: on the final candidate, (a) NDR 10 consecutive PASS; (b) a board actually clean except the policy cell — crash_consistency PASS within the UNCHANGED 90 s budget. D-401/D-PACE need not formally close first, but its board symptom must be gone without relaxing/reclassifying/suppressing/extending the test.

Consequence: the shared-directory create pace (D-32NODE-SHARED-DIR-CREATE-PACE, ruled design = delegation/sharding, sess436 items 1-2) is now on the critical path of item 1.
