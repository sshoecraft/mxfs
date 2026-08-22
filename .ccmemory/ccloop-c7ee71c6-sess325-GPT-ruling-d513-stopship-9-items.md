---
name: ccloop-c7ee71c6-sess325-GPT-ruling-d513-stopship-9-items
description: sess325 RULE-5 diff review of D-513 containment (0.12.0 sv C84100559): STOP-SHIP, 9 required pre-rig changes; full list in body + transcript
metadata:
  type: project
tags: [d-513, rule-5, quarantine, foreign-replay]
---

# sess325 RULE-5 ruling — D-513 containment diff review: NOT DEPLOYABLE YET

Reviewed: full 9-item implementation (sess323-325), builds clean as 0.12.0
sv C84100559E4BD2D5D0AB0BA. Core (c)+(a) design ruled SOUND; 9 required
changes before the rig cycle:

1. **Lease release on refusal path**: after successful publish, explicitly
   release/abandon the recovery execution auth WITHOUT advancing/completing
   the descriptor (new API e.g. mxfs_v5_dlm_recovery_release_terminal).
   Verify: no renewal churn, no unmount wait, no stale-auth reuse. Torn
   latch must be race-safe against delayed work from a prior slot
   incarnation.
2. **-EPERM conflict**: synchronously READ the canonical durable outcome
   (new read API), validate crc/incarnation/QUARANTINED, import it, latch
   terminal locally, release auth, STOP reaping. Never treat -EPERM as
   terminal without successful readback; readback failure → descriptor-read
   retry, not another full replay.
3. **Incarnation-keyed dedup**: seen_seq[slot] alone is wrong across slot
   reuse — track (victim_epoch, publish_seq) tuple in the XFS map too.
4. **Mount-time scan**: monitor pass + registration race means a late mount
   can miss existing outcomes. Register cb BEFORE monitor scan or replay
   all current outcomes at registration + synchronous descriptor scan
   before ops are exposed. Verify HB claim/reuse path refuses QUARANTINED
   sectors via every CAS path.
5. **Digest must not gate containment**: publish terminal even with failed
   digest reread — add outcome flags bit (use pad0 → flags,
   MXFS_RECOV_OUTCOME_F_DIGEST_VALID); digest_valid=false + zero digest.
   (Supersedes sess320's digest-fail→transient-retry rule.)
6. **PARK**: verify full DLM request cancellation before restart (CAW
   polled-CAS likely leaves nothing outstanding — verify); no sleep under
   locks; prefer wake on import/recovery-complete/shutdown; broad
   any-pending-recovery predicate acceptable ONLY if documented as
   deliberate containment-over-diagnosis trade.
7. **Q5 accepted-residue decision**: AG-gate -EIO into an already-dirty
   trans → dirty-cancel LOCAL shutdown possible. Either relax criterion to
   "zero timeout-cascade shutdowns" (racing-op local shutdowns accepted) or
   build activation/drain barrier. Must run concurrent metadata stress
   during refusal injection to test.
8. **Invalid outcome CRC**: desc QUARANTINED + bad outcome crc must not be
   silently skipped forever — persistent high-severity alert + fail closed
   fswide.
9. **Import stops reap**: cb must also set the torn latch for the victim
   slot so non-publisher survivors stop re-arming replay churn.

Rig plan additions (Q7): 3 refusal shapes (AG-mask POLICY, fswide POLICY,
TORN), conflict race (two proposals, loser imports winner), delayed-monitor
race, late-mount EIO-before-first-monitor-pass, slot-reuse rejection, park
wake matrix, concurrent alloc/create/rename/log-pressure during import,
count ALL force-shutdown entry points, corruption/error path matrix.
