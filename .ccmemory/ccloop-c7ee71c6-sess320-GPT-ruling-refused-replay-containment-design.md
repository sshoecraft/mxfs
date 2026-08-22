---
name: ccloop-c7ee71c6-sess320-GPT-ruling-refused-replay-containment-design
description: sess320 RULE-5 ruling #90: durable terminal-outcome record + survivor quarantine import + EIO error path (real plumbing); PENDING waits park not shut…
metadata:
  type: project
---

# sess320 — GPT ruling: refused-foreign-replay survivor containment (D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513 / #90)

Full text in sess320 transcript. Key points:

## Q1 — survivor behavior = (c)+(a), NOT (b) alone, (d) rejected
- Recovery-lease OWNER (only) durably publishes a terminal recovery-outcome record: victim slot+incarnation, fence cert id/epoch, lease epoch/owner, slice gen+digest, manifest digest, outcome {RECOVERY_PENDING, RECOVERED, TERMINAL_REFUSED}, refusal reason {policy / malformed / torn-incomplete / io-instability / authz}, impact-domain descriptor, publication gen/checksum. Do NOT mutate the victim's frozen descriptor beyond what B6/B7 permit — prefer a separate monotonic record. Record does NOT clear grants/authorize purge — it only synchronizes the quarantine decision.
- Survivors import it, build a cached quarantine map; acquires touching the domain fail IMMEDIATELY -EIO (not after 4 timeout cycles). ESTALE rejected (induces retries) — EIO is correct.
- While PENDING: dead-slot-blocked waits must NOT take the ilock-timeout→SHUTDOWN_CORRUPT_INCORE path; park recovery-blocked, monitored, rate-limited health alerts. (b)-style parking = temporary bridge only, not endpoint.
- ERROR PLUMBING MANDATORY: synchronized admission/acquisition contract — (1) check quarantine before enqueue, (2) wake/cancel existing waiters on quarantine publication, (3) re-check before consuming a grant, (4) return an error aborting the enclosing op. Pre-ilock check alone has publication TOCTOU; void-hook-return-without-lock categorically unsound. If above-hook coverage can't be complete, ilock adaptation must gain a return-capable path despite invasive caller work.
- Replayer crash before durable publication → normal lease expiry/re-election (that is not a "second attempt"). Before publishing terminal, owner must REREAD/verify the slice + record digest so transient I/O isn't mislabeled deterministic.

## Q2 — classification requires ALL of
dead+fence-certified; incarnation matches (not reused slot); durable terminal record for that slice/incarnation; requested mode actually conflicts with unpurged victim grant; resource present in frozen manifest; resource inside computed impact domain. Manifest cross-check done at import time, cached. Bitmap-vs-manifest disagreement = internal recovery fault → escalate, fail closed WIDER, never casual EIO.
- Impact domain may EXCEED held-set: union of manifest-held resources + resources derived from ALL parsed journal items + containing AG/global domains. Can't prove complete → widen to AG or FS. Genuinely torn/unparseable → FS-WIDE refusal stays required (availability never overrides integrity uncertainty).

## Q3 — interim gen-3 testing
Suspend general fence_during_write-class campaigns; only narrow containment tests with disposable FS + reformat after each induced refusal, one fault at a time, verify all survivors imported same record, D-state monitoring. Resuming sustained fence testing requires: repair/token-authorized-redo path, OR gen-4 exact enforcement + repair path for genuine refusals, OR mandatory reformat after every terminal refusal. Repair/restore procedure is NOT optional for production readiness even post-gen4.

## Q4 — build order (reordered from my proposal)
(i) containment → (iii) enforcement machinery behind hard-off/shadow gate (build NOW, before gen4) → B2/B3 → B4 (using enforcement-capable builds; verify terminal-refusal records survive upgrade/reboot/re-election) → gen-4 flip + enforcement enable → 108-capture campaign (pre-flip shadow captures earlier if prerequisite).

## Framing corrections
- Split the sess233 latch reason: POLICY_REFUSED_COMPLETE (parsed fine, shadow-passed, blanket policy refused — THIS incident) vs PHYSICALLY_TORN_OR_INCOMPLETE. Different containment confidence + repair options.
- Resource wait ≠ corruption boundary proof.
- Count nit: 32-node cluster → 31 survivors shut down + killed victim = 32 down.
