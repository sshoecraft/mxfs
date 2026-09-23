<!-- sess441 RULE-5 review of the item-5b bootstrap-owner landing: SS-1 retain owner key/ledger on refusal, SS-4 hb/transition serialization, SS-6 REVOKED… -->
# sess441 GPT review of the 5b landing (NOTE: the prompt lost the code body; the ruling is on the described design — treat line refs as symbolic)

STOP-SHIP before first rig measurement:
- SS-1/SS-10: after the seal, the ordinary unwind must NOT unregister the owner key / retire its ledger entry (evidence the record names; takeover is authorised only by fencing that key). APPLIED: mxfs_scsipr_retain_key on any post-claim failure path (P302).
- SS-2: owner exemption must be an exact identity, not key-only; a victim record publishing our key must fail closed. APPLIED: victim entry with pr_key==ours ⇒ P-BOOT-KEY-UNCLASSIFIED refuse (own-boot exemption handles the all-ours case).
- SS-3: unregister ambiguity — moot with retention.
- SS-4: heartbeat CAW vs SEAL/RECOVERING transitions must be serialised. ALREADY TRUE: both under b->lock, bs_reload_ours_locked validates by term/owner/nonce, CAS from the fresh image.
- SS-5: -ESTALE fail-stop; refuse() must not touch a record not exactly ours; release_claim only from CLAIMED. TRUE: bs_own_transition refuses; refuse() skipped when boot_hb_lost; loop checks boot_hb_lost per entry.
- SS-6: never note_dead_node before certification. TRUE: called only after recovery_acquire returns 0 (certified lease).
- SS-7: KEY_ABSENT_UNPROVEN never certifies. TRUE: certify refuses non-proving kinds; class 3 needs PREEMPT_ABORT_DONE.
- SS-8: fail closed on noident, overflow, duplicate identities. APPLIED duplicate-key check.
- SS-9: own-boot exemption must consider READ KEYS; zero-record case must not be vacuous. APPLIED: foreign key on target ⇒ total outage; n==0 returns earlier.

FIX-BEFORE-5D: F-1 post-seal registrant reconciliation before replay and again before completion (a key registered after the manifest READ KEYS is unfenced); F-2 durable defer/resume policy for -EBUSY (an unwind after seal = abandoned owner); F-3 class 3 never indexes slice arrays (true); F-4 explicit UNKNOWN_REGISTRANT kind, never fabricate node ids; F-5 re-verify frozen identity vs the victim sector before the intent (recovery pipeline does: intent CAS on the exact record); F-6 same-key same-boot = RESUME; F-7 READ FULL STATUS before global completion.

NOTES: window = lease_timeout + early poll is conservative only with monotonic reader clock and read failures never read as frozen (true: unread ⇒ refuse). Manifest FUA then SEAL order is right; verify FUA honoured on the target.
