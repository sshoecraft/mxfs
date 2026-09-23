<!-- sess402 RULE-5 ruling (D-402 / D-FOREIGN-REPLAY-UNGATED-IMAGES): 'victim bit present at replay' is unsound as proof; freeze+snapshot manifest at fenc… -->
# sess402 RULE-5 ruling — token-gate "held" predicate vs dead-holder bit lifetime

Evidence brought: kill1 (enforce off) single-owner AG 13 victim evaluated held/WOULD_APPLY=6,
shared AG 2 victim staleep; kill2 (enforce ARMED) shared-AG victims slots 30/31 (AG 5/6)
evaluated not_held=3/4 -> ATOMIC-SKIP -> POLICY-REFUSED -> AG quarantine, while the co-owner
test24 had ping-ponged AG 5 with the victim until 1 s before the kill and then sat blocked on a
"peer-held AG" 65 s until the quarantine EIO. Purge-on-lease-expiry KEEP_EX retains EX/PW
bits; closure purge runs after the verdict.

## Ruling (gpt-5.6-sol, full text in transcript c95147f5-successor sess402)
1. What may clear a dead node's EX bit before replay: legitimately only (a) a clean unlock
   that completed on the platter before death/fence, or (b) explicit post-fence cleanup AFTER
   authority evidence is preserved. NOT legitimate: co-owner "provably-stale" stripping on
   heartbeat staleness alone (HARD: expiry is not fencing and must not destroy replay
   evidence — audit this path first on shared AGs), BAST-timeout/orphan force, strand repair
   before fence+capture. Lease purge ruled out only if KEEP_EX is the executing branch — verify
   code, not the comment. A clean handoff remains possible despite the peer "blocked" (stale
   local DLM state, another resource, recovery serialization, repeated failed CAWs).
   DISCRIMINATING EVIDENCE: an ordered trace of every successful CAW on that slot (old image,
   new image, initiator slot/incarnation, completion, ordering vs PR-fence completion) + the
   waiter's exact resource and last CAW result. A slot dump only at not_held says what, not
   who/when.
2. "Victim bit present at replay" is NOT sound — a mutable current-state predicate used as
   historical proof. Preferred: FENCE-TIME MANIFEST SNAPSHOT — hard requirements: PR fence
   complete and victim commands settled; snapshot BEFORE any strip/grant/repair; durable and
   bound to victim slot, incarnation, fence event, slot generation, epoch, lineage; a
   RECOVERY_PENDING marker prevents takeover/writes until replay disposition. Hazards:
   inconsistent snapshot, slot/incarnation reuse, in-flight commands, epoch wrap, successor
   modifying the AG before old images replay. "lineage+epoch equality ignoring the bit" is
   sound only if EVERY grant (incl. same-node reacquire) bumps a non-reusable epoch and the
   resource is frozen first; "bit absent but epoch unchanged" = "no successor grant observed",
   not "held at death". Old-tenure issue: a live slice may hold committed records from a tenure
   cleanly released before death — a fence-time held-set will not validate them; needs durable
   clean-release coverage or a guarantee that clean release retires the recoverable log state.
3. Co-owner reacquisition is NOT proof of a clean victim drain (it may have acquired only
   because recovery stripped the dead holder). A CLEAN skip needs a durable CLEAN-RELEASE
   CERTIFICATE {resource, owner incarnation, lineage, grant epoch, drain_lsn} persisted after
   the tenure's metadata was flushed, covering the skipped log sequence, with bit-clear and
   successor grant causally after it; every buffer of the txn covered or replayable under
   frozen exclusive recovery. Outcomes: died mid-tenure -> freeze AG, replay under recovery
   ownership, flush, then clear/grant (quarantine/RO is the correct conservative result if
   replay cannot be authenticated); certified clean handoff -> REDUNDANT_CLEAN, never replay
   over successor writes; unknown -> keep recovery-pending/quarantine. Multi-resource txns
   cannot be CLEAN because one AG has a clean release.
4. Kill-test assertions keyed on fence-time state, not slot class. Single-owner killed holding
   EX: snapshot has the bit+epoch+lineage, all applicable items validate, replay completes,
   completion flushed before dead-bit purge, AG back in service with no quarantine. Two-owner:
   two DETERMINISTIC subtests — (i) mid-tenure crash with handoff frozen (peer must stay
   blocked until fence, snapshot, replay, purge; expect successful replay then peer grant, not
   not_held); (ii) post-clean-handoff crash (expect REDUNDANT_CLEAN, peer ownership intact, no
   replay over peer changes). Random ping-pong timing cannot establish the correct result.
   HARD ORDERING: detect -> PR fence + establish incarnation -> freeze/RECOVERY_PENDING the
   affected resources -> snapshot+publish slot bitmaps/epoch/lineage/generation into the FENCED
   descriptor -> classify log items vs snapshot + clean-release records -> recovery-exclusive
   replay before successor writes -> flush + durable completion -> conditional purge using the
   snapshotted tuple -> advance epoch, clear RECOVERY_PENDING, grant waiters. Judgment call:
   snapshot all slots vs only log-referenced ones (referenced is cheaper but needs the log read
   before any slot mutates; atomic recovery-pending marking is safer).

## Where this lands
D-FOREIGN-REPLAY-UNGATED-IMAGES (gate design) + D-TMPFILE-CHURN-KILL-FOREIGN-REPLAY-EFSCORRUPTED-402
(symptom). Instrumentation queued sess402: P-VMAN-NOTHELD slot image at the verdict (0.23.16);
still missing per the ruling: the ordered per-slot CAW mutation trace and the waiter's last CAW
result. Harness: tmpfile_churn_kill.sh auto:single / auto:shared victim classes exist; the
deterministic "freeze handoff then kill" and "kill after certified clean handoff" subtests do not.
