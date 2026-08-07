---
name: ccloop-c7ee71c6-sess131-GPT-ruling-protogen4-and-quarantine
description: sess131 RULE-5 ruling: MXFS_PROTO_GEN 3 to 4 APPROVED with 4 mandatory blockers; runtime quarantine of legacy FENCED/NONE descriptors REJECTED as wri…
metadata:
  type: reference
tags: [rule5, gpt-ruling, protogen, mixed-version, quarantine, recovery-descriptor]
---

# sess131 RULE-5 ruling (gpt-5.6-sol) — D-MIXED-VERSION-UNGATED-REPLAY

Asked: (A) is bumping `MXFS_PROTO_GEN` 3 -> 4 the right and sufficient mechanism for the 0.11.422 certified-replay gate; (B) should survivors durably QUARANTINE legacy uncertified FENCED/NONE descriptors.

## VERDICT

- **A: APPROVED. Blockers 1-4 are MANDATORY before closure.** The certified-replay rule IS a cluster protocol generation change even though the descriptor encoding is byte-identical — "the protocol's set of permitted participants and writes changed." The 1->2 precedent applies directly.
- **B: REJECTED AS WRITTEN.** An arbitrary survivor must NOT mutate the victim's descriptor merely because the mutation is restrictive.

## A — the four blockers

**Blocker 1 — recovery can start before envelope admission.** A gen-3 kernel could begin foreign replay before discovering the envelope says gen 4; layer 3 (heartbeat) cannot repair replay that already happened. Required invariant: read+validate envelope, require `cluster_proto_gen == MXFS_PROTO_GEN`, and ONLY THEN initialize disklock membership, recovery election, journal-slice discovery, or any replay-capable worker. Suggested implementation: an immutable `proto_admitted` mount-state bit that every recovery entry point asserts. **Audit list**: normal mount; remount and mount-retry; error recovery after a partially initialized mount; deferred recovery workers; mount-time XFS journal recovery callbacks; snapshot/secondary-superblock paths; administrative "recover only" entry points; anything that initializes disklock before the envelope check completes. **Do not ship the bump until this ordering is audited.**

**Blocker 2 — a mounted or suspended gen-3 node survives the upgrade.** Changing the envelope does not revoke state cached by an already-mounted kernel. A paused / partitioned / storage-disconnected gen-3 node may resume and replay before the gen-4 monitor fences it. 3->4 must be an OFFLINE CLUSTER TRANSITION, not merely an offline metadata write: stop/unmount every member; acquire an exclusive maintenance/storage lease; revoke or preempt all old PR registrations; invalidate the old membership epoch; ensure suspended nodes cannot regain LUN access without remounting; THEN update the volume generation. "Operators say all nodes are unmounted" is weaker than actual storage exclusion. Layer 3 fencing afterwards is defense in depth, not the transition mechanism.

**Blocker 3 — the generation update is not a crash-safe activation transaction.** Envelope copies / checksums / backup headers can disagree after a crash, so different nodes admit different generations. Define the upgrader's write ordering and interrupted-upgrade state; all authoritative envelope copies updated with FUA/flush; readers must FAIL CLOSED on disagreement and must never opportunistically pick an older valid copy.

**Blocker 4 — any unsafe build released as gen 4 permanently defeats the gate.** The disk generation names a behavioral contract, not a version string. Certified-replay check + descriptor-write restrictions + mount ordering are mandatory conformance requirements for gen 4. Add mixed-build tests proving every gen-3 build is rejected BEFORE recovery starts.

## A — rollout

"Accept N and N-1 read-only" is NOT safe: a read-only mount may still perform journal recovery, and foreign replay IS mount-time recovery; the dangerous gen-3 binary does not know gen 4 means "do not recover." **Hard refusal is the correct default.** A defensible RO compatibility mode would need a separate gen-4-aware path with no membership, no heartbeats, no local OR foreign replay, no metadata writes, no DLM participation, preferably against a snapshot — i.e. an offline inspection tool, not a mount.

Optional two-phase deployment to cut downtime (phase 1 is NOT a safety boundary): (1) deploy a transitional build carrying the certified-replay fix while the disk is still gen 3; (2) verify and fence out older builds; (3) offline activation to gen 4; (4) boot the final gen-4 build.

Correction to my framing, accepted: a correct new node does not trust `stage=FENCED` alone — it separately checks `fence_kind` and the certificate. The incompatibility is behavioral/semantic, not structural. That does not weaken the case for the bump.

## B — why rejected, and what to do instead

**Blocker 5 — quarantine written without ownership + sector serialization.** "One-way and more restrictive" is NOT a substitute for write authority. A survivor can hold a stale sector image and race the victim updating its heartbeat, a recovery owner advancing/replacing the descriptor, a purge or reuse for a new incarnation, another survivor becoming owner, or a sector-level RMW covering unrelated fields. Consequences: overwriting newer state, quarantining a REUSED slot, CRC corruption, permanent capacity loss on obsolete identity.

**Blocker 6 — writing the victim's sector before excluding the victim.** A live victim and a survivor can write the same sector concurrently. Proven exclusion is required before ANY survivor-side descriptor mutation, unless there is a genuinely independent atomic quarantine location the victim never writes.

Owner-only quarantine (option i) is acceptable ONLY with: ownership acquired via the existing owner/epoch protocol; descriptor identity + incarnation + sequence + expected old contents revalidated at commit; the same durable/conditional serialization as other descriptor advances; and victim-sector writes already proven safe.

**If those conditions cannot be met, option (iii) is the correct runtime behavior**: refuse replay, leave the descriptor UNCHANGED, publish a persistent health event / named rate-limited alert, and require an offline tool or a later authorized recovery transaction to alter it.

**Blocker 7 — no disposition or repair model exists for legacy obligations.** Automatic terminal quarantine can permanently destroy a slot that a future certified repair could have recovered; an ad-hoc un-quarantine could replay stale journal boundaries. An unmarked blocked descriptor is NOT equivalent to a quarantined one — the unmarked one can still be repaired by future software. Pick ONE policy before enabling automatic quarantine: (a) permanent abandonment, operator knowingly accepts loss; (b) certified reconstruction — fresh certified exclusion, revalidate victim identity/incarnation and journal state AFTER exclusion, build a NEW recovery transaction, never bless the old NONE descriptor; (c) offline administrative discharge with an audited decision. **Do not add a generic "clear quarantine" operation.**

## `chk_mxfs --upgrade-protogate`

Best place to **detect and inventory**, NOT to auto-quarantine. Recommended: acquire exclusive maintenance access and revoke live registrations; scan all descriptor locations and redundant copies; classify each (certified-valid / legacy FENCED-NONE / structurally invalid or CRC-bad / identity-sequence inconsistent / already quarantined); emit a durable upgrade report naming slot, victim identity/incarnation, stage, reason; for legacy NONE offer leave-unresolved-and-activate (gen-4 runtime fails closed anyway), an explicit destructive `--quarantine-legacy`, or a separately designed certified reconstruction; **refuse to synthesize a fence certificate** because the tool believes the cluster is offline.

Explicitly rejected: "refuse the whole generation upgrade whenever a NONE descriptor exists" as the default — leaving the volume at gen 3 preserves an old binary's ability to mount and replay ungated, which is worse. Upgrading to gen 4 with a blocked legacy descriptor is usually the safer state.

**Blocker 8 — the upgrader must not treat "offline" as exclusion evidence.** Administrative offline status is not durable proof the victim was excluded at the relevant time and cannot validate stale journal boundaries.

## Limitation to write into the entry

The bump is PROSPECTIVE. It does not prove a gen-3 node never performed an ungated replay before the upgrade. A stale FENCED/NONE descriptor is evidence of exposure, but its ABSENCE is not proof of safety — an unsafe replay may have completed and been purged. The upgrade procedure must state: gen 4 prevents future admission of unsafe replayers; it does not certify historical filesystem consistency; finding legacy or suspicious recovery records must trigger scrub/fsck and an operator-visible "previously exposed to ungated replay" status.
