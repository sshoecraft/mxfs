---
name: ccloop-c7ee71c6-sess50-GPT-ruling-step4-ordering-and-two-new-defects
description: sess50 RULE-5 GPT ruling on foreign-replay step 4: copied manifest CAN be dropped (CAW table is the manifest) but durable REPLAYED state CANNOT; both…
metadata:
  type: reference
tags: [foreign-replay, authority-token, D-FOREIGN-REPLAY, step4, gpt-ruling, purge-ordering, recovery-descriptor]
---

# GPT RULE-5 ruling — foreign-replay step 4 ordering (sess50)

Campaign: [[compiled-foreign-replay-authority-tokens]]. Asked adversarially with
line-verified code facts; GPT confirmed two NEW defects and partially accepted
my reduction of its own sess48 spec.

## The three claims I brought, and the verdicts

**CLAIM A (my reduction): "the CAW lock table IS the durable manifest, so no
separate descriptor + IMAGE_REPLAY_DONE is needed — just never purge a slot's
authority before its slice is known replayed."**
→ **PARTIALLY ACCEPTED.** The *copied* manifest may be dropped: authority tuples
may live solely in the CAW table provided they are checksummed, immutable before
REPLAYED, cover every class the gate needs, and cannot be overwritten by slot
reuse. But durable recovery *identity + completion state* may NOT be reduced away.

The exact crash window that forces it (quote): *replay output has become durable,
some or all CAW authority has been purged, but the replayer crashes before the
in-memory pending bit is cleared and before the HB-slot "done broadcast" is
durably established.* After a total-cluster crash the disk state cannot
distinguish "authority purged after replay" from "authority destroyed before
replay" — one reading loses acked data, the other wedges locks forever. A durable
REPLAYED state removes the ambiguity. It need not be a separate
`IMAGE_REPLAY_DONE` block — HB slot flag, CAW control record, or a slice-clean
transition all work — but semantically it IS a DONE marker.

Also raised on A(i): my "re-replay against an empty manifest is benign" argument
is NOT automatic. It holds only if the gate suppresses the whole *logical
transaction* in **every recovery pass** — intents/EFI-EFD, inode+quota items,
unlinked-list processing, pass-1 cancellation-table construction, recovery-time
alloc/free, and transactions with no ordinary buffer images. A gate that only
declines to install buffer images can make the second recovery run a *different
program*, not a subset of the first. Direct constraint on step 5.

A(iii): in-memory-only `recovery_pending` is acceptable **as a scheduling hint
only**. Losing it must cause a rescan+retry, never loss of the obligation.

**CLAIM B: mount-time own-slot purge is a real defect.** → **CONFIRMED.**
Sequence: N crashes holding AG EX with a dirty slice → remounts → PASS-1 →
purges its own CAW authority (`v5_mount.c:1769`) → heartbeats (so peers do not
see it stale) → 10-30 s of stale-purge + discovery + membership settle → only
THEN `xlog_recover`. In that window peer P legitimately acquires the AGs N
released and writes them; N's **ungated** PASS-1 replay then installs stale
metadata over P's newer work. The in-tree comment at `xfs_log.c:623-626` —
"safe because our unreplayed death left our grants quarantined" — is **false as
written**: we de-quarantine before recovering.
Fix = **(c) defer the purge while adopting/quarantining the old authority**, not
bare deferral: mount must enter a RECOVERING mode where the previous
incarnation's records stay conflict-blocking while the new instance still makes
progress (needs an explicit `RECOVERING_OLD_INCARNATION` / adopted-stale-ownership
/ recovery-only self-conflict bypass). A purely in-memory or lease-style global
fence is NOT sufficient — a crash loses both the fence and the manifest.

**CLAIM C: mount-time cross-instance stale-slot purge is a real defect.**
→ **CONFIRMED.** A non-advancing heartbeat proves "probably dead, may be fenced";
it proves nothing about the slice being clean, replayed, or disposable. Waiting
5 HB intervals is not fencing and is not evidence of log cleanliness.
Required flow: detect → PR-fence → mark/reconstruct the recovery obligation →
inspect the slice → clean ⇒ record durably then purge; dirty ⇒ replay while
preserving authority → flush → durable REPLAYED → purge.
Cheap sound clean-test: XFS's OWN validated clean-log discovery for that exact
slice+incarnation, or a matching durable replay-complete record bound to
{fs uuid, victim slot, victim boot/incarnation, slice identity, log
generation/target head-tail}. **Do NOT use a naive head==tail.** Heartbeat
timestamp, empty CAW ownership, a newly claimed slot, and absence of in-memory
`recovery_pending` are all UNSOUND clean tests.

## Binding invariant (GPT's wording, stronger than mine)

> For every fenced victim incarnation V and recovery target R, until a durable
> REPLAYED(V,R) state exists, all authority facts used by replay admission remain
> durable, immutable, and conflict-blocking; V's slot and slice cannot be reused.
> REPLAYED(V,R) may be written only after every admitted recovery effect is stable
> on storage. Authority purge and conflicting grants may occur only after
> REPLAYED(V,R) is durable.

Stronger than "never purge until replayed" because it defines *known*, and covers
mutation and slot reuse, not just explicit purge.

## Required ordering

fence victim → freeze recovery inputs (no slot/slice reuse, authority preserved,
conflicting grants blocked, self-purge and stale-purge locked out) → durable
RECOVERING descriptor → replay under a transaction-wide gate applied consistently
in all passes → make replay output durable (any error ⇒ incomplete, DO NOT purge)
→ durable REPLAYED → purge authority + retire incarnation → resume.

Mount handling: matching REPLAYED ⇒ suppress replay, finish any incomplete purge.
RECOVERING/no DONE with intact authority ⇒ retry recovery. Clean-log proof ⇒
transition to REPLAYED then purge. Identity/generation mismatch ⇒ fail closed.
**Dirty slice + missing authority + no REPLAYED ⇒ fail closed as UNRECOVERABLE,
not silently skip.**

Durable minimum: victim slot, victim boot/incarnation, slice identity, recovery
generation or target head/tail/LSN, state (RECOVERING|REPLAYED), checksum + fs
UUID binding. May stay in memory: election, pending cache, retry timers,
coordinator, workqueue state, parsed manifest cache, survivor notifications.

## Closing ruling

- Reduce the copied manifest if you want.
- Do NOT reduce away durable recovery identity and completion state.
- **Fix both mount-time purge paths BEFORE enabling the gate.**
- Do NOT trust PASS-1 quarantine until the self-purge ordering is reversed.
