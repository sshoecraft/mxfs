---
name: ccloop-c7ee71c6-sess383-GPT-ruling-outcome-import-chokepoint
description: sess383 RULE-5 ruling on the 3 measured fail-open arms in terminal-outcome import: one canonical validator reached via a quar_cb that RETURNS a dispo…
metadata:
  type: project
tags: [mxfs, d-513, rule-5, gpt-ruling, quarantine, admission, fs_gen]
---

# sess383 RULE-5 ruling — the terminal-outcome import chokepoint

Context: the sess333 pre-rig unit checks finally RAN (tools/recov_forge +
tests/d513_forged_record_checks.sh, real LUN, real mounts, 32/caw, 0.19.5).
Six shapes PASS; **three arms FAIL**, all in consumers other than the
classifier. Full measurements in ledger entry
D-TERMINAL-OUTCOME-IMPORT-UNVALIDATED-383.

## The three measured arms

- **A** `mxfs_v5_dlm_recovery_scan_outcomes` is a 4th import site that does
  NOT validate. A crc-valid record with `outcome=99` imported as a real
  AG-scoped verdict (`P241-RECOV-TERMINAL-SCAN ... importing`), and also fed
  `v5_closure_note_terminal` (which authorizes the selective grant purge).
- **B** `mxfs_disklock_recovery_read_outcome` has no fs_gen gate, so a
  PRE-MKFS GHOST (`fs_gen=0xdeadbeef` vs live `0x176ec8e4`) quarantined the
  live filesystem. The barrier ignored it correctly (`hb_gen_foreign`); the
  scan did not.
- **C** an FSWIDE quarantine imported by the scan does NOT refuse the mount —
  measured `mount rc=0` with `fswide=1` imported. The barrier's two FSWIDE
  gates both run ~0.5 s BEFORE the scan. Reachable without forgery: any
  legitimate FSWIDE verdict published between the barrier's sweep and
  registration (the late-mount case the scan exists for).

## Ruling

**Q1 — ONE canonical validator, reached through a callback that RETURNS.**
Do not duplicate the semantic predicate in dlm/ (two definitions drift, and
the policy is XFS-side: valid reasons, domain semantics, AG mask validity for
THIS fs, slot identity). Change `quar_cb`'s contract from "notification with
side effects" to "classify + import + return a disposition":
`VALID_AG / VALID_FSWIDE / INVALID_FSWIDE / FOREIGN / NOT_TERMINAL`.
Callers run `v5_closure_note_terminal()` ONLY on VALID_*, and only AFTER the
callback. **Do not infer "valid for closure" from "it imported FSWIDE" — an
invalid record imports FSWIDE by design.**
Make `mxfs_quarantine_import_oc()` private/low-level so no future consumer
imports unvalidated.

**The monitor's `oc->outcome == TERMINAL_REFUSED` prefilter is itself a
bypass.** An `outcome=99` record must REACH the validator and fail closed,
not be silently skipped pass after pass. Keep the dead-stamp gate; drop the
semantic prefilter. `-EPROTO`/`-EBADMSG` must likewise reach the fail-closed
path.

**Q2 — foreign generation gets a DISTINCT code, `-ESTALE`.** Full contract:
`-ENOENT` no descriptor · `-ESTALE` recovery object exists but belongs to
another fs_gen · `-EPROTO` current-gen descriptor malformed · `-EAGAIN`
current-gen valid, not quarantined · `-ENODATA` current-gen legacy zero
outcome · `-EBADMSG` current-gen nonzero outcome malformed · `0` validated
structural outcome. The gen gate runs BEFORE crc/semantic processing — a
stale pre-mkfs sector is outside the current filesystem's recovery namespace,
so malformed bytes inside it must not quarantine the new filesystem.
`-ESTALE` must NEVER cause backfill, closure-note, grant purge, slot
retirement/zeroing, or quarantine import. Log it rate-limited/aggregated
(current gen, observed gen, first slot, count) — foreign sectors are EXPECTED
after mkfs on this stack; a wrong LUN is a separate identity check. No
production caller wants a foreign record; a forensic tool uses a raw reader.

**Q3 — registration and admission are ONE synchronized transaction.** A mount
that discovers FSWIDE before the admission transition MUST fail -EIO;
admitting a known-globally-unusable mount is the zombie state the barrier
exists to prevent. (After full admission, transitioning a live mount to
EIO/quarantine is right — mount failure is no longer returnable.)
Do NOT simply move cache_init/scan before the barrier: registering callbacks
early exposes partially initialized XFS state and makes unwind harder.
Instead: init quarantine state → register cb while ADMITTING → scan → drain/
synchronize racing monitor callbacks → under the same synchronization check
FSWIDE and atomically go ADMITTING→ADMITTED or →FAILED → only then return
success. A bare `cache_init(); if (fswide) fail;` is INSUFFICIENT — the check
can read false and a callback import FSWIDE immediately after. Failure must
fully unwind: unregister cb, block new callbacks, drain in-flight, tear down
DLM/cache state, then free XFS state.
**Longer-term:** the barrier conflates "slots needing replay work" with
"slots carrying an admission-relevant terminal disposition".
`stage >= GRANTS_RELEASED` is a valid reason to omit a slot from the replay
cut, NOT to omit its persistent FSWIDE disposition from admission. The
barrier should examine current-generation terminal guards independently of
`get_recovery_pending_slots()`.

**Q4 — the closure path needs the validation, not just the import.** Closure
authorization requires: current fs_gen · descriptor structurally valid and
QUARANTINED · slot == desc.victim_slot · slot == oc.victim_slot · outcome
exactly TERMINAL_REFUSED · recognized reason · canonical domain · AG mask
valid for the mounted fs. One implementation of the predicate; the
callback's returned classification IS the closure path's proof.

**Q5 — further fail-open surface these shapes did not cover**
1. **Descriptor identity**: the classifier checks `oc->victim_slot == slot`
   but must also check `qd->victim_slot == slot` for non-legacy outcomes.
   The passing legacy/backfill test does NOT prove a crc-valid nonzero
   outcome paired with a MISPLACED descriptor is rejected.
2. **AG-mask bounds**: "nonzero" is not enough. A mask of only nonexistent
   AG bits is an effectively empty quarantine = fail-open. Canonical:
   FSWIDE ⇒ `ag_mask == 0`; AG_MASK ⇒ nonzero AND a subset of valid AG bits.
3. **Every read_outcome return** must be audited — I/O errors and unknown
   negatives must not look like absence; fail conservatively.
4. **No mutation before validation**: backfill, closure-note, grant purge,
   terminal retirement, hb zeroing, stage advancement. Fail-closed quarantine
   is an in-memory safety action, never authorization to alter the sector.
5. **Registration races**: the cb must not observe partially initialized
   quarantine/per-AG state, nor stay active during failed-mount teardown.
6. **Preserve** valid current-gen AG-scoped behaviour: mount admits, affected
   AGs EIO. Only FSWIDE (or invalid/unreadable mapped to fail-closed FSWIDE)
   refuses admission.
