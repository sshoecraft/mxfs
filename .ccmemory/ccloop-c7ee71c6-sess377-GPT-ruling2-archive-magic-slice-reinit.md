---
name: ccloop-c7ee71c6-sess377-GPT-ruling2-archive-magic-slice-reinit
description: sess377 follow-up RULE-5 ruling: distinct archive magic OK instead of INCOMPAT bit (with old-writer audit + slice_count invariant); full-overwrite sl…
metadata:
  type: project
tags: [rule5, gpt-ruling, quarantine, chk_mxfs, defect-376, archive]
---

«RULE-5 FOLLOW-UP RULING — archive magic vs INCOMPAT bit, slice reinit (sess377)»

Consult 2 of sess377, after patch item 1 and repair-step-1 were landed and
rig-verified. gpt-5.6-sol.

## Q1 — distinct archive sector MAGIC instead of a superblock INCOMPAT bit

APPROVED, conditionally. "Distinct magic is sufficient FOR CORRECTNESS, assuming
the complete old-writer audit; it is NOT sufficient to GUARANTEE archive
preservation across old software."

Sound only if ALL of these hold (this is the audit to run before building):
 1. old claim code cannot write outside 0..slice_count-1;
 2. every old reader of 0..63 rejects non-MXLK sectors BEFORE consuming any
    other field;
 3. no old repair, initialization, scrub, resize, or "clear invalid heartbeat"
    path rewrites sectors merely because their magic is unknown;
 4. the archive has NO role in admission, fencing, recovery, or in deciding
    whether the source slot may be reused;
 5. losing an archive AFTER the quarantine has been safely released cannot make
    the filesystem unsafe.

The hazard distinct magic does NOT close is PRESERVATION BY OLD WRITERS.
Concrete bad paths: expanding slice_count so an archived sector becomes
claimable; an old claim path on such an expanded volume treating MXAR as free;
an old checker or heartbeat-table initializer zeroing unknown/non-MXLK sectors;
an old administrative purge treating unknown magic as garbage rather than
skipping it. "New claim code skips archive magic" does NOT protect against an
OLD kernel after a geometry expansion.

REQUIRED INVARIANT to add:
> A volume must not increase slice_count across any occupied archive slot
> unless all affected archives have first been exported and removed or
> relocated.
Top-down allocation postpones the collision; it does not eliminate it.

Confirmed: after a successful repair the final state is source slot EMPTY,
slice reinitialized clean, fs consistency-checked — an old kernel claiming that
slot then is CORRECT, and the archive need not gate it.

Policy tension to state explicitly in the docs: if the archive is MANDATORY
durable audit evidence you cannot simultaneously promise unrestricted
old-kernel RW compatibility without proving old software never rewrites those
sectors. If it is BEST-EFFORT diagnostics after release, the framing is
consistent.

Digest note: the two-seed crc32c digest is fine as a wrong-token/corruption
detector but is NOT tamper-resistant. If "evidence" carries audit/forensic
meaning, archive and export should additionally carry SHA-256.

## Q2 — archive durability stays a release precondition

YES. Ordering retained:
 1. construct the archive from the still-present source guard;
 2. write it; 3. flush durably; 4. read it back INDEPENDENTLY and verify
 identity, checksum and the complete copied guard; 5. only then the first
 destructive operation on the source guard or slice.
Not required for fs consistency (the archive is non-semantic) — required to
uphold the protocol's evidence-preservation promise.

Archive region FULL: refuse by default; require export before pruning. Safe
export/prune sequence: export to a DIFFERENT durability domain; fsync the file;
reopen and re-read to verify the full archive digest; fsync the containing
directory if a new/renamed file is the retained copy; explicitly confirm the
archive identity being pruned; prune; flush and verify the slot is available;
archive the current quarantine into it and verify; continue the repair.
--export-archive must NOT silently write onto the same damaged MXFS volume and
call that independent preservation.

Break-glass is a policy choice: no bypass if evidence preservation is a hard
guarantee; otherwise a conspicuously named --release-without-archive that
demands the displayed verdict digest and emits a permanent operator-visible
warning. An ordinary --force is too weak. With no bypass, the archive is
OPERATIONALLY a release gate though not an on-disk correctness gate — document
that distinction.

## Q3 — reinitializing the XFS log slice

Choose FULL OVERWRITE + the canonical XFS empty-log formatter. An MXFS-side
generation field protects nothing unless XFS itself validates it in every log
record header — storing a generation in the heartbeat or slice descriptor will
NOT make upstream XFS reject old log sectors.

THE INVARIANT TO ASSERT:
> After the repair is durable, no pre-repair sector in the entire log slice can
> participate in discovery of a valid XFS log record, and the newly formatted
> log is a canonical empty log for the current filesystem UUID, log geometry,
> version and feature set.

Concretely: overwrite the ENTIRE physical slice with no gaps (not just headers
or the apparent used portion); never treat discard/TRIM as proof; flush; then
initialize using the same canonical XFS/libxfs logic used to clear or create an
internal log; flush; read back and validate BEFORE releasing the source guard.
Do NOT hand-construct "clean log headers": head/tail discovery also depends on
cycle stamps, record layout, UUID/version checks and log geometry, and a
partial handcrafted init can leave old sectors the cycle-number search
considers relevant.

Test assertions:
 - every basic block in the slice was overwritten after the quarantined
   incarnation;
 - the fresh log validates for the exact fs UUID, log version, sector size,
   stripe geometry and enabled features;
 - XFS log discovery resolves to the canonical empty/clean state — no
   transaction eligible for replay;
 - instrumented recovery reports ZERO recovered transactions/items from that
   slice;
 - no old valid log header or cycle-stamped block remains outside the
   intentionally generated fresh-log image;
 - the invariant still holds when the pre-repair image is deliberately built
   with cycle numbers around WRAP BOUNDARIES and plausible old record headers
   near BOTH ends of the slice.
Crash boundaries to test: during full overwrite; after overwrite before format;
during format; after format before flush; after archive before source release.
In every incomplete case the source guard must remain QUARANTINED and a retry
must RESTART the full-slice initialization rather than infer completion from a
partially written log.
FUA on every block is not strictly required if the block stack gives reliable
completion plus a final cache flush, but full-overwrite durability must be
established BEFORE the formatted-log durability is accepted.

## Q4 — other dirty slices

REFUSE. Do not build a second recovery engine inside chk_mxfs. Precondition:
every non-quarantined slice is settled and clean before destructive repair
begins. Normal sequence: bring the volume up on quarantine-aware software with
the quarantined slice excluded; let all recoverable journals replay/settle;
cleanly unmount everywhere; run the offline tool; the tool independently
verifies every non-quarantined slice is clean before proceeding. It must report
the EXACT blocking slots and their states, not "filesystem busy".

Why the precondition matters: the final consistency check must run on a settled
metadata image, else apparent inconsistencies may actually be resolved by
pending replay from another slice, a later replay could invalidate the
checker's conclusions, and the tool could erase the quarantined slice and only
then discover global recovery order was unresolved.

The read-only ARCHIVE/EXPORT step may run earlier (it touches no fs metadata).
The strict "all other slices clean" condition must hold before reinitializing
the slice, altering the source guard, or declaring repair success.
