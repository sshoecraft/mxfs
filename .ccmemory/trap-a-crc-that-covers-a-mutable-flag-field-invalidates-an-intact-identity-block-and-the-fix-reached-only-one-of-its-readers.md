---
name: trap-a-crc-that-covers-a-mutable-flag-field-invalidates-an-intact-identity-block-and-the-fix-reached-only-one-of-its-readers
description: TRAP (s118): the disklock identity crc covers hb->flags; guard writers move flags without re-binding it, so an intact block reads invalid — fixed in…
metadata:
  type: feedback
---

## The shape

`dlm/disklock.c` binds a heartbeat record's identity block with a CRC that
covers **`hb->flags`** (`hb_ident_crc()` mixes in slot, flags, fs_gen, node_id,
epoch). But the writers that install a fencing intent move the victim's record
to `RECOVERY_GUARD` **without re-binding that CRC** — only the retirement paths
re-bind. So the victim's own identity block, intact and byte-for-byte what a
fence of that victim needs, reads *invalid* to
`mxfs_hb_identity_valid()`.

This was found once before (0.75.77, D-0933, measured s565) and fixed by adding
`mxfs_hb_guard_identity_valid()` (`dlm/disklock.c:558`), which for a guard
record retries the CRC under the states the victim's own writer could have bound
it to (`ACTIVE`, `WITHDRAWN`, `RETIRE_PENDING`) while checking slot, fs_gen,
node, epoch and the block itself unchanged. **The fix was applied to the
admission reader only.**

## What it cost the second time

`dlm/bootstrap.c:1223` — the whole-cluster bootstrap scan — kept asking the
strict predicate. Every OTHER caller of the strict predicate restricts `flags`
to ACTIVE/WITHDRAWN/RETIRE_PENDING *before* asking, so a guard record never
reaches them; the bootstrap scan takes guard records as victims **on purpose**
(a terminal guard is excluded at `:1180`, a sub-terminal one is "a victim as
before" at `:1204`). That made it the single site that could be wrong, and it
was.

Consequence, measured five laps of five on 2/tcp at 0.89.44: after a total
outage with a fencing intent standing, the scan counted the guarded victim
`noident`, `P-BOOT-KEY-UNCLASSIFIED` refused the bootstrap, and **no node could
mount the filesystem at all** (`MOUNT_RC=32`, `MXFS DLM init failed — aborting
mount`), with both dead nodes' slices unreplayed. The control was in the same
sweep: cut 1 leaves the slot `ACTIVE`, reads `noident=0`, and passes.

## The two general lessons

1. **A CRC over a mutable field turns a legitimate state change into
   corruption-looking data.** When a checksum covers a field that some other
   writer is allowed to move, every reader needs to know which bindings are
   legitimate. Prefer not covering the mutable field; if it must be covered,
   there is no such thing as "the" validity predicate — there is one per
   legitimate binding set.
2. **When a bug is fixed by adding a second, laxer predicate beside the strict
   one, enumerate the strict one's callers then and there.** The 0.75.77 comment
   describes the failure perfectly and is 3 lines above the strict function; it
   still did not reach `bootstrap.c`, in a different file, three years of
   sessions later. Same shape as
   `trap-revoking-a-durable-class-misses-the-reader-that-reads-the-field-directly-instead-of-asking-the-classifier`.

## How to audit it

`grep -n mxfs_hb_identity_valid dlm/*.c` and, for each hit, check whether the
code has already excluded `RECOVERY_GUARD` by a flags test. A call with no such
test in front of it is a bug.
