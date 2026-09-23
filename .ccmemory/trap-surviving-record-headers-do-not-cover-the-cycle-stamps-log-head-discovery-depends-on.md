---
name: trap-surviving-record-headers-do-not-cover-the-cycle-stamps-log-head-discovery-depends-on
description: TRAP (D-0531, s60): a uuid mask that zeroes every block no current-uuid header covers can turn a dirty wrapped log into "totally zeroed" and skip rep…
metadata:
  type: feedback
tags: [log-recovery, d0531, slice, head-discovery, ruling, astra]
---

# Surviving record headers do not cover the cycle stamps head discovery depends on

## What happened
D-SLICE-CLAIM-TIME-INIT-UNTRUSTED-ZERO-531 was measured (s60j): a slice whose mkfs zero did
not land holds a previous incarnation's CRC-valid records with their own cycle numbers; a
fresh incarnation mounts clean (block 0 zero), commits a log-forced transaction, crashes,
and recovery's cycle-based head search lands on a stale header, xlog_header_check_mount
refuses the uuid (-117), the node cannot mount, the committed data is unreachable.

I implemented a reader-side fix in an hour: walk the slice, mark every block covered by a
record whose header carries this sb_uuid, and have xlog_do_io hand every other block back
as zero. It built. Astra rejected it with a counterexample I could not answer:

- After a wrap, record R's body crosses block 0; later a SHORTER record S overwrites R's
  header but not R's tail; R's body blocks at the physical end and at block 0 keep their
  legitimate cycle stamps and NO surviving header covers them. That is a normal layout:
  block 0 = newer cycle, last blocks = previous cycle, and the transition IS the head.
- The mask zeroes them; xlog_find_zeroed reads block 0 as cycle 0 → "totally zeroed log"
  → recovery skipped with forced transactions still in the slice. Silent loss, no foreign
  bytes required. Also: a torn current record with a correct h_len leaves foreign bytes
  inside its advertised extent, so the mask never equals the durably-zeroed image.

## The rules
- Head discovery consumes CYCLE STAMPS of every block, including obsolete record bodies
  whose headers are gone. Record identity (uuid) is not block provenance.
- "Never zero from inference" is about what recovery READS, not only what is written:
  filtering recovery's input can lose data exactly like zeroing the platter.
- A malformed or null-uuid header must never become "untrusted, therefore zero" — that
  hides corruption evidence.
- The fix is the ruled item (a): durable per-slice lifecycle record, INIT_REQUIRED at mkfs,
  the slot claimant zeroes the payload through the kernel FUA path and persists READY
  before its first journal write; never synthesise INIT_REQUIRED for an existing slice.

## Why this is a trap
The reader-side fix was cheap, self-contained, passed a plausibility read of
xlog_find_head, and would have PASSED the d0531 harness (the harness has no wrapped-log
arm). Its failure mode is silent and only appears on a long-lived slice. When a fix
changes what upstream recovery is allowed to see, the question is not "does it fix the
measured layout" but "what does upstream's discovery assume about every block", and the
answer for XFS is: the cycle history of the whole log since a durable zero.

Ruling text: docs/rulings/twin-hole-fix-zeroing-strictness.md (2026-09-19 section).
