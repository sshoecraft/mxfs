---
name: trap-hand-numbered-inode-flag-bits-shared-bit-28-check-sum-equals-or
description: TRAP (0.90.14): MXFS_IF_ACQ_REFUSED and MXFS_IF_ADOPTED_UNLINK were both 1U<<28 in xfs_inode.h; a DLM denial read as freer authority. Audit + static_…
metadata:
  type: feedback
tags: [xfs, inode-flags, static-check, trap]
---

# Two hand-numbered inode flags shared bit 28 of i_flags

## What bit
`xfs/xfs_inode.h` defines every in-core inode flag by hand as `(1U << N)`.
MXFS added flags at bits 17..31 over many sessions; two of them,
`MXFS_IF_ACQ_REFUSED` (the acquire classifier's "the DLM denied this inode"
mark, set on -EHOSTDOWN) and `MXFS_IF_ADOPTED_UNLINK` (the deferred reap's
"this node is the adopted freer of this orphan" mark, read by
`xfs_inactive`'s freer-authority decision) were both `1U << 28`, 194 lines
apart, and nothing complained. A denial therefore read as freer authority at
inactivation, and an adopted orphan read as a denial in the namespace
backstop. Found on 2026-09-28 while enumerating the flag table to explain
an unrelated -ESTALE (which it did not explain).

## How it was found and fixed
- List the table sorted by bit: `grep -n "define \(XFS_\|MXFS_IF_\)"` with the
  bit extracted; `(1 << __XFS_IPINNED_BIT)` needs the named-bit resolved.
- `scripts/inode_flag_bits_audit.py` does that and fails on any shared bit;
  it is a step of `tests/full_verify.sh`.
- The header carries `static_assert(MXFS_IF_ALL_FLAGS == MXFS_IF_ALL_FLAGS_SUM)`:
  the SUM of single-bit values equals their OR exactly when no bit is shared,
  a pure integer constant expression, no popcount builtin needed. A second
  assert checks no MXFS flag overlaps an upstream XFS flag.
- All 32 low bits were taken; the fix moved ACQ_REFUSED to `1UL << 32`
  (i_flags is unsigned long; a static_assert pins 64-bit) and added it to
  `XFS_IRECLAIM_RESET_FLAGS`.

## The lesson
- A shared word of hand-numbered bits needs a distinctness check IN THE
  HEADER, next to the definitions; a review cannot hold 34 defines in mind.
- `XFS_IPINNED` (bit 8) is a wait-bit KEY, never stored, so
  `MXFS_IF_FOREIGN_ZOMBIE` on bit 8 is deliberate and the check excludes it.
- When a symptom's only explanation is "a flag was set silently", enumerate
  the flag table first: a collision is the one way a flag gets set with no
  probe line from any of its own setters.
