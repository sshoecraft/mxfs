---
name: trap-truth-testing-a-gate-that-returns-a-verdict-rewrites-every-verdict-into-one-errno
description: TRAP (0.90.14): xfs_file.c gates did `if (mxfs_inode_incarn_estale(ip)) return -ESTALE;` while the gate answered -EIO too; fail-fast reads came back…
metadata:
  type: feedback
---

# A gate that returns a verdict must be propagated, never truth-tested

## What bit us (0.90.13 -> 0.90.14, 4/tcp realign laps s7a/s8a)

`mxfs_inode_incarn_estale()` started life (pre-0.74) answering only 0 or
-ESTALE (poisoned incarnation shell).  Since 0.74.0 it also answers -EIO for
the fail-fast verdicts: a grant held or mastered by a dead node whose recovery
is RECOVERY_BLOCKED (`mxfs_recovery_blocked_covers_ino`) and a quarantined
victim domain (`MXFS_IF_QUAR_EIO`).  Twelve file-operation gates in
`pal/linux/xfs_file.c` (read entry, the buffered/direct/splice under-lock
rechecks, write checks, write, fallocate, remap, open, mmap) still did

    if (mxfs_inode_incarn_estale(ip))
        return -ESTALE;

so every -EIO verdict was rewritten to "Stale file handle".  Lap
s7a_realignB_l1 showed 13 of 40 and 17 of 40 reads through held descriptors
returning ESTALE in 3-5 ms with ZERO poison probes in either journal; the ten
P-RBLK-COVERS-DEAD-MASTER refusals named exactly the first ten ESTALE'd files
in read order.  The iomap and fsync gates, written later, already returned
the gate's own value.

## The trap, generally

When a predicate grows a second non-zero answer, every caller that
truth-tests it silently collapses the new answer into the old one.  Nothing
warns: the code compiles, the caller "handles the error", and the wrong errno
only shows up in a lap that asserts the errno class.  Reading the gate's
source tells you what it returns; reading its CALLERS tells you what the user
sees.

## What to do

- A helper that returns an errno is propagated: `rc = gate(ip); if (rc) return rc;`.
  Truth-test it only where the caller cannot return an errno at all (a page
  fault handler returning a fault code) and say so at the site.
- When a gate gains a new verdict, grep every caller for `if (gate(` and fix
  the ones that hard-code the old one.  Do it in the same change.
- A lap that measures a fail-fast must assert the errno CLASS (0 or EIO), not
  just "returned quickly": the s6a/s7a arms only found this because the check
  named the errno.
- Fixed in 0.90.14 (`pal/linux/xfs_file.c`), verified by lap s8a_realignB_l1
  (tests/evidence/20260928T220430Z_tcpdr_s8a_realignB_l1): every read 0 or EIO.
