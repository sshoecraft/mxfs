---
name: trap-an-injector-that-ends-in-withdrawal-removes-the-very-teardown-caller-the-lap-was-built-to-observe
description: TRAP (s122): a withdrawn mount is shut down, and the final SB summary write skips on xfs_is_shutdown — so a withdrawal-ending injector makes put_supe…
metadata:
  type: feedback
tags: [measurement-integrity, vacuity, fault-injection, teardown, dlm]
---

# An injector that ends in a withdrawal deletes the caller you came to watch

When a lap's subject is something `put_super` does — an acquire it takes, a
lock it waits on, a write it issues — the injector that produces the state
must leave the mount **healthy**. Several of MXFS's fault injectors do not:
their ladder ends at a bounded deadline and then WITHDRAWS the filesystem, and
a withdrawn mount is shut down.

`mxfs_sb_summary_final_sync` (pal/linux/xfs_super.c:1786-1797) opens with

    if (xfs_is_shutdown(mp) || !xfs_log_writable(mp)) { ... return; }

logging `P-SB-SUMMARY-FINAL-SKIP` and taking **no cluster lock at all**. So on
a withdrawn mount the non-fallible SB summary acquire — the one caller the
fallible oracle never names, and the one a stalled page transition parks
forever — never runs. A lap built on such an injector measures nothing and
looks like a clean unmount.

## The concrete pair, for the stalled-transition work

- `recov_complete_inject=1` — fails the IMAGES_REPLAYED advance, retries with
  5/10/20/40 s backoff, then `P234-COMPLETE-DEADLINE` + relinquish +
  **withdrawal** at 120 s (dlm/v5_mount.c:9040-9067). It parks the descriptor
  below IMAGES_REPLAYED, which is what you want — and removes the caller,
  which is not. `recov_complete_inject=2` (invariant) withdraws too.
- `rman_inject=1` — fails the prover's manifest snapshot before the manifest
  write (`P-RMAN-INJECT ... mode=1`, dlm/v5_mount.c:9230). The attempt parks
  at SNAPSHOTTING, the RECOVERY_GUARD stands below IMAGES_REPLAYED, and the
  prover's mount stays **healthy**. That is the shape the lap needs.

## The general rule

Before choosing a fault injector, ask what state it leaves the OBSERVER in,
not only what state it leaves the SUBJECT in. An injector whose terminal
outcome is a withdrawal, a shutdown or a refused mount has, by that act,
disabled a whole class of teardown and unwind paths — and MXFS disables them
deliberately, with named skip branches (`P-SB-SUMMARY-FINAL-SKIP`,
`P960-REFUSED-MOUNT-NOCOVER` at xfs/xfs_log.c:2367). Those branches are
correct behaviour; they are also exactly why the lap would have read clean.

Related and worth knowing together: `xfs_log_quiesce` already carries a
hand-written exemption of this kind for the refused-mount unwind, added
because that unwind "parked on the very transition the mount had just been
refused for, until the takeover moved again (70 s)". The same hazard, met
once before and solved for one caller by removing that caller rather than by
bounding the wait.

Written while building `tests/nonfallible_transition_stall.sh` (MXFS 0.89.47);
the reasoning is in that harness's header.
