---
name: trap-a-bound-that-counts-its-own-poll-sleeps-is-not-a-wall-bound-and-a-mount-loop-with-no-signal-check-cannot-be-ended-by-timeout
description: TRAP (D-0980, 0.89.2): the admission barrier bounded its wait by summing msleep(1000)s; the 6 s takeover observation, ≤45 s stability proof and repla…
metadata:
  type: feedback
tags: [trap, mount-barrier, timeouts, d0980, signals]
---

# A bound that counts its own poll sleeps is not a wall bound, and a kernel loop with no signal check cannot be ended by `timeout`

D-0980 (s65f on 0.89.1, fixed 0.89.2, sess66). The joiner's `timeout 300 mount -t mxfs` had not returned 360 s later; the ssh wrapper's own bound died first. Same probe on the same build: refused at 30 s (four laps), completed at 164 s (one lap), hung >360 s (one lap, evidence lost).

## What the code did

`mxfs_dlm_mount_recovery_barrier` polled `msleep(1000); waited_ms += 1000;` and aborted at `waited_ms >= wait_bound` (30 s, or 30+62+30 s under the ghost extension). Every poll pass FELL THROUGH into a replay round, and the round's work was invisible to the bound:

- `mxfs_disklock_recovery_takeover` / `recovery_fence_takeover`: `mxfs_pal_sleep_ms(6000)` re-proving abandonment (s65g journal: P238-FENCE-TAKEOVER at :03, P236-FENCE-ATTEMPT-TAKEOVER at :10).
- `mxfs_slice_stabilize`: up to `mxfs_fr_stab_deadline_ms` = 45 s per slice per attempt, and a non-quiesced slice stays in the cut and pays it again next round.
- the replay, the ledger takeover scan (2.3 s), 64 sector reads per round.

So the "122 s bound" was 122 polls × (1 s + whatever the round cost). The `dbg_...platter_fallback` row in TIMEOUT_BUDGETS already showed it: "staging abort 152 s" for a 122 s bound.

And nothing in the loop looked at `fatal_signal_pending(current)`; `msleep` is TASK_UNINTERRUPTIBLE, so SIGTERM from `timeout` was queued until mount(2) returned on its own. The project had fixed the same class once already (0.75.72, the root iget retry) — the barrier next to it was left as it was.

## The two tests that find this class anywhere

1. Grep every bounded loop for how it advances its counter. `waited += POLL` next to a `sleep(POLL)` is a poll count. A bound must be `time_after_eq(jiffies, deadline)` (or a monotonic ms delta) taken from the loop's start, judged before new work is started, not only after a sleep.
2. Anything a process-context task waits in (mount, umount, ioctl) must reach a `fatal_signal_pending` check at every recovery-safe boundary, with a killable sleep (`schedule_timeout_killable`), and return -EINTR on cancellation (never -EBUSY: cancellation is not contention). Subordinate waits it calls (the 6 s observation) must be interruptible-but-never-shortened: re-sleep until the interval has elapsed, abandon on a fatal signal, never certify early.

## Design points from the consult (Astra 2026-09-19)

- Budget exhaustion is an availability refusal (-EBUSY); it is never permission to admit with incomplete recovery. Published progress stays published.
- A deadline cannot preempt a slice already being replayed; the guaranteed property is "no new work started past the bound". Print `overrun_ms` and `last_round_ms` on every exit: overrun > last round is a defect.
- The ghost extension is a cap granted once from the loop's start; a second ghost mid-wait buys nothing, and the extended bound is deliberately kept after every death is declared (the replay that becomes possible then needs its allowance).
- Pass the remaining budget into the acquire so a takeover whose observation + continuation cannot fit is refused up front (P238-TAKEOVER-NOBUDGET) instead of run.
- A failed mount has no post-mount settle: its debt must stay on the platter (frozen, pending) for the next owner. It already did; the cancel path reuses the bound's abort.

Harness: tests/d0980_barrier_killable.sh. Design: docs/rulings/mount-admission-barrier.md.
