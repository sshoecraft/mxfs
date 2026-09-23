---
name: technique-measure-the-before-and-the-after-on-one-build-with-a-knob-that-restores-exactly-the-old-answer
description: TECHNIQUE (s88): a one-line debug knob restoring the pre-fix answer gave a same-build A/B; two builds would have left every other difference as an ex…
metadata:
  type: feedback
---

## The problem with a two-build before/after

The usual shape is: measure on the old build, fix, measure on the new one. It
has two defects here. The old build has none of the new instruments, so the
"before" number often cannot be taken at all — you end up arguing the before
from a code reading. And every other difference between the two builds is an
alternative explanation for the change you are claiming.

## What worked instead

Add a test-only module parameter that restores the pre-fix answer **for
exactly the case the fix changed, and for nothing else**, then run the same
harness twice on the same build.

    /* dbg_auth_tail_blind: admit a mutating submission on a clustered mount
     * whose DLM is already detached WITHOUT consulting the lease — the
     * pre-fix gate.  A mount with a live DLM is gated exactly as with the
     * knob clear. */
    if (unlikely(mxfs_dbg_auth_tail_blind && !READ_ONCE(mp->m_mxfs_dlm))) {
            atomic64_inc(&mxfs_auth_tail_blind_n);
            pr_err_ratelimited("... TEST: the pre-fix gate is in force ...");
            return true;
    }

Measured (`tests/auth_lease_unmount_tail.sh`, build 9C1BADD4E8D0DB6A039D23E,
two arms, same node, same ordering, same injected park):

- blind: `tail_blind=1`, `P290-AUTH-CLOSED` count **0** — the lease was never
  consulted so it never closed — `umount` rc=0.
- gated: `P290-AUTH-REFUSED-LOG bno=356`, `tail_refuse=1`, `overdue_ms=8528`,
  `umount` rc=0.

Two arms, one build, one line of difference.

## The rules that keep it honest

- The knob must restore the old answer, not approximate it. If it changes any
  other path the A/B is contaminated again.
- It must log loudly and count separately, so a lap can never mistake a blind
  admission for a real one, and so an arm left armed is visible.
- The harness must disarm it at the end — an injection outliving its lap
  poisons the next one.
- A third arm with NO injection is still required. Without it, "zero refusals"
  in the blind arm is indistinguishable from an instrument that never fired,
  and a fix that broke every healthy case would pass.
