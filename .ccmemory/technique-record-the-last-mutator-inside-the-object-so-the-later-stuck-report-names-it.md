---
name: technique-record-the-last-mutator-inside-the-object-so-the-later-stuck-report-names-it
description: TECHNIQUE (0.90.23): a wedge seen minutes after its cause was named by storing caller+prior flags+item count in the buffer at xfs_buf_stale.
metadata:
  type: feedback
tags: [instrumentation, technique, xfs_buf, wedge, attribution]
---

# Record the last mutator inside the object; let the stuck report print it

**Problem shape:** the symptom (an item stuck in the AIL, a release drain
spinning, an unmount waiting) shows up seconds to minutes after the act that
caused it, on an object that many code paths touch.  A probe at the symptom
sees only the end state; a probe at every suspect floods the log and still has
to be correlated by hand.

**What worked (0.90.23, the stale that cancelled a queued cluster write):**
1. In the one funnel every suspect goes through (`xfs_buf_stale`), store in the
   object itself: `__builtin_return_address(0)`, the flags BEFORE the change,
   what it carried (attached item count), and a millisecond stamp.  Four
   fields in `struct xfs_buf`, no allocation, no lock beyond the one the
   funnel already requires.
2. Print one rate-limited line at the funnel only when the act is suspicious
   (items attached), with the caller as `%pS`.
3. At the symptom's existing report, print the stored fields.

**Result:** the cause was named in the first lap that reproduced, and the
funnel's own line had already named the dominant caller three laps earlier
without any wedge occurring.  The prior flags settled which of two competing
hypotheses was true (queued when staled vs staled before the flush).

**Details that mattered:**
- The per-buffer event ring only keeps the low 16 flag bits, and
  `_XBF_DELWRI_Q` is bit 22: the ring could say THAT a stale happened, never
  whether the buffer was queued.  Store the full prior flags.
- The unmount's stuck report (`mxfs_buf_diag_dump`) did not print the stored
  fields; the funnel's own line carried the evidence instead.  Add the fields
  to every report that can meet the object.
- Write the prediction before the run: which caller, which flag bit, what
  would falsify it.
