---
name: technique-discriminate-a-multi-stage-pipelines-verdict-on-its-start-then-wait-for-it-to-settle-never-on-one-fixed-instant
description: TECHNIQUE (s124): a capture taken at a fixed instant ended 24 s before the certificate it looked for, so the lap took the branch graded by the opposi…
metadata:
  type: feedback
tags: [measurement-integrity, harness, fencing, timing]
---

# Discriminate on the pipeline's START, then wait for it to settle

A lap that reads "did X happen?" once, at a fixed instant, reads whichever
stage of a multi-stage pipeline the clock happened to land in — and when the
two stages are graded by **opposite** rules, that is not a flaky lap, it is a
wrong verdict delivered confidently.

Measured s123a, `tests/fence_partition_reconnect.sh` ARM=network. The arm did
`sleep "$PART_S"` and then captured A's ring to count `P236-FENCE-CERTIFIED`.
The capture ended at A-time 1147; the certificate landed at 1171. **24 s
short.** `fen_a=0` took the "nobody fenced" branch, whose assertions are the
exact inverse of what a fenced lap owes, and three FAILs were printed against a
correct resolution.

## The shape of the fix

1. **The discriminator is the START of the pipeline, not its end.** For a
   fence: `P-PR-FENCE preempt-and-aborted`, `P236-FENCE-INTENT`,
   `P309-DEATH-FENCE-QUEUED`. Any one of them means a fence is under way, and
   the lap is on the fenced branch whatever the certificate count says yet.
2. **Once a start is seen, hold the condition and wait, bounded, for the end.**
   The partition is not healed while the pipeline runs — healing it mid-fence
   changes what is being measured.
3. **Derive the settle bound from what the pipeline is MADE OF**, not from
   patience: victim stops heartbeating once its I/O bounces (~2 s) + disklock
   dead window 62 s + queue/fence/LU-reset/certify/seal 5 s = 69 s measured,
   100 s bound.
4. **A settle that times out is a finding, not a slow pass.** A fence that
   proved exclusion and never certified consumes the victim's key, so no
   successor can prove exclusion again — the module's own
   `P236-FENCE-CERTIFY-FAIL` text calls that slice unreplayable by anyone.

## The generalisation

Whenever a lap's two branches are graded by opposite rules, the branch
selector must be a signal that is **monotone and early** (the start), never a
signal that is **late and racing the capture** (the completion). The late
signal then becomes an *assertion* on the branch the early one selected.
