---
name: technique-when-the-defects-trigger-is-unreachable-make-its-final-verdict-unconditional-under-a-knob-and-run-both-arms
description: TECHNIQUE (sess603, D-0946): the shutdown needed a shell state churn cannot make; a test knob that takes the existing platter verdict on EVERY recycl…
metadata:
  type: feedback
tags: [technique, verification, allocator, D-0946, harness]
---

# When a defect's trigger state is unreachable, make its FINAL verdict unconditional under a knob

D-0946: the allocator's own-obligation exemption handed out numbers whose platter
dinode was still live; the recycle gate's platter check caught it and shut the
filesystem down. The check was reached only by a "deferred deadshell" (a freed
in-core shell still carrying a mode or blocks), which ordinary churn never
produces — three harness modes and 16+ rounds scored DEADSHELL=0, and the only
reproducer was a death/rejoin lap at 3 hits in 16 laps.

What worked: do not fabricate the trigger state. Take the verdict the chain ends
in (read the platter, fail if live) and, under a test-only knob, take it on EVERY
instance the code path sees (every create-path recycle), reading real state with
the same reader the product trusts (a private bounce-buffer read, never the buffer
cache, so the knob perturbs nothing). Then run both arms:

- control arm (pre-fix allocator): the chain fired on the FIRST re-pick, 2.2 s,
  same inode number (132) as all three original occurrences, with the exact
  signature (disk_gen == ogen-1);
- fix arm: 4800 creates, the assertion ran ~770 times per round, live 0, and the
  allocator's refusal counter 90-240 per round proved the changed code carried it.

Two conditions make this sound, and both must be argued before trusting a fix-arm
zero or a fix-arm fire: (1) the widened verdict must be implied by the fix's
invariant — here "no open FREE obligation ⇒ free image durable" holds because the
obligation is retired only at the completion of the write carrying the image
(docs/free-publish.md); (2) the knob must read real state and must not touch the
caches or logs the product uses. Also expose exact resettable counters for both
the assertion and the arm under test; dmesg lines are print-budgeted (first 32,
then 1 in 500) and would have shown PUBPEND_LINES=32 in every round.

Sibling of `trap-a-verification-condition-that-a-healthy-build-cannot-produce-is-vacuous-by-construction-inject-it-at-the-verdict`
(D-0947, where the INPUT to the verdict was injected). Here the input is real and
only the verdict's reach is widened — preferable when a real reader exists.
