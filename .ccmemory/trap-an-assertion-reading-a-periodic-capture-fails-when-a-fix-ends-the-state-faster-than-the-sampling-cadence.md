---
name: trap-an-assertion-reading-a-periodic-capture-fails-when-a-fix-ends-the-state-faster-than-the-sampling-cadence
description: TRAP (s88): the blocked-task stack assertions read a 60 s-cadence sampler; the fix ended the wait in 3 s, so the sampler was empty and four call-site…
metadata:
  type: feedback
---

## What bit us

`tcp_lockreq_blackhole.sh` asserts *which call site* was blocked by grepping
the blocked task's kernel stack out of `w_samples.txt` — a file written by a
sampler that runs **every 60 s** through the armed window. That is fine when
the point of the lap is that the task stays blocked for minutes.

A new arm closed the authority lease under the waiter, and the fix ended the
wait **3 seconds** after the closure. The sampler never ran while the task
existed, `w_samples.txt` had no stack in it, and four assertions failed —

```
FAIL the blocked task was in an inode acquire            got=0 want=1
FAIL the blocked acquire was getattr's                   got=0 want=1
```

— on a lap where everything under test passed. The call sites were correct;
the file that was supposed to show them was empty.

## The general shape

**An assertion is only as good as the capture it reads, and a capture taken on
a cadence only contains states that outlive that cadence.** When a fix makes a
state shorter-lived — which is usually the whole point of the fix — every
periodic observer of that state silently goes blank.

Symptom to recognise: a verdict where the *substantive* assertions pass and the
*descriptive* ones ("it was blocked in X", "the counter was non-zero at the
time") fail together, all reading the same file.

## What to do instead

- Take a **one-shot capture at the moment the state is known to exist**, not
  only on the sampling cadence. The lease arm already had one — the pre-close
  probe, which exists to prove the waiter was genuinely blocked before the
  heartbeat was touched — and it carries the stack.
- Then select the capture by arm: the periodic file where the state is long-
  lived, the one-shot file where it is not. Do not point every arm at one file
  and do not delete the assertion.
- Deepen the one-shot capture to match the sampler (`head -20`, not `head -12`)
  or the selection silently loses frames the assertions grep for.

## The rule this is an instance of

When a new arm makes an existing assertion inapplicable, **split it by cause
and give the new arm its own replacement**, never relax or delete it. Here the
lease arm cannot assert "W reads the file again afterwards" — its mount is
withdrawn on purpose — so it asserts the *reason* instead: the filesystem was
shut down by the closure, and W did not quietly recover and read stale bytes.
An assertion removed without a replacement is an assertion relaxed.

## Related

- `trap-a-fix-that-adds-an-expected-signal-breaks-the-harnesss-nothing-happened-assertions-and-they-must-be-split-by-cause-not-relaxed`
