---
name: technique-put-the-finding-first-in-a-message-that-can-be-truncated-by-its-own-buffer
description: TECHNIQUE (s82): a 220-byte `why` buffer cut the refusal's reason mid-word and the lap FAILed on a phrase the kernel never printed; lead with the fin…
metadata:
  type: feedback
tags: [logging, harness, assertion, trap]
---

# A reason that is built as prose loses its finding to the buffer

Measured 2026-09-20 (`fence_gate_basis.sh sameboot`, 0.89.15).

The refusal composed its reason as *context first, conclusion last*:

```
"the deployment's clause '<57 chars>' covers a registration that disappeared
 with NO replacement of ours; what was observed here is '<31 chars>', which is
 a replacement and forces no session outcome, so the clause's premise does not
 hold"
```

into a 220-byte buffer. What reached the log ended `"...which is a repla."`.
The refusal was CORRECT and the lap FAILed anyway, on an assertion about a
phrase that existed only in the source.

The enclosing `printk` was 921 characters — the ceiling was the inner
`snprintf`, not the log.

## The rule

**Lead with the finding; context is what gets truncated.**

```
"the clause's premise does not hold — it covers a registration that
 disappeared with NO replacement of ours, and what was observed here is '%s'"
```

Same facts, same buffer, and the sentence that a grader (or a human at 3am)
needs survives the cut.

Corollaries:

- A composed reason is a fixed-size buffer whose worst case includes every
  interpolated identifier. Size it for that, or order it so the tail is the
  part you can afford to lose.
- An assertion written against a phrase from the SOURCE is asserting about a
  string the kernel may never emit. Read one real line out of the evidence
  before trusting the grep that grades it.
