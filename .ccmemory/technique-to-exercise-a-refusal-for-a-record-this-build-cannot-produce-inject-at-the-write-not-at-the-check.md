---
name: technique-to-exercise-a-refusal-for-a-record-this-build-cannot-produce-inject-at-the-write-not-at-the-check
description: TECHNIQUE (s83): a guard against records an older build wrote is unexercisable — substitute the value at the durable write, leaving every check intac…
metadata:
  type: feedback
tags: [testing, fault-injection, verification]
---

# Exercising a refusal whose input this build cannot create

A guard that refuses records written by an OLDER build is, by construction,
unreachable: the current build refuses to produce the thing the guard refuses
to accept, so the branch never runs and "it is obviously correct" is the only
evidence anyone has. That is an unexercised guard on an upgrade path, and it is
worth a defect record on its own.

**Inject at the WRITE, not at the check.** Substitute the value that goes onto
the platter, at the last point before the record is sealed, and leave every
producing check running against the value the attempt actually established:

```c
    want->desc.fence_kind = fence_kind;          /* what was proved */
    if (inject > 0 && inject != (int)fence_kind) {
        log("...INJECTED proved=%s written=%s — TEST ONLY...");
        want->desc.fence_kind = (uint16_t)inject; /* what lands on disk */
    }
    seal(want);                                   /* CRC covers the injection */
```

Why this shape and not another:

- **It cannot loosen anything.** Every constructor check still runs against the
  proved value. The values worth injecting are exactly the ones the consuming
  side then REFUSES, so an injected lap is strictly more conservative than an
  uninjected one. Compare with injecting at the CHECK — making a reader accept
  something — which removes the very safety the lap claims to measure.
- **The seal covers the substitution**, so the record is byte-for-byte what an
  older build would have left, not a record that fails its own CRC for an
  unrelated reason.
- **The substitution is logged with the certificate**, so no lap can mistake an
  injected value for a measured one, and the harness can make that line its
  non-vacuity gate: no injection line means the platter holds the sound value
  and the arm is grading the ordinary lap under another name.

The alternative — build the previous version, produce a real legacy record,
upgrade, and observe — is stronger evidence and much more expensive, and it
usually also needs a crash cut between "the record is durable" and "the record
is consumed". Do it when the injection cannot reproduce the state faithfully.
Here it could: the only difference between an injected record and a legacy one
is which build's code wrote the bytes.
