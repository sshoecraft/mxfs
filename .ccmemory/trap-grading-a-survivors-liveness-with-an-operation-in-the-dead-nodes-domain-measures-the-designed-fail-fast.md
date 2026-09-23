---
name: trap-grading-a-survivors-liveness-with-an-operation-in-the-dead-nodes-domain-measures-the-designed-fail-fast
description: TRAP (s83): a "is the survivor still serving?" check that did mkdir in the mount root graded a blocked victim domain, not liveness; use a domain the…
metadata:
  type: feedback
tags: [harness, measurement-integrity, recovery-blocked]
---

# The survivor's liveness check has to touch something the survivor owns

s83, verifying a fencing refusal: a new check asked "does the prover still
serve its own filesystem after refusing?" by doing `mkdir -p
/mnt/shared/<new>` plus a direct write, and it FAILed with rc=1.

That was not a broken survivor. It was `P240-QUAR-NSOP-REFUSE op=lookup ino=128
comm=mkdir rc=-5` — the namespace op was refused before any transaction because
the inode belongs to a node whose recovery is BLOCKED. Refusing it fast is the
designed behaviour, and the designed alternative is waiting out an acquire
budget, which would be worse.

**Two different questions, and only one of them is a verdict.**

- *Can the survivor still do work?* — ask it in a domain the survivor took
  **before the cut**: create the directory and fsync a file into it while the
  cluster is healthy, then write into that same directory afterwards. With the
  dead node's domain blocked, that returned rc=0 in under a second.
- *Did anything hang?* — that is the one to grade, and it is graded on the
  operation RETURNING: a `timeout N` kill (rc 124) is a hang, any other rc is
  not. Whether it succeeded is a FINDING to print, because how much
  availability a refusal costs depends on which domain the caller touched.

Grading success instead of return turns a designed fail-fast into a test
failure, and the reflex that follows — "loosen the assertion" — is how a real
hang would later get through the same check.
