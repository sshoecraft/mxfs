---
name: trap-a-lap-that-asserts-the-absence-of-a-behaviour-the-module-declares-it-will-perform-grades-the-inverse-of-the-design
description: TRAP (s124): the network-partition arm asserted "nobody may be fenced" over a term 3x the module's own declared tcp_death_grace_ms, so it FAILed a co…
metadata:
  type: feedback
tags: [measurement-integrity, fencing, harness, design-expectations]
---

# A lap that asserts the absence of a declared behaviour is grading the inverse of the design

`tests/fence_partition_reconnect.sh` ARM=network held a DLM-link partition for
`PART_S=120` s and then asserted **zero fence certificates**, on the stated
expectation that "the disklock heartbeat is the arbiter and the DLM link's loss
is not evidence of death".

The module says the opposite, in a live parameter:

    dlm/v5_mount.c:168   static int mxfs_tcp_death_grace_ms = 40000;
    dlm/v5_mount.c:170   module_param_named(tcp_death_grace_ms, ..., 0644);

A TCP peer that goes silent is SUSPECT and is declared dead if it fails to
reconnect inside that grace. 120 s is **three times** the tolerance the module
promises, so a fence was not a possible failure — it was the guaranteed,
correct outcome. The arm could only ever assert the inverse of the design.

On its first run (s123a) it scored a textbook-correct resolution as three
FAILs. What actually happened, off A's own ring:

    1063.47  TCP peer 203813669 disconnected — deferring death 40000 ms
    1103.58  P-PR-FENCE preempt-and-aborted ... EXCLUSION PROVED
    1103.58  P236-FENCEKIND kind=PREEMPT_ABORT_PROVEN_V1(23) proves_excl=1
    1168.69  P309-DEATH-FENCE-QUEUED  (B's heartbeat had stopped; dead window)
    1171.05  P236-FENCE-CERTIFIED kind=LU_RESET_WITNESSED_V1
    1173.43  P236-FENCE-SEALED, P163-RECOVERY-PENDING, foreign replay of slot 1

and on B: `P131-SELF-FENCE [PR_CONFLICT_FENCED]` after three RESERVATION
CONFLICTs. Every line is the behaviour the arm exists to require.

## The rule

**Read the module's own declared parameter and grade against it; never encode
the expectation as a constant in the harness.** A copied constant grades one
build's behaviour against another build's promise. The fixed arm does:

    GRACE_MS=$(rs 20 "$A" "cat $PARM/tcp_death_grace_ms")

and branches: inside the grace nobody may be fenced; past it exactly one side
must fence and owes the whole chain (certificate, seal, slice replay, victim
silent). Neither shape may produce two certificates.

## The related shape

Grade on the **observed** outcome and let the declared bound decide which
outcomes are *allowed*, rather than branching on the bound alone. The socket
needs time to notice the block (12 s, measured), so a partition close to the
grace may legitimately resolve either way, and a hard branch would fail a lap
sitting in that grey zone.
