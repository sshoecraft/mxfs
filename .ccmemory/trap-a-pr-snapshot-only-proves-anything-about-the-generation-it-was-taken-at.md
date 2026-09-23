---
name: trap-a-pr-snapshot-only-proves-anything-about-the-generation-it-was-taken-at
description: TRAP (sess573): I disproved a CORRECT persistent-reservation hypothesis with a capture taken at PR generation 2765 when the failure was at 2757 — the…
metadata:
  type: feedback
tags: [scsipr, measurement-timing, rule4, D-0950, generation]
---

# A state snapshot is evidence about ONE instant, and SCSI PR prints which one

sess573, rooting `D-...-UNMOUNTABLE-...-0950`.

The volume had become unmountable. I hypothesised stale SCSI persistent-reservation
state, took a capture, and got:

    chk_mxfs --pr-keys /dev/sda -> "PR keys on /dev/sda: 0 registered"
    sg_persist --in --read-reservation -> "there is NO reservation held"
    PR generation = 0xacd   (= 2765)

I wrote that the PR hypothesis was **disproven**. It was not. The failing mounts
had logged their own state at **generation 2757**:

    P304-PREOBSERVE 'mxfs' held=1 type=0x7 (WE-AR) holder_key=0x0 gen=2757
    sd 3:0:0:0: reservation conflict

A WE-AR reservation *was* held at the time of the failure, with `holder_key=0x0`.
Eight generations of PR OUT commands — my own repeated mount attempts and a
`module_swap_deploy` — had cleared it before I looked.

## The rule

**PR generation is a monotonic counter that changes on every registration
change.** Every MXFS PR probe prints it (`gen=`), and `sg_persist` prints it, for
exactly this reason: to let you check that a capture and an event refer to the
same state. If the generation in your capture differs from the generation in the
failing log line, **your capture is about a different world** and can neither
confirm nor refute anything.

Applies generally, not just to PR: any "I looked and it was clean" disproof of a
transient-state hypothesis must carry a stamp tying the look to the event —
generation, epoch, incarnation, LSN, boot id. Without one, "clean now" and
"clean then" are indistinguishable, and the failure mode is the dangerous
direction: it retires a true hypothesis.

Related and more general: `trap-a-silent-instrument-and-a-clean-system-are-the-same-observation`
(sess571). This is its time-shifted twin — a *loud* instrument read at the wrong
moment.

## What the evidence actually showed once matched by generation

The PR key is `derived from {host, boot, LUN}` — a function of the boot, not of
the incarnation — so every mount of a host within one boot registers the same
key. A dead incarnation's key is deliberately retained as the `PREEMPT AND
ABORT` fence target, so a fence aimed at the dead incarnation lands on the LIVE
successor's identical registration. Observed as a mounted node logging
`P305-RESV-SELF-GONE ... key is NOT registered while mounted` every ~5 s, then
self-fencing. Distinct initiator IQNs per node, so this is not a shared-nexus
artifact.
