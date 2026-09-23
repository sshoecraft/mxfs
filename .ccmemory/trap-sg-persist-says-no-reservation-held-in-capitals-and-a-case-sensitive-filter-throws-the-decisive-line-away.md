---
name: trap-sg-persist-says-no-reservation-held-in-capitals-and-a-case-sensitive-filter-throws-the-decisive-line-away
description: TRAP (s87): sg_persist -i -r prints "there is NO reservation held"; a filter greping 'no reservation' dropped it, so a purge poll waited out its whol…
metadata:
  type: feedback
tags: [scsi-pr, harness, measurement-integrity]
---

# `sg_persist` capitalises NO, and a case-sensitive filter deletes the answer

`sg_persist -i -r <dev>` reports an unreserved LUN as:

    PR generation=0x16d2, there is NO reservation held

A harness that pre-filters that output with

    sg_persist -i -r $DEV | grep -a 'Key=\|type:\|no reservation'

throws that line away, and the `resv_none()` predicate downstream — even a
case-INSENSITIVE one — then looks at a file from which the evidence has already
been removed. Case-folding at the predicate cannot repair a capture that was
filtered case-sensitively.

## What it cost

Lap `s87b` (fence_late_detection): the appliance purged every registration 30 s
after the prover was power-cut and released the reservation with it. The harness
polled for 120 s, never saw the string, and exited VACUOUS — on a lap where the
condition under test had in fact been reached, the victim was still blind, and
the probe would have fired. The wasted lap was ~5 minutes plus a VM boot.

## The shape of the rule

When a capture is pre-filtered on the remote side, the filter IS part of the
instrument. Grep it case-insensitively (`grep -ai`) and match on the noun
(`reservation held`) rather than on a phrase whose casing you assumed. Confirm
against the tool's real output once, not against what it "would" print.
