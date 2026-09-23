---
name: technique-a-refusal-arm-means-nothing-without-a-control-arm-in-the-same-lap-that-must-be-accepted
description: TECHNIQUE (s89): the absent-SARK PREEMPT AND ABORT probe measured two refusals; only the third arm, which had to be ACCEPTED, made them mean anything.
metadata:
  type: feedback
tags: [measurement-integrity, scsi-pr, harness-design]
---

# A refusal arm proves nothing without an acceptance arm beside it

Session 89, `tests/pr_absent_sark_probe.sh`, disposing of
`D-PREEMPT-AND-ABORT-CLAIM-RESTS-ON-AN-UNHONOURED-PRE-READ`.

## The shape of the trap

The question was: does this target accept a `PREEMPT AND ABORT` whose
service-action key names a registration that is no longer in the table? The
obvious probe issues that command and records the status. It came back
RESERVATION CONFLICT, which is the answer we wanted.

**But a refusal is the default outcome of a malformed command.** A wrong
reservation key, a wrong reservation type, a wrong device path, a tool that
builds the CDB differently than the kernel does — every one of those also
returns a refusal, and every one of them would have produced the same verdict
from the same probe. A lap that can only ever print "refused" is not measuring
the target; it is measuring whether anything works at all.

## What fixed it

A third arm in the **same lap**, with the same reservation key, the same
`prout-type`, the same device and the same tool, differing only in that the
service-action key was present in the table. That arm MUST be accepted, and its
assertion is written as a requirement, not an observation:

```
ck "arm C ACCEPTED (the apparatus CAN produce an accepted P&A)" "$C_RC" "rc=0"
ck "arm C advanced the PR generation" ... "advanced"
```

It was: `rc=0`, the named registration removed, PR generation `0x175f → 0x1760`.
The two refusal arms held the generation unchanged at `0x175e`. So the refusals
were about the absent key and nothing else.

## The generalisation

Whenever a lap's verdict is "the system refused X", ask what else in that lap
could have produced a refusal, and add the arm that distinguishes them. The
control has to differ in exactly ONE variable and has to be asserted as a
required PASS — a control that is merely "logged for information" gets ignored
the moment it disagrees.

The same reasoning is why the counterpart matters on the other side: a lap whose
verdict is "the system accepted X" needs an arm that MUST be refused.

## Also worth keeping from that lap

Read the **generation** either side of every PR command, not just the status. A
refusal that advanced the generation would mean the target acted anyway, and the
status alone cannot tell you that. Both refusal arms held it at `0x175e`, which
is a second, independent statement that nothing happened.
