---
name: trap-a-revisit-gate-keyed-on-the-ambiguity-marker-cannot-see-a-proof-that-was-never-published
description: TRAP (s80h): the resume gate required the durable MAY_HAVE_RUN arm, so a proved-but-unpublished certificate was revisited by nothing — the prover loo…
metadata:
  type: feedback
---

## What happened

0.89.13 added a bounded retry for a certificate whose CAS fails after exclusion
was PROVED, and claimed the resulting blocked state was *recoverable* rather
than terminal. The harness arm that spends the whole window
(`tests/fence_cert_publish.sh … spent`, `dbg_cert_fail_n=99`) asserted the
consequence the cluster actually feels: the peer must still get its filesystem
back. It did not — `MOUNT_RC=32`, `MOUNTED=0`.

The prover's own journal said why:

```
P238-FENCE-UNRECORDED slot=1 node=… rc=-5 tries=5
P238-FENCE-HOLDER-STATE slot=1 … state=LIVE why='our current incarnation'   (every ~30 s, forever)
```

The acquire path reached the slot on every pass and did nothing.

## Why

The 0.89.12 revisit gate required the durable ambiguity marker:

```c
(desc.flags & MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN) &&
ctx->fence_retry[slot].blocked && !ctx->fence_retry[slot].armed
```

Two states leave this node holding an unfinishable FENCING attempt, and only
one of them sets that flag:

- **ambiguous** — a PREEMPT-family command whose outcome was never established.
  MAY_HAVE_RUN is durable, so the gate sees it.
- **proved but unpublished** — exclusion was proved and the certificate never
  committed. The proof was volatile and died with the call; and when the proof
  came from the **sole-survivor exclusive-write gate**, there was no
  submission boundary to arm MAY_HAVE_RUN at all. The gate sees nothing.

Takeover cannot help either state: the attempt's holder is alive — it is us.

## The lesson

A revisit gate keyed on the marker of ONE failure mode is blind to every other
failure mode that lands in the same place. State the gate in terms of the
condition it exists for — "this node holds an unfinished attempt that nothing
else can take over" — and enumerate the ways to get there, rather than keying
on the most familiar one's breadcrumb.

It also generalises to the verification: the arm that caught this asserted the
CONSEQUENCE (the peer mounts) and not just the mechanism (a blocked marker with
the right words in it). Every mechanism assertion in that arm passed.

## The fix (0.89.13)

The gate accepts either the durable arm or a local `MXFS_RBLK_CERT_UNRECORDED`
blocked reason, the resume line names which state it is
(`left=PROVED-BUT-UNPUBLISHED` / `left=AMBIGUOUS`), and the revisit itself is
unchanged — read-only, no state-changing command, the exclusive-write gate
unreachable from it, and boot succession still gated on a retirement basis.
