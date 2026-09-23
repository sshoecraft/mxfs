---
name: trap-a-guard-written-for-the-self-direction-leaves-the-symmetric-peer-direction-open
description: TRAP: MXFS guarded "do not preempt MY OWN previous incarnation" but not "do not preempt a LIVE PEER holding the same derived key" — same hazard, othe…
metadata:
  type: feedback
tags: [fencing, scsi-pr, code-pattern]
---

# A guard written for the self direction leaves the symmetric direction open

Found sess576 while investigating the unmountable-volume defect.

## The shape

The SCSI PR key is derived per BOOT from {host_uuid, boot_uuid, fs_uuid}
(`dlm/prledger.c mxfs_prledger_derive_key`), and a host reaches the LUN over one
I_T nexus. So two successive incarnations on one host in one kernel carry the
**identical** key, and the target cannot tell them apart.

MXFS had already reasoned this through — **in one direction only.** The slot
fence in `dlm/v5_mount.c` carries `P238-FENCE-OWN-KEY`:

```c
if (vkey && ctx->pr_key && vkey == ctx->pr_key) {
        /* the victim holds THIS boot's key; a PREEMPT AND ABORT of it
           would preempt ourselves.  Issue nothing */
```

That compares the victim key against **the fencer's own**. A node cannot preempt
its own previous incarnation. Correct, and clearly written by someone who
understood the aliasing.

But when a **peer** fences a dead incarnation whose host has already remounted,
`vkey` is the victim host's key and `ctx->pr_key` is the fencer's — they differ,
the guard never fires, and the P&A lands on the live successor. Same hazard,
mirrored, unguarded.

## Why it is easy to miss

The comment on the existing guard is *about the aliasing*, so reading it leaves
you satisfied the aliasing is handled. It says "would preempt ourselves" — the
scope is in the sentence, and it is narrower than the hazard. A guard that names
the right danger can still cover a fraction of it.

The same asymmetry existed elsewhere in the protocol: the mount path refuses the
mirror-image case explicitly (`P305-PR-SAME-BOOT-DIRTY-PREDECESSOR`, "our
previous incarnation departed dirty in this same kernel"), which again reads as
coverage of the general problem and again is one direction.

## The general lesson

When a guard's predicate names **self** — our key, our slot, our incarnation,
our node — ask immediately what the same predicate looks like with *any other
live member* substituted, and whether that case is reachable. If the underlying
identity is not unique per incarnation, it usually is.

Related: enforce it at the **primitive** the callers funnel through, not at the
call sites. This one went into `mxfs_scsipr_fence_node`'s pre-command section,
which covers all four fence paths; guarding the one call site that showed the
bug would have left the other three.

## Also worth keeping

Excluding the victim **by node** rather than by liveness alone is what made the
new guard both safe and sufficient: a mount's node id comes from a per-mount
uuid (`uuid_to_node_id` at DLM init), so a successor on the victim's host has a
**different node id** with the **same per-boot key**. Excluding by node still
detects the successor, and a legitimate fence keeps working even if the victim's
record has not yet been marked not-live — which matters because the guard fails
closed and a false positive would stall recovery, a worse outcome than the bug.

Always test such a guard in **both** directions. A guard that refuses every
fence passes the positive test and makes recovery impossible; the control arm
(a key nobody holds must NOT trigger it) is what distinguishes working from
blanket-refusing.
