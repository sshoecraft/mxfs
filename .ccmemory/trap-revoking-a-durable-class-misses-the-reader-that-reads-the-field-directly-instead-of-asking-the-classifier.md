---
name: trap-revoking-a-durable-class-misses-the-reader-that-reads-the-field-directly-instead-of-asking-the-classifier
description: TRAP (s85): revoking fence kind 17 in the shared classifier missed a reader in xfs_log.c that compared desc.fence_kind itself — and it gated replay's…
metadata:
  type: feedback
---

# Revoking a class does not reach a reader that never asks

0.89.17 established the right shape: ONE classifier
(`mxfs_fence_durable_kind_supported`) that the certificate constructor and
every consuming reader ask, so minting is a subset of consumption by
construction. Revoking a kind should then be a one-line change in that
classifier.

It was not, and the site it missed was the worst one to miss.

## What the grep for the enum found, and what it meant

Revoking kind 17 in s85, the sweep for `MXFS_FENCE_KIND_SINGLE_NODE_EXCLUSIVE`
turned up ~20 hits. Most were comments or the name table. Three were live, and
two of those went through the classifier already. The third was this, in
`dlm/v5_mount.c`, reached from `xfs/xfs_log.c`:

```c
*out_cert_sn_excl =
    desc.stage >= MXFS_RECOV_STAGE_FENCED &&
    desc.fence_kind == MXFS_FENCE_KIND_SINGLE_NODE_EXCLUSIVE;
```

No classifier call. A direct comparison against the durable field. Its caller
sets `l_mxfs_untagged_authorized`, which is **replay's widest permission** —
whether untagged images may be applied at all. So after a revocation that
looked complete, an older build's durable kind-17 certificate would still have
unlocked the broadest replay authority in the tree, on the one path nobody
would look at again.

## Why the shape hides it

A reader that asks the classifier *contains the classifier's name*, so it is
findable by grepping for the classifier. A reader that compares the field
itself contains only the ENUM name — and the enum name appears in dozens of
comments, the name table, the forge's help text and the header, so it does not
stand out in the same sweep. The compliant readers are easy to find; the
non-compliant one is camouflaged by documentation.

## The sweep that actually works

When revoking or retiring a durable class, grep for **the field**, not the
class and not the classifier:

```sh
grep -rn "fence_kind ==\|cert_kind ==\|->fence_kind" --include=*.c .
```

Every hit is a decision made without the classifier, and each one has to be
justified or converted. The same applies to any durable enum with a central
interpreter: `stage`, `retire_basis`, `domain_kind`.

## And the ruling's own words are the test

"Ship no intermediate state in which refusing it at one reader still leaves
another honouring it." A revocation is atomic across readers or it is not a
revocation — so the sweep has to complete before the change lands, not after
the first lap passes. The matrix arm that forges the class and drives it
through the consuming side passes whether or not this reader was fixed,
because that arm exercises the claim gate, not the untagged-replay gate.
