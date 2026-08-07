---
name: ccloop-c7ee71c6-sess21-p195-exact-predicate-for-silent-mkdir-loss
description: sess21: P195-STALE-BASE-ALREADY-DIRTY is the EXACT deterministic predicate for the silent mkdir loss - fires ~1/storm run with an identical signature…
metadata:
  type: project
---

# sess21 — P195 is the exact, reproducible predicate for the silent mkdir loss

## Why this matters
The silent `mkdir` loss was a ~1-in-4 flaky DURABLE-FAIL — nearly impossible to
A/B. It is now a **deterministic, detectable predicate that fires ~1x per storm
run with an identical signature**, whether or not the run loses an entry. That
converts the whole problem from statistical to causal.

## The signature (identical every run)

    P194-EPOCH-STALE-OP ino=<X> op=lookup grant_epoch=2 valid_epoch=0
        dlm_mode=5 fmt=1 nx=0 size=6 dirty_here=1 gate=1 name=nodeN_1 comm=mkdir
    P195-STALE-BASE-ALREADY-DIRTY ino=<X> grant_epoch=2 valid_epoch=0

Byte-for-byte the ROUND-29 loss signature (pino=46137485, node24_1).
`fmt=1 nx=0 size=6` = an EMPTY shortform dir. `valid_epoch=0` = the base has
NEVER adopted.

## The mechanism, fully explained
The storm body runs, in ONE EX tenure:

    mkdir -p "$BASE/d$K"              # 32 nodes race; ONE wins and creates d$K
    mkdir "$BASE/d$K/node${R}_$m"     # then adds its own child

The node that WINS the create holds an in-core image that is:
- **dirty** (it just created the dir under this tenure), and
- **valid_epoch = 0** (it created the object; it never adopted anything).

Peers then add their entries and convert the dir shortform->block. The creator's
epoch never advances because it never adopts — and it never adopts because
EVERY keep-stale guard (P6 mid-tenure, P34F, P184...) legitimately protects a
dirty, self-created image. So the creator later adds its own child onto a base
that has been superseded, and the write-side backstop (P189) correctly refuses
to publish the behind-disk result. The entry dies. `mkdir(2)` returned 0.

## Two measurements that kill wrong approaches

1. **A freshness gate at `xfs_dir_lookup` CANNOT fix this.** Measured directly:
   of every genuine forward-stale hit, `dirty_here=0` occurred **0 times** and
   `dirty_here=1` **100%**. The tenure is ALWAYS already dirty by the lookup.
   `mxfs.dir_lookup_freshness_gate` therefore never engages — it is left
   default-OFF. Storm passes observed with it on were luck, not the fix.

2. **A bare `!=` epoch comparison on CAW is ~99% noise.** One run: 101 hits,
   **100 backward** (`grant<valid`, all `comm=rm`) and **1 forward**
   (`comm=mkdir`). The backward ones are the deliberate epoch clear at inode
   free (`mxfs_dlm_caw_clear_inode_epoch`, so a REUSED ino doesn't inherit a
   stale lineage) — an incarnation change, already owned by the
   dead-incarnation fences (P115). **Only `grant_epoch > valid_epoch` is
   genuine staleness.** Using `!=` forces ~100 spurious adopts per run and
   buries the single hit that matters.

## What the fix has to be
This is exactly GPT's "invariant violation" state: local mutations ALREADY exist
on an epoch-stale base, where neither keep-mine nor adopt-disk is correct and
merging is unsafe across the format conversion.

The creator cannot adopt because its create is unpublished. So the requirement
is: **publish (drain) our create, THEN adopt, THEN apply the child** — or fail
the operation. That is the SAME release-barrier work as open items (a)/(b)/(c):
a tenure must not carry an unpublished change into a state where it must adopt.

Do NOT attempt an image-level merge, and do NOT let mkdir(2) return 0 when the
result is knowingly discarded.

## How to reproduce / measure
    MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster
    tests/sf_mkdir_storm.sh 30 32 2 1
    # then capture dmesg YOURSELF (the storm dumps it only on FAIL):
    for i in $(seq 1 32); do tools/mxfs_sshpass.sh test$i \
        "dmesg | grep -E 'P194-EPOCH-STALE-OP|P195-STALE'" & done
Count P195. Any occurrence is a potential silent loss. Target: **0**.
