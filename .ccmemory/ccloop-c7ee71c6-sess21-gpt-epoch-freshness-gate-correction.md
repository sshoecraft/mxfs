---
name: ccloop-c7ee71c6-sess21-gpt-epoch-freshness-gate-correction
description: sess21 RULE-5 GPT: P6/P65 are NOT contradictory - epoch mismatch proves the base was stale at TENURE START, not that a peer wrote mid-tenure. Fix bel…
metadata:
  type: project
---

# sess21 — RULE-5 GPT consult: the epoch-override fix is at the WRONG LAYER

## The correction that matters (my analysis was wrong)

I claimed `P6-MIDTENURE-RELOAD-SKIP` and `P65-EPOCH-CONVGATE` assert
contradictory facts and that P6 must lose. **That is wrong.**

`grant_epoch=2, valid_epoch=0` does NOT prove a peer wrote *during* our EX
tenure. It proves our cached base was **already stale when the tenure began**.
Both statements are simultaneously true:

- No peer wrote after this EX grant began  (P6's premise — TRUE)
- Our base was already stale at grant time (P65's signal — TRUE)

P6 only proves the device cannot have become newer *during* the tenure. It says
nothing about whether the base was current *at the start*.

## Therefore the real defect is earlier

This whole sequence is already invalid before conversion is reached:

1. Acquire EX with epoch 2
2. Keep using an in-core base validated at epoch 0
3. **Do a lookup against it** (`P26-LKFMT err=-2` "node24_1 not present")
4. Mutate that stale base
5. Discover the mismatch only at conversion time

The negative lookup itself is suspect — it was computed against the epoch-0
image and never revalidated after EX was granted at epoch 2. Checking at
conversion is far too late.

**Do not re-attempt an image-level "who wins" reconciliation.** Once local
mutations exist on a stale base, neither "keep mine" nor "adopt disk" is
correct, and merging is unsafe across a format conversion — shortform->block
conversion, entry layout, free-space structures, nlink, size and child init are
ONE logical namespace transaction.

## The correct formulation (freshness gate at acquire)

    acquire EX with grant_epoch E
        if cached.valid_epoch != E:
            assert no current-tenure mutation exists
            invalidate / reload / adopt authoritative image
            cached.valid_epoch = E        # only AFTER adoption succeeds
        expose the EX tenure to the filesystem operation

Not unconditional device I/O — an unconditional **freshness decision**, with
epoch-match as the fast path. The gate must run before: trusting a negative
lookup or negative dentry; deciding whether conversion is needed; modifying the
in-core inode; joining the inode to a transaction; allocating the child or
changing parent link count.

If mismatch is discovered when local changes ALREADY exist, that is an
invariant violation, not a routine reload. Preference order: (1) abort/restart
the whole namespace op after adopting, (2) replay a retained *semantic intent*
(not an inode image), (3) fail-stop. Note XFS's journal carries physical/logical
redo, NOT a restartable namespace intent — so (2) is not available for free.

Once the mid-tenure gate exists, `P6-MIDTENURE-RELOAD-SKIP` should no longer
participate in ordinary coherence; keep it only as a defensive assertion.

## Split "committed"/"durable" into distinct states
1 modified in core; 2 attached to a transaction; 3 journal record durable;
4 home write submitted; 5 home write completed; 6 **published** (lock may move).
**The epoch must describe state 6**, not 1/2/3. Bumping the epoch at journal
commit while the grant recipient reads an older home image is not a coherent
publication protocol.

## Defects (a) release barrier, (b) partial cluster write, (c) in-flight order
All three are ONE missing invariant: *an incompatible grant must not transfer
while any write from the old tenure can still affect what the new tenure reads.*

A bare in-flight counter is NOT sufficient — it races with new submissions.
Correct release sequence:
1. **Close the tenure to new mutations and submissions** (a gate, synchronized
   with every path that can dirty or submit metadata)
2. commit required journal transactions
3. publish/checkpoint whatever the next owner will read
4. wait for every relevant write (incl. async/indirect submitters, ordering
   deps, device-cache flush)
5. account completion ONLY for bytes actually issued AND completed
6. verify no publication error and pending == durable
7. only then bump the published epoch and release/downconvert
8. on I/O failure do NOT hand off as if publication succeeded — error, withdraw,
   or fence

Writes need tenure attribution (resource, tenure/publication gen, exact
inode/range/sector, success/failure), not a raw count.

For (b): if one inode's write entails a whole-block RMW covering neighbours,
independent per-inode locks are the wrong granularity. Either lock the inode
cluster, or make writes genuinely disjoint with exact completion accounting, or
have one coherent owner assemble and publish the whole block. Re-dirtying after
authority is surrendered is wrong (that's the measured livelock) — **retain the
lock until the skipped inode is actually published or treated as fatal.**

## Validation must be deterministic, not statistical
30-round storms cannot validate this (the epoch path fires ~1x/run). Build
fault-injection/sync hooks and assert:

    no mutation if valid_epoch != grant_epoch
    no incompatible release if inflight != 0
    no release if pending_seq != durable_seq
    no completion may advance durability for a range not present in the I/O
    no write tagged tenure T submitted after T enters draining
    no write tagged T outstanding when T is released

GPT also suggests a small TLA+/PlusCal model — the state space (two owners,
epochs, dirty/logged/home states, delayed writes) is small and the failure is an
ordering-protocol defect.

## mkdir(2) silent success is NOT tolerable
Returning success for an operation the FS then knowingly discards is corruption,
not delayed-writeback semantics. If publication fails: roll back / restart, else
return EIO. If success was already returned, withdraw or fence rather than drop.

## GFS2/OCFS2
Copy the invariant, not the implementation: lock transition IS a coherence
boundary; old-owner writes complete/order before incompatible handoff; new owner
refreshes before use; journal-vs-home visibility explicitly defined; I/O errors
prevent falsely successful publication.
