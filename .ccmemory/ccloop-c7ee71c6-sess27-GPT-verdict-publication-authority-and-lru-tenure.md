---
name: ccloop-c7ee71c6-sess27-GPT-verdict-publication-authority-and-lru-tenure
description: sess27 RULE-5 GPT verdict: gen-equality is only the local test; the real bug is publication WITHOUT write authority at inode-CLUSTER granularity. Plu…
metadata:
  type: reference
tags: [gpt, rule5, sess27, publication-authority, unmount-leak, incarnation]
---

# sess27 RULE-5 GPT consult (gpt-5.6-sol) — verdict and actions

## A. On the typeflip fix I landed

**Keep it — but it is only the correct LOCAL test, not the root fix.**

- Within one incarnation the type cannot change, so `disk_gen == incore_gen` +
  type mismatch = one side is stale/corrupt. `disk_gen != incore_gen` = possibly
  different incarnations, and the numeric ORDER means nothing. Replacing `<=`
  with `==` removes an invalid assumption. A/B supports it.
- **The deeper invariant violation is: "a node published an inode image after it
  no longer had authority to publish that image."**
- **THE ARCHITECTURAL POINT — protection must be at least as coarse as the
  PHYSICAL WRITE UNIT.** MXFS writes the whole 16KB inode CLUSTER (P170-CLWR
  prints 21+ `ino:mode:gen` triples per write). Inode-level locks therefore do
  NOT prevent one slot's update from carrying **stale images of neighbouring
  slots**. Needs one of: cluster-block exclusive ownership; validated
  read/merge/write under a block lock; storage compare-and-write over the actual
  block plus expected block version. *"A compare-and-write used only to
  manipulate the DLM record does not fence a subsequent ordinary metadata
  write."*
- Required protocol properties: (1) dirty only while owning the write tenure;
  (2) before EX downgrade/release either all writes have landed at their final
  shared-LUN locations or a separate retained writeback authorization excludes
  incompatible publishers; (3) **already-submitted I/O must be drained too** —
  checking ownership at dirty/queue time is insufficient, an in-flight write can
  land after another node's commit; (4) every publication carries its incarnation
  + content epoch and a stale publication must FAIL, not overwrite; (5) coverage
  at write-unit granularity.
- **Safest rule: a plain PR holder may not initiate or complete home-location
  inode publication.** Delayed writeback after downgrade needs an explicit
  retained write token, not merely PR.
- ACTION: assert/trace whenever an inode-cluster write is submitted or completed
  without a matching write tenure/epoch.
- CAVEAT on my own fix: `di_gen` is 32-bit, so the equality guard is
  **probabilistic** (2^-32 collision per comparison). Acknowledge it; do not
  present it as absolute.

## B. Incarnation identity — di_gen can NEVER order incarnations

Generations are `get_random_u32()` (verified at xfs_icache.c:1902). `a<b`, `a>b`
carry no meaning; `a==b` is only a probabilistic identity check. Separate two
concepts:

1. **Allocation incarnation** — changes only on free+realloc. Durable 64-bit
   monotonic `alloc_incarnation`; identity = `(fs UUID, ino, alloc_incarnation)`.
   Must be assigned **transactionally under allocation serialization** and
   persisted with the new dinode. Do NOT derive it from a volatile DLM grant number.
2. **Content/publication epoch** — increments per committed metadata publication
   within an incarnation; used to reject same-incarnation stale writeback.

A DLM grant generation is NOT a durable incarnation id: record loss/recreation,
node/cluster restart, wrap, reuse after lock GC, and stale disk writes that
outlive the DLM record all break it.

## C. The unmount inode leak — THE NEW ANGLE (was stalled 3 sessions)

> The most useful fact is not nlink/PR/CACHED. It is that the inode is **on the
> inode LRU** and later has **i_count == 1**.

An inode joins the LRU after becoming unused. So the surviving reference belongs
to a **NEW busy tenure that began AFTER the inode had previously reached zero**.
That collapses the search to the FINAL `0 -> 1` transition after the last LRU
insertion — and it needs neither a global lifetime balance nor LIFO pairing,
which are exactly the two instruments already disproven here.

Instrument (temporary kernel patch is more reliable than module-side, since
`ihold()` is inline): `inode_add_lru()`, LRU removal/isolation, `__iget()`,
`igrab()`, `ihold()`, `iput()`, and any direct `atomic_long_*(&inode->i_count)`.
Record inode addr/ino/gen, old+new i_count, ts, cpu, pid/comm, stack id, and a
per-inode busy-tenure sequence. Ring buffer + stack depot / BPF stack ids, not
printk. A kprobe/fentry on generic `iput()` DOES see the VFS-side releases
(`dput->iput`, `d_splice_alias`'s internal iput) that are unhookable from the FS.

A raw `ihold()`/direct increment from zero is the suspicious case; a normal
`igrab()` of a cached zero-ref inode can be legitimate.

**FIRST: verify the unmount diagnostic itself does not igrab and manufacture the
reported count of 1.**

Second track: preserve a vmcore / use **drgn** on the live kernel and
reverse-search memory for the inode pointer; classify the containing object
(dentry not counted by the alias count, struct file, fsnotify mark, work/timer
payload, **the MXFS DLM object itself**, aio/io_uring, RCU-retired object).
Given `dlm_state=CACHED`, inspect the DLM object and every reverse pointer from
it — "cached lock object keeps an inode pointer but is not considered pending
work" is an ownership category distinct from the queue-arm sites already audited.

## D. Self-created / deferred-publish baseline

Neither stamping at create nor a sentinel is sufficient. Use an explicit state
machine: `LOCAL_UNPUBLISHED` / `VALID(incarnation, content_epoch, grant_tenure)`
/ `INVALID`. Do NOT represent LOCAL_UNPUBLISHED as numeric epoch 0.

**Critical warning about the fix I was about to write:** stamping the DLM's
CURRENT values at deferred publish is only safe if publication is a serialized
event. If the inode was already visible, a peer may have found it, locked it,
modified it, advanced the epoch and released — and copying the current epoch
then **LAUNDERS the missed update** and declares the stale local image coherent.
Since the captured local inode is ALREADY DIRTY, a blind reload is too late: the
operation must abort/retry or use a defined merge/replay path.

Prefer creating the child's DLM record while still holding the parent's
exclusive lock, before the new dirent becomes visible. A crash may leave an
unused DLM record — preferable to exposing an inode with no coherence state.

Replace `cached_grant_gen != 0` gating with an explicit validity/state check, and
make the baseline the **durable content-publication epoch**, not the grant
generation (a grant gen can change with nobody modifying data, and has
restart/wrap semantics). Avoid synthetic magic epoch values that `if (epoch)`
logic can accidentally accept.
