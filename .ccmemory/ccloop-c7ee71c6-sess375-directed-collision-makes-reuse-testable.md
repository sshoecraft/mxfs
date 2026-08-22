---
name: ccloop-c7ee71c6-sess375-directed-collision-makes-reuse-testable
description: sess375: the CAW slot hash is seedless FNV-1a and replicates EXACTLY in userspace (788/788 live slots, 0 mismatches) — so the tombstone/slot-reuse ha…
metadata:
  type: project
---

# Directed hash collision makes the slot-reuse hazard testable

**The wrong turn, recorded so it is not repeated.** sess375 argued the
tombstone/slot-reuse hazard was UNREACHABLE — slot binding is open-addressed
(`index = hash(resource) % 65536`, linear probe past tombstones,
`dlm/dlm_caw.c:3126,3187-3279`), so with a few dozen live slots a freed index is
re-bound only by a resource that hashes exactly to it (~1/65536 per acquire) —
and proposed substituting "both defenses exercised separately". **The RULE-5
review refuted it and was right.**

## Why it is reachable

`resource_hash_raw` (`dlm/dlm_shared.c:34`) is **seedless FNV-1a over the raw
bytes of `struct mxfs_resource_id`** — no boot seed, fixed layout:

    volume u64 @0 | ino u64 @8 | offset u64 @16 | ag_number u32 @24 | type u8 @28 | pad[3]

So home slots are computable outside the kernel. `tools/caw_slot_hash.py`:

- `verify` against a live `caw_slotdump --all`: **788 live slots at their
  computed home, 10 at probe+1, ZERO mismatches** — which also confirms the
  field values (inode resources really do carry `ag_number = 0`, `offset = 0`).
- `collide`: **2478 cross-AG colliding pairs among 18669 real inodes.**
- `pick`: one usable pair (home slot free, neither inode bound anywhere).

Expected cross-collisions ≈ n²/65536, so a few thousand candidate inodes is
plenty. Nothing is forged: A and B are ordinary files bound through normal
paths.

## The construction (tests/closure_reuse_directed.sh)

A and B are two real inodes with the SAME home slot S, in different AGs; the
forged refused domain is a THIRD AG so both stay out of closure and usable.
Victim writes A → A binds at S (verified on the platter). Kill. Publisher's
strip attempt for S pauses at the hint→read boundary
(`caw_inject_closure_pause_{where=1,slot=S,ms,n}` — timing only). Inside the
pause, real code empties S and Q re-binds B there. Publisher's authoritative
re-read must then see B and do nothing.

**The transition itself is REPRODUCED**, 4/4 runs, proven by a single-slot
READ(16)+FUA dump immediately before and after Q's read:
`magic=0x4d58444c ino=A` → `magic=0x4d584357 ino=B`.

## What still blocks it

The rebind lands AFTER the publisher has passed S, so `moved=0`. Emptying S
inside the pause needs the publisher's own blocked waiter to demand-scrub it —
and that scrub does not fire. Ledgered as
**D-CLOSURE-DEMAND-SCRUB-NOT-FIRING-FOR-BLOCKED-WAITER-375** (high): a waiter
sat `el_ms=76089` with `w=1` on a slot carrying the victim's out-of-closure EX,
on the node whose `closure_cand_mask` was set, while a sibling scrub on the
same node succeeded 4.1s after the scan entry.

## Structural facts worth keeping

1. **The publisher purges BEFORE it publishes.** `P299-CLOSURE-SCAN ENTRY`
   t=5763.421 vs `terminal outcome PUBLISHED` t=5842.475. So for the whole
   scan the publisher is the ONLY node holding the verdict, and **no remote
   survivor scrub can race it** — a concurrent actor must be local to the
   publisher. Two runs wasted before this was measured.
2. **The publisher is the recovery-lease owner**, identifiable at runtime from
   `P236-RECOV-CLAIMED` / `P238-RECOV-LEASE ... execution lease acquired`,
   ~0.2s before the scan entry.
3. **A re-bound slot can never carry the dead victim's bit** — whatever
   re-binds it is bound by a LIVE node — so the `flipped` counter (hint said
   out-of-closure, re-read says in-closure) is unreachable *on a reused slot*.
   `moved` is the achievable proof.
4. **Eviction releases CAW grants**: a fleet-wide `sync; drop_caches` took LIVE
   slots 1454 → 923.
5. **`find -printf '%i'` binds every inode it stats.** Enumerate BEFORE the
   quiesce, or the pair you picked is already bound and B gets pushed one probe
   past its home where it can never move back.
6. **`dd iflag=direct` on a slot sector returns a STALE image** — this target
   stack drops the SCSI FUA bit. Use `caw_slotdump --slot N` (added this
   session), which issues the same READ(16)+FUA the kernel's `read_slot` uses.
   A poller built on `dd` fired on a superseded tombstone and cost a run.
7. **`lmod` (`last_modified_ms`) is the WRITING NODE's monotonic clock** — it is
   NOT comparable across nodes. An ordering argument built on it is invalid.
