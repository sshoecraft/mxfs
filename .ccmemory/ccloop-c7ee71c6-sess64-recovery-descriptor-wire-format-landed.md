---
name: ccloop-c7ee71c6-sess64-recovery-descriptor-wire-format-landed
description: sess64: the sess63 GPT ruling's durable recovery descriptor now has a WIRE FORMAT (0.11.408) — 80B overlaying the evict ring in a GUARD record. Behav…
metadata:
  type: reference
tags: [foreign-replay, recovery, descriptor, disklock, on-disk-format, step1, in-progress, do-not-board]
---

# sess64 — recovery descriptor wire format landed (0.11.408)

Tree **0.11.408**, srcversion `50D0591F24309A58B91BFE4` (was 0.11.407 /
`C72F20487083A2CA52AC43C`).  **STILL DO NOT BOARD** — this is a type-level
change only; nothing reads or writes the new structure yet, so runtime
behaviour is byte-identical to 0.11.407.  The version rev exists so the
srcversion drift is not mistaken for an untracked build.

## What shipped

Step 1 of the sess63 sequencing list, first half: `struct mxfs_recov_desc`
(80 bytes) + `struct mxfs_recov_body` in `dlm/disklock.h`, plus a large
design comment that encodes GPT's five binding rules (ordering, victim
identity never overwritten, split broadcast predicate, victim-manifest
freeze, stale-descriptor-is-a-lease-not-a-slot).

### The placement decision — NO on-disk growth was needed

The HB record is exactly 512 B with **zero** reserved space
(40 hdr + 416 evict ring + 44 mepoch + 12 feat).  My first plan was to
shrink the evict ring 25→20 entries to carve 80 B.  That is unnecessary:
the descriptor only ever exists in a record whose `flags ==
MXFS_DISKLOCK_FLAG_RECOVERY_GUARD`, and the evict ring is

- **produced** only into a node's own ACTIVE record (`disklock.c:393-404`), and
- **consumed** only from a peer's ACTIVE record — the monitor's ring consumer
  at `disklock.c:607` is downstream of the `flags != ACTIVE → goto check_dead`
  bail at `disklock.c:557-560`.

So a GUARD record's 416 ring bytes are dead space in every existing build.
The descriptor is a **union member overlaying the ring**, costing nothing:
no region growth, no mkfs change, no ring-depth regression.  Both members
carry their own magic, so neither interpretation can misread the other's
bytes (a pre-sess64 sweep guard zeroes them → magic 0 → "no descriptor",
which is also how a sess43 sweep guard is told apart from a recovery lease).

### Layout facts (do not re-derive)

- `offsetof(struct mxfs_disklock_heartbeat, mepoch) == 456`.  I first wrote
  392 in the assert — that was the shrunk-ring arithmetic from the discarded
  plan.  40 + 416 = 456.
- Descriptor fields, all naturally aligned, total exactly 80:
  magic/version/stage, victim_epoch, owner_epoch, recovery_gen,
  owner_stamp_ms, victim_node, owner_node, victim_fs_gen, flags,
  victim_slot, owner_slot, slice_idx, slice_count, stage_seq, reserved, crc32c.
- Stages: NONE 0, FENCED 1, IMAGES_REPLAYED 2, OBLIGATIONS_DONE 3,
  GRANTS_RELEASED 4.  CONSUMABLE is the ABSENCE of the record (zeroed sector).
- `MXFS_RECOV_F_QUARANTINED` is terminal — GPT's ruling that an
  admitted-intent/rejected-done pair must never be guessed either way.

### Bug found and fixed on the way

`MXFS_BUILD_CHECK_HB()` is **referenced by nothing in the tree** — the kernel
half of the `#ifdef __KERNEL__` layout guard has never validated anything.
The only live checks were the user-mode `_Static_assert`s and the two at
`disklock.c:65-67`.  My new asserts are therefore placed OUTSIDE the ifdef so
they compile in both builds; verified by a deliberate failure (the wrong 392
constant tripped it) and then by a clean build of both.

## Next session — the .c side of step 1

Everything below is designed but NOT written.  All the code facts needed are
already line-verified in this note and sess63's.

1. `dlm/disklock.c`: `recov_desc_crc()` (bind the crc to the record's victim
   identity exactly as `hb_feature_crc` binds the feature block — copy that
   pattern), `recov_desc_valid()`, and:
   - `mxfs_disklock_recovery_begin(ctx, slot, victim, victim_epoch, flags)` —
     CAS from the exact observed ACTIVE-or-WITHDRAWN image to
     GUARD + desc{FENCED}, **preserving `node_id`/`epoch`/`fs_gen` as the
     victim's**, durable (FUA) before returning.  Must run BEFORE any CAW purge.
   - `mxfs_disklock_recovery_advance(ctx, slot, stage)` — monotonic stage CAS
     from the exact stored image; refuse to go backwards.
   - `mxfs_disklock_recovery_refresh(ctx, slot)` — re-stamp `owner_stamp_ms`
     (abandonment = 3 intervals with NO CHANGE; never clock arithmetic).
   - `mxfs_disklock_recovery_read(ctx, slot, *out)` and
     `mxfs_disklock_recovery_takeover(ctx, slot)` — takeover CASes only the
     owner fields + bumps `recovery_gen`, keeps victim identity AND stage, and
     the caller RESUMES from the recorded stage (never re-runs an earlier one).
2. **Split broadcast predicate** — `disklock.c:493-522`.  `still_dead_stamp`
   must stay TRUE while the slot is GUARD + descriptor naming the same
   `(pending_node, pending_epoch)`.  Without this the very first
   ACTIVE→GUARD CAS makes every peer fire `recovered_cb` and drop the grants
   recovery is deliberately freezing — the exact hazard GPT flagged.
3. **Freeze** — `mxfs_disklock_purge_node` (`disklock.c:1274-1309`) must
   (a) also match a GUARD record whose descriptor names the victim, so the
   final zero still happens, and (b) REFUSE to zero it while stage <
   GRANTS_RELEASED or QUARANTINED, returning an error so the caller cannot
   publish.  `mxfs_disklock_guard_slot` (sess43 sweep) must refuse a slot
   carrying a descriptor.  `claim_slot` already skips all GUARD slots in both
   variants (`disklock.c:2013-2017`, `2135-2145`) — nothing to do there.
4. `mxfs_disklock_find_node_slot`'s DISK-SCAN arm (`disklock.c:1879-1885`)
   currently matches ACTIVE|WITHDRAWN only.  Add GUARD-with-matching-victim,
   or a peer that never saw the death resolves slot = -1 and falls into
   `v5_lease_expire_cb`'s "owns no slice → purge immediately" arm
   (`v5_mount.c:1413-1426`) — which would purge in-memory grants for a node
   whose slice is mid-recovery.  The in-memory `slot_node_id[]` fast path
   masks this for peers that DID see the death, which is why it is easy to miss.
5. `v5_mount.c` wiring in `mxfs_v5_dlm_recovery_complete` (line 2017):
   `begin(FENCED)` → CAW purge → flush → `advance(GRANTS_RELEASED)` →
   `disklock_purge_node` (the zero = CONSUMABLE).  Note that the in-memory
   `recovery_pending[]` (`disklock.c:1585-1599`) is the ONLY progress record
   today — GPT's "in-memory bitmap cannot be the authoritative resume record"
   is exactly this; the descriptor replaces it as the durable one.

Only after that: quarantine terminal state → report-only admission + intent
inventory → authority transfer → intent completion → step-5 gate swap.
Step 5 must NOT ship before this; sess63 proved shipping it first is strictly
worse.
