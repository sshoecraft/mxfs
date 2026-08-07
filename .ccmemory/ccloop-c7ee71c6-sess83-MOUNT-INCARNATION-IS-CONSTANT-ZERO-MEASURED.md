---
name: ccloop-c7ee71c6-sess83-MOUNT-INCARNATION-IS-CONSTANT-ZERO-MEASURED
description: sess83: MEASURED on the live LUN — the disklock mount-incarnation epoch is a hard-coded 0 on all 31 live HB records, making ~8 recovery/fence incarna…
metadata:
  type: reference
tags: [sess83, disklock, incarnation, epoch, recovery-descriptor, fence-certificate, foreign-replay, step5.2, rule4, measured, critical]
---

# sess83 — the mount-incarnation epoch is a CONSTANT ZERO (measured)

Found while starting **step 5.2** of D-FOREIGN-REPLAY-UNGATED-IMAGES ("token v2:
be64 resource, **bound to victim slot + incarnation**").  You cannot bind to an
incarnation identifier that is a constant.

## The measurement (not code reading)

Raw sector read of the 64-slot heartbeat region off the **live** 32-node shared
LUN, decoded in python3 independently of the kernel module:

    disklock_offset=67117056 (from tools/chk_mxfs -v /dev/mapper/mpatha on test1)
    512B/record, epoch at byte offset 24 (magic0 flags4 node_id8 fs_gen12
    timestamp_ms16 epoch24 lock_count32)

    slot= 0 magic=0x4d584c4b flags=1 node=2204047808 fs_gen=1167495961 EPOCH=0
    slot= 1 ... EPOCH=0   (31 live records)
    distinct EPOCH values across all live HB records: [0]

Corroborating code fact: `grep` of the whole tree finds exactly ONE write to
`struct mxfs_disklock_ctx.epoch` — `ctx->epoch = 0;` in the constructor
(`dlm/disklock.c:1145`).  Every other appearance is a read.  `hb->epoch =
ctx->epoch` on every heartbeat/claim write, so the on-disk field can only ever
be 0.

## What that makes vacuous (all in dlm/disklock.c)

1. `hb_own_record()` (:457) — `cur->epoch == ctx->epoch` is 0==0.  The
   `hb_foreign_kind()` branch "a different incarnation of this node owns the
   slot" (:482) is UNREACHABLE.  A stale ACTIVE record left by our OWN previous
   incarnation reads as our live record.  This is the sess78 own-slot CAS
   predicate.
2. `desc.victim_epoch = cur->epoch` (:2483, :3121) = 0 — the durable recovery
   descriptor cannot name WHICH incarnation of the victim it is recovering.
3. `d->owner_epoch == ctx->epoch` ("is this recovery mine?", :1604 :1702 :2380
   :2437 :2892 :3080 :3368 :3511) reduces to `owner_node == local_node` — a
   REJOINED incarnation of the same node adopts its own prior incarnation's
   recovery lease.
4. `d->fence_prover_epoch == ctx->epoch` (:2895, :3257) — same for the sess75/76
   fence certificate.
5. The guard idiom `if (victim_epoch && d->victim_epoch != victim_epoch) refuse`
   (:2462 :2954 :3069 :3489 …) — callers pass an epoch read from disk, i.e. 0,
   so the incarnation check is **skipped entirely** at ~8 recovery sites
   (recovery_begin, takeover, fence_intent, fence_certify, claim, advance).
6. `mxfs_disklock_slot_holds_incarnation()` (disklock.h:1154) degenerate.
7. Line :290 `return epoch == 0 || d->victim_epoch == epoch;` → always true.

## Landing context already verified

- The HB **feature block CRC folds `epoch` in** (`mxfs_hb_feature_crc`, doc at
  disklock.h:493) — so the value is already identity-bound once it is real.
- There IS an enforced cluster-wide version gate: `proto_gen` published in the
  same sector; joiners quarantine until every live current-fs_gen peer
  validates; the monitor SCSI-PR-fences a live LEGACY/mismatched incarnation; a
  joiner facing an established incompatible cluster withdraws.
  `MXFS_PROTO_GEN` is currently **2** (include/mxfs/mxfs_super.h:71, bumped 1→2
  in sess75).  A 2→3 bump is the hard gate this change should ride.
- Primitives: `mxfs_pal_time_ms()` is MONOTONIC/boot-relative (documented NOT
  cross-node comparable, resets on reboot — do NOT use it as an incarnation).
  `mxfs_pal_time_real_ms()` = wall ms since Unix epoch.
  `mxfs_pal_get_random_bytes()` exists in both kernel and user PAL.
- net2 has a separate persisted `self_incarnation` counter
  (`net2_membership_inc_bump`, dlm/net2_membership.c:243) in the mepoch
  sub-record of the node's own HB sector — but the CAW rig does not run net2 and
  that counter lives in the very sector a purge zeroes, which is exactly the
  rejoin case.

## Candidate construction (NOT yet ruled on)

`epoch = (mxfs_pal_time_real_ms() << 16) | rand16`, forced nonzero, chosen
BEFORE the claim write so the claim itself carries it and the feature CRC binds
to it.  Open questions were sent to GPT (RULE 5) in sess83: ordering-vs-equality
requirements, whether the 8 `victim_epoch &&` sites may still accept a legacy 0,
token v2 shape (40B: version/class/flags/be64 resource/be64 grant_epoch/be64
owner_epoch/owner_slot/owner_node), and whether mutation-time provenance capture
must fail closed when a buf log item is relogged under two authorities.
**The consult had not returned when the session hit the relay boundary — re-ask
it, it does not survive the session.**
