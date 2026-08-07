---
name: ccloop-c7ee71c6-sess89-own-stamp-reclaim-is-dead-0-of-91
description: sess89: MEASURED 0 own-stamp reclaims of 91 claims — node_id is random per mount, so pass-1 and P237-RECOV-SUPERSEDED are unreachable. Steal hazard R…
metadata:
  type: reference
tags: [sess89, disklock, claim, node_id, slice_adopted, SUPERSEDED, unreachable, measured, refuted, withdraw]
---

# sess89 — the own-crash reclaim path is dead, measured 0/91

Build 0.11.420, srcversion `33018595D555FBE463F017B`, 32/32 mounted on caw.
No code changed this session. Two measurements, one new ledger entry
(`D-OWN-CRASH-RECLAIM-PATH-UNREACHABLE`, critical).

## PROVEN — pass-1 "own-stamp reclaim" never matches (0 of 91 claims)

`mxfs_disklock_claim_slot` pass-1 (disklock.c:4610-4624) matches
`expected->node_id == ctx->local_node`. But `node_id` is
`uuid_to_node_id(mxfs_pal_get_random_bytes(node_uuid,16))` drawn fresh at
**every** `mxfs_v5_dlm_init` (v5_mount.c:2494, 2497) — nothing in the tree
persists `node_uuid`. So pass-1 compares a fresh random 32-bit value against a
stale one.

Fleet measurement over every node's full dmesg history:
**0 `own-stamp reclaim`, 91 `fresh claim — slice ADOPTED`.** Successive mounts
of one host carry unrelated ids (test1: 1401183219 → 2204047808 → 2583145845);
nodes migrate slots freely (test30: 30 → 2 → 1).

### Two shipped consequences

1. **`xfs_log.c:623` calls pass-1 "the required own-crash recovery path."** It
   never runs. Every mount sets `XLOG_MXFS_ADOPTED_SLICE`, suppressing image
   replay of the inherited slice. disklock.c:4578-4584 warns that pushing a
   rebooted node onto pass-2 means "silently abandoning that node's own
   unreplayed journal slice" — that warned-of state is unconditional. Every
   node depends entirely on a **survivor** to replay its slice, so the
   whole-cluster-crash / no-survivor case has no proven replayer.
2. **`MXFS_RECOVERY_SUPERSEDED` is unreachable dead code.** disklock.h states
   its precondition: "only reachable through the claim pass-1 own-stamp
   reclaim." `recovery_begin`'s `cur->node_id != victim` gate (disklock.c:2795)
   always fires first. **This answers sess88's owed item 2**: the
   P237-RECOV-SUPERSEDED / -COMPLETE-SUPERSEDED arms have never fired on the
   rig because they *cannot*, not because the race was never run.

## REFUTED by measurement — the withdrawn-slot steal hazard

Hypothesis (from code reading): pass-2 accepts any slot with `flags != ACTIVE`,
which includes **WITHDRAWN** — and `mxfs_disklock_withdraw`'s own comment says
such a slice "may hold committed transactions whose buffers were only partially
destaged … Peers MUST replay that slice." With slots 0..31 ACTIVE and 32..63
empty, a withdrawn slot k<32 is the **first** non-ACTIVE slot the index-ordered
scan meets, so it is *preferred* over every free slot. Predicted: remount steals
slot k, marks it ADOPTED, suppresses the replay it owes.

**REFUTED.** `tests/withdraw_slot_reclaim_probe.sh test32 test1 100` —
GOINGDOWN(2) then remount. O_DIRECT slot-20 timeline sampled from test1:

    t+ 0.00s ACTIVE     node=1763081322 epoch=16225762881755121090
    t+ 2.06s WITHDRAWN  (the withdraw stamp)
    t+ 3.32s GUARD      (RECOVERY_GUARD — only 1.26s later)
    t+11.37s empty      (recovery done, slot zeroed)

The guard lands **1.26s** after the stamp; a remount needs ~12s (umount 1s +
mount 11s). Pass-2's explicit GUARD skip (disklock.c:4643-4646) holds, so the
remount correctly took **free slot 32**, not slot 20. Recovery ran end to end
— P163-RECOVERY-PENDING ×31, P234-RECOV-FENCED, P163-RECOVERY-COMPLETE,
P97-SWEEP-DONE — and **100/100 fsync-acknowledged files survived**. Zero
`P237-*` of any kind, consistent with the unreachability finding above.

This run *was* a rejoin raced into the detect+confirm window (12s after death,
well inside ~124s), so sess88's owed item 2 is discharged as far as it can be.

## New instrument (RULE 3)

`tests/withdraw_slot_reclaim_probe.sh [victim] [reader] [nfiles] [dev]` —
per-run kmsg marker on all 32 nodes, fsync-acknowledged payload (fsync file +
fsync parent dir, so loss is *acknowledged* loss), GOINGDOWN(2), O_DIRECT
250ms slot timeline from a survivor across the shutdown, then claim-kind,
survivor P163/P234/P237 census, and a durability count. Derived RULE-0 budgets
inline. Exit 1 on steal or on acknowledged loss.

`tests/mxfs_shutdown.sh <node>` already existed for the raw GOINGDOWN ioctl
(xfs_io cannot do it — its FSGEOMETRY probe fails first on mxfs).

## STILL OWED

- **Full board at 32/caw** — the regression gate for the proto_gen 3 bump.
  Not run in sess87, sess88, or sess89. This is the top of the next session.
- The no-survivor case (crash all 32 with acknowledged payload outstanding,
  bring one back) — the one path with no proven replayer.
- RULE-5 consult on the fix shape for the dead pass-1: stable persisted node
  identity vs. deleting pass-1 and covering the no-survivor case explicitly.
