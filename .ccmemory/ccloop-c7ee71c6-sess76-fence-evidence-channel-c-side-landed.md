---
name: ccloop-c7ee71c6-sess76-fence-evidence-channel-c-side-landed
description: sess76: fence-evidence channel C SIDE landed (0.11.416) — intent/certify/fence_takeover/claim/gate + cert validator. Prover wiring NOT done. sess75 s…
metadata:
  type: reference
tags: [fencing, recovery-descriptor, disklock, 0.11.416, in-progress, scsipr]
---

# sess76 — the fence-evidence channel, C side

Continues sess75 (wire format) and the sess74 ruling. **Version 0.11.416,
`make clean && make modules` exit 0.**

## FIRST: the sess75 stale-build suspicion was REAL

`make clean && make modules` moved srcversion
`C7336ABC002DF02F219BC17` → **`BEC27B5DF71E9C0F33EAEAB`**. sess75's
second incremental build after editing `include/mxfs/mxfs_super.h` did
NOT pick up `MXFS_PROTO_GEN=2`. The memory `Make clean before rebuild
for multi-file changes` is load-bearing — obey it after any .h edit.

## ⚠️ STILL DO NOT DEPLOY

Same reason as sess75: the descriptor says v2 and the gate exists, but
**nothing publishes a certificate yet** because the prover is not wired.
Deploying now = every peer death produces an uncertified descriptor and
every replay refuses. Fail-closed, but a hang, not a working FS.

## LANDED in `dlm/disklock.c` (all five declared bodies + a sixth)

1. **`mxfs_recov_cert_proves_exclusion()`** — the validator. Full sess74
   Q4 list. Note the trick: it recomputes `recov_desc_crc()` from the
   descriptor's OWN `victim_fs_gen/victim_node/victim_epoch`. Since
   `recov_desc_of()` validated the same crc against the record HEADER,
   both passing proves the descriptor's internal identity agrees with
   its header — the "descriptor-vs-header" check comes free.
2. **`recovery_fence_intent()`** — ACTIVE/WITHDRAWN → GUARD{FENCING},
   durable before the P&A. `owner_term` stays **0** (attempt lease ≠
   execution lease); `fence_term` = 1.
3. **`recovery_fence_certify()`** — refuses `!proves_exclusion`,
   `resv_type != WR_EX_RO`, key 0, and key-drift vs the intent —
   **before touching the platter**. Stage→FENCED and owner→UNOWNED in
   ONE CAS.
4. **`recovery_fence_takeover()`** — NEW, not in the sess75 declaration
   set. The prover-died-with-intent-durable case: bumps `fence_term`,
   lets a successor retry the P&A and certify ITS OWN result. Never the
   dead prover's (sess74 ruled that inference unsound). Sleeps
   ABANDON_MS — never on the HB thread.
5. **`recovery_claim()`** — certificate checked BEFORE ownership, so an
   elected replayer gets `-EPERM "wait for a prover"` rather than
   `-EBUSY "someone else has the job"`. Idempotent when already ours.
6. **`recovery_replay_authorized()`** — the gate. FRESH read every call,
   never a snapshot. `auth == NULL` = pre-claim probe (certificate only);
   non-NULL also revalidates the execution lease → `-EBUSY` if taken over.

### Signature change vs sess75

`fence_intent` gained a **`uint64_t victim_key`** parameter (the key the
caller is about to preempt). It is recorded in `fence_victim_key` at
FENCING as the INTENDED key, and certify overwrites it with the key
actually removed, **refusing a mismatch** (P236-FENCE-KEY-DRIFT). That
made `struct mxfs_recov_fence_auth.victim_key` honest instead of dead.
The field's meaning moves with the stage — documented in disklock.h.

### A hole closed while there

`recovery_advance()` now refuses `d->stage < FENCED` **and** any target
`stage <= FENCED`. Without it, a caller passing `auth == NULL` (which
degrades to the owner-identity test, and the prover IS the owner during
FENCING) could advance its own intent straight to FENCED — manufacturing
a fence with `fence_kind` still NONE. New probe:
`P236-RECOV-ADVANCE-PREFENCE`.

## Probe names added (all P236-*)

`FENCE-INTENT`, `FENCE-INTENT-FAIL`, `FENCE-ATTEMPT-BUSY`,
`FENCE-ATTEMPT-TAKEOVER`, `FENCE-UNREADABLE`, `FENCE-NOT-PROVED`,
`FENCE-NO-RESV`, `FENCE-KEY-DRIFT`, `FENCE-LEASE-LOST`,
`FENCE-CERTIFIED`, `FENCE-CERTIFY-FAIL`, `CLAIM-UNCERTIFIED`,
`RECOV-CLAIMED`, `REPLAY-REFUSED`, `RECOV-ADVANCE-PREFENCE`.

## NEXT — exactly where I stopped

**Step 3: wire the prover inside `v5_pr_fence_dead_node_rc()`**
(`dlm/v5_mount.c:694`), NOT at its four call sites (v5_mount.c:757, 762,
790 vergate, 1396, 1650) — whichever node's P&A wins first consumes the
victim key, so any fence path skipping intent/certify permanently
destroys that slice's route to recovery.

Shape: `find_node_slot(dead_node)` → slot+epoch → `fence_intent(slot,
dead_node, epoch, (uint64_t)dead_node, slice_idx, slice_cnt, 0, &fauth)`
→ existing `mxfs_scsipr_fence_node()` → `fence_certify(slot, &fauth,
fres.kind, fres.resv_type, fres.victim_key, fres.pr_generation)`.
`-EEXIST` from intent = someone already certified, proceed. `-EBUSY` =
another prover owns the attempt, do not issue a second P&A.

Slice arithmetic is already written at `v5_mount.c:2092-2094`:
`slice_cnt = ctx->log_node_count`, `slice_idx = dead_slot % log_node_count`.

**Step 4:** replace `mxfs_disklock_recovery_begin()` at
`v5_mount.c:2097` with `recovery_claim()`, and move claim+gate BEFORE
the replay at both dispatch sites (`xfs/xfs_mxfs_dlm.c:~42090` live work
fn, `~42509` mount barrier). `recovery_begin()` is now the DEPRECATED
path — it still writes a bare FENCED descriptor with `fence_kind` NONE,
which every gate refuses. That is D-FENCED-STAGE-WITHOUT-PROVEN-
EXCLUSION exactly; it dies when step 4 lands.

**Step 5:** blocker 3 — refuse RW clustered mount without a qualified
exclusion mechanism.
**Step 6:** blocker 6 — `mxfs_disklock_get_slot_node_id()`
(`disklock.c` ~2904 pre-edit) returns 0 for any non-ACTIVE record.

## Still deferred (unchanged from sess75)

`ctx->local_key = (uint64_t)node_id` (`dlm/scsipr.c:31`) — the PR key is
the bare node id with no incarnation. The descriptor binds the
incarnation (it lives in the victim's own sector, carries victim_epoch),
so this is not load-bearing for the gate, but it is a real weakness.
