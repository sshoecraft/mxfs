---
name: ccloop-c7ee71c6-sess75-descriptor-v2-wire-and-protogen-landed
description: sess75: descriptor v2 fence-certificate WIRE + FENCING intent stage + MXFS_PROTO_GEN 1→2 landed (0.11.415, builds clean). C-side impl NOT written yet.
metadata:
  type: reference
tags: [fencing, recovery-descriptor, wire-format, version-gate, 0.11.415, in-progress]
---

# sess75 — descriptor v2 wire + version gate landed; C side still to write

Continues the sess74 fence-evidence-channel ruling (see
`ccloop-c7ee71c6-sess74-GPT-ruling-fence-evidence-channel-6-blockers`).
Unblocks ledger #8/#9/#10 once complete.

**Version 0.11.415. `make modules` and `make tools` both exit 0.**

## ⚠️ DO NOT DEPLOY THIS BUILD AS-IS — it is a half-landed protocol change

The wire and the gate are in; the behaviour is not. Nothing calls the new
API yet, so the fence path still publishes NO certificate while the
descriptor version says v2. Finish the C side first.

**Also: the second `make modules` returned the SAME srcversion
(`C7336ABC002DF02F219BC17`) after editing `include/mxfs/mxfs_super.h`.**
That is suspicious given the memory `Make clean before rebuild for
multi-file changes`. **Do `make clean && make modules` before trusting that
MXFS_PROTO_GEN=2 is actually in the .ko**, and re-check srcversion.

## LANDED

### 1. `MXFS_PROTO_GEN` 1 → 2 (`include/mxfs/mxfs_super.h`) — blocker 5

This is the HARD PREREQUISITE, not bookkeeping. sess74 refuted "per-slot
version mismatch is fail-closed": a v1 replayer REPLAYS FIRST and consults
the descriptor only at completion, so it would replay a v2-fenced slice on
the old ungated path. The three C7 enforcement layers (XFS sb incompat bit,
envelope `cluster_proto_gen`, HB feature block + vergate fence) now exclude
v1 recovery code from the cluster outright.

**Consequence: a v1-formatted volume will REFUSE TO MOUNT.** The rig's
`MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` re-mkfses, so it is fine
there; `chk_mxfs --upgrade-protogate` is the offline path otherwise.

### 2. `MXFS_RECOV_DESC_VERSION` 1 → 2, descriptor 80 B → **120 B**

`mxfs_recov_body.pad` 336 → 296. Still overlays the evict ring, still 512 B
record, no mkfs change. All static asserts pass (120 B, cert at 76, crc last
at 116, record 512, mepoch still at 456).

The certificate — written ONCE in FENCING→FENCED, immutable thereafter:

```
 76 fence_kind         u16   enum mxfs_fence_kind proved
 78 fence_resv_type    u16   MXFS_PAL_PR_TYPE_* at the verify
 80 fence_victim_key   u64   the PR key the P&A removed
 88 fence_prover_epoch u64
 96 fence_stamp_ms     u64
104 fence_prover_node  u32   never 0 once certified
108 fence_pr_gen       u32   DIAGNOSTIC ONLY — never a gate
112 fence_term         u32   FENCING-ATTEMPT term (≠ owner_term)
116 crc32c             u32
```

`recov_desc_crc()` needed no change — it already covers
`offsetof(crc32c)` bytes, so it picks the certificate up automatically.

### 3. Stage ladder renumbered, FENCING intent inserted

`NONE=0, FENCING=1, FENCED=2, IMAGES_REPLAYED=3, OBLIGATIONS_DONE=4,
GRANTS_RELEASED=5`. Safe ONLY because of the PROTO_GEN bump. FENCING
authorises NOTHING (rule-1 amendment).

### 4. `MXFS_RECOV_OWNER_NONE 0` — UNOWNED as a distinct state

Plus `struct mxfs_recov_fence_auth` — the FENCING-ATTEMPT lease tuple, kept
as a SEPARATE TYPE from `mxfs_recov_auth` (the execution lease) so
presenting one where the other is required cannot type-check. Carries
`victim_key` observed BEFORE the P&A.

### 5. API declared in `dlm/disklock.h` (definitions NOT written)

- `mxfs_disklock_recovery_fence_intent()` → GUARD{FENCING}, prover-owned,
  durable BEFORE the P&A. Returns `-EEXIST` if already certified,
  `-EBUSY` if another prover holds a live attempt lease.
- `mxfs_disklock_recovery_fence_certify()` → FENCING→FENCED, writes the
  certificate and RELEASES ownership in the SAME CAS (leaves it UNOWNED).
  Must refuse any result that does not prove exclusion.
- `mxfs_disklock_recovery_claim()` → claim an UNOWNED certified descriptor
  as execution owner; whole-descriptor CAS, revalidate the certificate,
  `owner_term` → 1 atomically. Must be IDEMPOTENT when already ours (so
  `recovery_complete` can re-claim to re-acquire its auth).
- `mxfs_disklock_recovery_replay_authorized(ctx, slot, victim, epoch, auth,
  site)` → THE CENTRAL GATE (blocker 4).
- `mxfs_recov_cert_proves_exclusion(d, fs_gen, slot, victim, epoch, &why)` →
  validation against an already-read snapshot, no second I/O.

`dlm/disklock.c` now `#include "scsipr.h"` for
`mxfs_fence_kind_proves_exclusion()`.

## NEXT — in this order

1. **`make clean && make modules`**, confirm srcversion actually moves.
2. Write the five function bodies in `dlm/disklock.c` (insert after
   `mxfs_disklock_recovery_takeover`, which ends ~line 2575). Model them on
   the existing `recovery_begin` / `recovery_takeover`: read_prio → decide →
   `recov_desc_seal` → `recov_cas_durable`.
   Full validation list for the gate (sess74 Q4, ALL of them): version
   exact, crc, record identity triple, `victim_node`, `victim_epoch`,
   `victim_fs_gen`, `victim_slot == slot`, `slice_count != 0 &&
   slice_idx < slice_count`, `recovery_gen != 0`, stage ≥ FENCED,
   `mxfs_fence_kind_proves_exclusion(fence_kind)`,
   `fence_resv_type == MXFS_PAL_PR_TYPE_WR_EX_RO`, `fence_victim_key`
   binding, `fence_prover_node != 0`, not QUARANTINED, and the owner tuple
   after claim. Also validate descriptor-vs-header internally:
   `d->victim_node == hb->node_id && d->victim_epoch == hb->epoch`.
3. **Wire the prover inside `v5_pr_fence_dead_node_rc()`**
   (`dlm/v5_mount.c:694`) — intent → P&A → certify — NOT at the four call
   sites. Reason: whichever node's P&A wins FIRST consumes the evidence
   (the victim key is then absent for everyone else), so a fence path that
   skips the intent/certify pair destroys the slice's only route to
   recovery. That includes `v5_vergate_cb` (v5_mount.c:790).
   A live victim can clobber the intent with its own ACTIVE heartbeat
   write — that is fine and fail-closed: the certify CAS then fails.
4. Replace `mxfs_disklock_recovery_begin()` in
   `mxfs_v5_dlm_recovery_complete()` (`dlm/v5_mount.c:2097`) with
   `recovery_claim()`, and move the claim+gate BEFORE the replay at both
   dispatch sites (`xfs/xfs_mxfs_dlm.c:~42090` live work fn,
   `~42509` mount barrier), plus the IMAGES_REPLAYED transition,
   destructive manifest work, and sector zeroing.
5. Blocker 3: refuse RW clustered mount without a qualified exclusion
   mechanism (UNSUPPORTED / ADVISORY_TOPOLOGY may not count as fenced).
6. Blocker 6: `mxfs_disklock_get_slot_node_id()` (`dlm/disklock.c` ~2904)
   returns 0 for any non-ACTIVE record — needs a descriptor-aware resolver.

## Deferred, explicitly (not one of the six blockers)

`ctx->local_key = (uint64_t)node_id` (`dlm/scsipr.c:31`) — the PR key is the
bare node id and carries NO incarnation. sess74's certificate notes want it
derived/validated against `{fs_gen, victim_node, victim_epoch}` so a stale
event cannot certify removal of a recycled numeric key. The descriptor
binds the incarnation (it lives in the victim's own sector, carries
`victim_epoch`, and the sector is not reusable until CONSUMABLE), so this
is not load-bearing for the gate — but it is a real weakness and the fence
caller would need the victim epoch to fix it.
