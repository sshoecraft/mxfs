---
name: ccloop-c7ee71c6-sess92-fence-evidence-wiring-inventory
description: sess92: the complete line-verified wiring inventory for the dead fence-certificate channel (it is 7 dead entry points, not 5) + the STALE ledger text…
metadata:
  type: reference
tags: [sess92, disklock, fence-certificate, dead-code, wiring-inventory, D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION, D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION, D-RECOVERY-TAKEOVER-UNREACHABLE, D-PR-FENCE-PREEMPT-WITHOUT-ABORT, ledger-stale]
---

# sess92 — wiring the fence-evidence channel: the complete recon

Verified against 0.11.421 (`C2230B2B7487F93ED23EFF8`). Nothing written yet;
this is the inventory so the next session does not re-derive it.

## Why this cluster and not the ledger's #1

The ledger orders `D-FOREIGN-REPLAY-UNGATED-IMAGES` step 5.2 first, but that
step is **report-only by its own recon** — the defect does not close until 5.4+.
The dead-code finding is the blocking mechanism for **three** criticals at once
(`D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION`,
`D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION`, `D-RECOVERY-TAKEOVER-UNREACHABLE`),
so it is the higher-leverage target. Stated in the ledger, per the state hook's
"unless you state why not".

## CORRECTION to sess91: it is SEVEN dead entry points, not five

sess91's table missed two, and they are the most important two:

| symbol | callers |
|---|---|
| `mxfs_disklock_recovery_replay_authorized` (**THE CENTRAL GATE**, `disklock.c:4021`) | **0** |
| `mxfs_recov_cert_proves_exclusion` (`disklock.c:3367`) | only `:3963` (claim) + `:4084` (the gate) — **both themselves dead** |

Plus sess91's five: `recovery_takeover`, `recovery_claim`,
`recovery_fence_intent`, `recovery_fence_certify`, `recovery_fence_takeover`.

**The entire fence-certificate + exclusion-gate subsystem — the sess74/75/76
campaign, its on-disk wire, and its proto_gen bump — has never executed.**
Only `recovery_begin` (1 caller) and `recovery_advance` (2) are live.

## STALE LEDGER TEXT — fix this before anything else

`D-PR-FENCE-PREEMPT-WITHOUT-ABORT` still reads *"NOT YET FIXED … No code written
yet."* **That is wrong.** `dlm/scsipr.c:465` is
`mxfs_scsipr_preempt(ctx, victim_key, true)` — abort=true — landed sess71
(0.11.413) and RIG-VERIFIED sess73 on 0.11.414:
`P236-FENCEKIND kind=PREEMPT_ABORT_DONE(16) proves_excl=1`, 1 winner / 30 losers.
Only the entry's `next` item 4 is genuinely outstanding: *a test that proves the
in-flight write is excluded*, not merely that recovery still passes.

## The live flow today (0.11.421)

```
death → v5_handle_node_death (v5_mount.c:1434)
        v5_pr_fence_dead_node()          ← fres.kind COMPUTED, LOGGED, DISCARDED
        resolve dead_slot  (AFTER the fence, :1455)
        v5_start_slice_recovery → mark_recovery_pending (IN-MEMORY ONLY)
                                → v5_dispatch_slice_recovery (:1280)
                                     lowest_live_slot == me → dead_node_notify_fn
   … replay runs, ungated …
     v5_complete_slice_recovery (:2150)
        recovery_begin()   ← writes GUARD stage=FENCED DIRECTLY, fence_kind=NONE
        advance(IMAGES_REPLAYED) → CAW purge → flush → advance(GRANTS_RELEASED)
```

The descriptor is written **after** the replay. It is a post-hoc record, not the
pre-replay authority the design assumes.

## The three fence call sites (all of `v5_pr_fence_dead_node_rc`)

1. `v5_mount.c:1445` — `v5_handle_node_death`, live path, BOTH detectors
   (monitor passes real slot+epoch; lease passes `-1, 0`).
2. `v5_mount.c:1728` — `v5_settle_resolve` (`:1619`), used by BOTH the mount
   barrier (`mxfs_v5_dlm_mount_recovery_cohort`, `:1891`) and the post-mount
   settle. Has `slot`, `was` (node) and `ctx->mount_stale_epoch[slot]` in hand.
3. (`v5_pr_fence_dead_node` at `:765` is just the bool wrapper of #1/#2.)

Both real sites therefore have **slot + node + epoch** available at fence time.

## The two replay dispatch sites to gate

- `xfs/xfs_mxfs_dlm.c:42090` — live foreign-replay work fn.
- `xfs/xfs_mxfs_dlm.c:42509` — mount barrier, step (c), inline per-slot rounds.
  Its step (b) DOES fence, via `mount_recovery_cohort` → `v5_settle_resolve`.
- Plus the re-election sweep, `v5_mount.c:1309-1323`.

## Two facts that make the wiring tractable

- **`victim_key == (uint64_t)victim_node`** (`scsipr.c:298`). The key is known a
  priori, so `fence_intent` can be made durable BEFORE `fence_node` is called —
  no need to split READ KEYS out of `mxfs_scsipr_fence_node`.
- **A GUARD slot is NOT claimable.** `mxfs_disklock_claim_slot` (`:4631`)
  explicitly skips `flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD` at
  `disklock.c:4707` ("sess43: NEVER claim a slot carrying a recovery GUARD").
  So publishing the intent/certificate at FENCE time — long before replay —
  does **not** open the slot to a joiner. This was the main hazard I expected
  to block the reordering; it does not.

## Open design questions for the RULE-5 consult (not yet asked)

1. The 30 losers all call the fence. Only the winner may certify; the losers
   must consume. Confirm `fence_intent`'s CAS is the right single-winner gate
   and that a loser arriving at `KEY_ABSENT_UNPROVEN` must simply wait.
2. Availability policy when no certificate can exist — `ctx->scsipr == NULL`,
   `UNSUPPORTED`, `ADVISORY_TOPOLOGY`, `NO_RESERVATION`. Gating means recovery
   BLOCKS on such rigs. The sess69 ruling says block; needs an explicit,
   actionable blocked state + escape hatch, and this rig is PR-active (sess70)
   so the 32/caw board should stay green.
3. The lease detector passes `victim_epoch = 0`; the certificate must bind an
   incarnation. The victim's own sector is still ACTIVE at fence time and
   carries its real epoch in the header — is reading it there the right source?
   (sess91 measured the lease arm has never fired on this rig.)
4. Mount-barrier cohort victims are from a PREVIOUS boot. Same treatment?
