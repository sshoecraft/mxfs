---
name: ccloop-c7ee71c6-sess71-preempt-abort-landed-and-GPT-evidence-protocol
description: sess71: PREEMPT AND ABORT + typed fence outcome LANDED (0.11.413, builds clean, not deployed). GPT: key-absence is NOT exclusion proof; losers must c…
metadata:
  type: reference
tags: [recovery, fencing, scsipr, critical, gpt-ruling, in-progress]
---

# sess71 — PREEMPT AND ABORT lands; GPT rules key-absence is not exclusion proof

Build **0.11.413**, srcversion `0EFFB0C5CD0031DDD412D3B`. `make modules` exit 0,
no new warnings. **NOT deployed, NOT boarded yet.**

## 1. THE RULE-5 CONSULT (re-issued from sess70; this time it returned in-window)

Given the CORRECTED premise (per-node PR ACTIVE, WE-RO reservation held, one key
per node, SCST iSCSI, dm-multipath 2 paths). GPT's binding points:

1. **`HARD_PR_ABSENT_RESERVED` is NOT sufficient.** Victim-key absence proves only
   that *new* conflicting writes are rejected. It does NOT prove (a) the
   already-accepted task set completed/aborted, (b) the victim cannot re-REGISTER,
   (c) every victim I_T nexus was covered.
2. **PR GENERATION does not close the re-registration race** — not atomic, not a
   lease. Use it as *dating/reconciliation* evidence only, never as the exclusion
   primitive. (That is exactly how 0.11.413 uses it.)
3. **Plain PREEMPT leaves an abort gap**, so a race LOSER observing "key absent" is
   claiming a guarantee the winner never obtained.
4. **Winner protocol:** serialize per victim/epoch -> one designated fencer issues
   0x05 -> waits for completion -> verifies status/reservation -> **durably
   publishes** {LUN/WWID, victim incarnation/key, completed-0x05, generation} where
   the victim cannot modify it -> only then may the elected node replay. Losers
   CONSUME that evidence; they may not re-derive it from the registration table.
5. **Never map a losing 0x05 RESERVATION CONFLICT to success.**
6. **One 0x05 covers both multipath registrations** if both carry the same victim
   key in the same PR domain (SPC removes ALL registrations matching the SARK).
   Verify afterwards that no descriptor with that key remains.
7. Use READ FULL STATUS (not READ KEYS) to audit per-path coverage: check
   all_tg_pt, relative target port, iSCSI TransportID, holder bit. **Kernel pr_ops
   does NOT expose READ FULL STATUS** — this is an out-of-band `sg_persist
   --in --read-full-status /dev/mapper/mpatha` rig validation, still OWED.
8. **0x05 can take long / time out** under deep queues. On timeout the outcome is
   UNKNOWN -> declare exclusion unproven. Never proceed to replay because a later
   status read shows the key absent.

## 2. WHAT SHIPPED IN 0.11.413

- `pal/pal.h` + `kern.c` + `user.c`: `mxfs_pal_scsi_pr_preempt(..., bool abort)`.
  RESERVATION CONFLICT now returns **-EBUSY, not 0** (the load-bearing lie).
- New `mxfs_pal_scsi_pr_read_reservation()` + `struct mxfs_pal_pr_reservation`.
- `mxfs_pal_scsi_pr_read_keys()` gained a `uint32_t *generation` out-param.
- `dlm/scsipr.h`: `enum mxfs_fence_kind` (explicit stable numbering — these go on
  disk in descriptor v2), `struct mxfs_fence_result`,
  `mxfs_fence_kind_proves_exclusion()` (true ONLY for PREEMPT_ABORT_DONE),
  `mxfs_fence_kind_name()`.
- `dlm/scsipr.c`: `mxfs_scsipr_fence_node()` takes `struct mxfs_fence_result *out`.
  Now: reads keys+gen -> classifies -> **requires a held WE-RO reservation**
  (new NO_RESERVATION refusal) -> issues **0x05** -> on success **re-reads keys and
  verifies victim gone + own key present** before claiming PREEMPT_ABORT_DONE.
- `dlm/v5_mount.c`: new `P236-FENCEKIND node=%u kind=%s(%d) proves_excl=%d gen=%u`
  log on every fence. TRANSITIONAL — the replay gates still consume the int.

## 3. NUMBER-SPACE TRAP (cost me a silent always-fail-closed bug; do not re-derive)

`sd_pr_read_reservation()` stores `scsi_pr_type_to_block(...)`, i.e. the **Linux
`enum pr_type`** where WE-RO is `PR_WRITE_EXCLUSIVE_REG_ONLY == 3`. The **SCSI wire**
value (what `sg_persist -i -r` prints, what user.c parses raw) is **5**. Comparing
the block-layer value against the wire constant never matches -> every fence would
have failed closed. `kern.c` now translates to the WIRE space; `MXFS_PAL_PR_TYPE_*`
is the single space the PAL contract exposes.

## 4. STRUCTURAL FACTS FOR THE NEXT STEP

- `struct mxfs_recov_body { struct mxfs_recov_desc desc; uint8_t pad[336]; }` —
  **336 bytes of free pad**, so extending the 80-byte descriptor to v2 is easy;
  just move bytes out of pad and update the BUILD_BUG_ONs in `dlm/disklock.h`
  (lines ~449, ~473) which assert `sizeof == 80`.
- **`recovery_begin()` is called at COMPLETION time**, `dlm/v5_mount.c:2079`, inside
  `mxfs_v5_dlm_recovery_complete()` — i.e. AFTER the replay already happened. GPT's
  protocol needs the evidence published BEFORE replay, so `recovery_begin()` must
  move to fence time (this is also sess66's outstanding ruling).
- **The fence winner and the replayer are different nodes in general.** Fence runs on
  every survivor that detects the death; the replayer is `lowest_live_slot`
  (`v5_dispatch_slice_recovery`). So once RACE_LOST stops returning success, the
  durable-evidence channel is **mandatory** — without it the elected replayer
  (usually a race loser) would never start and recovery would stall entirely.
  DO NOT gate the dispatch sites until the evidence publish/consume path exists.

## 5. NEXT STEPS, IN ORDER

1. Descriptor **v2**: add `victim_excl_kind`, `victim_excl_pr_gen`,
   `owner_excl_kind` (+ the victim key). Bump `MXFS_RECOV_DESC_VERSION`.
2. Move `recovery_begin()` to fence time; the fencer publishes the evidence.
3. Teach the fence path to **consume** a published descriptor: on RACE_LOST /
   KEY_ABSENT_UNPROVEN, read the victim slot's descriptor; if it shows
   PREEMPT_ABORT_DONE for the SAME victim_epoch, proceed as EVIDENCE_CONSUMED
   (add that kind); else refuse, durably, as RECOVERY_BLOCKED_NO_IO_EXCLUSION.
4. Only then gate `xfs/xfs_mxfs_dlm.c:42090` (live work fn), `:42509` (mount
   barrier) and the re-election sweep on `mxfs_fence_kind_proves_exclusion()`.
5. Rig: probe whether **6.8's dm-multipath implements `pr_read_reservation`** —
   6.19's `dm.c` does (`dm_pr_read_reservation`), 6.8 is unverified and the module
   runs on 6.8. If it returns -EOPNOTSUPP on `/dev/mapper/mpatha`, the new
   NO_RESERVATION refusal fires on EVERY fence and all recovery stops. **Check this
   before boarding.** Cheap check: deploy and grep `P-PR-NORESV` / `P236-FENCEKIND`.
6. Board 32/caw `fence_during_write` + `crash_consistency` (green baseline at
   0.11.412: 8/8 17s/60s and 204/204 86s/90s).

## 6. Rig state
32/32 VMs were running and mounted at sess70. 0.11.413 is built but NOT deployed —
the fleet still runs 0.11.412 (`2C85D70AD8070513B81D772`).
