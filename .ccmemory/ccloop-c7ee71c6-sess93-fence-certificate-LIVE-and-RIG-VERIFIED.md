---
name: ccloop-c7ee71c6-sess93-fence-certificate-LIVE-and-RIG-VERIFIED
description: sess93: the fence-evidence channel is WIRED and RIG-VERIFIED on 0.11.422 — 1 prover / 1 certificate / consumed by a DIFFERENT node / recovery publish…
metadata:
  type: reference
tags: [sess93, MEASURED, rig, fence-certificate, disklock, 0.11.422, D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION, D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION, D-RECOVERY-TAKEOVER-UNREACHABLE]
---

# sess93 — the fence-evidence channel is LIVE, and MEASURED on the 32-node rig

Build **0.11.422**, srcversion `E2D57B3CB50F847A936ACC8`, deployed to all 32
nodes (prep 71 s). Probe: `tests/fence_evidence_probe.sh test32 150`.

## The measurement (no injection — just kill a node and read the logs)

```
=== fence-evidence probe: slot=6 node=2836646140 ===
  intent (P236-FENCE-INTENT)         nodes=1  test3
  P&A issued (P236-FENCEKIND)        nodes=1  test3
  certified (P236-FENCE-CERTIFIED)   nodes=1  test3
  lease taken (P238-RECOV-LEASE)     nodes=1  test1     <-- DIFFERENT NODE
  published (P163-RECOVERY-COMPLETE) nodes=1  test1
  UNGATED completes (must be 0)      nodes=0
  gate refusals                      nodes=0
PROBE PASS
```

The certificate itself:

```
P236-FENCE-INTENT slot=6 victim=2836646140 epoch=5529438801257918979
    key=2836646140 slice=2/4 prover=1096797821 term=1
P236-FENCEKIND node=2836646140 kind=PREEMPT_ABORT_DONE(16) proves_excl=1
    gen=2187 rc=0 [prover slot=6 term=1]
P236-FENCE-CERTIFIED slot=6 victim=2836646140 epoch=5529438801257918979
    kind=PREEMPT_ABORT_DONE resv=0x05 key=2836646140 pr_gen=2187
    prover=1096797821 term=1 — exclusion is PROVED and durable
P238-RECOV-LEASE slot=6 node=2836646140 inc=5529438801257918979 stage=2
    — execution lease acquired against a CERTIFIED fence
P163-RECOVERY-COMPLETE slot=6 node=2836646140
```

`stage=2` on the lease is MXFS_RECOV_STAGE_FENCED — test1 CLAIMED a descriptor
somebody else certified; it did not create one. That is the whole point.

**test3 proved, test1 consumed.** That prover-vs-replayer split is exactly the
sess73 asymmetry (`lowest_live_slot` elects independently of who wins the PR
race) that made the certificate necessary, and it reproduced on the first run.

The other 30 survivors logged `P238-FENCE-DONE` — "already certified by another
prover; issuing no second PREEMPT AND ABORT". **Before 0.11.422 all 31 issued
one.** That is the direct evidence for the sess93 Q1 single-winner ruling.

## What changed in 0.11.422

`dlm/v5_mount.c`
- **`v5_pr_fence_prove()`** — new. The PROVER: `fence_intent` (durable) →
  `mxfs_scsipr_fence_node` (P&A) → `fence_certify`. Only the intent-CAS winner
  issues the P&A. Three-valued return: 0 = a certificate exists, >0 = none
  (caller records the death but the slice is unfenceable, and
  `v5_settle_resolve` routes it to residue so the sess58 item-6A mount gate
  still aborts cleanly), <0 = hard stop (self-fence, or no observed
  incarnation → `-ENODATA`).
- **`v5_handle_node_death`** — slot is now resolved BEFORE the fence (the
  intent lives in the victim's sector, so the prover needs it). Slot-owning
  deaths go through the prover; the no-slot fallback keeps the bare fence.
  A detector with `epoch == 0` (lease-only) fences nothing and marks nothing:
  an epoch-0 pending marker would make `v5_start_slice_recovery`'s is_pending
  guard swallow the monitor's later REAL detection (GPT Q3).
- **`v5_settle_resolve`** — mount barrier / settle now calls the prover with
  `slot` + `ctx->mount_stale_epoch[slot]` (a genuinely observed incarnation
  from `confirm_dead_mask`). `-ENODATA` joins `-ESTALE` as terminal in the
  retry loop.
- **`mxfs_v5_dlm_recovery_acquire()`** — new, THE GATE. Claims the certified
  descriptor once and parks the auth in `ctx->recov_auth[slot]`
  (`recov_auth_mask`), held across replay + completion per GPT correction 1.
  `-EBUSY` + owner proved dead → `recovery_takeover` (**closes
  D-RECOVERY-TAKEOVER-UNREACHABLE's mechanism**). `-EPERM` + prover proved
  dead → `recovery_fence_takeover` then re-run the prover, which resumes our
  own attempt and issues a NEW P&A. `-EPERM` otherwise is the WAIT state —
  there is no timeout after which replay becomes allowed.
- **`mxfs_v5_dlm_recovery_release()`** — drops the cached tuple; called after
  publication (the sector is zeroed, so the lease no longer exists).
- **`recovery_complete`** — `recovery_begin` REPLACED by
  `recovery_acquire` + `replay_authorized(&auth, "complete-start")` before the
  irreversible CAW purge.

`dlm/disklock.c` / `.h`
- **`mxfs_disklock_recovery_slot_status()`** — new, read-only classifier.
  `recovery_claim` collapses "already published", "victim rejoined and
  self-recovered", and "never fenced" all into -ENOENT, and the correct
  response differs completely (retire the marker vs refuse and keep it).
  Returns CONSUMABLE / SUPERSEDED / UNFENCED / FOREIGN / DESCRIPTOR /
  UNREADABLE, using recovery_begin's own supersession predicate unweakened.
- **`mxfs_disklock_recovery_begin()` RETIRED** — refuses at entry with
  `P238-RECOV-BEGIN-RETIRED` / -EPROTO. It minted `FENCED` + `fence_kind=NONE`,
  which is the uncertified descriptor every gate must refuse (GPT correction 3).
  Body retained below the return for reference.

`xfs/xfs_mxfs_dlm.c`
- Both replay dispatch sites gated on `mxfs_v5_dlm_recovery_acquire()`:
  `mxfs_dlm_foreign_replay_work_fn` (re-arms via `mxfs_reap_sched`, tag
  `freplay-fence`) and the mount barrier's inline round.

## Entry-point census after the change

`recovery_claim`, `recovery_takeover`, `fence_intent`, `fence_certify`,
`fence_takeover`, `replay_authorized`, `cert_proves_exclusion` — **all now
have live callers.** `recovery_begin` has none, deliberately.

## What is NOT done (from the sess93 ruling's release unit)

- No explicit durable/observable `RECOVERY_BLOCKED_FENCE` state — only log
  lines (P238-FENCE-UNPROVEN / -NOPR / -UNRECORDED / -COMPLETE-UNFENCED).
- No admission-time validation that PR/WE-RO/persistence can actually produce
  evidence (GPT Q2), and no APTPL request+verify (Q4).
- Mixed-version safety (A): old binaries still replay ungated; existing
  uncertified FENCED/NONE records are refused by the gate but not quarantined.
- Anti-rejoin enforcement (B), reservation-health-after-certify (C),
  exact-incarnation liveness for the takeovers (E), the crash matrix (G).
- Full board on 0.11.422 not yet run at the time this note was written.
