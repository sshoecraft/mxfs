---
name: ccloop-c7ee71c6-sess93-FINAL-0.11.426-board-and-ledger
description: sess93 FINAL: 0.11.426 shipped, board 26 PASS/0 FAIL, ledger 24 open of 63 (14 critical). 6 closed + 7 filed this session. Where each remaining fence…
metadata:
  type: reference
tags: [sess93, FINAL, 0.11.426, board, ledger, handoff, dead_timeout_ms, zero-epoch]
---

# sess93 final state — 0.11.426

Build **0.11.426**, srcversion `04D5E19C04085CCF9837E1E`, deployed 32/caw.
Board: **26 PASS, 1 FLAKY (`scaling_curve`, pre-existing, PASSes now), 0 FAIL,
1 POLICY.** Ledger: **24 open of 63** — 14 critical, 4 high, 3 major, 2 minor,
1 unset.

Session net: 23 open → 24 open, via **6 closed and 7 filed**. The count went up
because wiring a dead safety mechanism exposed what the mechanism still lacks.

## Version-by-version

| ver | what |
|---|---|
| 0.11.422 | the prover (`v5_pr_fence_prove`), the gate + execution lease, both replay dispatch sites gated, `recovery_begin` retired, `recovery_slot_status`, takeover + fence-takeover wired |
| 0.11.423 | `mxfs_scsipr_exclusion_holds()` re-check at 4 points |
| 0.11.424 | log-ordering honesty fix |
| 0.11.425 | `RECOVERY_BLOCKED_FENCE` debugfs surface |
| 0.11.426 | `dead_timeout_ms` rename + `P238-FENCE-ZEROINC` |

## 0.11.426 in detail

**`lease_timeout_ms` → `dead_timeout_ms`.** The old name never configured the
lease: it feeds `mxfs_disklock_set_dead_timeout_ms()` and nothing else, while
the lease's own timeout is `MXFS_LEASE_TIMEOUT_DEFAULT_MS` (600000, lease.h)
which nothing ever writes. `lease_timeout_ms` remains a working deprecated
alias (`dead_timeout_ms` wins if both set) and logs the correction at load.
RIG-VERIFIED with `MXFS_EXTRA_MODARGS='lease_timeout_ms=16000'`:
`dead_timeout_ms=16000` resolved from the alias plus the deprecation warning.
**The deliberate decision the ledger asked for: the lease does NOT track it**
(sess43 — a rejoining node takes a new node_id, so peers hold the dead identity
for up to ten minutes; shortening that would make a rejoining node race its own
ghost).

**Zero-incarnation descriptors are now unconstructible.** `fence_intent()`
refuses `!inc_valid(cur->epoch)` with `P238-FENCE-ZEROINC`. Exhaustive audit:
there are exactly TWO writers of `desc.victim_epoch` in the tree
(`grep 'recov.desc.victim_epoch\s*=' dlm/`) — `recovery_begin` (retired) and
`fence_intent` (now guarded). Upstream, `v5_pr_fence_prove` refuses
`dead_epoch == 0` outright. Downstream,
`mxfs_recov_cert_proves_exclusion` has always required nonzero.

Also established: the ruling's feared "naked purge node N, epoch E with E=0"
**does not exist** — `mxfs_disklock_purge_node(ctx, node_id)` takes no epoch,
and purge-by-node-id cannot hit a reincarnation because ids are random per
mount (sess89).

## Where each fence-cluster defect stands now

| id | state |
|---|---|
| D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION | **CLOSED** |
| D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION | **CLOSED** |
| D-RECOVERY-TAKEOVER-UNREACHABLE | **CLOSED** |
| D-FENCE-RESERVATION-HEALTH-UNCHECKED | **CLOSED** |
| D-FENCE-BLOCKED-STATE-UNOBSERVABLE | **CLOSED** |
| D-PR-REGISTRATION-NOT-PERSISTENT-APTPL | **DISPROVED** (kernel sets APTPL; PTPL_A=1 on the rig) |
| D-RECOV-ZERO-EPOCH-DESCRIPTOR-AUTHORITY-UNPROVEN | OPEN — patched at the cause, needs the injection test |
| D-FENCED-VICTIM-MAY-REREGISTER | OPEN, CONFIRMED — needs the WE gate or fabric revocation |
| D-MIXED-VERSION-UNGATED-REPLAY | OPEN — needs a feature bit / negotiation decision |
| D-FENCE-CAPABILITY-UNVALIDATED-AT-MOUNT | OPEN — admission check, pieces exist |
| D-FENCE-CRASH-MATRIX-UNTESTED | OPEN — 11 injection points |
| D-PR-FENCE-PREEMPT-WITHOUT-ABORT | OPEN — only the in-flight-write test remains |

## The next three, in the order I would take them

1. **`D-FENCE-CAPABILITY-UNVALIDATED-AT-MOUNT`** — most of it is already
   written. `mxfs_scsipr_exclusion_holds()` does the reservation + key-view
   half; what is missing is a `PERSISTENT RESERVE IN / REPORT CAPABILITIES`
   PAL primitive (the block PR API does not expose it, so it needs a raw
   SCSI path like `mxfs_pal_scsi_read_fua_bdev` uses) to assert `PTPL_A`.
   **Ordering hazard to respect:** the FIRST mounter establishes the
   reservation, so a strict check must run AFTER the PR register/reserve step
   or it fails the first node. Decide the failure action per condition
   (refuse / read-only / single-node) — GPT requires it never be silent.
2. **`D-RECOV-ZERO-EPOCH...` closure test** — inject epoch 0 into a victim's
   ACTIVE record and assert `P238-FENCE-ZEROINC`. **Trap:** `hb_feature_crc`
   covers `fs_gen/node_id/EPOCH`, so a naive rewrite makes
   `hb_feature_state` read !OK and a DIFFERENT arm fires — reseal the feature
   crc or the probe measures the wrong refusal.
3. **`D-PR-FENCE-PREEMPT-WITHOUT-ABORT` item 4** — hold a large in-flight
   write on the victim (io_uring, or a stalled O_DIRECT write against a
   suspended device-mapper target), fence from a survivor, resume, assert the
   victim's bytes are NOT on the platter. `tests/pr_reregister_probe.sh`
   already produces the fenced-and-still-running state that no criterion had.

## Board hygiene note

`showstat.sh` now excludes `win_src=none` runs from the FLAKY tally at both jq
sites. That signature means the P8 scanners' producer (`dirent_durability`)
never ran in that boot, so they scanned ZERO lines: the FAIL is correct, but a
run that could not OBSERVE cannot CONVICT. **Never split a board into chunks
without keeping each scanner with its producer** — `dirent_durability` must
precede `dirent_publish_integrity` and `dirent_type_integrity`.
