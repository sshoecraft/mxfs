---
name: ccloop-c7ee71c6-sess93-OUTCOME-6-closed-blocked-state-live
description: sess93 OUTCOME: 6 defects closed (5 FIXED AND VERIFIED, 1 DISPROVED), 7 filed, 0.11.425 shipped. Fence-evidence channel live + blocked-state debugfs…
metadata:
  type: reference
tags: [sess93, OUTCOME, 0.11.425, fence-certificate, recovery-blocked, debugfs, ledger, board]
---

# sess93 outcome — the fence-evidence campaign, start to finish

Build **0.11.425**, srcversion `D0163D2220C5CC2063611BA`. Full 32/caw board
**26 PASS / 0 FAIL** under unchanged acceptance criteria (2 pre-existing FLAKY
cells, `scaling_curve` + `dir_reuse_coherency`, both PASS now).

Ledger: **23 open → 24 open**. That is 6 closed and 7 filed — the count went up
because wiring the mechanism exposed what the mechanism still lacks, which is
the honest direction.

## Closed

| id | disposition |
|---|---|
| D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION | FIXED AND VERIFIED |
| D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION | FIXED AND VERIFIED |
| D-RECOVERY-TAKEOVER-UNREACHABLE | FIXED AND VERIFIED |
| D-FENCE-RESERVATION-HEALTH-UNCHECKED | FIXED AND VERIFIED |
| D-FENCE-BLOCKED-STATE-UNOBSERVABLE | FIXED AND VERIFIED |
| D-PR-REGISTRATION-NOT-PERSISTENT-APTPL | **DISPROVED** (my own filing, same session) |

## Filed (from the two RULE-5 rulings)

`D-FENCED-VICTIM-MAY-REREGISTER` (critical, CONFIRMED by measurement),
`D-MIXED-VERSION-UNGATED-REPLAY` (critical),
`D-FENCE-CAPABILITY-UNVALIDATED-AT-MOUNT` (high),
`D-FENCE-CRASH-MATRIX-UNTESTED` (high),
plus the two that closed the same session.

## Versions

- **0.11.422** — the prover (`v5_pr_fence_prove`), the gate
  (`mxfs_v5_dlm_recovery_acquire` + execution lease held across the replay),
  both replay dispatch sites gated, `recovery_begin` retired,
  `recovery_slot_status` classifier, takeover + fence-takeover wired.
- **0.11.423** — `mxfs_scsipr_exclusion_holds()` re-check at four points.
- **0.11.424** — log-ordering honesty fix (an earlier cut announced
  "this slice may now be replayed" and revoked it microseconds later).
- **0.11.425** — `RECOVERY_BLOCKED_FENCE` at
  `/sys/kernel/debug/mxfs/<dev>/recovery_blocked`.

## The four probes, all reusable, all in `tests/`

| probe | proves |
|---|---|
| `fence_evidence_probe.sh` | 1 prover / 1 P&A / 1 certificate / consumed by a DIFFERENT node / published |
| `recov_takeover_doublefault_probe.sh` | kill victim, catch the owner claiming, kill the owner → a third node takes over and finishes |
| `pr_reregister_probe.sh` | a fenced victim CAN re-register and write (the critical finding) |
| `excl_lapse_probe.sh` | a returned victim is detected, the recovery STOPS, and the block is surfaced in debugfs |

## The blocked-state record, as it reads on the rig

```
slot=3 reason=EXCL_LAPSED rc=-1
  victim      node=3772707794 incarnation=11921365376053614700 key=0xe0def3d2
  fence       kind=KEY_ABSENT_UNPROVEN(6) resv_type=0x05 pr_gen=3068 term=0
  ownership   prover=0 recovery_owner=0
  timing      blocked_for_ms=92822 attempts=4 last_attempt_ms_ago=2243
  ACTION      the fenced victim is REGISTERED AGAIN and can write to this
              LUN right now.  Stop it, or fence it at the target, before
              this slice can be recovered.
```

`first_ms` is stamped once and KEPT: how long a slice has been unrecoverable is
the number an operator acts on, and restamping per retry would hide it. The
kernel-API half lives in `xfs/xfs_mxfs_dlm.c`, not `dlm/`, so the DLM layer
still builds user-mode (architectural invariant 4).

## Two method lessons worth more than the code

**1. A grep of MXFS's source is not evidence about SCSI-level behaviour.**
I filed `D-PR-REGISTRATION-NOT-PERSISTENT-APTPL` because `grep -i aptpl`
returned nothing in the MXFS tree. The bit is set one layer down:
`/src/linux` `drivers/scsi/sd.c` `sd_pr_register()` ends with
`sd_pr_out_command(..., (1 << 0) /* APTPL */)`. The rig confirmed it three ways
— `REPORT CAPABILITIES` says `PTPL_A: 1`, SCST exports
`pr_file_name=/var/lib/scst/pr/mxfs` and that file holds the registrant table,
and `pr_state` records each registrant against its **stable iSCSI IQN**, not
just the random per-mount key. Check the target's REPORT CAPABILITIES before
asserting anything about what MXFS does or does not request.

**2. Never split a board across chunks without the producers.** Running the P8
scanners (`dirent_publish_integrity`, `dirent_type_integrity`) in a chunk that
did not contain `dirent_durability` gave `window=0 win_src=none` on 13 nodes and
two red cells that were nothing to do with the build. The FAIL was correct; the
FLAKY attribution to MXFS was not. `showstat.sh` now excludes `win_src=none`
runs from the flake tally at both jq sites — a run that could not OBSERVE cannot
CONVICT.

## Where the fencing story actually stands

The certificate is now produced, consumed, gated on, taken over, and re-checked
— and it is honest about what it proves. What it proves is a **completed
eviction event**, not continuing exclusion: `pr_reregister_probe.sh` measured a
preempted node re-registering and writing. GPT ruled the only sound in-band fix
is a temporary single-holder WRITE EXCLUSIVE gate (needs a cluster-wide
freeze/drain protocol MXFS does not have) and the only fully sound fix is
target/fabric revocation (outside a kernel module). Both are on
`D-FENCED-VICTIM-MAY-REREGISTER` with the ruling's six binding requirements.
