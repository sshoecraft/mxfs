---
name: design-a-fence-kind-that-proves-only-admission-needs-a-declared-retirement-basis-and-refusal-is-the-default
description: DESIGN (0.89.13, Astra s80 ruling): documenting an unwitnessed premise is not fixing it — the production path must fail closed, defaulting to refusal…
metadata:
  type: project
---

## The ruling (Astra, session 80, on D-BOOT-SUCCESSION-…-NO-TASK-RETIREMENT-WITNESS)

0.89.12 had written the premise down: a comment in `v5_boot_succession_consume`, a
sentence in the P238 log line, a rig declaration in `data/rigs.json`, and a
`tests/lib/rig.sh` accessor that aborts a HARNESS on an undeclared rig. The ruling
on that package was blunt:

> **Harness gating does not constrain a mounted filesystem.** The remaining defect
> is not "the module does not read rigs.json" — it is that *the production
> recovery path can authorize replay without establishing, or enforcing a
> justified dependency for, the retirement of previously accepted victim writes*.

Points that changed the design:

1. **Default to refusal.** "A configuration lacking a required storage guarantee is
   not a complete configuration for this recovery method." An integrity fix may
   deliberately sacrifice a recovery route's availability; you do not owe an
   equally available replacement before closing an unsafe-authorization defect.
2. **A per-LUN qualified profile, never a global `trust_retirement=1`.** Scope it to
   the target identity, the firmware/configuration and the LUN, and define what
   invalidates the qualification.
3. **An assertion is not a witness.** Record in the certificate WHICH basis was
   used — "target operation completed" and "deployment contract relied upon" are
   different claims and must never collapse into "proved".
4. **The contract must state the ORDERING, not a vague property.** Not "this target
   eventually retires tasks on nexus loss" but: every command accepted from the
   lost nexus has completed or been aborted, effects ordered before subsequent
   I/O, BEFORE the registration-absence event the fence keys on. And the event's
   CAUSE matters — arbitrary registration absence is not evidence of nexus-loss
   cleanup.
5. **A negative workload measurement characterises; it does not establish the
   boundary.** "No late change was observed in these blocks over this interval" is
   not "every accepted command had retired at the cut". Reads see logical
   contents through caches, not the platter.
6. **There IS one standard active retirement primitive**: a successfully completed
   LOGICAL UNIT RESET aborts outstanding tasks for the LU across I_T nexuses, and
   unlike a key-directed PREEMPT AND ABORT its scope does not depend on the
   victim's registration still existing. It is not a drop-in line inside a fence
   function — it aborts the survivors' I/O too, so it needs the live cluster's
   submissions quiesced, the completion bound to the LUN and fencing epoch, and
   no admission gap around it. A locally-failed reset, a TCP disconnect, or entry
   into Linux error handling is NOT that witness.

## What 0.89.13 implements

- `struct mxfs_pal_target_id` + `mxfs_pal_scsi_target_id()` (`pal/pal.h`,
  `pal/linux/kern.c` via `scsi_vpd_lun_id()` and the scan-time INQUIRY fields;
  `pal/linux/user.c` issues the two INQUIRYs itself and mirrors the kernel's
  designator preference so one contract resolves identically in both builds).
- `enum mxfs_retire_basis` {NONE, TARGET_OP, QUALIFIED_CONTRACT} and
  `mxfs_scsipr_retire_basis_nexus_loss()` (`dlm/scsipr.[ch]`), comparing a
  five-field contract `<vendor>:<product>:<revision>:<lun designator>:<clause>`
  against what the LUN reports. The revision is in the contract deliberately: a
  firmware upgrade stops the match, so the qualification must be re-measured.
- Module parameter `target_retire_contract`, default empty → refuse. The refusal
  is `P238-BOOTSUCC-NO-RETIRE-BASIS` and the attempt stays KEY_ABSENT_UNPROVEN.
- The rig ships its declaration through `run.sh` → `tests/setup/prep_node.sh`,
  which also resolves it from `data/rigs.json` when a caller says nothing.

## What is NOT closed by it

Permitting the QNAP profile on the strength of three probe laps fixes
*unqualified default use* and leaves *the assurance of the permitted profile*
open. The module cannot detect a target that violates the contract; the tests
verify enforcement of the contract boundary, not the truth of the assertion.
Do not erase that residual by calling it configuration.
