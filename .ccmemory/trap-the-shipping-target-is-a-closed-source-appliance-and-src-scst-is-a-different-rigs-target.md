---
name: trap-the-shipping-target-is-a-closed-source-appliance-and-src-scst-is-a-different-rigs-target
description: TRAP (s75): /src/scst is the OLD rig's target. data/rigs.json declares the 2/tcp LUN as a QNAP appliance, so target-source arguments and every dm-del…
metadata:
  type: feedback
tags: [rig, scsi-pr, measurement-integrity, qnap]
---

# The target whose source is on this host is not the target under test

`/src/scst` holds SCST 3.11.0-pre+caw-abort-reclaim.5, it builds the `scst.ko`
in `/lib/modules/$(uname -r)/extra`, and reading it answers SCSI-target
questions precisely. **It is not the target the 2-node TCP rig uses.**

`data/rigs.json` declares that rig's LUN as a **QNAP TS-453 Pro iSCSI target**
(`naa.6e843b6393a5a6ed918bd4f4fdb8e7d6`, both nodes see it as `/dev/sda`,
`host_image: null` because no file on clyde backs it). The nodes' own dmesg
says it too: `scsi 3:0:0:0: Direct-Access QNAP iSCSI Storage 4.0`. clyde's
preflight even reports "SCST not loaded".

## What this invalidates

- **Any argument from SCST's source about target behaviour on this rig.** It is
  background, never a contract. Session 75 read SCST's PR path and found a real
  ordering guarantee (PR IN and PR OUT share `dev->dev_pr_mutex`, and PREEMPT
  AND ABORT does its `wait_for_completion(&pr_aborting_cmpl)` inside that
  window, so a concurrent READ KEYS cannot see the removal before the abort
  drains) — true, and irrelevant to the shipping configuration.
- **Every experiment that instruments the target.**
  `tests/fence_inflight/inflight_ab.sh` holds the victim's write with `dm-delay`
  under the target's backing store and times the PR completion from an ftrace
  probe on `scst_cmd_done_pr_preempt`. Both need owning the target, so neither
  runs against the appliance.
- The tree's measured "SA 0x05 blocks 12.3 s and the victim's write lands
  126 us before the PR completes, against SA 0x04 returning in 0.2 ms with the
  write landing 12 s after" (quoted in `pal/linux/kern.c`) is an **SCST**
  measurement.

## What is left

Measure from the initiators only, or use a target-enforced primitive. And
whatever a measurement establishes on the appliance is a *qualified* contract
for that target, firmware and session topology — requalify when any of them
change, exactly as the `pr_registration_on_session_loss` declaration in
`data/rigs.json` already requires for the purge behaviour.
