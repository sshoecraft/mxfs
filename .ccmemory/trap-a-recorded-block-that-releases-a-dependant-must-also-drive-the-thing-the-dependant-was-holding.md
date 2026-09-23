---
name: trap-a-recorded-block-that-releases-a-dependant-must-also-drive-the-thing-the-dependant-was-holding
description: TRAP (D-SOLE-SURVIVOR-GATE-NEVER-RESTORED, 0.87.12): the terminal refusal released the gate dependant but nothing then called the restore; WE(1) stay…
metadata:
  type: feedback
tags: [fencing, scsipr, gate, terminal, design]
---

# Releasing a dependency is not the same as driving what it was holding

0.82.6 said "a terminal refusal now releases the dependant as publication does" — and it did: `v5_gate_dep_clear(..., "refused-terminal")` ran at both terminal publication sites. But the gate restore was only ever CALLED from the recovery-complete publication and from the PR worker re-driving a restore already marked due. A terminal verdict did neither, and the platter sweep (correctly) exempts a quarantined descriptor, so nothing owed the gate and nothing lifted it. Measured 2/tcp (s610h, 0.84.24; s51term_ctl, 0.87.11): WE(1) held by the survivor for its lifetime, the returned victim refused at its PR-ledger publish (P-PRKEY-PUBLISHED rc=-52) on every mount, a two-node cluster at one node.

The shape to look for: a state machine where "X no longer holds Y" is implemented as clearing a bit, while "attempt Y" is triggered from a different event. Every path that clears the LAST holder of a bit must either attempt the action or mark it due for a worker that attempts it. Grep for the set of `*_clear`/`release` sites and check each one against the set of sites that call the action.

## The fix (0.87.12) and the two hazards the consult added

`v5_gate_terminal_release` marks the restore due under the gate lock FIRST (progress never depends on the inline call reaching the conversion; the PR worker re-drives a due restore every 2 s) and then runs the same checked primitive as every other restore. Design consult (Astra, 2026-09-18):

1. A gate installed for a victim whose key the target already purged rests on "key absent", which proves nothing about a revived incarnation that re-registers under WE(1) (REGISTER is always allowed; only writes are excluded). Converting to WE-AR would authorise it at once. So the owed sweep now reports quarantined gate-kind descriptors with their victim keys and the restore re-checks each with a fresh synchronous bracket, converting only on a proven ABSENT (`P-PR-GATE-RESTORE-VICTIM-PRESENT` otherwise). Measured: P-PR-KEY-STATE-SYNC state=ABSENT why=absent-proven 19 ms after the verdict, WE-AR restored 1 ms later.
2. The joiner must install the terminal refusal synchronously, not on a later monitor pass. Already true: the mount barrier imports the verdict (P241-RECOV-TERMINAL-IMPORT before 'Ending clean mount') and the registration-time outcome scan validates it again (P241-RECOV-TERMINAL-SCAN) before any filesystem op; the returned victim's create in its old directory fails EIO (P240-QUAR-NSOP-REFUSE).

Harness arm: `MODE=terminal_rejoin tests/d_intents_2tcp_open_efi.sh` (obl_complete_enable=0 on the survivor forces the terminal verdict on the fix build; EXPECT=refuse is the control). The LUN carries a quarantined slice afterwards: `MXFS_FORCE_PREP=1 ./run.sh 2 tcp prep_cluster` before anything else.
