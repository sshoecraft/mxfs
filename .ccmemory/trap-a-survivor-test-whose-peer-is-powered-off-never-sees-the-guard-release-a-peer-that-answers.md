---
name: trap-a-survivor-test-whose-peer-is-powered-off-never-sees-the-guard-release-a-peer-that-answers
description: TRAP (0.90.68): rig self-restart-test kept the victim OFF during the survivor's mount; on pve1 the peer was UP without DRBD, the guard released it mi…
metadata:
  type: feedback
tags: [drbd, testing, trap]
---

The rig's self-restart-test (held and released) passed on 0.90.68: the survivor excluded its dead peer at boot and mounted alone. On the physical pair the same path failed: pve2 was UP with DRBD unconfigured (broken install), so 65 s after pve1 excluded it, pve1's guard got a clean ssh answer ("DRBD Unconfigured, no MXFS mount, refcnt 0") and RELEASED it while pve1's own survivor mount was still in its startup fence. With no inhibit and no Connected Secondary peer the fence could prove nothing (P-DRBD-STARTUP-FENCE-UNPROVEN after 120 s) and the mount was refused; the survivor path then gave up (unit failed).

**Why:** a peer that is powered off answers nothing, so every release path that needs the peer's answer is dead code in that test. Real failures leave the peer up but broken far more often than off.

**How to apply:** for any survivor/exclusion test, run a variant where the excluded peer is UP and answering but without the service (unit masked, DRBD down) during the survivor's whole recovery, not only powered off. Same family as trap-a-death-test-whose-victim-dies-between-swaps-never-tests-a-lock-held-across-death. Defect: D-DRBD-GUARD-RELEASES-THE-PEER-UNDER-THE-SURVIVORS-OWN-MOUNT (fix in 0.90.69: own_mount_pending holds the release until this node's boot program has mounted).
