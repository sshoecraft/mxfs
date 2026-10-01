---
name: trap-a-whole-rig-run-after-rig-groups-setup-finds-no-shared-lun-run-rig-sh-first
description: TRAP (0.90.37): rig_groups.sh setup logs every node into its group target only; a whole-rig board then fails in 1 s (no rig tag). Run scripts/rig.sh…
metadata:
  type: feedback
tags: [rig, rig-groups, release-chain, scst]
---

## Symptom

`tests/board_4node_chain.sh` (and the release chain's window laps through it) exits rc=1 in about a second with: `net-mesh-direct: the rig tag could not be resolved from /dev/disk/by-path/ip-192.168.120.1:3260-iscsi-iqn.2026-05.local.mxfs:shared-lun-0; no yardstick, no board`. No board log is written.

## Cause

`scripts/rig_groups.sh setup` logs each node out of everything and into its own group's target only (by design, for isolation). After group work (g2/g4/g8), test1..8 no longer see `:shared`.

## Fix

`scripts/rig.sh <N>/net/mesh/direct` (or the configuration about to run) cleans all 32 nodes' plumbing and logs test1..N into `:shared` on the single portal; it verifies every node sees the by-path device. Measured 14 s for 8 nodes. Images are preserved. Re-run `scripts/rig_groups.sh setup` before going back to group runs.
