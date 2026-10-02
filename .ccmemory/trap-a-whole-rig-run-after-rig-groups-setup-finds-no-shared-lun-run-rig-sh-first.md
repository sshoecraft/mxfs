---
name: trap-a-whole-rig-run-after-rig-groups-setup-finds-no-shared-lun-run-rig-sh-first
description: SUPERSEDED 2026-10-01: rig_groups.sh and :shared are gone; every run borrows a pool LUN. See reference-test-luns-come-from-the-pool-tools-lun-pool-sh.
metadata:
  type: feedback
tags: [rig, pool, superseded]
---

SUPERSEDED 2026-10-01. scripts/rig_groups.sh and the :shared target no longer exist; run.sh and tests/board_4node_chain.sh borrow pool LUNs (tools/lun_pool.sh), so a whole-rig run after group runs no longer needs a rewiring step. See reference-test-luns-come-from-the-pool-tools-lun-pool-sh.

The general lesson that still holds: binding a node to one target logs it out of every other, so whatever bound it last decides what it sees. The pool's alloc rebinding is the only thing that does this now.
