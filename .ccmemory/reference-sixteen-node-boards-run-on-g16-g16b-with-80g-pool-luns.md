---
name: reference-sixteen-node-boards-run-on-g16-g16b-with-80g-pool-luns
description: 16-node boards: groups g16 (test1-16) / g16b (test17-32), each needs an 80G pool LUN (lun12, lun13); they overlap g2/g4/g8 so run at another time.
metadata:
  type: reference
tags: [rig, 16-node, lun-pool, release]
---

Since 0.90.42 (2026-10-03) the release matrix includes 16/net/mesh/direct and 16/disk/caw/direct.

- Lab file (`~/.config/mxfslab/lab`) has `group g16=test1..16 g16b=test17..32`. They overlap g2/g4/g8 and g2b/g4b/g8b, so the 16-node pair cannot run side by side with the smaller boards: the release chain is `CLAIM=16 SIDE_BY_SIDE=0 POWER=1 tests/release_verify_chain.sh V` (16-node suites inside full_verify, then the 8/4/2 boards in one side-by-side step; LOWER is derived from the release matrix).
- run.sh asks the pool for an 80G LUN at 16 nodes ("no LUN of at least 80G is free" otherwise). The pool is 11 x 20G + 2 x 80G (lun12, lun13); creating the two 80G took / from 76% to 85% used against the preflight's 88% gate — there is no room for a third without deleting something.
- test29-32 are normally shut off; `scripts/lab_power.sh up group:g16b` brings them up in ~26 s and they are wired for pool LUNs.
- Both 16-node boards side by side (32 guests) took ~22 min wall; 16/disk/caw/direct was 31/31 on the first run.
- ag_strand_repair needs 32 rounds at 16 nodes: with 16 rounds, 5 of 16 nodes on net/mesh never released an AG and failed `strands=0` (harness coverage, not an FS fault).
- A filtered `./run.sh <cfg> --group g <row>` after a full board is refused ("cluster is prepped for ... you requested ..." with identical values); run single rows through `tests/board_4node_chain.sh <label> <cfg>:<row>@<group>`, which re-forms the cluster.
