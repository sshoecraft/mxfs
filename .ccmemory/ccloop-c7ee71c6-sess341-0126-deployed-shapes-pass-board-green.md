---
name: ccloop-c7ee71c6-sess341-0126-deployed-shapes-pass-board-green
description: sess341: 0.12.6 deployed 32/caw; shape4 genuine-TORN + shape1-under-load both PASS zero shutdowns (replayer alive = #91 verified); knob-off board GRE…
metadata:
  type: project
tags: [d-513, d-513b, rig-verification, 0.12.6, board-green]
---

# sess341 — 0.12.6 rig verification: shapes PASS, board green

Build: 0.12.6 sv FE2B7E1CF2A875536F20577 deployed to all 32 nodes (tools/ binaries were missing — `make -C tools` required before prep; prep 134s).

## Rig results (driver tests/d513_refusal_containment.sh, victim test6)
- **Shape 4** (genuine mid-replay TORN, TORN_ITEMS=3 VICTIM_LOAD=20 VICTIM_LOAD_MODE=inode): PASS. TORN rc=-117, verdict published durable (FSWIDE ag_mask=0x0 seq=1), P240-QUAR-IMPORT on 31/31, ZERO shutdowns/withdraws, 31/31 mounted **including replayer test1's live mount — the #91 D-FOREIGN-SHADOW-UNWIND-HOST-SHUTDOWN-513B fix verified under injection** (satisfies sess328 Q2(b)).
- **Shape 1 under load** (POLICY, same load env): PASS. AG-MASK ag_mask=0x1 published+imported 31/31, zero shutdowns, zero dirty-cancel LOCAL residue (Q5/Q3).
- **Knob-off regression board 32/caw: GREEN — 24 PASS, 0 FAIL** (3 FLAKY historical, open_defects POLICY red). fence_during_write 32/32 8/8 checks (natural fence + replay clean), crash_consistency 32/32 204/204, dir_reuse_coherency 32/32 72/72 — the three cells red since sess319 all recovered. Fence-class board suspension (sess320 ruling Q3) effectively LIFTED — containment now rig-verified.

Board ran in batches (budget sums <560s each) with prep_cluster re-prep between quarantine-leaving tests. Each d513 run leaves a durable quarantine → re-prep mandatory after.

## Ledger updated (both entries, sess341 items appended)
- #90 D-...-CLUSTERWIDE-SUICIDE-513: REMAINING = pre-rig checks 1-4+5+6 (forged wrong-shape/unknown-kind/-EPROTO outcome sectors; fswide abort preserves unrelated late death; lone-node torn mount publishes + -EIO; AG-scope hb sector NOT zeroed by cohort_complete).
- #91: REMAINING = injected replay-write IO error arm (foreign provenance must not shut down b_mount; live-mount IO error must still shut down).

## Next
Forge-sector checks need the outcome record layout (disklock.c:3593 recov_outcome_fill, validation 386-446) + write path to LUN (from a node via dd to the mxfs device hb sector, or clyde-side backing store). Lone-node torn mount = single-node cluster + shape-4 knob + mount. After those: #91 write-error injection arm (likely new knob), then dispositions for #90/#91.
