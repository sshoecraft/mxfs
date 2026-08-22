---
name: sess384-whole-cluster-loss-chain-361-474-ungated-513
description: sess384: ONE measured 32-node incident chains #361 -> #474A -> ungated-images refusal -> FSWIDE quarantine -> 0/32 nodes usable; the board called it…
metadata:
  type: project
tags: [incident, rule6, 361, 474, 513, 374, 32caw]
---

## The incident — 2026-08-20T20:32:39–20:35:54Z, 32/caw, 0.19.6 sv 2D543FD0F9F9B833BCA747F

Ran during `./run.sh 32 caw rsync_paired crash_consistency`. Ended with **0 of 32
nodes usable**: `ls /mnt/shared` -> Input/output error on all 32, mounts still
in /proc/mounts. Verified 18 minutes later at 20:50Z.

The board line for it was:

    FAIL rsync_paired (nodes_pass=0/32 states:NO_TERMINAL_RECORD=32 hostload=20.30) [60s/60s]

and the state hook plus the #374 ledger entry both told the next session that
NO_TERMINAL_RECORD is a capture failure and NOT to diagnose the filesystem from
it. That guidance was actively wrong here and cost a session.

## The chain (each step measured, dmesg -T, all 32 nodes swept)

1. **20:32:39–44 — D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361.**
   test10, test14, test2: `Corruption of in-memory data (0x8) detected at
   xfs_trans_cancel+0x15e/0x170 (xfs/xfs_trans.c:1088). Shutting down filesystem.`
   test29 in the same window: `Metadata I/O Error at xfs_inactive_ifree+0x566`.
2. **20:32:54–20:33:31 — D-NOINO-RELFENCE-AIL-FREEZE-474 arm A.** Thirteen more
   (test1,4,9,12,15,16,17,18,19,20,21,22,27), all identical:
   `P-NOINO-RELFENCE-WEDGE ino=<n> — shutdown (un-durable no-inode lock NOT
   released)` then `Metadata I/O Error (0x1) detected at
   mxfs_dlm_noino_bast_work_fn+0x19b/0x1b0 (xfs/xfs_mxfs_dlm.c:21274)`.
   Preceded on each by a storm of `P-NOINO-LISTDRAIN ... fence stalled`.
   **17 of 32 dead — the exact 17/32 signature #361 was opened on.**
3. **Election churn.** Survivors log `not elected for dead-slice replay (lowest
   live slot 0, local 23)` while slot 0 (test1) is *already dead*; the first
   elected replayer then died mid-recovery and test26 (node 1957942981, slot 3)
   was **re-elected for 15 pending slices at once**.
4. **D-FOREIGN-REPLAY-UNGATED-IMAGES.** Replay of 10 slices refused:
   `P227-FR-TORN-UNPUBLISHED slot <n>: replay refused 2-3 committed unauthorized
   image(s) — the victim's partial home-writeback cannot be ruled out, so
   publishing would publish a torn platter` -> `POLICY-REFUSED, rc=-117
   refused=2 malformed=0 dvalid=1`.
5. **Terminal verdicts published.** 8 were `domain=AG-MASK` (slots 1,5,6,8,11,
   17,21,27). **2 were `domain=FSWIDE`** — slot 25 (victim 915164091,
   digest=c3b40687) and slot 29 (victim 758930932, digest=2538e319).
6. **D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513.** Every survivor imported
   them: `P241-RECOV-TERMINAL-IMPORT` -> `P240-QUAR-IMPORT ... fswide=1
   ag_mask=0x0 phase=ADMITTED`. An FSWIDE quarantine EIOs the WHOLE filesystem,
   so the **15 nodes that never shut down were bricked by the import**.

## Why this matters beyond the four defects

A single rsync workload took a healthy 32-node cluster to total loss in ~3
minutes, and every layer downstream of the first shutdown made it worse rather
than containing it. The refusal path is fail-closed by design, but fail-closed
at FSWIDE scope on a 32-node cluster is indistinguishable from destroying the
filesystem.

## Forensics

`/tmp/mxfs_sess384_incident/{test1,2,3,10,14,25,29}.dmesg.gz` — full rings.
Node-id map for that incarnation: test1=4169258251 test2=1930990524
test3=1865586340 test4=758930932 test9=1326882800 test10=1579870540
test12=542699815 test14=3524163776 test15=2312625666 test16=4175245570
test17=2368676697 test18=3742979371 test19=915164091 test20=1067309737
test21=3469223756 test22=3566929934 test26=1957942981 test27=2590001356
test29=1221788529.
