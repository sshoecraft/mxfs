---
name: ccloop-c7ee71c6-sess33-icluster-phaseA-board-green-one-wedge
description: ICLUSTER knob=1 on 0.11.290/291: 11-criterion board GREEN (fairness ghost-dirents gone); ONE unattributed conv-worker wedge; ctx-punt shipped but 0 e…
metadata:
  type: project
---

# sess33 — ICLUSTER Phase A: board green at knob=1, one wedge to root

## Why this campaign
GPT closure ruling for D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY (recorded
in the ledger entry): the mask family is verified containment but closure
requires ownership as coarse as the 16KB write unit. ICLUSTER routing
(`mxfs.icluster_dlm`, load-time 0444, built ccloop-72513a13, inert 274
builds) is mechanism 1. 16KB storage CAW is NOT possible (slot CAW=512B).

## Phase A results (0.11.290 then 291, 32/caw, MXFS_EXTRA_MODARGS='icluster_dlm=1')
GREEN at knob=1: dlm_fairness 17s (**the historical knob=1 ghost-dirent
residual from ccloop-72513a13 sess4 is GONE** — fixed by intervening dirent
work), strong 4s, posix 6-7s, cache 28s, mmap 4s, membership 6s, zsl 26s,
fence 21s, crash 69s, dir_reuse 106s (slightly FASTER than knob=0's
110-112s), dd 65s ×2. ex_close_release_ms already 0 (old trigger off).

## THE WEDGE (once, on 290-knob1, unattributed — top priority on recurrence)
dir_reuse FAIL 0/32 NO_TERMINAL_RECORD=32 → crash BLOCK "test15
sync-wedged". Live stacks: kworker `xfs-conv/dm-1 xfs_end_io` AND
`mxfs-ino-bast` worker BOTH D in folio_wait_writeback ←
filemap_write_and_wait ← `mxfs_dlm_bast_process+0x5ed`; syncs piled on
sync_inodes_sb. Shape = conv worker running bast_process waits on folios
whose writeback-clearing ioends are in ITS OWN merged batch (no other
worker can complete them). **The call chain between xfs_end_io and
bast_process was NOT captured** (truncated trace) — hypothesis 1
(trans-free drain `mxfs_trans_drain_inode_unlocks` inline) got a guard in
291 (P152 punt extended: `xfs_task_in_ioend()||xfs_task_in_writepages()`
→ dwork, why=ioend-ctx, bastq_src=17) but **0 engagements fleet-wide** —
wrong chain or the window simply didn't recur (5 knob=1 laps since, all
green, 0 hung-task warns). 291 passes are therefore UNATTRIBUTED to the
guard; the guard stays (costless, correct for its chain).
**NEXT OCCURRENCE: before ANY re-prep run `echo w > /proc/sysrq-trigger`
on the wedged node and pull `dmesg | tail -300` — the frames between
xfs_end_io and mxfs_dlm_bast_process are the whole question.** Candidate
chains to check against the full stack: iop_release→xfs_iunlock→ilock_end
inline arm (journal_info already NULL at that point!), the iclus coverage
sweep entering bast_process for a swept sibling, dip-parent site 29210.

## Pace note (RULE 0, honest)
One dd lap on 291-knob1 hit 240s/240s (PASS-at-box) with ZERO hung-task
warns and normal late_ok → distributed slowness. Host loadavg was 15-19
(game server ~350% + tesseract bursts 215%). Next dd lap: 65s. Watch —
if 240s recurs at low load it's a knob=1 tail-latency defect.

## Phase B/C remaining
B: root the wedge (recurrence capture above), soak knob=1. C: GPT closure
requirements 2-4 for the publish defect (publisher coverage proof,
forced-collision verification with incarnation/epoch oracle, deterministic
oracle for the merge remainder) — then default-ON decision + ledger close.
Deploy line: `MXFS_FORCE_PREP=1 MXFS_EXTRA_MODARGS='icluster_dlm=1'
./run.sh 32 caw prep_cluster` (knob is load-time 0444).
