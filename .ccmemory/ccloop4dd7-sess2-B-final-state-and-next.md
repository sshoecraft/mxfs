---
name: ccloop4dd7-sess2-B-final-state-and-next
description: sess2 STOP: v0.11.53 CFF7AD86 built NOT deployed; 8 fixes landed (list inside); next = deploy, fresh-FS rounds; remaining flavors = dir/AGI lineage f…
metadata:
  type: project
---

# ccloop-4dd7 sess2 STOP-POINT (relay boundary)

## Tree state: v0.11.53 srcversion CFF7AD866A1FE9E74191273 — BUILT, NOT YET DEPLOYED
Deploy first thing: `MXFS_FORCE_PREP=1 ./run.sh 2 tcp prep_cluster` (~55s, mkfs-fresh), then rounds:
`N1=test1 N2=test2 MXFS_PASS=/tmp/.mxfs_pass scripts/agi_wedge_repro.sh 180 24` (watch window now DUR+60,
but ALWAYS verify logs: grep -cE 'Corruption|Internal error|unrecoverable' per node + mount check).

## Fixes landed sess2 (all uncommitted; on top of sess1's six)
1. P116 handoff-adopt arm (xfs_mxfs_dlm.c ~18102) — PROVEN + firing/rescuing.
2. SETSIZE-REVALIDATE-MISS (xfs_iops.c xfs_setattr_size) — PROVEN + firing/rescuing.
3. IFREE-REVALIDATE-SKIP 2 arms (xfs_inode.c xfs_inactive_ifree): mode==0 adopted-free +
   bucket-empty-peer-freeing (coherent AGI read under held AG DLM). Arm1 proven; arm2 landed after
   round-2 ino 8388737 (disk mode live + bucket empty = peer free undestaged) — needs live verify.
4. xfs_lock_two_inodes ABBA breaker (i_dlm_tries* fields; bounded m1 + drop-m0-backoff-retry;
   P-ABBA-BACKOFF) — FIRING (48×/round) and rescuing.
5. mxfs_dialloc_reserve_ino (xfs_ialloc.c, both selection points): bounded child-ino EX reservation
   BEFORE inobt RMW; -EAGAIN skips AG while clean; P-DIALLOC-RESV-{BUSY,DIRTY}. GPT-reviewed design
   (invariant: no new blocking DLM acquire after trans dirty). Firing (RESV lines) + deadlock-3 shape
   not seen since.
6. P-IUNLINK-RECYCLE-HEAL (xfs_inode_util.c xfs_iunlink_insert_inode): leaked prior-life bucket
   entry (head==our agino) now ADOPTED as the insert instead of detect-only -EFSCORRUPTED in dirty
   droplink (round-3 v0.11.52 ino 0x80008e shutdown). NEEDS VERIFY.
7. agi_wedge_repro.sh watch window DUR+8→DUR+60 (false "no escalation" fixed).
8. Instrumentation: P145-ALLOC (xfs_alloc_fixup_trees), P148-DIRSHRINK (xfs_dir2_shrink_inode with
   dir_gen/loaded_gen/acq_epoch/valid_epoch stamps), P34C-DIRGROW + same stamps.

## Round stats on v0.11.50-52: ~50-60% clean; each failure a DIFFERENT flavor (whack-a-mole is
converging — inobt double-free family GONE since fix 1-3+5; liveness deadlocks GONE since 4+5).

## REMAINING WALL — dir/AGI lineage family (RULE-6 OPEN)
- R3@v0.11.51: dir 131 block0 + new LEAF both mapped to SAME physical block (AG1 bno 27 =
  fsb 0x4001b = daddr 2093440) → xfs_dir3_leaf_read verifier -117. Suspected: stale-base
  xfs_dir2_shrink_inode freed live block (peer's lineage) → bnobt handed it out twice.
  P145-ALLOC/P148/P34C stamps now in place to name the poison step on next firing.
- R3@v0.11.52: ino 0x80008e durable on-disk dinode garbage (P-SFV-FAIL disk_differs=0) 1min into a
  round + leaked AGI bucket entry → agi-recycle -117 (now healed by fix 6, but the GARBAGE DINODE
  producer is unfound — could be residue from same-FS earlier rounds; use FRESH-FS rounds
  (prep every round) for attribution).
- GPT flagged: live-peer-holder on a "free" candidate ino = allocation-coherency invariant hole
  (the unpublished-create / divergent-inobt window) — instrument idle-stale vs active-old-incarnation
  vs current-incarnation when P-DIALLOC-RESV-BUSY fires.

## Open items queue (task #3): DLM timeout policy (E: release cached grants + clean EAGAIN before
shutdown), dead-peer journal recovery, AGI Phase-B, pve2 flush_workqueue wedge, xfs_lock_inodes
(rename N-inode) same backoff treatment, strikeout re-arm hole (moot if cycles prevented, verify).
Then: ≥5 consecutive clean fresh-FS rounds → deadshell_repro 8/8 → full ./run.sh 2 tcp suite.

## GPT consult (full text in transcript ~12:05): phase plan = observability (op phase states),
create fix (done as #5), truncate AG preflight (NOT done — truncate still ino→AG inside dirty trans;
next structural piece if deadlocks recur), generalized clean lockset API, C detector later.
