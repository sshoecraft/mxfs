---
name: ccloop-c7ee71c6-sess388-geometry-win-keepdirty-refuted-durability-gate-needed
description: sess388: #474 nonblock-acquire root FIXED (0.19.38); AG-count geometry A/B PROVES pace root (64 AGs=all PASS laps1-3); keep-dirty REFUTED+reverted (c…
metadata:
  type: project
tags: [sess388, 474-fixed, geometry-agcount, keep-dirty-refuted, publication-durability, pace, fossil-next-unlinked]
---

## sess388 net result (build path 0.19.34 -> 0.19.38)

CURRENT TREE = 0.19.38, sv 8087F629696C553597F2D6A (byte-identical to 0.19.35:
the keep-dirty experiment was reverted). Rig LUN now **128 GiB, agcount=64**.

### WINS (measured, verified)
1. **#474 root PROVEN + FIXED.** The AIL-freeze/relfence wedge that killed
   1-3 nodes/lap was the NONBLOCK AG acquire parking on `pag_dlm_acquire_lock`
   (held by a sibling thread across its whole CAW poll) while the caller held
   ILOCK. Proof: a full hold/wait probe on `pag_dlm_lock` (mxfs_pag_dlm_lock/
   _unlock, P-AGMUTEX-*) fired ZERO times in a failing lap; disasm showed
   __mxfs_ag_dlm_lock+0x122 = `lea 0x248(%r14)` = pag_dlm_acquire_lock
   (pahole offset 584), NOT pag_dlm_lock (432); P-AILMIN owner stacks =
   rsync in xfs_inactive_truncate->__xfs_free_extent->mxfs_ag_dlm_trylock
   ->mutex_lock, >5s. FIX (0.19.35): nonblock arm does mutex_trylock on
   pag_dlm_acquire_lock and returns -EAGAIN (P-AGTRY-LOCALBUSY); the -488
   post-roll seam then drops ILOCKs. Clean laps show 0 wedges.
2. **Pace root = AG-count GEOMETRY.** agcount=25 on the 50 GiB LUN (32x64MB
   log slices force a 2 GiB log that must fit one AG -> agcount=device/2GiB).
   node_slot % agcount makes slots 25..31 collide with 0..6 -> 14 shared-AG
   nodes = EXACTLY the slow/failing set. GEOMETRY A/B (grow img to 128 GiB,
   SCST resync_size, fleet SCSI rescan + `multipathd resize map mpatha`,
   mkfs -n 32 -> agcount=64, NO lock-code change): rsync_paired laps 1-3 =
   all 32 nodes 14-27s PASS (was 34-60s+ FAIL, 11 never finished); posix_multi
   + dir_reuse_coherency PASS all laps. GPT-ruled: sizing rule agcount>=nodes
   (2x for perf class); ledger D-RSYNC-LAP-PACE-AG-SHARING-388.

### REFUTED + REVERTED (do not repeat)
- **keep-dirty at the P119 non-EX iflush skip is NET-NEGATIVE.** Returning
  -EAGAIN (keep the item dirty in the AIL) instead of laundering when an
  obligation is open:
  - broad form (pend!=dur, 0.19.36): kept FREED shells dirty (ifree final
    NL-mode core write has no converter) -> AIL-min froze -> test2/test24
    P-NOINO-RELFENCE-WEDGE within ONE lap.
  - PUBOB-only form (0.19.37): the armed unlink obligation is held at PR
    (mode=3); xfsaild can't write it (P119 skips non-EX) and only the
    release-path reldefer converter reaches it -> AIL froze on test32 ->
    foreign-replay TORN refusal -> FSWIDE quarantine bricked 31 nodes.
  LESSON (== GPT ruling-4 hazard): keeping an item dirty WITHOUT a guaranteed
  converter just relocates the wedge. The fix is the durability GATE, not a
  keep-dirty.

### REMAINING ROOT (the honest blocker)
- **Publication durability.** Two symptoms, one root: (a) fossil
  di_next_unlinked at iget -> P-IUNL-LOGSAME rename shutdown
  (D-FOSSIL-NEXT-UNLINKED-388); (b) aged-FS dirent_durability late publication
  (durable_loss=7-8, but ALL entries present on live re-check = visibility>4s,
  NOT data loss) because the AG-release audit defers 2x2s on unrepaired splits
  left by unlanded unlinks. FIX per GPT ruling iii: a sanctioned converter
  PINNED to the authority-release fence so the removal (di_next_unlinked=
  NULLAGINO) lands on the home block before reuse/authority release; plus (ii)
  store-at-iget (consult committed-next store at xfs_inode_from_disk, keyed by
  ino+gen). Build (ii) first (cheap, same-node case), then (iii) as a real
  release-barrier stage. This is NOT a one-liner.

### tools added
- tests/rsync_stall_stacks.sh — 10Hz /proc/<pid>/stack sampler for rsync/sync
  fleet-wide during ./run.sh; per-node blocking-edge histogram + slow-vs-fast.
- mxfs_pag_dlm_lock/_unlock forensics (agmutex_warn_ms param, P-AGMUTEX-*) in
  xfs_mxfs_dlm.c — harmless, in-tree; use to catch pag_dlm_lock hold/wait.

### NEXT SESSION START
Cluster is at 0.19.38/64 AGs, healthy (32/32 mounted+readable after the last
re-prep). Continue: build the publication durability gate (D-FOSSIL ruling
ii then iii); then a clean 3-lap d385 at 64 AGs incl. the aged dirent_durability
row; then the mkfs/mount agcount<nodes warnings. CRITERIA NOT MET.
