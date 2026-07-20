---
name: sess52-residual-is-dir-fork-revert-DABUF-shutdown-cascade
description: sess52: option B (broad-skip+acq-wait, C16AAEAC) FIXES tcp_dlm livelock+slowness → 3/5 reliable. Residual = dir-fork-revert {EXTENTS,nx=0} DABUF shut…
metadata:
  type: project
---

## sess52 — option B works; the REAL residual is the dir-fork-revert DABUF shutdown

### OPTION B (build C16AAEAC, KEEP) — broad release-skip + acquire-side LOCKED-wait — WORKS.
`MXFS_EXTRA_MODARGS='dir_pr_release_fast=2 dir_acq_lockwait=60'`. Reliability loop = **3/5 full 17/17**
(runs 1,4,5 PASS; 2,3 FAIL). The tcp_dlm_scaling LIVELOCK is FIXED (EDEADLK counts dropped
hundreds→~4; the run-3 tcp_dlm_scaling FAIL was a SHUTDOWN, not a livelock). dir_reuse_coherency is
FASTER (round 18@3min vs baseline round 24@6min) and PASSES. acquire-wait (LOCKED-WAIT) fired 0× —
the LOCKED race is rare; the wait is a cheap insurance backstop. See [[sess52-FIX-broad-skip-plus-acquire-lockwait-optB]].

### THE RESIDUAL (both run-2 and run-3 failures) = dir-inode FORK REVERT -> DABUF-hole SHUTDOWN -> CASCADE.
NOT a livelock, NOT the broad-skip (PROVEN: every P51-REL skip on the corrupted inodes was a
self-demote or EX-drain that baseline param=1 ALSO does; the only broad-only skip was ino=128 AFTER
the corruption). It is the PRE-EXISTING sess45/sess77/sess80 DABUF-map-hole family (xfs_da_btree.c:2814
`!(flags & XFS_DABUF_MAP_HOLE_OK)`), intermittent (~40%).

**Mechanism (node1-LOCAL; node2 had ZERO NXSHRINK):** node1's reload reverts its in-core dir fork to
the invalid `{di_format=EXTENTS/BTREE, nx=0, size>0}` state (format says data blocks, extent map
empty). Then xfs_create/xfs_remove maps a dir block -> xfs_dabuf_map HOLE -> EFSCORRUPTED -> the
already-DIRTY xfs_trans_cancel -> `Corruption of in-memory data (0x8) ... Shutting down`. node1 FS down
-> fence_during_write+fault_netpartition+soak+tcp_dlm_scaling all FAIL (cascade). Whatever create/rm-
heavy test runs at corruption time is the one that "fails first".

**Two sub-cases (decisive P62/P133 forensics):**
- **RUN 2 (subdir reuse, GEN MISMATCH):** ino=8928577, reload `incore_gen=3555416468` vs
  `disk_gen=65196620`, disk freed (mode=0). The reload ADOPTED a freed DIFFERENT-incarnation image
  in-place -> P-RELOAD-IOPS-REWIRE new_mode=00 -> {EXTENTS,nx=0} -> create DABUF. The existing sess116
  P116 guard ADOPTS a disk-free image when clean+NL (assumes peer freed THIS inode) — but a gen
  mismatch proves it's a DIFFERENT incarnation. **FIX (build CE9B0FD4, UNVERIFIED): P52-RELOAD-
  FREEDREUSE-DIR-SKIP** at xfs_mxfs_dlm.c ~6841 (before P116): if disk mode S_IFMT==0 && in-core
  S_ISDIR && disk di_gen != in-core i_generation -> keep live in-core dir, don't adopt, i_dlm_stale=false.
- **RUN 3 (ROOT dir ino=128, SAME incarnation gen=0):** `P32-IFLUSH-NXSHRINK ino=128 incore_nx=0
  disk_nx=1 incore_size=312 disk_size=4096 relflush=0 dlm_mode=5 comm=rm` — node1 (EX) flushed a
  shortform in-core over a block on-disk image (root reverted block->shortform), orphaning the data
  block; a LATER xfs_remove (68s after) mapped it -> DABUF. P62 for ino=128 showed no clean shrink
  signature (murkier; possibly a legit block->shortform conversion that orphaned the block = sess32/33
  leaf-vs-data tear). **NOT yet fixed.** Candidate: extend P33-DIRGROW-REVERT-SKIP (xfs_mxfs_dlm.c
  ~6940, requires mem_nx>=2 + dg_inflight) to keep in-core when i_dlm_mode==EX even if clean (under
  EX the disk can't be legitimately smaller); OR the GPT Step-4 fork-flush fence (below).

### PRIOR GPT-5.5 DESIGN (memoized, for the broader fix): [[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]]
+ [[sess-tcp-FENCE-correct-location-iflush-cluster-not-iflush]]. Core: "no stale in-core fork may ever
reach the on-disk dinode." Step 4 = fence the fork flush in **xfs_iflush_cluster** (xfs_inode.c:5393,
the `continue`-skip loop — NOT xfs_iflush which force-shuts-down on error) unless validated under the
current DLM epoch. The P32-IFLUSH-NXSHRINK detector (xfs_inode.c:4852) is the right SIGNAL but is
log-only. Step 4 UNIMPLEMENTED. Existing guards P32/P33/P34D/P62/P74/P78/P116/P133 all miss these.

### NEXT (in progress at relay): reliability loop on CE9B0FD4 (option B + run-2 guard),
/tmp/sess52_optB2.log. If run-2 fixed but run-3 persists (~4/5) -> add the run-3 EX-keep / iflush-cluster
fence. If 5/5 -> make dir_pr_release_fast=2 + dir_acq_lockwait=60 the code DEFAULTS, rebuild, re-verify
PLAIN `./run.sh 2 tcp`, THEN write marker. Reliability harness: tests/tcp/reliability_loop.sh (now dumps
/tmp/relrun_${r}_node{1,2}.dmesg on PARTIAL).
