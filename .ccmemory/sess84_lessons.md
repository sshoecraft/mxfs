---
name: sess84_lessons
description: "sess84 (ccloop, 2026-06-04) — cache_coherency still FAIL (only failing criterion; 11/12 PASS). PROVEN via P-SFDIR-RELOAD/FASTEX cross-node timeline that the shortform-dir lost-update = the LAST committer's dirent (always node1/lowest-id, which adds last) is durably lost: it commits count=N, but disk stays count=N-1 and a later reload reverts its own in-core. NOT concurrent-EX (CAW-EXCL-VIOLATION=0, CAW-DUP-SLOT inode=0). Two fix attempts on the BAST-release durable-flush path did NOT fix it (build 83522A1B still loses node1). Detector build 564A41EF (P-SFDIR-REVERT + reg-only early-out gate) built, NOT yet deployed/run."
metadata:
  node_type: memory
  type: project
  originSessionId: 2051855d-d301-4626-951d-406c0a2cbfe2
---

# sess84 lessons (ccloop run 29df431e, 2026-06-04)

## STATE: only cache_coherency FAILs (passed=2 failed=2 of 4). 11/12 criteria PASS.
rsync_paired 103%, single_node 104%, all robustness/tooling green. The ship gate
is blocked SOLELY by cache_coherency. Build on nodes at session end: **83522A1B**
(durable-flush-for-dirs + reg-only early-out + P-SFDIR-FASTEX + inode dup-slot
detector). Local tree built to **564A41EF** (adds P-SFDIR-REVERT detector) — NOT
deployed.

## PROVEN ROOT (RULE-4, cross-node P-SFDIR timeline, NOT guessed)
cross_visibility (4 nodes each `echo hi > nodeN.txt` in ONE shared dir
`.mxfs_test/cross_visibility`, which is SHORTFORM/LOCAL = dirents inline in dinode):
- **node1.txt is DURABLY lost from ALL nodes incl test1's own view, every run.**
  Same for the barrier dirs (`.mxfs_barriers/<name>/nodeN`, also shortform) → node1's
  marker missing → peers wait the full 120s barrier timeout twice → the "240s slow"
  symptom is a CONSEQUENCE of the lost-update, not separate.
- Timeline (P-SFDIR-RELOAD logs the disk dirent set at each EX-acquire reload;
  P-SFDIR-FASTEX = new sess84 always-on detector at the dir-EX FAST-PATH re-grant,
  dumps the cached fork used as RMW base): the nodes form a clean RMW chain
  {nodeA}→{nodeA,nodeB}→{nodeA,nodeB,nodeC} and **node1 (test1) ALWAYS adds LAST**:
  it does mode=5 (EX) ACQ-SLOW, reloads count=3 CORRECTLY (sees the other 3), adds
  node1 → count=4 in-core, commits — **but disk stays count=3 and node1's count=4 is
  never durable; a later test1 reload (ACQ-SLOW) re-reads stale count=3 and reverts
  its OWN in-core count=4 → node1 loses its own file.** It is the LAST committer that
  loses (node1 happens to always be last; lowest-id finishes the chain).
- **REFUTED concurrent-EX**: zero CAW-EXCL-VIOLATION (single-slot) AND zero
  CAW-DUP-SLOT for INODE locks (I extended the sess47 dup-slot detector from AG-only
  to INODE at dlm_caw.c ~L1307 — fired 0×). So the CAW inode mutual-exclusion is
  SOUND; the loss is pure WRITE-side durability of the last committer's dinode.

## MECHANISM (the CIL-window early-break)
The shortform dirent add commits into the CIL. For a brief window the inode log item
is NOT yet in the AIL and NOT pinned, yet the in-place dinode on disk is STALE. Two
places assume "!in_ail && !pinned ⇒ durable" and skip flushing during that window:
1. bast_process dir drain loop (xfs_mxfs_dlm.c ~L1171): `mxfs_dir_data_durable`
   returns TRUE for LOCAL (no data blocks), so break cond = `!in_ail && !pinned` →
   iteration-0 early break → release with dinode stale.
2. The reg-file deterministic durable block (~L1378, sess79) has an early-out
   (`!in_ail && pin==0 → skip`) with the SAME CIL-window hole.

## FIXES TRIED (did NOT fix — build 83522A1B still loses node1)
- Extended the L1378 deterministic inode-cluster flush (log_force→imap_to_bp→
  iflush_cluster→bwrite→blkdev_flush) to S_ISDIR (was S_ISREG only). The dinode holds
  shortform dirents so this SHOULD make them durable.
- Then gated the early-out to S_ISREG only, so dirs ALWAYS run the flush loop (whose
  first action log_force collapses the CIL window).
- **STILL node1.txt missing.** So either (a) the LAST committer (node1) is NEVER
  routed through bast_process (it holds the dir EX sticky-cached and the test ends
  before a peer BASTs it — peers only do PR reads in verify), so the BAST-release
  flush never runs for node1; OR (b) node1's in-core count=4 is reverted by a reload
  BEFORE any flush. The cv4 timeline shows test1 DOES later ACQ-SLOW (lost the lock =
  was BAST'd), but its re-acquire reload read count=3 → either flush didn't run or
  wrote count=3.

## NEXT (deploy 564A41EF, instrument, then fix the RIGHT path)
1. Deploy 564A41EF (has P-SFDIR-REVERT: fires in reload when disk_cnt < incore_cnt
   for a LOCAL dir = self-clobber, logs in_ail/pin). Run cross_visibility, grep
   P-SFDIR-REVERT on test1 → PROVES whether node1's count=4 is reverted by a stale
   reload and whether it was in_ail/pinned (un-durable) at that moment.
2. The likely real fix surface is NOT bast_process (last committer isn't BAST'd) but
   EITHER: (a) make EVERY shortform dir commit durable promptly (flush dinode at the
   commit / at iunlock-when-holders→0 sticky point, multi-node only) so peers + own
   later reload see count=N — BUT watch rsync_paired perf (heavy dir writes); OR
   (b) make reload REFUSE to drop in-core dirents that aren't yet durable (the
   shortform analogue of sess39 RELOAD-SIZE-DROP-SKIP: if reloading a LOCAL dir would
   lower the count while our inode is dirty/in-AIL/CIL, keep in-core) — but (b) alone
   doesn't make PEERS see node1 until durable, so (a) is needed for cross-node
   visibility. Probably need BOTH, or make the last committer flush at iunlock.
3. CHEAP REPRO: `tests/run_tests.sh --nodes 4 --phase cluster --test
   test_cross_visibility` (NODE_OFFSET=16, hosts test1-4 via HOST_OFFSET=0). ~200s
   when failing (2× 120s barrier timeouts). Deploy = rmmod+umount all, `bash
   tests/reset4.sh 4`. ALWAYS reset between runs — colliding/orphaned mxfs_test.sh
   procs from killed runs contaminate (saw both cross_visibility AND a stale
   rename_visibility runner racing → all timeouts).

## Detectors added this session (all always-on, instr=0-safe, KEEP)
- **P-SFDIR-FASTEX** (xfs_mxfs_dlm.c, dir-EX fast-path return ~L2519): dumps cached
  shortform dirent names used as RMW base at a no-reload fast-path EX re-grant.
- **CAW-DUP-SLOT extended to INODE** (dlm/dlm_caw.c ~L1307): was AG-only.
- **P-SFDIR-REVERT** (xfs_mxfs_dlm.c reload ~L1939, build 564A41EF only): fires when
  a LOCAL-dir reload would drop the in-core count.

See [[sess83_lessons]] (EXTENTS-dir evict drain, the noino-BAST root for block dirs)
[[sess82_lessons]] [[sess53_lessons]] (sess53/55 flagged "force reload on dir-EX
fast-path re-grant" — but sess84 proves the loss is WRITE-durability of the last
committer, not read-staleness). State head = sess84.
