---
name: sess-tcp-SEED-ROOT-ino131-free-lost-to-evict-ring-overflow
description: SEED ROOT of dir_reuse 2/tcp: node2 NEVER receives INODE_FREE for dir ino=131 (gets it for the 100 file inodes 2097xxx). rm-rf frees ~101 inodes/roun…
metadata:
  type: project
---

## dir_reuse 2/tcp — THE SEED (build AFE4E833). This explains the whole circularity. Marker NOT written.

### PROVEN: node2 never learns the dir inode was freed+recreated.
`grep EVICT-RING-FLAG test2.log | grep ino=131` → **0**. node2 DOES receive INODE_FREE for the 100 FILE inodes (ino=2097303..2097312, ~10 each), but NEVER for the DIR ino=131.

### MECHANISM: evict-ring OVERFLOW.
Each round, rank1 `rm -rf D` frees ~101 inodes: the dir (ino=131, freed FIRST) + 100 files (50 data + 50 .md5). The disk-heartbeat eviction ring is **MXFS_EVICT_RING_ENTRIES = 28** deep (dlm/disklock.c). 101 frees ≫ 28 between node2's heartbeat reads → the ring overflows; the consumer (disklock.c ~414) clamps to the newest 28 entries (the file inodes) and DROPS the oldest (ino=131's free). So node2 NEVER gets ino=131's INODE_FREE → never marks its cached dir inode XFS_ISTALE_CAW → never reloads the new incarnation.

### CONSEQUENCE (the full chain, now end-to-end):
1. node1 rm-rf's + mkdir's D each round → ino=131 reused, NEW incarnation, block0 freshly allocated @ fsb=15 (daddr 120).
2. node2's cached VFS inode for ino=131 keeps the PRIOR incarnation's fork (block0 → freed daddr 112). The free notification that would invalidate it is lost to ring overflow.
3. node2 fast-path-grants the dir EX on the stale incarnation (cached per-inode-NUMBER DLM lock looks valid; no reload) and/or its slow-path reload reads the oscillating disk. node2 modifies+flushes block0→112.
4. mxfs_iflush_cluster_merge_dirs treats node2's EX-held dir slot as authoritative (block0→112 written via co-resident child-file cluster flush), reverting node1's canonical block0→120.
5. getdents iterates the stale in-core map → reads block0 @ 112 (missing node1_f1..f12); lookup uses the leaf @ 120 → lookup_fail=0. readdir short.

### FIX (ring-INDEPENDENT — do NOT rely on the lossy 28-entry ring for the dir):
**Incarnation-verify on dir-EX acquire (and dir lookup/readdir).** On acquiring/using the dir inode, compare in-core `VFS_I(dp)->i_generation` to the on-disk `di_gen` (cheap read, or carry di_gen in the DLM LVB/grant). If they differ, the inode number was reused (freed+recreated) → FORCE a full reload (xfs_idestroy_fork + xfs_inode_from_disk) and invalidate the cached dir-EX grant + cached dir buffers, BEFORE any modify. This is GPT-5.5's "validate on DLM acquire, not the heartbeat ring." node1 creates a fresh di_gen each round, so node2's stale i_generation will mismatch → reload → adopt block0→120.
- Entry points: dir-EX fast-path grant (xfs_mxfs_dlm.c ~8558 P-DIRFASTEX — currently NO incarnation check) and slow-path acquire; readdir (xfs_dir2_readdir.c:631) and lookup. Add a di_gen-vs-i_generation gate that forces MXFS_IF_DIR_RELOAD / reload.
- ALTERNATIVE/COMPLEMENT: make the dir-inode INODE_FREE not lost to overflow — e.g., publish a single "dir-subtree freed (ino=131)" coalesced marker, or prioritize/separate dir-inode frees from the 100 file frees so the dir free survives the 28-entry ring. But the incarnation-verify is the robust primary (frees can always overflow under churn).

### VERIFY after fix: re-run drc; node2 should reload ino=131 to the fresh incarnation (block0 fsb=15) every round; P-DIRIFLUSH node2 should always show fsb=15; drc-FAIL=0 across ≥4 runs; then `./run.sh 2 tcp` = 17/17.
Build AFE4E833 (P-GROW0 + P-DIRIFLUSH detectors, gated dirwr/instr). [[sess-tcp-WHY-merge-misses-it-EX-held-stale-incarnation-fork]] [[sess-tcp-ROOT-stale-incore-extent-map-getdents-blk0-daddr]] [[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]]
