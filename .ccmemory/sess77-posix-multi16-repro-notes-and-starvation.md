---
name: sess77-posix-multi16-repro-notes-and-starvation
description: sess77 repro notes: standalone concurrent mkdir+touch+file-create (even with readdir pressure) does NOT reproduce the cwr_write dir corruption; needs…
metadata:
  type: project
---

## sess77 repro attempts for posix_multi16 dir-corruption (see [[sess77-posix-multi16-durable-dir-format-content-corruption]])

### What did NOT reproduce the corruption (build 3DC74E7D, clean reboot each time)
- `tests/repro_barrier_coherency.sh` 16 nodes: PASS in 6s (pre-creates dir with 1 node, distinct adds).
- `tests/repro_sfblock_corrupt.sh` (NEW, KEEP) 16 nodes × 30 rounds — concurrent `mkdir -p D`
  create-race + `touch D/nodeN` distinct adds: 0 corruption.
- Same + per-round 16×64k file-creates into a shared TESTDIR (mimic cross_write_read data files):
  0 corruption in 30 rounds.
- => the cwr_write dir-inode format/content corruption is NOT triggered by concurrent
  mkdir-race + distinct-add + file-create alone. It needs the REAL mxfs_test.sh harness pattern,
  where `barrier_wait` runs an aggressive `find`/readdir (PR) loop on the shared dir CONCURRENTLY
  with the create storm (EX), AND it only fired after several prior cluster tests had run
  (accumulated state / specific inode-cluster layout). It is intermittent: 1 random node of 16.

### Side finding (real, but a DIFFERENT symptom than the corruption)
Adding a 6s concurrent readdir storm (`while ...; do ls $TD; ls $D; find $D; done`) on all 16
nodes DURING the create storm caused a cluster-wide LIVENESS STALL: 9+ nodes piled up ~16 D-state
readdir procs each (blocked in iterate_dir / buffer locks), round 1 never completed in 5+ min, NO
shutdown. This is the sess50 CAW writer-starvation (PR readers re-grant among themselves, EX
create starves) amplified at 16 nodes. Contributes to posix_multi16 slowness independently of the
corruption. The repro's storm was toned down to 2s/ls-only after this wedged the cluster.

### Recommended next-session approach (RULE 4)
Don't chase a standalone repro further — use the REAL test as the reproducer:
1. Clean `virsh destroy+start` ALL 16 + reset4.sh 16 (cluster is likely D-state-wedged now; reboot).
2. Instrument the sf->block dir conversion (xfs_dir2_sf_to_block / xfs_bmap_local_to_extents) and
   the inode-cluster flush/FUA-reload for DIRECTORY inodes: log ino, di_format transition, di_nextents,
   and whether the data-fork bytes written match the format. Gate behind mxfs_instr.
3. Run `run_tests.sh --nodes 16 --phase cluster` (MXFS_TESTS_DIR=/src/mxfs/tests, MXFS_NODE_OFFSET=16)
   in a loop until a node shuts down with the "node7"-bytes-as-bmbt-rec corruption on a barrier dir.
4. Catch the moment di_format becomes EXTENTS/BTREE while the literal area still holds shortform
   dirents (or the inode-cluster buffer is flushed with a stale fork). Guard, rebuild, re-run.

Marker NOT written: posix_semantics_multi16 + rsync_paired still FAIL. fence_during_write FIXED
this session (PASS, build 3DC74E7D).
</body>
