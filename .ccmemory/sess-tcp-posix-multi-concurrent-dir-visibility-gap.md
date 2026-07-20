---
name: sess-tcp-posix-multi-concurrent-dir-visibility-gap
description: SHARP REPRO: posix_multi exposes a DURABLE concurrent-same-directory LOST-UPDATE. Both nodes concurrently insert 100 dirents into one dir; each ends…
metadata:
  type: project
---

## CLEAN REPRODUCIBLE CORE BUG (build B77AD901)
`./run.sh 2 tcp posix_multi` (or manual posix_multi.sh both nodes) fails ~every run with a
DURABLE concurrent-directory lost-update — the same fundamental coherency bug the project
has fought for 30+ sessions, now reproduced on TCP/LIO (NOT infra/CAW-specific):

- Each node creates 100 files (node${R}_file1..100) into ONE shared dir
  (/mnt/shared/.posix_multi) concurrently, then a coord_barrier (which PASSES), then rank1
  counts `ls node*_file*`.
- RESULT: every node persistently sees ONLY ITS OWN 100 (`count exp=200 got=100`), and only
  its OWN renamed file. PROVEN durable: 3 repeated reads minutes later on BOTH nodes still
  give 100 each (node1 sees node1_*, node2 sees node2_*). NEITHER sees the union.
=> NOT read-staleness (doesn't self-heal). It's a durable LOST-UPDATE: both nodes inserted
their 100 dirents onto a STALE base and committed, each clobbering the peer's 100. The dir
DLM EX serialization + reload-on-acquire is NOT making node B build on node A's committed
dir image (and vice-versa) for high-volume block/leaf-format dirs.

## Why other tests pass / this is the lever
- strong_consistency (separate per-node counter files) PASS 2/2 stable.
- zero_silent_loss (10 own-named files/node) PASS 2/2 (low volume, separate names — the dir
  lost-update needs enough concurrent entries to collide).
- cache_coherency subtests (1, 30 files) sometimes pass. posix_multi (100/node) reliably fails.
This is the cleanest repro of the core dir-coherency bug yet — use it.

## Family / prior art (read before fixing)
Dir-block durable lost-update: sess83 (F08CE615 drain dir blocks before unlock), sess88
(73B57CCD no-inode BAST drains dir-data by AG), sess80-82 evict-ring, sess41 shortform,
sess119 (concurrent-mkdir TOCTOU on shortform parent), sess126 (mkdir-race loser). The
mechanism: a node modifying a dir must, on acquiring dir EX, RELOAD the peer's durable dir
image (all data blocks, block/leaf fmt) BEFORE applying its inserts; and on release drain
all dir DATA blocks durable. Evidently the multi-block (100-entry) concurrent case still
loses updates on TCP. INSTRUMENT: in xfs_create / dir_createname, log dir i_dlm_dir_gen +
the dir's on-disk entry count vs in-core at EX-acquire and at commit, on both nodes, for the
.posix_multi dir; find where node B's base lacks node A's 100.

## TWO failure modes (don't conflate)
1. THIS durable dir lost-update (reproducible, posix_multi).
2. An intermittent coord_barrier desync (other runs; one node lags >COORD_TIMEOUT with NO
   captured FS D-state — possibly MQTT-broker latency under load). Fix #1 first (reproducible).

## Status / NEXT
6 multi-node tests wired (see [[sess-tcp-suite-port-multinode-tests]]). strong_consistency +
zero_silent_loss reliably PASS. cache_coherency/posix_multi/mmap/dlm_fairness fail on #1/#2.
Criterion (all multi-node 2/tcp PASS) NOT met. Fix the durable dir lost-update next.
5 code fixes KEEP: [[sess-tcp-2node-three-root-fixes]], [[sess-tcp-progress-subtests-123-pass]].
</body>
