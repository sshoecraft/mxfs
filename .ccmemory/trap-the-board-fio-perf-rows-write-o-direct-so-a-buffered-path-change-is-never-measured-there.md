---
name: trap-the-board-fio-perf-rows-write-o-direct-so-a-buffered-path-change-is-never-measured-there
description: TRAP: fio_perf / fio_perf_vs_xfs use --direct=1; a buffered-write change (0.90.104 write-time alloc) reads 142% of XFS there untested. Measure dd buf…
metadata:
  type: feedback
---

tests/suite/fio_perf.sh runs fio with `--ioengine=libaio --direct=1 --iodepth=32`. Its board rows (fio_perf, fio_perf_vs_xfs: seqW/seqR/randW/randR as % of XFS) therefore never pass through the buffered write path or writeback. A change to buffered writes (0.90.104: a cluster mount's buffered write allocates at write time via xfs_direct_write_iomap_begin) can sit behind a green "seqW=142%" without ever having been measured.

The user asked (2026-10-08) "how about normal non-drbd single writer - it used to be as fast as xfs; is it?" — the board could not answer it.

How to measure the buffered path: tests/rig_buffered_write_vs_xfs.sh (dd 1 GiB buffered conv=fsync on the rig's shared LUN: MXFS write-time alloc, MXFS dbg_cluster_delalloc=1, native XFS on the same LUN; it reformats the LUN, re-prep afterwards with `MXFS_FORCE_PREP=1 ./run.sh 2/net/mesh/direct prep_cluster`). Measured 0.90.104/0.90.105: MXFS 0.96-1.07 s, delalloc 0.88-0.89 s, XFS 0.92-0.97 s. The FIRST dd after a mount is slow whatever the mode (1.4-2.8 s): interleave arms and discard or reverse the first lap.

On DRBD the picture is different: the in-flight write cap (drbd_inflight_kb) bounds a lone buffered writer (see D-DRBD-WRITE-BOUND-HOLDS-LONE-WRITER-TO-HALF-XFS).
