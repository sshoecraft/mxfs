---
name: trap-delalloc-is-a-per-node-promise-two-hosts-promise-the-same-blocks-and-writeback-discards-data
description: TRAP (0.90.104): XFS delalloc reserves from the node's own counter; near full both hosts accept writes, 2nd writeback page-discards data
metadata:
  type: feedback
---

Even with exact per-node free counters, delayed allocation on a cluster mount loses data near full: both hosts reserve the same last free blocks (xfs_bmapi_reserve_delalloc -> xfs_dec_freecounter, local only), write() succeeds on both, and the writeback that allocates second gets ENOSPC in xfs_bmapi_convert_delalloc -> "writeback error" + "XFS: page discard" on BOTH hosts, fsync fails. tests/pve_delalloc_overcommit.sh reproduces on the first run (fill to 3 GiB free, both dd 2 GiB buffered conv=fsync).

Fix shape that worked (0.90.104): on a cluster mount, xfs_buffered_write_iomap_begin routes to xfs_direct_write_iomap_begin, the path upstream already uses for files with an extent-size hint ("can't use delayed allocations when using extent size hints") — unwritten extents allocated at write time under the AG locks, ENOSPC at write(). Test-only knob dbg_cluster_delalloc=1 restores delalloc for A/B. Cost on small-file churn ~14% throughput.

Lesson: any per-node reservation of a shared resource (space, inodes, quota) is a promise the peer can also make; it needs either a cluster-wide grant or to be turned into the real allocation under the shared lock.
