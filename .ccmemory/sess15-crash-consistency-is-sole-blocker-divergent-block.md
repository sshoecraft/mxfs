---
name: sess15-crash-consistency-is-sole-blocker-divergent-block
description: sess15: FULL 2/tcp suite = 15/16 PASS, crash_consistency SOLE blocker (1/2 nodes). P-RELFLUSH shows SAME daddr flushed by test1 (node1-only entries)…
metadata:
  type: project
---

## sess15 (build C10D1837, de-ratelimited P-RELFLUSH + mxfs_dir_block_names). FULL `./run.sh 2 tcp` = 15/16 PASS; SOLE FAIL = crash_consistency (nodes_pass=1/2). All others (cache_coherency, dlm_fairness, tcp_dlm_scaling, zero_silent_loss, posix_multi, rsync_paired, soak, fence, fault, mmap, strong_consistency, dlm_membership/scaling, scaling_curve) PASS. crash_consistency PASSED standalone but FAILS in-suite → real + flaky.

## crash_consistency = exactly the cc_blockdir scenario: both nodes write 50 O_SYNC files + 50 .md5 into ONE shared dir (.crash_consistency), barrier, drop_caches, then each node re-reads EVERY node's files+md5sums + total count. A test2 dirent (e.g. node2_f15/f16) durably vanishes → checksum/count FAIL. Lost entries are ALWAYS test2's (test1 is the clobberer; its block writes win).

## P-RELFLUSH EVIDENCE (ino=131, build C10D1837): the SAME physical block daddr=496 was flushed by test1 with names=[. .. node1_f17..f23] (ONLY node1 entries) and by test2 with names=[. .. node2_f10..f14] (ONLY node2 entries). => each node's in-core block0/data-block base contains ONLY ITS OWN entries, NOT the peer's. Last writer to that daddr wins; the other node's whole block's worth of dirents is lost. This is a DIVERGENT-BASE block RMW: neither node's data block reflects the merged set. CAVEAT: ino 131 was REUSED across iters (cc_blockdir rm's each dir), so the test1-vs-test2 daddr-496 lines MAY be different incarnations — running cc_nogap_noreuse.sh (unique dirs, NO rm, no settle-gap) to get a reuse-free trace and confirm whether two nodes flush the SAME incarnation's block with disjoint entries.

## TIMING: the loss needs TIGHT back-to-back concurrency. Probes with a ~1s settle gap between mkdir and the concurrent create (per-iter `dmesg --clear`) do NOT reproduce (cc_minrepro 40/40, cc_reuse_scoped 30/30 clean), while no-gap cc_blockdir loses in <15 iters. crash_consistency's coord_barrier synchronizes both nodes → tight concurrency → triggers it. So it is NOT a settle/eventual-consistency issue; it is a genuine concurrent-RMW divergent-base lost-update under tight timing.

## STILL OPEN: is each node building block0 from a base missing the peer's entries because (a) the releasing node's data block wasn't durable so the acquirer cold-read stale (release gap) or (b) the acquirer fast-pathed/failed-to-reload the peer's durable block (acquire stale)? Get the reuse-free P-RELFLUSH trace: if test2 flushes daddr D with [.,node2_f15] and test1 LATER flushes SAME D with [no f15] → acquire-side stale clobber. Detectors in build C10D1837 (KEEP for now): de-ratelimited P-RELFLUSH+names, mxfs_dir_block_names(), P-H14 incore SF list, dir_force_evict param. [[sess15-PIVOTAL-loss-requires-inode-daddr-reuse]] [[sess15-ROOT-concurrent-sf-to-block-conversion-double-alloc]]
