---
name: session71-perf-investigation
description: rsync perf investigation — IOPS is the bottleneck, not FUA. Write-back metadata caching is the fix.
type: project
---

Session 71 (2026-03-21): rsync performance investigation on real QNAP iSCSI.

**Root cause**: 43,000 small synchronous writes at ~550us each (iSCSI round-trip). XFS does 1,400 large writes. IOPS count is what matters — FUA vs non-FUA has identical latency on the QNAP.

**Failed approaches**: journal batching (checkpoint frequency defeated it), FUA removal (no latency difference on QNAP).

**Planned fix**: Write-back metadata caching. Dir_cache and inode_cache route writes through block_cache (mark dirty, flush on BAST/sync). Journal accumulates entries, writes in bulk periodically. Single-node: nothing hits disk until sync. Multi-node: BAST triggers flush before lock release. Block_cache already does this for btree nodes — extend to all metadata.

**Why:** XFS batches hundreds of transactions into one large journal write every ~5 seconds. MXFS does one synchronous round-trip per transaction. The DLM lock is the coherency gate — no need to flush until someone asks (BAST).

**How to apply:** Next session implements write-back caching for dir_cache/inode_cache through block_cache, plus batched journal writes with periodic flush timer.
