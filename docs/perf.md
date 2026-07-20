# MXFS Performance Optimization Plan

## Strategy

Optimize bottom-up: get single-node performance as close to raw XFS as possible first, then scale up node count incrementally. Each node-count tier must pass all correctness tests before moving to the next.

## Baseline (2026-02-18)

Raw XFS vs mxfs on test1, 10GB iSCSI LUN, Debian 12.12, kernel 6.1:

| Test | Raw XFS | MXFS | Overhead |
|------|---------|------|----------|
| Sequential write 100MB | 66.4 MB/s | 2.1 MB/s | 31x |
| Sequential read 100MB | 95.0 MB/s | 4.6 MB/s | 21x |
| Create 1000 files | 367/s | 46/s | 8x |
| Stat 1000 files | 252/s | 254/s | 1.0x |
| Delete 1000 files | 378/s | 53/s | 7x |
| Create 100 dirs | 294/s | 61/s | 5x |
| Remove 100 dirs | 340/s | 73/s | 5x |
| Mixed workload | 168/s | 28/s | 6x |

## Phase 1: Single-Node (1 node, no DLM contention)

Goal: get within 2-4x of raw XFS on all benchmarks.

### Round 1 — Write Path (IMPLEMENTED)

1. **Skip disk read for new blocks** — `mxfs_block_cache_get_new()` / `cache_ensure_new()` skips `mxfs_pal_bdev_read()` for freshly allocated blocks. Eliminates 25,600 unnecessary reads per 100MB write.
2. **Bulk write API** — `mxfs_block_cache_write_range()` takes the cache rwlock once for an entire contiguous block run instead of 3 times per 4K block. Cuts rwlock ops from 76,800 to ~200 per 100MB.
3. **Coalesced flush** — `mxfs_pal_bdev_write_gather()` builds a single multi-page bio for contiguous dirty blocks instead of one bio per block. `flush()` and `flush_range()` sort dirty entries and batch contiguous runs.
4. **Larger I/O buffer** — `MXFS_IO_BUF_SIZE` increased from 256KB to 1MB. Reduces `mxfs_write()` calls from 400 to 100 per 100MB.

### Round 2 — Read Path (TODO)

- **Skip disk read for cached blocks on read path** — currently `mxfs_kern_read_iter()` bounces through a kmalloc buffer. Could map block cache entries directly.
- **Read-ahead** — on sequential read pattern, prefetch next N blocks into cache in a single bio.
- **Bulk read API** — mirror `write_range` with a `read_range` that takes the rwlock once.

### Round 3 — Metadata Path (TODO)

- **Batch inode dirty flush** — currently each `mxfs_inode_cache_dirty()` + `put()` cycle is independent. Batch multiple inode flushes into a single device write + flush.
- **Dir cache write coalescing** — `flush_block_dir()` writes one block at a time. Use `write_range` for multi-block dirs.
- **Reduce inode cache rwlock scope** — the inode cache uses a single global rwlock. Consider per-bucket locks or read-side lockless hash lookup.

### Round 4 — Allocation Path (TODO)

- **Delayed allocation** — don't allocate physical blocks until flush/fsync. Accumulate logical writes in the block cache, allocate contiguous extents at flush time.
- **Preallocation hints** — when writing sequentially, request larger contiguous extents from the allocator up front.

### Measurement Criteria

After each round, re-run the full benchmark suite:
- `dd if=/dev/zero of=/mnt/shared/testfile bs=1M count=100 conv=fdatasync` (sequential write)
- `dd if=/mnt/shared/testfile of=/dev/null bs=1M` (sequential read, after drop_caches)
- 1000-file create/stat/delete
- 100-dir create/remove
- Mixed workload (100 files: create+write+read+delete)
- Full test suite pass required: `./test.sh --nodes 1 --phase single` (12 tests)

## Phase 2: Two-Node (2 nodes, DLM active)

Goal: overhead from DLM contention < 2x vs single-node mxfs for non-conflicting workloads.

### Benchmarks

- **Non-conflicting**: Each node writes to separate files/dirs. Should be near single-node speed.
- **Read sharing**: Both nodes read same file. PR locks should allow concurrent access.
- **Write contention**: Both nodes write same file alternately. Measures BAST + flush latency.
- **Metadata contention**: Both nodes create files in same directory. Measures dir lock thrashing.

### Optimization Targets

- **BAST flush latency** — with coalesced flush, BAST response should be faster (fewer bio submissions). Measure BAST-to-grant latency.
- **Lock caching effectiveness** — single-node holds locks indefinitely. Two-node, locks are released on BAST. Measure cache hit rate.
- **TCP message latency** — DLM lock request → grant round-trip time.

## Phase 3: Four-Node (4 nodes)

Goal: linear or near-linear scaling for non-conflicting workloads (4 nodes should get ~4x aggregate throughput on separate files).

### Benchmarks

- **Parallel independent writes**: 4 nodes, each writing 100MB to separate files
- **Parallel dir ops**: 4 nodes, each creating 250 files in separate dirs
- **Shared dir contention**: 4 nodes all creating files in the same directory
- **Sequential consistency**: node A writes, node B reads, verify data visible

### Optimization Targets

- **DLM mastering load balance** — FNV-1a hash distributes lock masters. Verify even distribution across 4 nodes.
- **TCP mesh overhead** — 4 nodes = 6 TCP connections. Measure message backlog.

## Phase 4: Eight-Node (8 nodes)

Goal: identify any O(n) or O(n^2) scaling bottlenecks.

- **DLM BAST fan-out** — 1 write to a shared resource sends BASTs to up to 7 holders. Measure total BAST processing time.
- **Discovery overhead** — 8 nodes announcing every 5 seconds. Verify no message storms.
- **Lock wait queue depth** — under contention, up to 7 waiters per resource. Verify FIFO fairness holds.

## Phase 5: Sixteen-Node (16 nodes)

Goal: stable operation, no hangs, no starvation.

- Stress test: 16 nodes all doing mixed create/write/read/delete for 10 minutes
- Fault injection: kill 1 node during stress test, verify recovery
- Lock starvation test: verify no node gets starved under heavy contention

## Phase 6: Thirty-Two Node (32 nodes)

Goal: full-scale validation at maximum supported cluster size.

- All Phase 5 benchmarks at 32 nodes
- Measure aggregate throughput scaling curve (1 → 2 → 4 → 8 → 16 → 32)
- Profile: DLM lock latency distribution, BAST processing time, TCP message rates
- Identify the bottleneck ceiling and document it

## Results Log

Record all benchmark results here as they are collected.

### Round 1 Results — Write Path Optimization (2026-02-18)

test1, Debian 12.12, kernel 6.1, 50GB iSCSI LUN (local NVMe-backed), 1GbE network.

| Test | Raw XFS | mxfs (before) | mxfs (after) | Improvement |
|------|---------|---------------|--------------|-------------|
| Seq write 100MB | 83.2 MB/s | 2.1 MB/s | **49.6 MB/s** | **23.6x faster** (31x→1.7x overhead) |
| Seq read 100MB | 104 MB/s | 4.6 MB/s | 3.8 MB/s | regression — read path not yet optimized |
| Create 1000 files | 15.5s | 21.7s | 36.0s | regression — needs investigation |
| Stat 1000 files | 3.9s | 3.9s | 4.0s | parity (1.02x) |
| Delete 1000 files | 15.4s | 18.9s | 32.8s | regression — needs investigation |
| Create 100 dirs | 1.66s | 1.63s | 2.83s | regression — needs investigation |
| Remove 100 dirs | 1.53s | 1.36s | 2.72s | regression — needs investigation |
| Mixed workload | 3.52s | 3.53s | 6.76s | regression — needs investigation |

**Write path: massive win.** 2.1 → 49.6 MB/s. Overhead dropped from 31x to 1.7x.

**Read path: untouched, still 27x overhead.** Now the primary bottleneck.

**Metadata ops: regressions detected.** Create/delete/mkdir/rmdir all slower than baseline. Possible cause: the `write_range()` or contiguity detection code may be adding overhead to the metadata path which also calls `mxfs_write()` for small writes. Needs profiling.

**Next target: read path optimization (Round 2), then investigate metadata regressions.**

### Round 2 Results — Read Path + Multi-Page Bio (2026-02-18)

test1, Debian 12.12, kernel 6.1, 50GB iSCSI LUN (local NVMe-backed), 1GbE, MTU 9000 (but TCP MSS 1448).

Two fixes applied:
1. Block cache read-ahead: `cache_ensure_readahead()` reads 256 contiguous blocks (1MB) on miss
2. Multi-page bio in PAL: `bdev_sync_io()` builds single bio with up to 256 pages instead of one bio per page

| Test | Raw XFS | mxfs (before) | mxfs (after) | Improvement |
|------|---------|---------------|--------------|-------------|
| Seq write 100MB | 88.4 MB/s | 49.6 MB/s | **50.6 MB/s** | stable (multi-page bio helps writes too) |
| Seq read 100MB | 116 MB/s | 3.8 MB/s | **66.4 MB/s** | **17.5x faster** (29x→1.75x overhead) |

**The root cause was `bdev_sync_io()`.** It was doing `submit_bio_wait()` per 4K page — 256 separate synchronous I/Os per 1MB. Rebuilding it to use multi-page bios (one `submit_bio_wait()` per 1MB) fixed both read and write paths at the PAL layer. The block cache read-ahead ensures sequential blocks are loaded in one I/O instead of on-demand per-block.

**Both read and write now at 1.75x overhead vs raw XFS.** Remaining gap is inode cache get/put per 1MB chunk + block cache hash/LRU overhead.
