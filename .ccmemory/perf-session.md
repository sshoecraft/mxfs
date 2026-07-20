# Performance Optimization Session (2026-02-19)

## Summary
Optimized mxfs v2 I/O from 2.1/3.8 MB/s to near-native single-node and working 4-node cluster.

## Performance Results

### Single-Node (vs raw XFS)
| Test | Raw XFS | MXFS | Notes |
|------|---------|------|-------|
| New file write | 63-82 MB/s | 79-83 MB/s | mxfs faster (no journal) |
| Overwrite | 88 MB/s | 83 MB/s | 5.7% overhead |
| Cold read 100MB | 84 MB/s | 80 MB/s | 95% of native |
| Cold read 500MB | 101 MB/s | 98 MB/s | 97% of native |

### Multi-Node
| Nodes | Write | Read/node | Dir visibility | Clean unmount |
|-------|-------|-----------|----------------|---------------|
| 1 | 79 MB/s | 98 MB/s | N/A | PASS |
| 3 | 38-50 MB/s | 60 MB/s | PASS | PASS |
| 4 | 38 MB/s | 60 MB/s | PASS (4/4) | PASS |

## Key Insight: mxfs v2 is NOT a stacking filesystem
It reads XFS on-disk format directly — effectively a simplified XFS without journaling. This is why writes can be faster than raw XFS (no journal overhead).

## Optimizations Applied (in order)
1. **Multi-page bio** — bdev_sync_io builds 256-page bios (was 1 page per bio)
2. **Block cache readahead** — 256 contiguous blocks (1MB) on miss
3. **Direct I/O fast path** — bypass block cache when peer_count==0
4. **4MB→16MB I/O buffers** — reduce per-chunk DLM/cache overhead
5. **virt_to_page zero-copy** — no alloc/copy in bdev_sync_io
6. **Single-node alloc skip** — defer cache flush when no peers
7. **Pipelined bio reads** — 16 concurrent bios for reads
8. **kvmalloc for large buffers** — handles >4MB via vmalloc
9. **Bulk read API** — single DLM lock for entire file read
10. **Block cache rwlock yielding** — release every 256 blocks to prevent starvation
11. **cond_resched throughout** — prevent soft lockups during long I/O

## Bugs Fixed This Session (~15)
- Peer socket leak on unmount (pending_sock tracking)
- Dir cache coherency (put_dir eviction, invalidated flag, PR path check)
- DLM epoch-based stale lock detection
- DLM ghost lock purge (purge_stale_for_resource)
- DLM pending entry ordering (setup before BAST send)
- BAST for uncached inodes (cleanup unlock)
- BAST send retry (3x with backoff)
- Asymmetric multicast peer connection fallback
- Inbound peer registration with lease/DLM
- Unmount kthread shutdown (condvar + UDP shutdown)
- Lease RT priority (sched_set_fifo_low)
- Lease timing (1s renew, 60s suspect, 180s timeout, 6 misses)
- Lease send time budget (500ms cap)
- Dir cache epoch invalidation
- Unmount DLM deadlock (shutting_down before flush)
- Unconditional bdev_flush in fsync

## Network Environment
- MTU 9000 set on: clyde br0+enp6s0, ESXi vSwitch1, all 32 VMs, QNAP
- QNAP TCP MSS still 1448 despite MTU 9000 (firmware issue)
- iSCSI params capped by QNAP: FirstBurst 64KB, MaxBurst 256KB, InitialR2T=Yes
- VM→QNAP path: VM → ESXi vSwitch → clyde br0 → enp6s0 → QNAP (routed)
- clyde direct to QNAP: 101 write, 117 read MB/s
- VM to QNAP: ~65 write, ~112 read MB/s (warm cache)
