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

### 2026-08-23 (sess401-402) — O_TMPFILE churn breakdown, D-TMPFILE-CHURN-the budget rule-PERF-400

32 nodes/caw, each node `open(O_TMPFILE) -> write 4K -> linkat -> unlink -> close`
in a private dir, no contention.  ftrace function_graph on one node
(`tests/tmpfile_churn_ftrace.sh`): mxfs p50 **5.0 ms/iter** vs native 0.07 ms =
~11 synchronous storage round trips per iteration, all MXFS-added:

| term | cost | root |
|---|---|---|
| (a) unlink: `mxfs_dlm_dir_inode_durable(parent)` = log_force + iflush_cluster + sync bwrite | 1.7 ms | gate `!self_created \|\| i_dlm_dir_gen>0` fired on every dir (dir_gen==1 from the first acquire). FIXED 0.23.14 `mxfs_dir_op_needs_publish` / `dirop_virgin_skip` → unlink 0.48 ms, p50 3.2 ms (verified sess402: board, 6-lap d385, churn, dirent_durability) |
| (b) close → sync inactivation: inode CAW lock + open-holders slot read + ifree (of which per-ifree AGI FUA re-read 0.22 ms) | 1.2 ms | 0.23.15 knob `ifr_agi_disk_check` (1 legacy / 2 shadow / 0 off) — shadow arm not yet measured |
| (c) linkat: publish lock_routed + `mxfs_dlm_verify_rawmode` | 0.6 ms | NOT the fresh-inode P108 verify (skips self_created) — it is the un-throttled dir-EX CAW verify (`dir_ex_verify_caw`, every idle dir-EX cache hit = one 512B FUA slot read; sess8 phantom-EX rationale). 0.23.16 adds `verify_site_{p108,direx,s6,s7}_n` to attribute by measurement first |
| (d) create: `mxfs_dialloc_try_reserve` CAW ino reservation | 0.3 ms | ruling priority 4: chunked reservations under AG tenure |

Ceiling (budget) = 2× native = 0.14 ms/iter.  Shared-dir shape (32 nodes, one
dir): still rc=124 at 6 s / 200 iters (EX ping-pong) — D-32NODE-SHARED-DIR-
CREATE-PACE.  Related: crash_consistency's first run after a fresh prep is
80-88 s because it creates 3200 dirents through one shared dir EX (~27 ms per
create); re-runs 16 s (D-401).

## 32-node shared-directory create pace — attribution (sess435, 0.41.5/0.41.6)

The `crash_consistency` row (100 O_SYNC creates per node into ONE shared
directory, 32 nodes) runs at its 90 s budget.  Where the time goes, measured:

| measurement | tool | result |
|---|---|---|
| per-node phase walls (FAIL archive 20:20Z) | `tests/cc_phase_walls.py` | datawrite median 30 s, md5write 39 s, verify 9 s, barriers ≤ spread |
| blocked-stack profile, 32 nodes | `tests/cc_stackprof.sh` | 26.5 % of blocked ticks in `caw_wait_for_grant`; release side 1.25 % |
| grant-wait-loop entries > 5 ms | `P138-WAIT` / `P138-AGWAIT` (0.41.5) | 13 inode, 2 AG lines fleet-wide (< 1 s) |
| whole-acquire accounting | `P138-ACQ` / `P138-ACQSUM` (0.41.6) | INODE: 19 000 acquires, **1 989 s fleet = 62 s per node**; AG negligible |
| dominant resource | report `top resources` | shared dir ino 25165952: 772 acquires > 5 ms, 1 958 s, mean 2.5 s, p90 6.1 s, max 9.7 s |

So the whole create wall is the **directory EX lock rotating around 32 nodes**:
each node waits ~2.5 s for its turn (an acquire is many nudge-woken laps that
end without a grant — no single wait-loop entry exceeds 5 ms), then holds a
short tenure (~4 creates), giving ~20 ms per create fleet-serialized.  The AG
locks, the per-create holder work, and the release pipeline are not the wall.
`tests/cc_grantwait.sh report` prints all of the above; `P138-ACQSUM` lines
are cumulative per module load (a prep resets them).

Open: `tests/cc_tenure_timeline.py` (grant instants vs `P138-BAST` releases)
for tenure length, creates per tenure and handoff dead time; then the fix
shape (longer/batched tenures vs cheaper work under the lock vs handoff
latency) goes to a design-consult consult.  Ledger: D-32NODE-SHARED-DIR-CREATE-PACE,
D-CRASH-CONSISTENCY-FLEETWIDE-BARRIER-TIMEOUT-401.

### sess436 — cycle anatomy by lock mode (0.41.6) and design-consult ruling

`tests/cc_tenure_modesplit.py` over the 01:00-01:06Z journals
(`tests/evidence/sess436_tenure_modesplit/report.txt`):

| measurement | EX (mode=5) | PR (mode=3) |
|---|---|---|
| grants on the shared dir | 257 (7-11 per node) | 515 (9-25 per node) |
| acquire elapsed p50 / p90 | 7.0 s / 8.5 s | 787 ms / 959 ms |
| fleet inter-grant gap p50 / p90 | 310 ms / 337 ms | 1 ms / 852 ms |
| per-node period p50 | ~9.0 s | ~0.97 s |

EX grants arrive ONE at a time every ~310 ms fleet-wide: a strict 32-node
rotation (~9 s per revolution).  PR grants batch (8-10 nodes within 25 ms)
right after each EX grant.  The 310 ms is `inode_mht_ms=300`
(`xfs/xfs_mxfs_dlm.c:13189`, `mxfs_dlm_mht_defer_bast`): the holder keeps the
dir EX for the Minimum Hold Time and does ~13 serial `dd oflag=sync` creates
in it (~23 ms each — node-local sync latency; the dir ILOCK is held <1 ms per
create), so the EX is held ~95% idle while 31 nodes wait.  Release
(`P138-BAST`, 500): p50 9.2 ms (log force `sb` 2.1/17.6 ms, drain `b2`
1.9/17.4 ms, unlock CAS `su` 3.6/11.6 ms p50/p90); holder-release → next
grant dead time p50 9.75 ms, p90 303 ms; 496/499 handoffs to a different node.

Floors: 3200 creates × 23 ms serialized ≈ 74 s (measured ~70 s); immediate
release would serialize 3200 × ~10 ms handoffs ≈ 32 s.  A one-transfer-per-
create design needs the whole op-end → next-op-start path ≲ 1 ms to reach
single-digit seconds.

Design-consult ruling (`docs/rulings/shared-dir-create-pace-mht-delegation.md`):
short term, MHT becomes a *maximum useful quantum* (REVOKING on BAST, bounded
post-BAST batch, release when idle, zero grace with remote waiters) plus
direct baton transfer via `yield_to`, successor-only fast polling and waiter
aging — a fairness/regression fix, not 2× native.  The real fix is directory
delegation with remote-op combining (owner keeps EX, peers forward creates,
data writes overlap) or physical directory sharding (lock striping alone is
insufficient).  Measurements before building: per-create trace points, raw
CAW transfer-floor bench, `inode_mht_ms`/grace sweep
(`tests/sess436_chain2_0417_intents_mht.sh`), release dirty-work
classification, private-dir headroom run.

### sess436 — MHT sweep and headroom (0.41.7/0.41.8)

`inode_mht_ms` sweep on crash_consistency (chain 2): 0 → FAIL BUDGET_EXHAUSTED
(EX grant every 23 ms, one per create; release 10.4 ms + dead time 10.6 ms);
10 → FAIL (24 ms); 50 → FAIL (64 ms, ~2 creates/tenure); 300 → PASS 86 s.  The
tenure is quantized at MHT+~13 ms in every leg; the per-create serialized cost
is ~23-32 ms whatever the MHT — the handoff (~20 ms/hop: ~6 ms adopt + dir
re-read/rebuild + create, ~10 ms release drain, ~7 ms transfer) is the floor.

Headroom (chain 5, `MXFS_TEST_ENV="CC_PRIVATE=1"`): one private subdirectory
per node → **PASS 17 s/90 s, 32/32**; the shared-directory control in the same
chain → FAIL.  test9's INODE-class acquire sum: 1.66 s private vs 72 s shared.
The shared directory's single lock is the whole gap.  Delegation (ruling
option 1) is barred by the sess68 user directive (no asymmetric MDS, no
per-op RTT); the directive-compatible fix is symmetric directory sharding.
