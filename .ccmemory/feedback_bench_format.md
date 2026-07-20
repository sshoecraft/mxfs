---
name: Standard benchmark report format
description: Multi-node benchmarks must use full fio suite with per-node columns, never dd
type: feedback
---

Never use dd for benchmarks. Always use fio with the full 4-workload suite (direct I/O, libaio, iodepth=32):
- Seq Write 1M
- Seq Read 1M
- Rand Write 4K
- Rand Read 4K

**Multi-node report format**: One table per node count. Rows = workloads, columns = node names + aggregate.

Example (4-node):

| Workload | test1 | test2 | test3 | test4 | Aggregate | XFS Baseline |
|---|---|---|---|---|---|---|
| Seq Write 1M | X MiB/s | X MiB/s | X MiB/s | X MiB/s | X MiB/s | 510 MiB/s |
| Seq Read 1M | X MiB/s | X MiB/s | X MiB/s | X MiB/s | X MiB/s | 540 MiB/s |
| Rand Write 4K | X IOPS | X IOPS | X IOPS | X IOPS | X IOPS | 51,063 IOPS |
| Rand Read 4K | X IOPS | X IOPS | X IOPS | X IOPS | X IOPS | 80,280 IOPS |

The XFS Baseline column shows the single-node XFS numbers (Session 65, Samsung 870). Always include this for context.

**Why:** dd only tests sequential throughput and doesn't report IOPS or latency. fio with the standard parameters gives consistent, comparable numbers across sessions. Per-node columns expose straggler patterns and contention hotspots.

**How to apply:** Every benchmark report uses this format. Single-node uses one column. Multi-node uses one column per node + aggregate.
