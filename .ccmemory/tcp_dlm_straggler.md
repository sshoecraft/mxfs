---
name: TCP DLM straggler issue
description: TCP DLM transport has a severe straggler pattern at 3+ nodes — confirmed as TCP-specific, not present in CAW DLM
type: project
---

TCP DLM has a severe per-node throughput imbalance (straggler pattern) during concurrent sequential writes. At 4 nodes on tcm_loop, TCP showed 7.7x spread between fastest and slowest node. CAW DLM on the same hardware shows 1.01x spread (near-perfect balance).

**Why:** Root cause is in the TCP DLM transport, not in allocation, caching, or the filesystem itself. The CAW DLM (disk-based, SCSI Compare-And-Write) eliminates the straggler entirely, proving the issue is transport-specific. Likely causes: TCP lock grant serialization, head-of-line blocking, or keepalive/timeout interactions under concurrent lock traffic.

**How to apply:** This is a known issue to investigate and fix in the TCP DLM path. When benchmarking, always test both transports. Do not assume TCP and CAW DLM will perform similarly under concurrent multi-node writes. For production deployments where write balance matters, CAW DLM is currently the better choice.

**Evidence (Session 69, 2026-03-20):**
- CAW DLM 4-node new-file write: 130/129/129/129 MB/s (spread 1.01x, agg 517 MB/s)
- CAW DLM 3-node new-file write: 168/173/168 MB/s (spread 1.03x, agg 509 MB/s)
- CAW DLM 2-node overwrite: 346/351 MB/s (spread 1.01x, agg 697 MB/s)
- TCP DLM 4-node (prior data): 7.7x spread between fastest and slowest node
- All tests on tcm_loop (Samsung 870 1.8TB via LIO iblock, QEMU scsi-block passthrough)
