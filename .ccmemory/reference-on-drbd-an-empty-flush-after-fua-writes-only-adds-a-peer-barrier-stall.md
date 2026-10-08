---
name: reference-on-drbd-an-empty-flush-after-fua-writes-only-adds-a-peer-barrier-stall
description: DRBD 8.4: FUA write completes once the peer's disk holds it; empty flush = local flush + P_BARRIER the peer drains at. Dropping 3 ledger flushes cut…
metadata:
  type: reference
---

On DRBD (8.4, protocol C) a FUA write is replicated as DP_FUA and acknowledged only once the peer's disk holds it, while an empty flush (blkdev_issue_flush) completes on the LOCAL flush alone and is sent to the peer as a P_BARRIER, at which the receiver drains every outstanding peer write and flushes (wo:f). So:

- a flush after a FUA write on DRBD makes nothing more durable on either host, and
- it stalls the NEXT replicated write behind the peer's barrier drain.

Measured 0.90.103 on the physical pair (tests/pve_ledger_commit_profile.sh, 100 fsynced creates): the ledger page commit's three flushes were only 2-3 ms each when idle, yet removing them (store fua_durable on DRBD) cut commits from 36-77 ms to 20-27 ms and the emulated swaps from 13-38 ms to 11-17 ms; create totals 5.2-7.5 s -> 2.5 s. The flush's own latency understated its cost.

Corollary: a plain write + empty flush is NOT durable on the DRBD peer; batched writes that relied on that (tauth page_write_many) must use FUA there.

Measurement trap seen at the same time: the first create runs after a pair update carried the post-remount ledger takeover (600-1200 page writes per 100 creates); compare runs only when page_write calls are back to ~0.4-0.6 per create.
