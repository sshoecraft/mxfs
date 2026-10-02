---
name: ruling-tauth-ledger-recovery-scan-cost-sparse-summary-first
description: Consult 2026-10-01: fix ledger recovery-scan cost with a crash-ordered sharded occupancy summary first; population sizing only after enforced bounds.
metadata:
  type: project
---

Design consult (GPT, 2026-10-01) on D-TAUTH-RECOVERY-SCANS-SCALE-WITH-LUN-SIZE-NOT-LEDGER-USE.

Facts going in: ledger pages hold 31 entries, a resource lives only on its home page (hash % npages), FREE tombstones are reusable unless open-holder marks pin them, page-full returns -EDQUOT and the requester waits with no forcing mechanism, and no per-node cap on cached grants exists. 1 TB: takeover scan 14.5 s, live_pages=1 of 541,201.

Ruling:
- Ship B first: an occupancy summary where bit = "page may hold anything recovery must inspect" (ACTIVE, UNKNOWN, pinned FREE, and for the orphan sweep any non-UNOWNED page authority). Order: set the bit durably BEFORE the page's first non-empty commit; clear it only AFTER a canonical empty page is durable. False positives are harmless; a false zero is corruption.
- The summary blocks need shadow copies + crc + seq and ONE serialized writer per shard (align shard ownership with page ownership), fencing and epoch checks across ownership moves. Two masters doing RMW on one summary block lose bits.
- An invalid summary shard falls back to scanning that shard's page range, not the whole ledger.
- Clear bits incrementally when pages go empty, or they saturate and scans go back to O(npages).
- A (size npages from nodes x records) is NOT safe alone until R_per_node is an enforced admission bound and page-full has a bounded answer (reserved slot, admission limit below 31, alternate placement, or a bounded failure). Seeded FNV is not collision resistant.
- The double orphan sweep: a fixed second pass is not a correctness boundary. Drop it only after instrumenting changes between passes and proving quiescence, or replace it with a barrier / dirty-page worklist.
Measure first: per-page occupancy high-water broken down by reclaimable vs not, 0->1/1->0 rates, page-full events with holder identities, and the actual hash histogram.
