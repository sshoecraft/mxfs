---
name: ruling-tauth-recovery-cost-is-flush-amplified-takeover-batch-it-first
description: Consult 2 (2026-10-01): ledger recovery cost is per-page takeover flushes (~9 ms/page, 75 s at 20 GB/8 nodes); batch with 2 barriers first, range aut…
metadata:
  type: project
---

Supersedes the first consult's "occupancy summary first" (ruling-tauth-ledger-recovery-scan-cost-sparse-summary-first), whose premise broke on two facts: pages never return to UNOWNED, and an 8-node board left 79% of a 20 GB ledger owned (orphan sweep cand=8785, prepared=8017, scan 406 ms, total 75,063 ms; takeover 708 pages in 8,221 ms => ~9 ms per page, each its own durable shadow write + flush).

Ruling (GPT, 2026-10-01):
1. C now: batch authority transitions. Order per chunk: fence the old authority (durable view/membership), write PREPARED images, FLUSH, write ACTIVE images, FLUSH, only then serve grants. Two barriers per batch, never one at the end (device may reorder). PREPARED must carry transition identity (target, epoch/view, transition id) or be deterministically resumable. Per-page seq picks the image; writer legitimacy needs epoch + durable membership. Crash-inject every point; takeover must be idempotent.
2. D (range/view-table authority) is the only asymptotic fix: O(ranges) not O(pages).
3. B (release empty pages) only if measured cold-empty fraction justifies it; use a new FREE state, not mkfs UNOWNED; freeze/drain/recheck/write/flush before release; FREE-with-records is never legal; hysteresis against thrash.
4. A (small npages) only after a page-full/overflow design; without it A trades recovery time for liveness.
Measure first for C: decompose the 9 ms (PREPARE write, flush, ACTIVATE write, flush, read/validate, locking, retry) and sweep batch sizes 1..2048.
