---
name: trap-routing-ledger-authority-transitions-through-the-group-commit-is-slower-on-drbd-than-one-span-swap-each
description: TRAP (0.90.109, measured): prepares/activations through tauth_group_commit batched ~7 pages but cost 21 ms/page vs 13-17 one span swap each. Reverted.
metadata:
  type: feedback
tags: [trap, drbd, ledger, group-commit, performance]
---

A ledger authority transition (mxfs_tauth_ledger_prepare / _activate → lpage_write_fresh_locked) writes the page with ONE span swap on DRBD (store span_commit: compare sector 0, write the whole 4 KiB page, in one acquisition of the pair's swap lock).

The group commit (lpage_write_grouped, tauth_group_commit=1) uses the TICKET protocol instead: a ticket-swap wave, a body scatter, then a publish-swap wave. That is TWO lock acquisitions per batch.

Measured on the physical pair (0.90.109, tests/pve_depart_wall.sh, evidence tests/evidence/pve_depart_wall/20261009T042820Z):
- departure transitions routed through it batched about 7 pages (gc_batches=139, gc_pages=973);
- the hand-off cost 20.8-21.9 ms a page, against 12.7-16.7 ms a page at one span swap each;
- per acquisition: enter ~3.4 ms, wait for the peer ~14 ms, critical section 14-21 ms, release ~5 ms.

The change was reverted. On DRBD the cost lives in lock acquisitions, which involve the peer, not in barrier count, so batching that doubles acquisitions loses.

Also from the same runs: the swap server saw swaps=512 batches=512 for a departure with 8 worker threads, so concurrent callers were NOT reaching the swap together. Look upstream of the swap (the instrument: P-TAUTH-DEPART worker_ms drain/prepare/send, peak_inflight) before trying to batch at the swap.
