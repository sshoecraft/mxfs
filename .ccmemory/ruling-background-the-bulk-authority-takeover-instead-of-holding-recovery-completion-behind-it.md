---
name: ruling-background-the-bulk-authority-takeover-instead-of-holding-recovery-completion-behind-it
description: Design consult ruling (Astra, 2026-09-17, D-0962): recovery completion need not wait for the bulk page takeover; the barrier is "old incarnation fenc…
metadata:
  type: reference
tags: [ruling, dlm, tauth, ledger, recovery, D-0962]
---

# Ruling: recovery completion must not wait for the bulk authority takeover (D-0962)

Consult answered 2026-09-17. Shape: after a peer dies, the survivor's recovery
completion runs `v5_handoff_takeover` inline — a page-by-page transfer of every
ledger page the dead incarnation owned, measured at **7984 pages × ~13 ms =
103-107 s**. `P163-RECOVERY-COMPLETE` and `P-PR-GATE-RESTORE` publish only after
it returns, so the survivor holds a single-holder Write Exclusive reservation for
that whole time and the rebooted victim cannot re-register or rejoin.

## Verdict

**The necessary barrier is weaker than "all pages transferred".** It is: *the old
incarnation can no longer write or grant authority, and every request to an
untransferred page has a safe, live takeover path.* Under those conditions the
bulk pass is **eager cleanup and latency prewarming, not recovery safety**, and
belongs on the departure worker.

Micro-optimising the per-page cost is the wrong target: "the main fix should
remove 7,984 unrelated pages from the rejoin critical path. Logging and I/O
optimisations then reduce background debt and first-access latency, rather than
being responsible for meeting the recovery budget."

## Why this is safe HERE (checked against the tree, not assumed)

Every precondition the ruling names already exists and was itself ruled on:

- **Priority on-demand takeover ahead of the pass** — `dlm_authority_settle_record`
  runs before the loop; a request on a settled incarnation's page takes that page
  over on demand (`P-TAUTH-TAKEOVER-ONDEMAND`). (sess588 ruling, item A.)
- **Progress-aware retryable wait** — `P960-AUTH-TRANSITION-WAIT/STALLED/NOQUEUE`,
  a 30 s no-progress bound, `-EREMCHG`/`-EAGAIN` as a retryable outcome rather
  than a shutdown. (sess588 ruling, item B.)
- **Admission gating, cancel only between page transactions, unbounded join at
  unmount, orphan sweep queued after every processed departure.** (D-0953 ruling.)
- **The safety-required purges already run BEFORE the takeover** in the completion
  (ledger purge, `mxfs_dlm_purge_node`, then the handoff), so backgrounding the
  sweep does not move a purge across the barrier — the specific mistake the
  consult warned about.
- **The queue mechanism exists**: `v5_depart_queue2(..., takeover_only=true, ...)`
  already puts a takeover-only job on the departure worker, used by
  `v5_settled_incarnation` and `v5_orphan_sweep_queue`.

## The hazard backgrounding CREATES, which the gate currently masks

`mxfs_dlm_handoff_takeover` checks `dlm_bootstrap_node(ctx) != ctx->local_node`
**once, at entry**. That is sufficient only because the held Write Exclusive gate
prevents the victim rejoining mid-pass. Background the pass and membership can
change under it: the returning node may become the eligible owner, or bootstrap,
while the old pass is still preparing/activating/purging pages.

Required with the move:

- **Revalidate bootstrap certification and page ownership per page**, not once per
  pass. The candidate bitmap is not authority (D-0953).
- **Pin recovery ownership** for the affected pages to the survivor for a recovery
  epoch, admitting the returning node without immediately rebalancing authority to
  it; rebalance by the ordinary handoff once pages are ready.
- **Identity is `(node, incarnation)`, never the node number** — the returning node
  must not reclaim its own previous incarnation's records, and a purge must never
  delete a newer incarnation's records because the numeric id matches.
- Audit whether the WE reservation is silently providing single-writer semantics
  for ledger updates. If "CAS-like" `mxfs_tauth_ledger_prepare` is only *locally*
  serialised, releasing the gate early opens a protocol hole.

## Load-bearing dependency

The progress-aware wait keys on `ctx->takeover_pages_done`. That counter is
currently incremented even when `mxfs_tauth_ledger_activate` fails, and the sess588
ruling already said "counters count completions once; ACTIVATE alone is not
completion". So a waiter can see progress on a pass that is transferring nothing.
**Fix the accounting before backgrounding** — see the defect record for
`dlm_takeover_page` counting a PREPARED-only page as taken over.
