---
name: ruling-departure-worker-teardown-cancel-between-pages-unbounded-join-no-quarantine-by-deadline
description: Design consult ruling (Astra, sess586, D-0953): cancel a bulk page takeover only between pages; normal unmount joins the worker unbounded; a deadline…
metadata:
  type: reference
tags: [ruling, dlm, tcp, teardown, takeover, D-0953]
---

# Ruling: stopping the departure worker's bulk page takeover at unmount (D-0953)

Consult answered 2026-09-12 (sess586) on the fix for the use-after-free panic in `dlm_page_now_mine` (survivor unmounted inside a minutes-long takeover of a dead authority's ledger pages; teardown ignored the worker's 30 s join timeout and destroyed the engine under it).

## Verdict
- **Cancellation boundary = page-transaction boundary**: before starting another page, after the previous page reached a completed or explicitly responsibility-transferred outcome. Never propagate -EINTR into a page's substeps (prepare → activate → mark MINE → purge → import; or PREPARE + FROZEN hand-off to a remote owner).
  - untouched page under a dead authority: safe to leave frozen (recoverable by sweep/on-demand).
  - PREPARED(target) durable, not activated: safe only if a mechanism completes it while the target is LIVE (our departure does not make a live peer dead). In MXFS the target consumes PREPARED-to-it at its next request on the page (dlm_page_acquire), so a lost FROZEN message is not stranding — but verify per shape.
  - ACTIVE(us) before purge/import: the most dangerous local window; finish the page, never "undo" it.
- **Normal unmount joins the worker WITHOUT bound** (precedent: unmount waits for own parked fence/recovery work). Keep the 30 s as a diagnostic (SLOW line), never as permission to continue destruction. A wedged LUN hanging unmount is recoverable; a UAF is not.
- **Quarantine is valid only with the entire dependency closure retained**: engine, tables, ledger + device refs + I/O completions, slot map, transport/send buffers/ACK handlers, mutexes, mount ctx, and anything outer layers release after the teardown hook returns. Module pinning protects code, not objects. Also a PROTOCOL quarantine: a stuck worker must not keep mutating the ledger under an incarnation whose storage authority (PR key) was already relinquished — retaining memory while allowing stale-incarnation writes swaps a UAF for ledger corruption.
- **"Begin departing" means close admission**: gate EVERY takeover entry point (worker, orphan sweep, on-demand, receive-side hand-off, retries), not just the worker; a transaction admitted just before the gate closed is waited for. Own-authority freeze/hand-off enumeration must run AFTER the join (verified in MXFS: v5_depart_worker_stop precedes mxfs_dlm_handoff_depart).
- **Frozen pages after an interrupted pass are a liveness hazard for a survivor that stays mounted** (the sweep ran only at mount settle). Add a guaranteed trigger — membership-change reconciliation (MXFS: queue the orphan sweep after every processed departure). "Someone might remount" is not survivor liveness.
- Candidate bitmap is not authority: each page transition must revalidate ledger authority + membership (dlm_takeover_page re-reads and uses conditional ledger writes).

## Verification it required (beyond "no panic")
Prove overlap (pass in flight when unmount starts; remaining count > 0 on the interruption line); the old build's STUCK + panic as control; recovery of the left pages by the next bootstrap's sweep AND by a survivor that stays mounted (two different laps); pauses at each dangerous boundary (post-PREPARED, post-ACTIVE, post-send) before departing; a releasable >30 s I/O delay to exercise the unbounded-join policy; conflicting lock requests across recovery; requests parked before the cancellation and after. False passes: unmount after the pass finished; freed memory still mapped; quarantine mistaken for cleanup; a remount healing what strands a mounted survivor.
