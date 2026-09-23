---
name: ruling-joiner-during-authority-takeover-priority-service-progress-aware-wait-staged-mount-abort
description: Design consult ruling (Astra, sess588, D-0960/D-0352): A priority on-demand takeover + B progress-aware wait as a distinct retryable outcome + C stag…
metadata:
  type: reference
tags: [ruling, dlm, tauth, ledger, mount, D-0960, D-0352]
---

# Ruling: a lock request on a page whose dead authority a live bootstrap is taking over (D-0960, D-0352)

Consult answered 2026-09-12 (sess588). Shape: a joiner's root-inode request lands on a page under the last leaver's dead incarnation while the bootstrap's takeover-only pass (~15k pages, minutes) runs; REMASTER answers exhaust the 60-retry loop in ~18 s and the XFS classifier's arm (3) shuts the node down.

## Verdict
A (priority service) fixes latency; B (progress-aware waiting) fixes retry semantics; C (mount abort) fixes abort semantics. **A alone must not close the defect**; ship A+B plus transition-aware mount abort, keep fail-stop for genuine safety failures.

## A — priority takeover of requested pages
- Only if page-index order is incidental (audit: no cross-page dependency in prepare/activate/purge/import; serialize the whole per-page transaction, not just ledger writes).
- Re-validate authority/incarnation and bootstrap certification when servicing a queued request; "unreachable" alone never authorizes a takeover.
- Dedupe, bound the set, fair scheduling; the receive thread only enqueues/wakes.
- The sequential scan skips already-serviced pages safely; counters count completions once; highest index activated is NOT a completion watermark; the orphan sweep still needs the whole cohort; keep D-0953 cancellation between transactions.

## B — progress-aware wait
- A distinct retryable "authority transition" outcome, not a blanket REMASTER exemption; requires a validated dead/settled predecessor AND a live certified bootstrap.
- Progress must be causally tied to eventual service of THIS page: own-page-only is too quiet for a sequential pass; any-page can hide starvation. Use a stable pass identity + monotonic completion of the work ahead of this page (or, with priority service, the target transaction's progress / advancement of the bounded queue ahead). Count distinct completed transactions, never repeated reads, heartbeats, request ACKs or max page index; ACTIVATE alone is not completion.
- A 30 s NO-PROGRESS watchdog is policy; its expiry means "transition stalled, retryable failure", never corruption, never membership escalation — and that classification must survive both the 60-retry loop and the 4-attempt XFS wrapper. The wait must be cancellable and hold nothing the takeover needs. Bootstrap change → re-validate, not an endless reset.

## C — mount abort
- An explicit mount lifecycle/abort state covering all acquisition paths, not a root-iget special case — but NOT "mounting ⇒ bypass safety handling".
- Not VFS-published ≠ no distributed effects: heartbeat membership, slice ownership, PR registration already exist and replay may have written the LUN. Staged abort: stop new work + quiesce, release locks / settle journal and recovery obligations, then leave membership and release slice/slot/PR in the protocol's order. Never unregister protection while writes or recovery obligations remain; replay cannot be unwound; if safe cleanup is impossible the existing containment/fencing stays.
- The state already reached, not the lock's name, decides the cleanup.
