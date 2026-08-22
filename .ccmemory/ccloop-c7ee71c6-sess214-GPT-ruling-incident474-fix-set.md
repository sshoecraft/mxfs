---
name: ccloop-c7ee71c6-sess214-GPT-ruling-incident474-fix-set
description: sess214 RULE-5 ruling (gpt-5.6-sol): hole(b)=b2+b3+recovery-barrier as ONE unit, NO general lock steal; hole(c)=c1+c2 progress cookies; armA=a1 autho…
metadata:
  type: project
tags: [incident474, rule5, recovery, cascade, authority]
---

# sess214 RULE-5 ruling — incident474 containment fix set (gpt-5.6-sol)

Full text in sess214 transcript. Key points, implementation-binding:

## Hole (b) — recovery ordering deadlock: ship as ONE "recovery containment package"
- **b2 PRIMARY**: strict phase split. Fence+certify all victims -> recovery barrier/epoch -> replay ALL pending victim slices (pure buffer-level replay only, NO lock-taking sweeps between slices) -> durably mark each replay-complete -> purge grants -> THEN run all deferred sweeps (adopted-bucket etc.) -> leave barrier. New victim certified mid-batch: add to replay phase or start new epoch.
- **b3 MANDATORY backstop**: elected replayer NEVER self-withdraws on lock timeout while victim recoveries pending. Timeout path must CLASSIFY holder: certified-fenced+replay-pending -> redirect to recovery ordering (replay that victim next); certified-fenced+replay-complete -> purge stale grant + retry; live-unserviceable -> serviceability policy; live+progressing -> bounded retry; unknown gen -> stop epoch, reconcile. b3 WITHOUT b2 = permanently stuck replayer — must land together.
- **b1 (general steal) REJECTED**: fencing proves no-future-writes, NOT crash-consistency of grant-protected metadata pre-replay. Never publish a stolen grant to ordinary threads. Only a narrowly-scoped "replay bypass / recovery revocation" is safe: certified-fenced holder + caller is elected recovery context + operation is buffer-level replay ONLY + grant stays RECOVERY_BLOCKED, never becomes ordinary EX.
- Audit replay call graph: pure replay must not enter ordinary DLM acquisition; add WARN_ON_ONCE assertions.
- Recovery claims + replay-complete markers must be durable + epoch-tagged (replacement replayer idempotency).

## Hole (c) — c3 (=c1+c2), staged rollout
- c1 serviceability states in HB record: SERVICEABLE/WITHDRAWING/UNSERVICEABLE/RECOVERING(/FENCED). Advisory only (hard wedge may never write it).
- c2 progress must be holder+grant-specific: gen/mode/mask don't change while held, so "record changed" is NOT progress. Needs per-holder acquire cookie + bast_request/ack seq + owner_progress_seq bound to exact grant incarnation (anti-ABA on slot reuse). Owner progress = txn commit / log force / AIL item advanced / iflush advanced / unlock entered — HB thread beat is NOT progress; DLM daemon ack alone is NOT progress.
- Extension policy: no verified progress = no extension; bounded increments; absolute max deadline; on expiry escalate against the NONPROGRESSING HOLDER, not the waiter (esp. when waiter is recovery coordinator). Rollout: telemetry first, then gate extension.
- If hot CAW slot too expensive for progress counter: separate disk mailbox/service record.

## Arm A — a1 as authority-epoch state machine ("authority package", ship together)
- ifree after authority loss NEVER defensible. dlm_locked=1 is a reference, not authority.
- States AUTH_EX_OPEN -> AUTH_CLOSING -> AUTH_NL + authority_epoch + active_auth_txns count.
- Op start: verify actual EX mode + AUTH_EX_OPEN, capture epoch, inc active_auth_txns, RECHECK, then dirty/commit. Commit-time assert epoch still owned.
- BAST release: EX_OPEN->CLOSING atomically, block new auth-txns, wait active ones drain, capture last auth LSN, force+drain, on-disk release, ->NL, epoch++.
- Post-release inactivation: abort/requeue if not yet dirtied; to continue, REACQUIRE EX (never while holding ILOCK), revalidate, restart. Boolean b4_noauth fix alone insufficient — must close release-vs-new-txn race.
- a2 also needed for cross-pair wait: HARD RULE no blocking remote DLM acquire/CAW poll while holding ILOCK (inspect->drop ILOCK->acquire DLM->re-ILOCK->revalidate->restart). Skipped AIL item != drained; skip reasons must be visible state.
- a3 containment OK only if EX stays held, no unlock, no free/reuse, not mistaken for completion.

## Priority order
1. b2+b3+barrier (terminal collapse mechanism) 2. a1 authority machine 3. a2 ILOCK rule 4. c3 5. a3.
