<!-- sess425 RULE-5 ruling (D-0341): txn-scoped PENDING_RELEASE bypass + re-scan on every retirement; master re-commits release alone; never ACK OK while… -->
# sess425 RULE-5 ruling — concurrent-release DOUBLE-GRANT page wedge (D-0341)

Evidence brought: deterministic usermode repro (tests/tauth/concurrent_release_test) of the 0.35.0
32/tcp wedge: promote_waiters ignored EVERY PENDING_RELEASE holder → EX decided over a sibling's
durable bit → bundle [REL, GRANT] refused -EBUSY → release entry stranded PENDING_RELEASE, releaser's
retry ACKed OK as "duplicate" → page never drains (FREEZE-DRAIN-TIMEOUT), all EX blocked.

## Ruling (GPT, verbatim gist)
(a) (1)+(2) sound: ignore a PENDING_RELEASE only when its exact entry/gen is a release item of the
txn being built; every other PENDING_RELEASE blocks with its durable mode; PENDING_DURABLE blocks.
Re-scan rule: EVERY terminal retirement (local, remote, bundled, release-only fallback) removes the
entry under the table write lock and THEN runs promotion; the last of concurrent finalizers sees all
earlier removals — no lost wakeup. "Every retirement triggers promotion" is the clearer invariant.
-ESTALE counts as retired only if it proves this holder incarnation is absent/superseded (grant-id keyed).
(b) Master re-commits the release alone on a definitive grant-attributable refusal; deny/roll back the
grants; retire on readback or proven -ESTALE; trigger promotion. If release-only also fails
(IO/ambiguous), keep PENDING_RELEASE attached to a MASTER-owned retry/reconcile item — never wait on
the client. Duplicate handling: a retry finding PENDING_RELEASE must attach/kick or say "still
pending", never ACK OK; ACK OK only once durable retirement or supersession is known.
(c) Invariant: every PENDING_* entry has exactly one live master-owned driver. Audit list: ambiguous
commit outcome (reconcile, don't free/deny); worker/alloc/shutdown/remaster failures hand pending work
to recovery; refused conversion restores prior GRANTED mode; cancel/release during PENDING_DURABLE;
multiple release items all driven; master restart reconciles in-flight ops by ledger ids; freeze
barrier before drain test but keep commit/retry workers running; delivery failure after a durable
grant → master must revoke/release, not discard.

## What landed (0.35.1, dlm/dlm.c)
promote_waiters(…, txn) + dlm_txn_retires; dlm_promote_txn re-scan when `retired`; refused bundle →
ack_deferred + dlm_txn_recommit_releases; dlm_mark_release_stuck (lk->rel_id/rel_remote/rel_failed_ms,
P-TAUTH-RELEASE-STUCK) + dlm_release_redrive_tick from mxfs_dlm_release_retry_tick; process_remote_release
PENDING_RELEASE branch: no ACK, re-drive if stuck; MXFS_ERR_LEDGER_BUSY (appended) → MXFS_DLM_RETRY;
P-TAUTH-DLM-STATS at release_all. Ledger knobs: commit_delay_once_ms, refuse_grant_once,
fail_commit_once_rc + fail_commit_skip. Probe: mxfs_dlm_page_pending_count.
