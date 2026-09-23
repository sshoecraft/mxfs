<!-- sess488 RULE-5 ruling for D-0487 AIL pin: fail-stop right, refuse LOCKED no stale, coherent not-held snapshot, no tail condition, 10 s grace diagnost… -->
# GPT ruling on the D-0487 terminal behaviour (2026-09-04 ~06:33Z)

Proposal reviewed: stop staling in the skip arm, return XFS_ITEM_LOCKED, per-item
first/count accounting in the BLI, identity-rich P126, after T=10 s with AG still
unheld and tail unchanged -> P126-AIL-PINNED + xfs_force_shutdown(CORRUPT_INCORE);
same for bmbt; debugfs injector logging an unheld AGI unchanged.

Rulings:
(a) Fail-stop is right. A BLI may be deleted without home I/O only with positive
proof the exact logged incarnation is durable; the push has none (XBF_STALE,
equal contents, a prior xfs_bwrite, re-acquire, verifier pass are NOT proof).
"Written by drain then relogged" = a newer incarnation; iodone should delete,
a push-time deletion path hides a completion bug. Use SHUTDOWN_CORRUPT_INCORE
consistently with P131-INVAL-REFUSED. Legality must be based on the BLI's
immutable authority/identity, not only "node holds the AG now" (epoch-E image
must not become writable under epoch E+1).
(b) XFS_ITEM_LOCKED is the honest retry class (PINNED prompts futile log forces);
audit the fork's LOCKED consumers (item stays, no busy-spin, other items proceed).
The tail pinned for T is acceptable as a bounded diagnostic interval. Do NOT
assume shutdown removes the item — prove xfs_ail_push_all_sync exits after
shutdown on this fork and that teardown disposes the BLI; and that calling
xfs_force_shutdown from the push context is safe (it is not: ail_lock held ->
queue work).
(c) Remove the "AIL tail unchanged" condition — the tail can advance while the
refused item stays and later becomes the oldest; "still unauthorized after T"
suffices. Per-item state: first coherent mismatch, last diagnostic, count,
identity/LSN at first refusal, report-once flag; a re-log does not reset.
Wrap-safe jiffies.
(d) Injector: read the AGI through the normal transactional read (real verifier,
b_ops), bypass only the DLM authorization, log unchanged, commit, then a
SYNCHRONOUS log force so the item is not log-pinned when the timer starts;
choose an AG unheld by the injector and quiescent; the txn poisons the slice
(replay must refuse it) -> scratch FS only. Assert: BLI in AIL at expected LSN,
authority "no valid grant", not log-pinned after force, no home write,
terminal message once, push_all_sync exits by shutdown, teardown safe, replay
refuses, peer metadata unchanged.
(e) 10 s is operationally fine but "two orders" was wrong (it is four above 1 ms);
the real fix is a coherent authority snapshot (seqcount / single atomically
published state / epoch-before-after with retry) — the timer starts only from
a coherent not-held observation. Alert lands at T + max push retry interval.
bmbt arm: same policy, identity from owner/tenure, fail-stop not retry.

Applied in 0.69.6 (report only) + planned 0.70.0 (terminal). Coherent snapshot
implemented as epoch-before/hint/holders/epoch-after with epoch==0 (every
release-commit point publishes 0 before its unlock; the acquire publishes the
epoch then holders=1 under pag_dlm_lock).
