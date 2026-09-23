<!-- sess465 RULE-5 ruling on the D-0524 pubob race fix: entry-authoritative under the pubob lock, in-flight token consumed under lock, exact predecessor… -->
# sess465 GPT ruling — D-0524 (free_commit vs 'flushed' discharge lost update)

Verdict: proposed (a)+(b) fixes the reported race but NOT stop-ship complete. Ranked:

- S0-1 Lockless readers get no coherent snapshot even if writers hold m_mxfs_pubob_lock. Make the STORE ENTRY authoritative for ALL decisions: copy-in takes the pubob lock, reads the entry kind, publishes an explicit in-flight token {NONE, UNLINK_INFLIGHT, FREE_INFLIGHT}; completion takes the lock and CONSUMES the token while rechecking the entry; gate reads/promotes under the lock. i_mxfs_freeob = diagnostic cache only. Audit lock order buffer lock/ILOCK -> pubob lock vs gate/reclaim/P55C.
- S0-2 Gate radix lookup must pin the inode (RCU + i_flags_lock reclaim exclusion / reference), revalidate ino/gen/mount/entry kind/committed after pinning; never hold the pubob lock while taking inode-cache locks/ILOCK unless order proven. Reclaim-refusal ordering: install entry, then publish reclaim-blocking flag with release semantics; discharge retires entry+token before allowing reclaim.
- S0-3 free_abort cannot blindly restore UNLINK: record the predecessor {UNLINK | NONE | CHAIN_LIVE(+chain/gen/epoch)} when entering FREE_PENDING and restore EXACTLY that on a definitely-uncommitted abort. Uncertain commit outcome / shutdown: do NOT downgrade — fail closed.
- S0-4 Successful ifree must never end without a FREE entry: FREE_PENDING->FREE, UNLINK->FREE, absent->create FREE (preallocate; failure after committed difree = shutdown, not an error), FREE idempotent, CHAIN_LIVE/unknown = protocol failure.
- S1-5 Store pending_epoch at ifree start; gate self-heal requires pending_epoch == releasing tenure epoch AND committed proof; mismatch/orphan/ambiguous = immediate fail closed. Never assign 'whatever epoch is current'.
- S1-6 xfs_iflush_abort / error iodone: clear only the in-flight flag+token, never touch the entry; discharge only on SUCCESSFUL durable completion; shutdown: retain, no free_abort for a possibly-committed outcome.
- S1-7 'superseded' must carry the same proof as a FREE completion (durable mode=0 at home); a why-string cannot authorize dropping FREE.

Orderings enumerated as correct with the fixes (UNLINK completion before ifree; copy-in before ifree + completion during pending -> stale token cleared; commit before old completion -> stale; FREE copy-in after commit -> discharge; copy-in in post-commit/pre-free_commit gap -> conservative, P55C flushes later). Two images in flight impossible ONLY if: same buffer object, copy-in needs the buffer I/O lock, no second token until the first completion consumed it, completion iteration finishes before buffer reuse, abort/error consume the token — assert/document.

Q5: FREE_PENDING at the gate is ALWAYS failed bookkeeping (a genuine ifree holds the AG EX; the gate cannot run) — no 20 s defer. Gate by kind: UNLINK audit nlink=0 durable; FREE mandatory P55C flush then discharge; FREE_PENDING + committed proof + matching epoch -> loud tripwire, promote, audit same lap; FREE_PENDING without proof / orphan / epoch mismatch -> immediate fail closed; CHAIN_LIVE existing rule; unknown -> fail closed.

Tests to add beyond the fault-injection knob: absent predecessor, abort during stale completion, I/O error/iflush_abort, post-commit/pre-free_commit copy-in, entry allocation failure, gate/reclaim race, epoch mismatch.
