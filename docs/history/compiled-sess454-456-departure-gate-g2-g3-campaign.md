<!-- sess454-456: departure I/O gate G2/G3 build+STOP-SHIP rework to 0.61.1, D-0519 closed, D-0520 filed+fixed, D-0517 census/probes, review#5 NO-GO. -->
# Departure I/O gate (G2/G3) landing campaign — sess454-456 (2026-09-02, 0.60.0→0.61.2)

Central topic: building the mount-departure I/O accounting gate (token-per-buffer-I/O,
freeze/drain, CAS-guarded slot release) that makes MXFS PR-key retirement fail closed, plus
two riding defects (D-0519 recovery-latency false-fail, D-0520 fence-intent incarnation
adoption, D-0517 foreign-replay cluster-buffer clobber) surfaced by the same chain-of-boards
rig campaign. Chains 74-80 are one continuous, gated, detached pipeline; only one board runs
at a time and each stage rebuilds `mxfs.ko` and gates on the previous stage's DONE marker.

## G1 → G2 (sess454, 0.60.0 → 0.61.0)

0.60.0 landed G1: every `-EOPNOTSUPP → write_sector_fua` fallback in `dlm/disklock.c` made
fail-closed (ruling D7 companion — runtime CAW loss fails closed since TCP is already refused
for clustered RW at admission, sess448) — `hb_cas_own_slot`, `release_slot` RETIRE_PENDING
stamp, withdraw stamp CAS, `recov_cas_durable`, guard lay/refresh/zero, all tagged
`P304-CAS-NOCAW`. D-0518 closed F&V on this build. Chain 73's board was clean except the known
D-0401/D-32NODE-SHARED-DIR-CREATE-PACE timeout.
`docs/history/docs/history/docs/history/compiled-sess454-456-departure-gate-g2-g3-campaign.md`

0.61.0 landed G2 (rulings D1/D6/D8): a departure mutex moved into `scsipr` (re-entrant by
pid, every PROUT wrapped); `mxfs_scsipr_settle_absent` = fresh CAS bracket with a single-use
proof token; probe_stop bounded to 5s then quarantined (module pin, never silently dropped);
a v5 retire-worker thread drives settle→CAS→disklock retire, stopped bounded everywhere it's
torn down, and mount refuses under quarantine.
`docs/history/docs/history/docs/history/compiled-sess454-456-departure-gate-g2-g3-campaign.md`

Chain 74 on 0.60.0 initially looked like a regression: joiner/unknown FAIL with fence
certified but `P163-RECOVERY-COMPLETE=0` after 150s (was 93s on 0.59.3). Root cause proven
FALSE: the harness's `count()` only read the `MARK=count` header, and
`P163-RECOVERY-COMPLETE` was never listed in `$MARKS` — always read as 0. Direct log-sweep
evidence showed recovery actually completed in 6.3s. **Lesson: a harness that "FAILs" against
its own incomplete mark-list is a harness bug, not a regression — verify what the counter
actually counts before trusting the verdict.** MARKS fixed to include the missing patterns.
D-0519 marked fixed pending final evidence.
`docs/history/docs/history/docs/history/compiled-sess454-456-departure-gate-g2-g3-campaign.md`

## G3 design and first landing (sess454 end → sess455)

G3 (rulings D2/D3/D4) design: a per-mount spinlock over `{departure_stage, buf_io_inflight}`;
`xfs_buf_submit_bio` after FROZEN is rejected (`io_after_freeze=true`, completed -EIO through
the normal ioend path exactly once), else counted; completion decrements under the lock and
wakes a waiter at zero; underflow marks the mount `m_mxfs_iocnt_corrupt` and is **never
clamped or repaired**. Ordering: unmountfs+flush → FROZEN → drain → freesb/workqueues/
shutdown_devices (gate still rejects into DIRTY) → quiesced check → release CAS → post-flush →
late unregister.

Session ended mid-implementation: `xfs_mount.h`/`xfs_buf.h`/`pal/linux/xfs_buf.c` landed
(new `mxfs_depart_acct` struct replacing the old scalar fields), but `pal/linux/xfs_super.c`
was untouched — **tree did not compile**, with a precise 6-item TODO left for the next session
(acct alloc, `mxfs_departure_quiesced`, put_super stage/drain/reorder, mount-unwind path,
`xfs_mount_free` acct put, D4 late-completion test knob).
`docs/history/docs/history/docs/history/compiled-sess454-456-departure-gate-g2-g3-campaign.md`

sess455 finished the landing: `xfs_super.c` freeze/drain/reorder, orphan-buffer check, the D4
synthetic late-token injector, and two new settle-arm tests (`slowrace`, `latecomp`).
`docs/history/docs/history/docs/history/compiled-sess454-456-departure-gate-g2-g3-campaign.md`

## GPT STOP-SHIP on the G3 implementation (sess455)

RULE-5 review of the just-landed G3 code returned **STOP-SHIP**, 10 required changes — the
single most consequential ruling in this campaign:
1. Drain must **wait uncapped** for real tokens (a capped-then-proceed drain touches freed
   `bp`/`mp` on a late real completion); only the `corrupt` path may abandon after one bounded
   round.
2. Token retire must happen at **terminal completion points only**, never before an
   error/retry disposition — a resubmit must carry the same token, not re-take it.
3. Post-freeze **rejected** generations must be accounted separately from admitted ones and
   discounted first, because concurrent submissions on one buffer are real in this tree.
4. The drain must also wait for `rejected_pending == 0` (async completions route to
   `m_buf_workqueue` and are otherwise invisible to it).
5. An orphaned buffer (`xfs_buf_free` with live tokens) must **keep** the acct reference
   (deliberately leaked) rather than drop it.
6. Every decrement must be checked against `inflight > 0` before applying — no silent
   underflow.
7. The departure mutex must be taken **after** `xfs_shutdown_devices`, not around workqueue
   destruction, or a worker issuing a PR OUT deadlocks against it.
8. The late-token injector must be list-based under a spinlock, not a singleton unlocked
   pointer (that shape was a UAF on exit).
9. **Honest test labeling**: a real post-freeze `xfs_buf` late completion is structurally
   impossible on a healthy unmount (every in-flight buffer holds `b_hold`, and
   `xfs_buftarg_drain` already waits) — the synthetic-token test proves the drain *waits*
   (renamed arm `latewait`), not that late I/O is tolerated.
10. A post-CAS flush failure must be worded as "release durability uncertain; key retained
    so peers expire and fence" — not treated as failure.
`docs/rulings/g3-gate-impl-stop-ship-10-items.md`

## Rework to 0.61.1 and D-0519 closure (sess455)

All 10 items landed same session: token-take moved to the top of `xfs_buf_submit_ex`; retire
moved to terminal-only sites (`__xfs_buf_ioend` + the transient-error exit of
`xfs_buf_ioend_handle_error`) with a `b_mxfs_io_carry` flag for resubmits; rejected-generation
counting added (`b_mxfs_io_rejected` / `acct->rejected_pending`), overflow at 255 rejects and
corrupts rather than saturating; orphan path keeps the ref; drain uncapped in 2000ms rounds
(`P304-RETIRE-DRAIN` / `-DRAIN-STALL` / `-DRAINED`, `-DRAIN-ABANDONED` only after corrupt);
departure lock moved past `xfs_shutdown_devices`.

Chain 77 (0.61.0, pre-rework) exposed a harness bug in the new `slowrace` arm: the arm paused
peers but not the victim's own-key path, so the victim won the race in under a second instead
of exercising the intended key-reuse race — **redesigned** to pause peers 8s and remount the
victim at +3.5s.
`docs/history/docs/history/docs/history/compiled-sess454-456-departure-gate-g2-g3-campaign.md`

Chain 77 completion: **D-0519 CLOSED FIXED AND VERIFIED** (chain 76 evidence: 12/12 laps,
fence→RECOVERY-COMPLETE latency 0-1s vs 93s prior, P163-FENCED-SEEN on 29-30 peers). Two more
harness bugs found and fixed here:
- **TRAP**: kernel logs PR keys as unpadded `0x%llx` (e.g. `0x7fca569fb753541`); `chk_mxfs
  --pr-keys` prints 16-digit zero-padded hex. An exact-string comparison between them silently
  drops any key whose value happens not to need all 16 digits — normalize both sides
  (`printf '0x%016x'`) before comparing, never compare raw.
- The `trunc` arm only armed the one-shot fault on peers that queued the record bracket (half
  the fleet under the 0.61.0 worker model), leaving the other half's RESV-FAIL path
  unexercised — fixed by arming on every peer.
Test budgets in `tests/sess452_chain71_retire_pending.sh` were tightened from measured walls
(78-111s) down to 100-230s per arm.
`docs/history/docs/history/docs/history/compiled-sess454-456-departure-gate-g2-g3-campaign.md`

0.61.1 built in tree (sv `5AF0FCA5`), chain 78 launched (6 settle arms including new
`latewait`, then 12 RETIRE_PENDING laps, then the full 32/caw board). D-0517 (foreign-replay /
inode-cluster-publish-without-authority) census resumed from where sess448 evidence left off;
D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO flagged as possibly a **sweep-list gap** — chain 61's
probe never grepped the actual refusal patterns (`P238-FENCE-ZEROINC`,
`P238-FENCE-NOINTENT`), so "silence" may never have meant "didn't fire."
`docs/history/docs/history/docs/history/compiled-sess454-456-departure-gate-g2-g3-campaign.md`

## D-0520 and D-0517 progress (sess456)

Chain 78 passed 6/6 settle arms; D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO's "silence" confirmed
as a probe sweep-list gap (fixed by rewriting `tests/incarnation_mismatch_probe.sh` with full
capture). New defect filed and fixed same session: **D-FENCE-INTENT-ADOPTS-SECTOR-
INCARNATION-GUARDS-UNOBSERVED-SUCCESSOR (D-0520, high)** — chain 61's nonzero-incarnation
GUARD at t+0.5s named a successor epoch E2 while E1 was still the one declared dead; fixed in
`dlm/disklock.c mxfs_disklock_recovery_fence_intent` with a supersession predicate
(`P237-FENCE-SUPERSEDED` when the epoch advanced legitimately vs `P237-FENCE-INC-MISMATCH`
otherwise, plus `P237-FENCE-DESC-FOREIGN` for a mismatched descriptor tuple) and a
corresponding arm in `dlm/v5_mount.c`. Landed as 0.61.2, gated behind chain 79.
`docs/history/docs/history/docs/history/compiled-sess454-456-departure-gate-g2-g3-campaign.md`

Chain 78 finished clean (12/12 laps, board 15 rows with only the known
crash_consistency pace timeout). D-0517 census completed: the create's on-disk data survived
to the kill and was overwritten later by recovery — two candidate mechanisms, H1 (an older
whole-cluster **buffer** image replayed because the buffer recovery path has no per-slot
change-count check, only class-3 token check) and H2 (a peer holding the same AG republished a
stale cached cluster). Root-cause instrumentation landed for chain 80: `P-DINO-CLOBBER`
(pal/linux/xfs_buf.c, knob `mxfs.dino_clobber_check`) and `P-FR-DINO-BUF`
(pal/linux/xfs_buf_item_recover.c, `cached_before` via `xfs_buf_incore` before the replay's
`xfs_buf_read`). Key fact confirmed by code reading: the buffer-recovery pass-2 handler
(`xlog_recover_buf_commit_pass2`) reads through the live replayer's cache with no freshness
flag and an LSN-skip that is cross-slice-meaningless; ICLUS grant never invalidates the cached
cluster buffer (only the iget-miss ladder does).
`docs/history/docs/history/docs/history/compiled-sess454-456-departure-gate-g2-g3-campaign.md`

## Review #5: NO-GO (sess456)

RULE-5 review of 0.61.1 (G1+G2+G3 together, with chain 77/78 evidence) returned **NO-GO**.
Of the review-#3 conditions: 4 and 6 MET; 1,2,3,5,7,9 PARTIAL; **8 (I/O gate fails closed on
any accounting violation) UNMET** — the STOP-SHIP finding. D-377 and D-0356 both left
PARTIAL/NO-GO.

STOP-SHIP: an `untokened` terminal completion (no token, no pending rejection — provenance
unknown) is currently only observed, not rejected. `mxfs_departure_quiesced()` must treat
nonzero `untokened` as blocking release (mount stays dirty/key-retained), with either the
default of marking the whole account CORRUPT on any unclassified untokened completion, or an
explicit audited "no-I/O software completion" class with everything else corrupt.

High-severity gaps requiring deterministic (not incidental) test arms before the gate can be
called proven: (1) a genuine post-freeze rejection through `submit_ex`, (2) a transient-error
retry-carry exercising exactly one token across two attempts, (3) an orphan buffer carrying
`rejected_pending`, (4) the 255-boundary overflow/underflow case, (5) a submission injected
during freesb/workqueue-destruction/device-shutdown (the FINAL assertion, not the drain, must
be what blocks release there). Also unresolved: the release/unregister crash invariant needs a
full per-cut state table (does the release CAS image still *name the key*, or does it go
anonymous?) rather than a single "pr_restamp crash PASS." Uncapped drain itself was ruled
**not** a blocker.
`docs/rulings/review5-0611-no-go-untokened-failclosed-6-conditions.md`

## Recurring failure modes across this campaign

- **A harness "FAIL" is not evidence of a regression until the counting/marking logic is
  checked** — two of three chain-77/78 "failures" (unknownresv, trunc) and one of chain-74's
  (the MARKS omission) were all harness bugs, not product defects.
- **Never trust an exact string/hex comparison between two tools that format the same value
  differently** (kernel unpadded hex vs `chk_mxfs` padded hex) without normalizing both sides
  first.
- **GPT RULE-5 review of an as-landed implementation, not just the design, caught real
  concurrency/lifecycle bugs the design ruling didn't** (rejected-generation double-counting,
  orphan UAF-adjacent ref-drop, lock-ordering deadlock) — implementation review is a distinct,
  necessary step from design review in this workflow.
- Chains rebuild `mxfs.ko` at each gated stage and must never be rebuilt while a prior chain
  is still running — every stage's launcher checks the srcversion changed before proceeding.
