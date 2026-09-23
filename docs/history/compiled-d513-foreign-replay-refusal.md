<!-- D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513 (#90): sess320-337 discovery, GPT containment design, 4 review/stop-ship cycles 0.12.0-0.12.4, sess3… -->
## D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513 (ledger #90), sess320-337

### sess320 — discovery: a refused foreign replay kills the whole cluster
0.11.513, 32/caw, `fence_during_write`: victim slot=3 killed mid-write holding EX on a
shared dir. test1 elected replayer, certified lease OK, hit one committed txn with 3
buf items all v3-tokened. The blanket ATOMIC-SKIP in `xlog_do_recovery_pass`
(xfs_log_recover.c:2856-2863 at the time) treats ANY buf item as taint — the token gate
was shadow-only, advisory, not enforced — so the txn was skipped,
`mxfs_xlog_recover_foreign_slice` returned -117, and the sess233 TORN latch froze
grants on the affected resource with **no repair or token-authorized-redo path**.
All 31 survivors' acquires on that resource then blocked for the full timeout budget
and fail-fast at `mxfs_dlm_ilock_begin` shut every one of them down with
SHUTDOWN_CORRUPT_INCORE — a genuine incore state, not real corruption. One killed
node took the fleet from 32 up to 32 down in ~6 minutes.
P273-SHADOW-EVAL on the same txn showed WOULD_APPLY=3/ENFORCEABLE_WOULD_APPLY=3 —
had gen-4 token enforcement (still gated behind `MXFS_PROTO_GEN=3`, per the sess175
ruling) been live, this specific replay would have applied cleanly and no refusal
would have occurred. That does not remove the defect: an actual TORN/refused replay
must never suicide survivors, enforcement or not.
`docs/history/docs/history/docs/history/compiled-d513-foreign-replay-refusal.md`

### sess320 — GPT containment design (RULE-5 ruling)
Design settled: on a refusal, the recovery-lease OWNER durably publishes a monotonic
terminal outcome record (victim slot+incarnation, fence cert, lease epoch, slice/
manifest digest, outcome ∈ {PENDING, RECOVERED, TERMINAL_REFUSED}, reason ∈ {policy,
malformed, torn-incomplete, io-instability, authz}, impact-domain, digest checksum) —
never mutating the victim's frozen descriptor beyond what the pre-existing recovery
protocol permits. Survivors import it into a cached quarantine map and fail acquires
into the domain IMMEDIATELY with -EIO (never ESTALE — that induces retries), never via
the 4-cycle timeout→SHUTDOWN_CORRUPT_INCORE path. Required plumbing: check quarantine
before enqueue, wake/cancel waiters on publication, re-check before consuming a grant,
abort the op with an error — a pre-ilock check alone has a publish-time TOCTOU.
Classification requires ALL of: dead+fence-certified, incarnation match, durable
terminal record for that slice, requested mode actually conflicting, resource in the
frozen manifest AND in the computed impact domain (impact domain may legitimately
exceed the held set — union of manifest + parsed journal items + containing AG/global;
can't-prove-complete widens to AG or FS, never narrows). Bitmap/manifest disagreement
escalates and fails WIDER, never casual EIO. Interim: suspend general
`fence_during_write` campaigns until containment lands; narrow single-fault tests only,
disposable FS, reformat after each induced refusal.
`docs/rulings/refused-replay-containment-design.md`

### sess325 — first review of the containment landing (0.12.0): STOP-SHIP, 9 items
Reviewed sess323-325's 9-item implementation. Core (c)+(a) design ruled sound but not
deployable: (1) refusal path must explicitly release/abandon recovery auth without
advancing the descriptor; (2) -EPERM on conflict must synchronously read back the
canonical durable outcome and import it before latching terminal — never treat -EPERM
as terminal on its own; (3) dedup must key on (victim_epoch, publish_seq), not
seen_seq[slot] alone (slot reuse); (4) mount-time outcome-scan/registration race needs
cb-before-scan or a full outcome replay at registration; (5) a failed digest reread
must still publish terminal (flag DIGEST_VALID clear), not block containment — this
supersedes sess320's original "digest fail → transient retry" rule; (6) PARK requires
full DLM request cancellation before restart, no sleep under locks; (7) Q5's
accepted-residue criterion needs either relaxing to "zero timeout-cascade shutdowns"
(local dirty-cancel shutdowns counted separately) or an activation/drain barrier;
(8) invalid outcome CRC on a QUARANTINED descriptor must alert persistently and fail
closed FSWIDE, never silently skip; (9) import must also set the torn latch so
non-publisher survivors stop re-arming replay churn. Also specified the Q7 rig plan
(3 refusal shapes, conflict race, delayed-monitor race, late-mount race, slot-reuse
rejection, park wake matrix, concurrent-op stress during import).
`docs/rulings/d513-stopship-9-items.md`

### sess328 — 3 more rulings before rig time
-EPERM→-ENODATA arm (intent-path quarantined descriptor with no outcome record, i.e.
legacy pre-#90-format state) is STOP-SHIP as latch-with-no-import: peers park forever,
remount can't reconstruct the verdict. Fix: backfill terminalization — recognize
`descriptor==QUARANTINED && outcome==EMPTY` as LEGACY_INTENT (new reason code,
distinct from TORN/POLICY), CAS the empty slot to a synthesized terminal record while
holding the gen-matched lease, read back canonical, import, latch, release. If the
format itself can't backfill, every node must independently derive the same
deterministic FSWIDE import — never indefinite park. `freplay_force_refusal` test knob
is valid phase-A plumbing coverage only; the real acceptance bar needs one genuine
UNAPPLIED-POLICY refusal (sess320's shape) and one genuine MID-REPLAY TORN refusal
(real cancel/unwind, no writes past the failure point); knob must be one-shot and
scoped to (victim slot, recovery generation) — a sticky global makes later recoveries
ambiguous. Q5 residue relaxation confirmed with predeclared thresholds: 0-3 of 31
survivors under saturated stress acceptable, >3 or scaling with stress means the
activation/drain barrier is required, near-majority means the relaxation is cosmetic
and fails; track shutdowns/exposed-node-count as the real metric.
`docs/rulings/enodata-backfill-knob-scope-q5-thresholds.md`

### sess330 — sess329 premise disproven; mount-ordering hole found; backfill API + barrier classification designed
Code-verified: `recovery_claim` calls the exclusion evaluator BEFORE its
owner-reacquire check and refuses ANY `F_QUARANTINED` descriptor — so no node can ever
acquire the recovery lease on a quarantined descriptor, meaning sess329's
post-acquire verdict check and backfill helper were unreachable for the legacy case.
Separately found a mount-ordering hole: the admission barrier runs inside
`xfs_mountfs`, but quarantine-cb registration and `recovery_scan_outcomes` run in
`mxfs_dlm_cache_init` AFTER `xfs_mountfs` — so once any slot is quarantined, every
mount of every node aborts -EBUSY forever (the barrier's todo list never clears).
GPT ruling: build a dedicated leaseless `backfill_legacy_intent()` API (not a general
auth==NULL publish_refusal, not a TERMINALIZE lease mode) with a narrow predicate —
reason exactly LEGACY_INTENT, FSWIDE only, desc identity+CRC valid, QUARANTINED set,
outcome region exactly all-zero — full-record CAS at the same durability as normal
publish; CAS loss rereads and either imports, retries, or fails closed (never
overwrites nonzero bytes). The barrier must classify each pending slot from a stable
desc+outcome snapshot BEFORE attempting acquire: valid terminal → import + mark
resolved; legacy all-zero → authless backfill then import; malformed → local
fail-closed FSWIDE; live non-quarantined → normal acquire+replay. A FSWIDE import must
fail the mount immediately (-EIO, before `log_mount_finish`), never bypass. One shared
classifier/terminalizer must serve the barrier, the reap loop, and mount-time
registration scan alike.
`docs/rulings/leaseless-legacy-backfill-barrier-classify.md`

### sess333 — review of the sess330 design's landing (0.12.2): 6 stop-ships
Verdict: do not run the rig. (A) Every barrier -EIO exit must run
`mxfs_v5_dlm_mount_defer_late_deaths(drained & ~replayed & ~terminal)` through a common
`abort_fswide:` label — `mxfs_barrier_classify_slot` returning bare -EIO meant the
caller never set the slot's terminal bit; API changed to return 1 + a `bool *fswide`
out-param so the caller sets `terminal` FIRST. (B) The classifier's -ENODATA
brc==0 arm ("first durable verdict wins") could import an unvalidated raced record —
needed the same validation as the case-0 arm (outcome==TERMINAL_REFUSED, known reason,
valid domain, nonzero AG mask when AG-scoped), else fail closed FSWIDE; fixed by
factoring one shared `mxfs_freplay_import_verdict()` used at all three import sites.
(D) — the real target defect still survived on the mount path: a lone-survivor cold
start where the barrier's own replay refuses publishes NOTHING, so the mount just
-EBUSY-loops forever with no operator-facing quarantine ever created. Fixed by making
the barrier's replay site run the exact same publish/conflict/import/latch state
machine as the reap path, factored into one shared helper. Additional: backfill needed
an identity check (`d->victim_slot != slot → -EPROTO`) since the legacy signature
(QUARANTINED flag + all-zero outcome) has no other checkable field; -EPROTO from a
backfill reread must fail closed like -EBADMSG (it was retrying forever); and the
FSWIDE admission gate needed an unconditional check at both barrier start and the
successful-admission boundary, not only after classifying a todo slot. (C, E, F ruled
acceptable as-is.)
`docs/rulings/d513-0-12-2-review-6-stopships.md`

### sess334 — sess333's 6 stop-ships landed, 0.12.3 built (not deployed)
All 6 items plus the C cleanup landed in `xfs_mxfs_dlm.c` (barrier API, shared
`import_verdict`, shared `publish_refusal` state machine, backfill identity check,
-EPROTO fail-closed, FSWIDE gates) and `disklock.c` (backfill identity). Builds clean,
no rig verification yet — fleet still down from sess325's suspension, needs
`prep_cluster`.
`docs/history/d513-6-stopships-landed-0-12-3.md`

### sess335 — review of the 0.12.3 landing: NO-GO, 3 more stop-ships
Pattern held: every landing needed a fresh review and every review found something.
(1) The barrier's pre-publication `mxfs_dlm_invalidate_cached_views()` return value was
discarded — a failed cache drop could publish + AG-admit while stale/partial replay
images stayed cached; fixed to check the return and `continue` (leave the slot in the
cut) on failure. (2) The FSWIDE admission gates from sess333 item 6 were bypassed by an
early `if (!mp || !mp->m_mxfs_dlm) return 0` fail-open success path — reordered so the
quar_fswide gate runs between the two null checks. (3) `publish_refusal`'s -EPERM arm
retained the recovery lease on a transient readback failure, freezing the victim's
grants with no publisher — fixed by releasing once at the top of the -EPERM arm
(landed same session). Confirmed after these three: no further review pass required,
remaining items are cleanup.
`docs/rulings/0-12-3-review-3-stopships.md`

### sess337 — new defect: refused replay can shut down the REPLAYER'S OWN live mount
32/caw rig, 0.12.4, first genuine shape-4 (multi-item torn replay with a real applied
prefix) run: `xlog_do_recovery_pass` (xfs_log_recover.c:4359) on a pass-2 error with a
non-empty buffer_list calls `xlog_force_shutdown(log, SHUTDOWN_LOG_IO_ERROR)` before
staling the partial-checkpoint buffers — but `log` is the SHADOW xlog used for foreign
replay, and `xlog_force_shutdown` sets shutdown on `log->l_mp`, which for the shadow
IS THE REPLAYER'S OWN LIVE MOUNT. The verdict still published correctly
(TORN/FSWIDE, 31/31 imported) but the replayer itself died — exactly the survivor
suicide class D-513 exists to prevent, and reachable by any natural torn foreign slice
with ≥1 applied item. GPT fix: add `xfs_buf_delwri_fail()` in `pal/linux/xfs_buf.c` —
run the normal buffer failure-completion path (dequeue, clear _XBF_DELWRI_Q, set
b_error/stale, run iodone) with NO device IO and NEVER touching mount shutdown state;
`xlog_do_recovery_pass`'s error arm calls this instead of the shutdown+submit sequence
when running an untrusted (foreign-shadow) replay. Every `b_iodone` callback reachable
from this path must be audited for its own shutdown calls, since provenance (foreign
vs live) can't be inferred from `b_mount` alone. Filed as a separate linked defect, not
folded into #90 — closure requires shape-4 zero host shutdowns, drain-before-publish,
and confirmation that a live-mount IO error still shuts down normally. Same session
also produced containment's first genuine natural-refusal PASS under real
churn-load: 1 refuser, AG-MASK publish, 31/31 import, 0 shutdowns — and the operational
insight that only XFS_LI_INODE items genuinely apply on foreign replay, so shape-4
fault injection needs a pure-inode victim load to exercise a real applied prefix.
`docs/rulings/foreign-shadow-unwind-host-shutdown.md`

### Recurring pattern across this chain
Every one of sess325/333/335's "landed" reviews found real, rig-blocking holes in the
prior session's landing — never zero. Treat a D-513-class containment/quarantine
change as needing at minimum one post-landing RULE-5 diff review before rig time, and
do not assume a clean build or a passing narrow test means the landing is complete.
The containment design itself converged on: durable monotonic terminal-outcome
records, a single shared classify/import/publish state machine reused by every entry
point (barrier, reap, mount registration), immediate -EIO on a quarantined domain
rather than timeout-driven shutdown, and fail-CLOSED-WIDER on any ambiguity (unknown
outcome kind, invalid CRC, unreadable backfill) rather than narrowing scope to keep
availability.
