<!-- Compiled sess382: #380 P-INODE-WEDGE root chain, GPT rulings on changecount/equality/SELFAHEAD, fix 0.18.2-0.19.4, natural-population measurement, 47… -->
# D-RELOG-BEHIND-DISK-OBLIGATION-DEADLOCK-WEDGE-380 — sess382 arc, root to closure

Full chain for defect #380 (the P-INODE-WEDGE self-shutdown), from proven
mechanism through the GPT ruling that redirected the fix, to FIXED AND VERIFIED
on 0.19.4.

## Mechanism (0.17.5) — `docs/history/docs/history/docs/history/compiled-380-inode-wedge.md`

`xfs_iflush` has 11 "safe skip" fences (`error = 0; goto flush_out`) and none of
them stamps `i_mxfs_pub_flush_seq`. The publication obligation
(`pending_seq != durable_seq`) is left permanently open. The release drain
(`mxfs_dlm_bast_process`) sees the open obligation and re-logs the
"clean-but-unlanded" core (`P146V-UNLANDED`) via `xfs_trans_log_inode`, which
itself **increments `pending_seq`** — the drain's own repair feeds the counter
it is waiting to close. Measured: `pending` 577→643 in 5s while `flush` stayed
frozen at 4. Badness never decreases, the 60s no-progress bound expires,
`mxfs_inode_wedge` pins the grant, whole mount shuts down. Recovery only
happens by luck — an unrelated local reader touching the inode within the
window via `mxfs_dlm_reload_inode`'s adopt path; the release machinery alone
never recovers it.

Built a deterministic reproducer: `mxfs.dir_adopt_at_acquire=0` (forces the
fence precondition) + `mxfs.dir_epoch_incarn_gate=0|1` (arm selector), driven
by `tests/p32e_fence_ab.sh`. Paired A/B, one build: control wedged 1/32 nodes
in 117s, fixed arm 0 wedges in 77s.

A candidate contributing cause — `xfs_inode.c:7851`'s P32E fence comparing dir
epoch raw instead of through `mxfs_dir_epoch_superseded()` — was a real
contract violation (fixed, `P32E-RAWDIVERGE` probe added) but **disproved** as
the wedge cause: `P32E-DIREPOCH-FENCE`=14, `RAWDIVERGE`=0 on stock knobs, i.e.
the raw compare and the predicate never disagreed in practice because
`P211-EPOCH-REBASE` (dir2.c operation gate) normalizes `valid_epoch` before
`xfs_iflush` runs. Kept the patch (closes a documented hole, zero cost) but did
not credit it with the fix.

GPT RULE-5 ruling at this point: a fence that abandons a publication must
**resolve** the obligation explicitly (not `durable = pending`, which launders
a lost update); add a `resolved_seq` frontier with an outcome
(DURABLE/SUPERSEDED/REPLAYED/UNRESOLVED_CONFLICT); drive the reload from a
release-side worker, never inline at the fence (ABBA folio-lock site); an
UNCOPIED obligation with no subsumption proof must still pin/fence.

## Fix landed, injected case only (0.18.2) — `docs/history/docs/history/docs/history/compiled-380-inode-wedge.md`

Three changes:
- **(A)** One chokepoint: `xfs_iflush`'s `flush_out` sets `i_mxfs_pub_fenced`
  when it returns SUCCESS without stamping `flush_seq` while an obligation is
  open — replaces checking at each of the 11 fence sites.
- **(B)** Release-side consumer: `mxfs_dlm_bast_dwork_fn` (outside the drain,
  not the ABBA site) drives `mxfs_dlm_reload_inode` for a fenced publication
  before the deadline check, bounded `MXFS_RELDEFER_RELOAD_MAX=3`. Never
  touches `durable_seq` directly; existing keep-guards stay authoritative;
  `P177-OBLIGATION-DROPPED-AT-ADOPT` still reports a dropped change; a bailed
  adopt does not restamp progress (fail-closed preserved).
- **(C)** `xfs_trans_log_inode` stops bumping `pending_seq` under
  `i_mxfs_pipe_relog` — the drain's own re-log is not a new committed change.

Caught in review, not testing: `xfs_inode_alloc` uses `kmem_cache_alloc`, not
zalloc — the two new fields had to join the explicit reset block or a recycled
inode inherits a stale verdict.

Technique: **give the cause a switch.** `mxfs.iflush_fence_fault_ino` forces a
chosen inode's flush into the exact fence shape; `tests/iflush_fence_wedge.sh`
reproduces in ~90s. Three attempts against the natural trigger with existing
knobs had given 1 hit; the injection harness gave it every time. Paired A/B,
one build (0.18.0): lever on → 4 hits, durable 6→10, no wedge, mount up; lever
off → 689 hits, durable stuck at 6, wedge, mount down. Repeated 0.18.1/0.18.2.
Full board 25 PASS/2 FLAKY/0 FAIL/1 policy cell, all three builds.

**Left open on purpose:** all 9 natural `P382-RELDEFER-RELOAD` firings read
`closed=0` — the adopt bailed on its own keep-guards and the obligation was
never reconciled. The fix was proven against the injected cause (adopt
succeeds) but unproven on the natural trigger (adopt bails). Suspected cause:
`P34J` demote-wait — reload runs concurrently with an active demote.

## GPT ruling on changecount + canonical equality — `docs/rulings/2-changecount-and-canonical-equality.md`

Addresses why natural firings closed=0: correlation showed the fence is always
`P119-NONEX-FLUSH-SKIP`, the reload does wait for the demote
(`P198-RELOAD-DEMOTE-WAITED`, so P34J is not a bail cause after all), and the
outcome is `P-RELOAD-IDENTICAL` or `P34F-RELOAD-SELFAHEAD-SKIP`.

- **Q1 (changecount):** the drain's re-log is itself a CORE-logging
  transaction and therefore bumps `i_version`/`di_changecount` — MXFS's
  cross-node freshness stamp. A re-log storm walks the in-core version past
  the platter purely from repair attempts, producing a false SELFAHEAD. Ruled
  correct to suppress both the upstream and the MXFS forced bump under
  `i_mxfs_pipe_relog`: a re-log is a new publication *attempt*, not a new
  *modification*. Guard required: assert the canonical persisted image is
  unchanged across a pipe re-log, or the suppression is too broad.
- **Q2 (equality):** the proposed `P-RELOAD-IDENTICAL` extension (add nlink +
  LOCAL fork bytes) is not sufficient — equal `nextents` isn't equal extents,
  equal LOCAL length isn't equal LOCAL bytes, and inline btree roots, attr
  fork, ownership/timestamps/flags/block counts are all still uncovered.
  Required: full canonical field-by-field (or serialize+byte-compare)
  comparison, excluding publication-only fields, checked against the image
  owed by the obligated sequence — not whatever is in core at reload time.
  Equal changecount + unequal canonical image is an **invariant violation**:
  do not adopt, do not stamp durable, fail closed.
- **Q3 (SELFAHEAD):** don't shut the mount down. Retain the obligation,
  asynchronously request EX holding no folio/txn/DLM locks, then after grant
  reload and reclassify (exact match→durable; valid newer descendant→
  superseded; ours still authoritative→publish under new EX; divergent same
  version→fence). The correct rule is "some recovery agent must obtain
  publication authority and then publish-or-prove-superseded," not "the
  original node must retake EX." An inode-scoped blocked state with an EX
  recovery enqueue is an acceptable intermediate; dropping the obligation
  because reacquisition was inconvenient is not.
- **Q4 (order):** land Q2 (equality oracle, fail-closed on weak match) before
  Q1 (changecount suppression) — otherwise Q1 converts self-inflated SELFAHEAD
  outcomes into false-equal-changecount closes exactly in the P175 class.
  Required test battery: `bad_episode` counter must be zero across positive
  controls for both exact-match and deliberate-mismatch, non-zero eligible
  count.

## Natural population measured (0.19.0/0.19.1) — `docs/history/docs/history/docs/history/compiled-380-inode-wedge.md`

Built the Q2 canonical equality oracle (`mxfs_home_equals_owed`), telemetry-only
(`P383-HOME-VS-OWED`), fails closed on anything it can't fully compare (EXTENTS
and BTREE forks refused outright). Result: 29/29, then 41/41 extended-probe
natural fence-abandoned publications are **freed-inode destage at NL** — the
inode was freed locally (`mode=00`), gen is exactly one above the platter's
(the free bump), the platter still holds the prior live incarnation, and
`xfsaild` destages the free while holding no grant. These are genuine owed
publications correctly refused equality — not the stale-shell/behind-disk shape
#380 was opened on. They resolve on their own (board green, only 6
`P382-RELDEFER-RELOAD` firings, zero wedges).

Consequence: do not build out the Q2 equality-close path — it never fires
naturally. Keep the oracle as telemetry / fail-closed gate only.
`i_generation` (`get_random_u32`) does not order two incarnations; use
`i_dlm_unpublished`, `i_mxfs_self_created`, `i_mxfs_dead_incarn_gen` to
discriminate staleness, never gen arithmetic.

## Changecount fix verified (0.19.2) — `docs/history/docs/history/docs/history/compiled-380-inode-wedge.md`

Landed Q1: `xfs_trans_log_inode` suppresses both bumps under
`i_mxfs_pipe_relog` (lever `mxfs.relog_holds_version`). Paired A/B, one build,
120 identical re-logs: lever off → in-core version 4→403 phantom bumps; lever
on → 4→5 (the two real touches the test performed). Does **not** by itself
prevent the wedge (both arms still wedged with `reldefer_reload=0` to force the
storm) — it removes the false SELFAHEAD, not the wedge itself.

Method note: a `dir_reuse_coherency`@32/caw board A/B was the wrong instrument
— that criterion never drives `P146V-UNLANDED` hard enough to exercise the
suppression (both arms read 0). The re-log path only fires meaningfully under
fault injection, not ordinary board workloads. New reusable harness:
`tests/knob_ab.sh <nodes> <dlm> <knob> <value> <probes> <criteria>`.

## CLOSED, FIXED AND VERIFIED (0.19.4) — `docs/history/docs/history/docs/history/compiled-380-inode-wedge.md`

Two more test levers unlocked full closure, after two prior sessions failed to
reproduce naturally: `mxfs.iflush_fence_fault_ino` (as above) plus
`mxfs.reldefer_noprogress_ms` (shrinks the observation window 60s→2s — the
fences/obligations/deferrals are unmodified, only how long the test waits
changes). This finally produced a **natural** wedge with zero injection.

Final fix = (A) chokepoint + (B) release-side reload consumer + (C) both
counter runaways (`pending_seq` and `i_version`/`di_changecount`) suppressed
under `i_mxfs_pipe_relog`. Verified both causes on one build lineage:
injected-lever-on 4 hits/no wedge/mount up vs lever-off 689 hits/wedge/mount
down (0.18.0-0.19.2); natural at shipping defaults — pre-fix WEDGE=1/all 32
mounts down, fixed WEDGE=0/none, full board green on six builds.

Two claims retracted on the session's own evidence, worth repeating as
discipline: the P32E patch looked like the fix until `RAWDIVERGE=0` disproved
it; a "deterministic reproducer" claimed after one success was refuted by the
next two runs — score a reproducer over ≥3 runs before writing it down.

Byproduct: one wedge took down all 32 mounts, two nodes left unrecoverable
(module loaded, unmounted, counters frozen — needed VM destroy/start). Filed as
`D-WITHDRAWN-NODE-CASCADE-NONCONTAINMENT-474`, now with a cheap deterministic
harness (disable the three fix levers, `reldefer_noprogress_ms=2000`, run
`dirent_durability` + `ag_strand_repair`).

## Related, same incident (474) — `docs/rulings/3-grant-progress-publication.md`

Separate GPT RULE-5 ruling covering incident474 hole (c)/(c2) — the
still-mounted, still-beating holder that never releases a grant
(`tests/hold_grant_liveness.sh`, `mxfs.hold_grant_fault_ino`, reproduced
`P-WAIT-EXTEND el_ms=120159`, 129.6s acquire). Distinct from #380 but
cross-referenced by it via the cascade non-containment defect above; the
sess382 changecount fix (C) above is itself an instance of this ruling's Q3
rule ("re-logging must not count as progress"). Ruling shape:
- Progress lives in a dedicated per-node single-writer table (A/B page, CRC,
  monotonic `publication_seq`), not the CAW slot (reproduces hot-LBA
  serialization) and not slot generation/heartbeat (frozen generation is
  ambiguous between stuck and busy-elsewhere). On-disk protocol change ⇒
  `MXFS_PROTO_GEN` bump.
- One table entry per outstanding BAST (bound to
  node/mount epoch + canonical_resource_id + grant_cookie +
  acquire_slot_generation + bast_request_id + drain_epoch), not a node-wide
  counter; unrepresented grants on table-full must read as "no verified
  progress," never silently rotated.
- Progress = monotonic closure over a **fixed** obligation ledger snapshotted
  at BAST accept, phases `DRAIN_ACCEPTED → ... → SLOT_RELEASE_COMMITTED`;
  event counting (re-logs, retries, txn commits) is not sufficient since a
  loop can tick those forever — work that replaces one obligation with an
  equivalent new one does not count as progress.
- Escalation ladder when a serviceable holder stops progressing: re-challenge
  → targeted local intervention on the holder → quarantine/quiesce →
  self-withdrawal/force-shutdown (sacrifice the mount, not the node) →
  external SCSI-PR fencing only if withdrawal isn't acknowledged. Expiry never
  means the waiter may assume ownership — only that holder-directed recovery
  begins.
- Rollout: publish-only → shadow → enforce-on-injected-faults → subset →
  cluster-wide. Decisive falsifier: shadow policy denies for "no verified
  progress" but the holder then completes normally with no intervention —
  that's a hard stop on enforcement.
