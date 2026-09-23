<!-- sess152-160: P248 lreq owed-path leak — root cause, 0.11.455 fix-A/B, moot-leak regression found+fixed 0.11.456-457, disk proof + census, both defect… -->
# P248 owed-path lreq registry leak: root cause, fix, moot-leak regression, and closure (sess152-160)

Campaign closing two ledger defects: D-RELEASEALL-LREQ-RETIRE-MISSING and
D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK. Both are about the CAW `lreq`
registry (per-slot tenure/holder tracking in `dlm/dlm_caw.c`) failing to
retire entries when a node's shutdown (`release_all`) touches an obligation
via the "owed" path instead of the main path.

## Symptom and initial root (sess152)

32-node teardown census (`./run.sh 32 caw prep_cluster`) showed the main
release_all retire path clean at scale (30/32), but 2/32 nodes leaked exactly
one lreq entry each, always via the **owed path**: P248-LREQ-LEAK-ENT on the
root inode, preceded by `P109-CLR-RELEASE-ALL cas_rc=-108` (=-ESHUTDOWN) and
`P257-RELEASEALL-RESIDUE owed=1`.

Chain: `stop()` sets `ctx->running=false` at the STOPPING election *before*
release_all runs → `caw_slot()`'s retry loop refuses retries when
`!ctx->running`, so during release_all any first-attempt I/O error (e.g. a
one-shot SCSI UNIT ATTENTION from 32-node teardown storm PR churn) is
terminal, swallowing the original errno as -ESHUTDOWN → entry becomes
"owed" → sess151's owed path deliberately does not retire entries →
`caw_owed_worker_fn` drain clears the slot bits but `lreq_gc` (dlm_caw.c:2036)
refuses to destroy any entry with `tenure[m] != 0`, and nothing in the owed
discharge path clears tenure → entry survives = the leak.
`docs/history/docs/history/docs/history/compiled-p248-owed-registry-leak-campaign.md`

Operational notes from this session: fleet census via per-node sequential
`dmesg|grep` times out at 32-way fanout — use one dmesg pass + multi-pattern
awk instead. Also hit an unrelated clyde host wedge (2 stuck ext4 `mount`
procs since Aug 5, not MXFS) that hangs `ps`/`pgrep`; scan `/proc/[0-9]*/stat`
directly instead (see the unkillable-wedge rule in CLAUDE.md).

## design-consult ruling and 0.11.455 (sess153-154)

GPT ruling: **fix A** — retire tenure in `caw_owed_release`, under `lreq_lock`,
condition `attempted && !pending && ctx->ops_closed && ctx->release_all_done`,
before `lreq_gc`. Two tripwires fail closed (keep tenure, don't retire) rather
than warn-and-proceed: `attempts != 0`, or a context-wide publication
generation counter (`lreq_finish_gen` vs a `stop_finish_gen` snapshot taken in
phase 4 right before `caw_release_all_body`) mismatch — this catches
publication racing in on *any* entry, not just the one being retired.
**Fix B** — bounded: on release_all body CAS rc==-ESHUTDOWN, allow exactly one
extra retry (the extra slot re-read eats the pending UA so the next real
attempt succeeds); scoped to the release_all loop only, not `caw_slot`'s
general behavior.

Five consumable test-injection knobs were added to drive deterministic
regression cases (`caw_inject_take`: decrement-and-true pattern, user-mode
stub `#define caw_inject_take(k) (false)`): K1 `caw_inject_ra_casfail`, K2
`caw_inject_owed_enoent`, K3 `caw_drain_budget_ms` (override), K4
`caw_inject_pubfreeze_bump`, K5 `caw_inject_dow_casfail`. New P-tags: P263
retire event, P266 tripwire-refused, P267 retire summary, P268 release_all
IO-retry summary. Landed as 0.11.455 (srcversion A559A52088F7FC1BF400138),
built clean, not yet deployed. Six deterministic cases (c1-c6) were designed
to positively exercise: forced RA CAS fail→owed→retire (c1), terminal
-ENOENT retract→retire (c2), drain-budget-exhausted→no retire/leak stands
(c3), transient fail→requeue→retire-on-terminal (c4), mid-run owed completion
(release_all_done=false)→no retire (c5), and pubfreeze-gen-bump→tripwire
refuses (c6). Constant note: only `release_all`'s untrack-on-proof site is
unconditional; every mid-run discharge path leaves the resource tracked, so a
mid-run worker discharge gets revisited legitimately by teardown release_all.
`docs/rulings/p248-ruling-and-edit-plan.md`
`docs/history/docs/history/docs/history/compiled-p248-owed-registry-leak-campaign.md`

## tests/p248_inject.sh written; c4 exposes a deeper bug (sess155)

`tests/p248_inject.sh` written (the source-tree rule) implementing cases c1-c6 with
kmsg-marker-delimited windows and single-awk parsing. c1 and c6 PASS exactly
as designed. **c4 fails on one assertion**: `caw_inject_dow_casfail` (K5) is
never consumed, and neither c1 nor c4 shows the expected P6H-ABORT-RECONCILE
line — meaning the teardown owed discharge in *both* cases completed without
any CAS at all, contradicting the fix-A model of "drain CASes the bit clear
then retires." Three hypotheses raised (bit already absent / plan logic wrong
/ mode-mapping bug); flagged for disk-evidence resolution (the instrument-first loop), since no
existing tool dumps a live CAW slot from the LUN.
`docs/history/docs/history/docs/history/compiled-p248-owed-registry-leak-campaign.md`

## Root mechanism found: holder_moot inversion at teardown (sess156)

Code-read root, pending disk proof: `lreq_plan`'s `holder_moot` optimization
(`if (e->tenure[giveup_mode]) plan->holder=false, plan->holder_moot=true` —
originally a sess122 corruption-class save reasoning "the owner's unlock will
clear it") is **correct mid-run but inverted at teardown**, where the owner
never unlocks — the tenure record itself IS the leak. At teardown, owed
residue publishes a maximal mask across all modes; the EX (and sometimes PR)
mode with live tenure gets `holder_moot=true` → the retract path clears the
mode from the mask **without ever issuing a CAS** → mask empties → fix-A's
retire condition fires → tenure memset destroys the only evidence, while the
EX bit is still physically set on the LUN. This means 0.11.455 not only
leaked the on-disk bit in real (non-injected) release_all failures, it
additionally suppressed the P248 leak *report* that 0.11.454 would have made.

Disk-evidence method proven this session: envelope super at LUN byte 0
(`disklock_offset@64`, `disklock_size@72`), CAW slot table base =
`disklock_offset + 32768`, slot N at `base + N*512`; slot struct fields
(`magic@0`, `gen@4`, `resource@8`, `holders_ex@40`, `pw/pr/cw/cr@48/56/64/72`,
`waiters@80`, `granted_mode@88`, `waiters_ex@120`, `open_holders@152`,
`ex_grant_epoch@160`). **Trap**: a single-sector `dd bs=512` read returns
stale zeros on `/dev/mapper/mpatha` (multipath/SCST read incoherency) — must
use a 1MB-window scan (`dd bs=1M skip=64 count=34 iflag=direct`) into
`/dev/shm`, then parse with python3 `struct`, to get disk truth.
`docs/history/docs/history/docs/history/compiled-p248-owed-registry-leak-campaign.md`

## Moot leak proven on disk; 0.11.456 fix (sess157)

Injected c1 departure on 0.11.455, no remount: disk scan from the peer node
confirmed slot 39847 (ino 128) still `MXCW`-live with `holders_ex=0x1` after
a "clean" departure that printed P267-retired — proving the holder_moot leak
directly (control run with no injection: correctly TOMB). Ledgered as new
critical defect D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK.

GPT-approved one-predicate fix, landed as **0.11.456** (srcversion
4CA76BE55B7B45177024681), deployed both test nodes: new helper
`lreq_world_frozen(ctx)` = `ops_closed && release_all_done &&
lreq_finish_gen==stop_finish_gen`. In `lreq_plan`'s tenure branch: not-frozen
→ moot unchanged (mid-run behavior preserved); frozen + other live modes
present → **defer** (P269-FROZEN-TENURE-ATTEMPTS, never moot); frozen + this
mode alone → **permit** (holder stays true so drain actually CASes it clear).
In `lreq_owed_retract`: a moot-strip of a tenured mode while frozen is now
*refused* (P270-MOOT-RETRACT-REFUSED) rather than silently applied. A proven
holder-strip via real CAS now logs P271-OWED-DISCHARGE as positive proof.
`tests/p248_inject.sh` parsing extended for p269/p270/p271; c1/c4 now assert
P271≥1 and no P269/P270.
`docs/history/docs/history/docs/history/compiled-p248-owed-registry-leak-campaign.md`

## Verification round 1: c5 vacuous, harness beacon race found (sess158)

0.11.456 verify: c1/c4/c6 PASS (P271 live, no P269/P270 false-fires). c5
(mid-run owed completion, meant to exercise K5 mid-run) is **structurally
vacuous at 2 nodes** — code proof: mid-run owed obligations only arise from
stale-holder divergence strips (rare) or give-up cleanups on wait timeout
(120s ≫ churn round length), and a healthy unlock deliberately publishes no
obligation at all (sess124 design), so K5's injection point is essentially
unreachable without forcing a give-up. Fix designed: new knob K6
`caw_inject_wait_expire` to force a wait-timeout give-up deterministically
(exits the acquire poll loop's normal timeout break path, zero production
logic change) — arm K5 first then K6, so the forced give-up's
`drop_own_waiter` CAS hits the injected -EIO.

Separately, c3/c2 never ran because the pre-c3 re-prep aborted: root-caused
as a **harness-only** race, not an MXFS defect — a joining node's discovery
listener can hear the peer's announce and print `MXFS-MEMBERSHIP` up to 4ms
*before* its own `DLM initialized` line; `run.sh`'s gate awk resets its
capture at the init line, so the early beacon is invisible and the gate
false-FAILs an actually-converged cluster. Fix: emit an unconditional
post-init membership beacon on both CAW and TCP transports so the harness
gate always has something to see, with no change to run.sh itself needed.
`docs/history/docs/history/docs/history/compiled-p248-owed-registry-leak-campaign.md`

## 0.11.457: full 6/6 deterministic suite passes (sess159)

Landed K6 + the unconditional beacon fix + c5 rewrite as **0.11.457**
(srcversion E44F37271ED23D708AFD84C). All six cases pass for the first time:
c5 deterministically hits P272 (forced wait-expire) → P245-RECONCILE-EXHAUST
(K5's -EIO) → obligation stands correctly, no premature retire. c3 needed an
assertion fix, not a code fix: an unclean departure legitimately emits *two*
P259 lines (a CAW verdict line and a separate v5 GOODBYE-suppression line,
sess131) — the test had assumed one. c2 (terminal -ENOENT) passes cleanly.
Beacon fix verified across 4 field preps with zero gate false-fails.
`tests/p248_disk_proof.sh` authored (syntax-checked, not yet run) to
automate the disk-scan verification from sess156-157 as a repeatable script.
`docs/history/docs/history/docs/history/compiled-p248-owed-registry-leak-campaign.md`

## Closure: disk proof + 4x fleet census (sess160)

`tests/p248_disk_proof.sh` run: first pass exposed an `od` output-collapsing
bug (`od` collapses repeated 16-byte lines to `*`, shifting awk field
indices; the shifted PR mask decoded as a leading `0` that bash then
evaluated via `0x$v & bit` as multiplication instead of bitwise-AND, silently
returning 0/pass on garbage) — fixed with `od -A n -v` plus strict per-mask
16-hex-char validation, decode faults now hard-error rather than silently
passing. Authoritative rerun: owed slot correctly TOMB with all five holder
masks clear of the departed node's bit; three control slots also correctly
TOMB — direct A/B against the sess157 baseline (0.11.455 leaked
`holders_ex=0x1`) confirms the fix.

`tests/p248_census.sh` written and run for 4 full 32-node teardown cycles on
32/caw: every window across all 32 nodes shows zero on every P248/P253-P272
counter that should be zero, and consistent nonzero P263/P267/P271 only where
expected. Both defects dispositioned **FIXED AND VERIFIED**:
D-RELEASEALL-LREQ-RETIRE-MISSING and D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK.
Ledger 30→28 open. No further module changes; 0.11.457 remains the fleet
build. The p248 test family (`p248_inject.sh`, `p248_disk_proof.sh`,
`p248_census.sh`) stays in `tests/` for any future regression — do not reopen
either defect without new evidence.
`docs/history/docs/history/docs/history/compiled-p248-owed-registry-leak-campaign.md`

## Recurring lessons

- **Fail closed, not warn-and-proceed**, on any registry-retirement tripwire
  (attempts counter mismatch, publication-generation mismatch) — keeping the
  leaked evidence is strictly better than destroying it on a guess.
- **An optimization correct mid-run can be wrong at teardown.** `holder_moot`
  ("owner's unlock will clear it") assumes a future unlock exists; teardown
  is precisely the case where it doesn't. Any "someone else will clean this
  up" shortcut needs an explicit frozen/teardown-phase check.
- **Consumable injection knobs** (`caw_inject_take`: decrement-and-true, with
  a user-mode `(false)` macro stub) are the established pattern here for
  forcing deterministic regression cases through paths only reachable by
  rare transient I/O errors at scale.
- **32-node dmesg census must be one pass + multi-pattern awk**, never
  per-pattern greps or per-node sequential greps — both blow the 12s/node
  harness timeout.
- **Single-sector direct reads on `/dev/mapper/mpatha` can return stale
  zeros**; always disk-scan a full 1MB window and parse in-memory.
- A harness gate can false-fail a correctly-converged cluster on pure timing
  (discovery-vs-init-print ordering); the fix was making the module's own
  output unconditionally observable, not touching the harness gate.
