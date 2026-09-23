<!-- sess476-482: D-0537 SB-lock, CANCEL tokenization, D-0538 quarantine, vacuous-PASS evidence audit, D-401 pace, invariant-audit technique. -->
# sess476-482 campaign: SB-summary-lock, CANCEL tokenization, vacuous-pass audit, pace ceiling

Continuous ccloop log sess476→482 on the c7ee71c6 run. Five defect threads, one
systemic evidence-integrity failure (vacuous PASS), two audit techniques that
generalize, and two instrumentation traps. All builds 0.64.30→0.66.0.

## D-0537 — SB summary lock released by no-inode BAST under a live holder

Chain 116v2 `holderfail` arm (sess476) was real: X (test4) parked an epoch-1
hold, Y (test5) got LOCK rc=0 epoch=2 only 2s before X was destroyed —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.
Root: the SB summary key has no in-core inode, so a BAST hits the no-inode
ORPHAN release path (`__mxfs_dlm_bast_notify` → `mxfs_dlm_noino_bast_work_fn`)
and unlocks from under `put_super` even while the key is live-held. Fix
0.64.33: `P-SB-SUMMARY-BAST` probe + `sb_summary_bast_refuse` knob (default 1),
holder mark set before the granting CAS. Proof lap (knob 0) reproduced
(`RELEASE-under-live-holder`, Y epoch2 in 328ms); fix lap (knob 1) queued —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.
A companion `latedirty` arm wedge on 0.64.33 was a harness/root-lock ordering
issue, not an FS defect (0.64.36 pre-warms the root EX at `put_super` entry).
sess479 closed the loop: knob=0 reproduces (`RELEASE-under-live-holder`, Y
epoch2 449ms), knob=1 suppresses (`REFUSED-live-holder`, Y waits 71490ms),
chk 0, on the shipping build 0.64.37 — 9/9, only the combined
normal+adversarial+latedirty rerun (`s479k`) left before FIXED AND VERIFIED —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`,
`docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.

## D-FOREIGN-SLICE-INTENTS-ABANDONED — untagged CANCEL buffer items

Chain 105 probe (sess476): 100% of untagged recovered buffer items are CANCEL
records — `xfs_buf_item_format_segment` never appends the authority trailer on
the STALE branch, so every `xfs_trans_binval` (bmbt collapse, dir/attr block
free, AG btree free, inode-cluster free) produces an unauthenticated CANCEL
that trips ATOMIC-SKIP. design-consult ruling (fix A over fix B — a CANCEL is not
authenticated by another image's authority in the same txn):
`docs/rulings/cancel-item-untagged-fixa-tokenize-binval-pass1-verdict-aware.md`.
Fix A: capture authority in `xfs_trans_binval` before stale conversion, lift
the STALE gate on both size/format sides identically, tag the CANCEL with
`XFS_BLF_MXFS_AUTHORITY`, class-map by owner (bmbt/dir/attr→INODE,
AG-structures→AG, inode-cluster→ICLUS, SB→SB). Companion pass-1 hazard: pass 1
adds every CANCEL unconditionally, so a later-REFUSED txn's CANCEL can
suppress an earlier ADMITTED txn's image before quarantine publishes —
untrusted CANCELs are PARKED through pass 1 and resolved by a pure classifier
(`mxfs_cdefer_resolve`) at pass-1 end, verdict-hash-checked against pass 2 —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`,
landed as 0.64.34-36 —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.
sess479 nearly closed it (positive set + both FORGE negative laps clean on
0.64.37) but was blocked on a **false regression**: chain 105's STRICT lap
reported `classless=9` — `xfs_log_recover.c`'s authority-class tally switched
only on AG/SB, so `INODE`(3) and `ICLUS`(4) fell into `default: n_none++`. The
9 were correctly-tokened bmbt CANCELs (class 3); a second accumulator in the
same capture (`P273-SHADOW-EVAL`) already said `classless=0` and was the
cheap corroborating signal. Fixed 0.64.37 with explicit INODE/ICLUS cases plus
`ino=`/`iclus=` fields —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`. Confirmed
clean (`ino=4 iclus=0 classless=0`, `CANCELTOK: 8 class=3 st=1`) —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md` — final
disposition blocked only on D-0538 below —
`docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.

## D-0538 — AG quarantine refuses on encounter instead of steering the allocator away (high, possibly critical)

Found sess479: an AG-scoped quarantine is enforced by refusing -EIO when an
allocation lands on it, not by excluding it from the allocator's eligible set
— so an ordinary create can EIO purely by which AG the allocator picked (4/5
or 5/5 writers one lap). design-consult ruling: correct design is steer-away
(retry in an eligible AG, refuse only when the op is AG-bound or nothing is
eligible, plus a pre-commit quarantine-generation revalidation); precedent
already in-tree at `pag_disklive_q` (inode quarantine skip-and-re-pick in
`xfs_ialloc.c`). Severity hinges on whether the EIO takes the mount down (then
critical) —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`,
`docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.

## D-0532 — re-dirty fix DISPROVEN; the real bug was the ordering gate

sess479: the re-dirty fix still failed (`got=0 want=1` for P-BAST-PAUSE,
pwrite_wall_ms collapsed 9119→50). Ring trace proved the peer wrote and
released *before* the holder parked — the ordering gate
`... | grep -qv '^0$'` matches "any unexpected output", not a numeric test,
so it was never actually waiting on the hold. Fixed with an integer-count
gate, bounded retries, explicit ABORT if the holder never parks, and
one-clock timestamps. The re-dirty itself (the `S_ISREG` already-durable
early-out) stands; no lap has proven the concurrent case yet —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.

## The vacuous-PASS family — this project's dominant evidence failure

Six independent harness defects across sess479-480 all produced a false PASS
or false FAIL on work that never ran, consolidated in
[[vacuous-pass-the-dominant-evidence-failure-in-this-project]]:
1. unprepped fleet scored as failures (chain 116 ran all 4 arms after a
   preflight refusal, rc=3) — fixed with `prep_arm()` recording no verdict on
   prep failure (chains 105/116/117);
2. `$vslot` single-quoted so the remote grep matched nothing ever, in
   `d_intents_undischarged_verify.sh:224` — see also
   `docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`;
3. chain 117's ordering gate `grep -qv '^0$'` — see D-0532 above;
4. `tmpfile_churn_kill.sh` injected nothing across 3 matrices (chains
   85/89/100) yet printed VERDICT PASS — O_TMPFILE names exist only between
   `linkat` and `unlink` inside one loop iteration, so a peer `ls` sampled at
   0.7s intervals always read `entries=0`;
5. chain 119 (`s480a`) hit a run-lock refusal, then ran `showstat.sh`
   **unconditionally**, which rendered the *previous day's* board
   (`.last_run.json` unchanged) as if it were this build's result — would have
   falsely satisfied D-FOREIGN-REPLAY-UNGATED-IMAGES criterion (2). Fixed:
   pin `run_id` before the board, require it to move, hard-FAIL with no
   conditions table otherwise;
6. `ls -dt <glob> | head -1` scoring a streak harvest — when a row doesn't
   run, the glob returns the previous lap's directory and its stale VERDICT is
   counted toward a *consecutive* streak criterion.

The two gate shapes that fix the class: a **vacuity gate** (assert the
injection counter is nonzero, FAIL loudly at zero) and a **freshness gate**
(pin the rendered artifact's identity before the step, require it changed
after). Symptoms to grep for in old evidence: `got=0 want=N` beside
`VERDICT PASS`, `entries=0 statted=0`, a `DONE` seconds after `START`.
Consequence for the ledger: closed:found has been <1.0 every month on record,
and some unknown fraction of the *closed* side rested on exactly this kind of
measurement, so the ratio is optimistic on both sides —
[[vacuous-pass-the-dominant-evidence-failure-in-this-project]].

Offline follow-up: `tools/closure_evidence_audit.py` screened all 198 ledger
records (106 closed) for vacuity signatures. Result: 2 SIGNATURE hits, both
verified false positives (refusal lines on superseded re-run attempts the
record already labels as such) — **zero confirmed contaminated closures**, but
only ~33% of closed records cite a followable artifact at all (71 cite
nothing machine-checkable). The tool itself had two vacuity bugs: it measured
directory-name timestamps instead of START/DONE log lines (5 false
`INSTANT_DONE_WITH_PASS`), and it only followed `.log` paths, missing the
majority of evidence that lives in a directory —
`docs/cost-audit.md`.

sess480 also explained, by construction, why the ICLUS churn matrices (item 4
above) could never fire: `mxfs_iclus_disk_release` has 5 call sites, and
`mxfs_iclus_unlock` — the one exercised thousands of times by the churn —
only reaches it when `bast_pending && disk_mode > NL && !busy`; an ordinary
unlock with no peer demand retains the grant and never enters the marker
block. Confirmed empirically: forced eviction ran, probe still read
`iclus_marked=0`. New vacuity gates on chains 85/89/100 correctly turned this
into `VERDICT FAIL` —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.

## D-401 / criterion (2) pace investigation

0.64.37 board: `crash_consistency FAIL 91/90s`, 32/32 `BUDGET_EXHAUSTED`, but
**zero** correctness failures on any node — pure wall-time, accounting
audited against the node's own watchdog record, not a harness synthesis —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.
design-consult ruling: criterion (2) of D-FOREIGN-REPLAY-UNGATED-IMAGES **FAILED as
written** — do not relabel PASS, and do not point it at a sharded directory to
discharge it (sharding is opt-in). Defensible as a release-cleanliness gate,
poor as this record's verification criterion (orthogonal mechanism, single
sample, controlled by a different open defect: D-401). A replacement
criterion needs demonstrated orthogonality, a predetermined run sequence, and
a test that actually fails with the fix reverted. On the tail-latency
mechanism itself: p50=10ms flat with multi-second-tail outliers is not
explained by "contention" — a table of 8 discriminating trace signatures
(queueing / convoy / lease-quantum / timeout-retry / fairness / lost-wake /
scheduler-convoy / log-convoy) and an experiment order (run without the 90s
deadline first; measure creates-per-grant; perturb lease/timeout in a
diagnostic build; plot tail vs queue depth) —
`docs/rulings/criterion2-illformed-and-d401-tail-discriminators.md`.

sess482 (chain 124) decomposed where the shared-directory create cost actually
sits: op-index 1 of 8 carries 93.9% of all create ms at P=32 (uniform would be
12.5%), while ops 2-8 run *faster* than the private arm's steady state —
consistent with closed-loop clients where the entire queue-drain and cold
first-touch cost lands on op1 by construction, not with a per-create handoff
cost (the design-consult rule corrected an earlier draft that read this as reusable admission
state). Re-derived pace ceiling: deleting the EX-wait fraction entirely (48%
of the 8-rotation budget) yields at most 1.92x — still under the 2.84x needed,
so directory-lock elimination alone cannot fit this row in 30s; the binding
term is elsewhere (private-arm-only, single node still goes 4.6→27.8ms/create
across N with nothing shared but the mount). Two discriminators queued: an
F-ladder sweep for a batching-quantum spike, and a grant-epoch trace of
creates-per-ownership-epoch. Also: D-FOREIGN-REPLAY-UNGATED-IMAGES criterion
(3) MET on sv EAD72FC7EC56BA505829901 (NDR streak, 10 consecutive real rows);
(1) and (2) remain —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.

## Rig/harness operational traps

**A chain's DONE is not "the rig is free."** Gating four independent chains on
one predecessor's `DONE` line let all four (plus a session-orphaned parked
instance) wake within 30s and race `/tmp/mxfs_run.lock`; one build
(`make modules`) began relinking `mxfs.ko` while a board's preps were
insmod'ing it over NFS — caught with seconds to spare. Fixes:
`tests/rig_wait_free.sh` waits on the lock itself (via `/proc/*/fd` +
`comm`, never `pgrep -f`/`ps aux`), a sequencer script runs stages in one
process instead of fanning out, and a build is now treated as a rig operation
exclusive with any run. Second-order trap surfaced by the same incident:
**a script parked in its gate loop still counts as "running"** for the
never-edit-a-running-script rule — editing chain 119 while a prior session's
instance slept in its gate shifted its resume offset by byte count, and it
resumed detached from its own logging (board ran, `criteria.json` updated, but
the chain's own log stayed empty) —
[[trap-done-gate-is-not-rig-free-run-lock-is-the-real-resource]],
also the launch-cascade version of the same trap (launch ONE chain, confirm
past prep, then queue the next) —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.

**Awareness-doc updates via Bash are invisible to the drift hook.** The
project-awareness `track` hook is `PostToolUse` on `Edit|Write|MultiEdit`
only; `cat >> subsystems/tools.md` writes correct bytes but never registers,
so the Stop-hook `sync` check keeps reporting drift no matter how much correct
prose lands. Same class as the Read-tool rule (ccmemory injection on `Read`) and the
ledger guard: which *tool* performed the write is itself semantic in this
harness —
[[trap-awareness-track-hook-only-sees-edit-write-not-bash-heredoc]].

Also sess479: host disk over its 88% preflight ceiling (89%, 202G) from 13G of
finished-session scratch trees plus a 26G orphan VM disk image superseded by a
`.new` sibling — fixed by identifying and removing the true orphan (verified
no domain's dumpxml referenced it), not by widening the ceiling —
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.

## sess481 instrumentation traps

**A probe existing is not a probe covering your path.** `P132-CREATE`
decomposed create cost since sess132 but gated its clock on `is_dir` — every
workload that actually sets the create ceiling (32-node crash_consistency,
create-scale curve, shared-dir pace) creates *files*, so the one attribution
probe for the open question never ran for ~350 sessions. Check, in order: the
gate on the *clock* (not just the print), the print *threshold* (silent reads
identically for "fast" and "unmeasured"), and any per-boot print cap. An
absent measurement and a zero measurement render identically —
`p132_attribute.py` now refuses to print a table with no covering input —
[[trap-a-probe-exists-is-not-a-probe-that-covers-your-path-check-its-gate]].

**Cumulative vs last-value fields, and naming a residue after what you
suspect.** Two wrong root causes in one session: (1) subtracting two
cumulative CAW-unlock fields and naming the 9.42ms residue "slot I/O service
time" — nothing measured slot I/O, the residue contained an un-instrumented
hash-chain walk and an uncounted backoff sleep; the rule is to name it
"unaccounted" and go find a direct probe. (2) Dividing a last-value field
(assigned with `=` every poll) by a cumulative counter produced a fabricated
"0.22ms per read"; the actual per-poll values (grepped by `+=` vs `=` at each
assignment site) gave 0.77ms mean, and forced retracting a related "~242ms
unaccounted" claim built the same way. Check before dividing: cumulative or
per-iteration (grep the assignment operator), same-episode denominator, does a
direct probe for the suspected mechanism already exist —
[[trap-check-cumulative-vs-last-value-before-dividing-probe-fields]].

## sess482 — two audit techniques that generalize

**Audit a stated invariant against every site that must honour it.** Many
defects here are one site out of N that forgot a rule the code states in a
field comment. Method: find the invariant, enumerate every site that must
honour it, diff them — conformance is usually byte-identical so the outlier is
unmistakable. Found `D-PHANTOM-GRANT-BAIL-SKIPS-EPOCH-BUMP-DCACHE-ABA-482`:
9 of 10 `i_dlm_mode` transitions to NL bump `i_dlm_epoch`, one doesn't.
Completeness matters — 18 writes total, all in one file, checked for a `= 0`
spelling that would dodge a by-name grep (none), and eyeballed a comparison
that a naive assignment regex would misflag. A source audit proves the
invariant was *violated*, not that the buggy branch *executes*: its own probe
fired 0 times in a 2.9M-line row, and "a printk count is not a denominator"
unless the precondition itself is counted too —
[[technique-audit-a-stated-invariant-against-every-site-that-must-honour-it]].

**Audit by primitive, not by scenario.** Pick a primitive with a stated
precondition (`mxfs_v5_dlm_ag_unlock` — pure release, no draining, must not be
called without a completed drain pipeline per Architectural Invariant #1),
enumerate every caller, diff what each does first. Cooperative release runs 9
drain steps before unlocking; unmount release (`mxfs_dlm_ag_force_release_all`)
runs 1 of 9 — filed as
`D-UNMOUNT-AG-RELEASE-SKIPS-DRAIN-PIPELINE-INVARIANT1-482` (critical), and as
candidate arm (e) for `D-AGIFC-...-408` (the #1 critical record, mechanism
unknown for 12 days, whose existing arms (a)-(d) were all about replay, none
about unmount). Ordering hazard on the same path: `xfs_unmountfs`'s AIL
push/log force happens *after* this release site in `xfs_fs_put_super`, so AG
grants are published free before this node's own metadata reaches platter,
and a peer's post-release write into that AG can be durably reverted by this
node's own post-release AIL push. A platter-reading audit
(`mxfs_agifc_release_audit`) had never reported a mismatch at the unmount
site in 938 evidence dirs, but had 4 uncounted silent early exits (shutdown
state, single-node, unimplemented leaf-walk btree levels, and — likely
decisive — it only runs when the AG is `release_now` i.e. still held at
`put_super`, so cooperatively-handed-off AGs are never examined there at
all). Same lesson as the vacuous-probe family one level up: a zero from an
instrument that may not have run is not evidence — 0.67.0 adds exit-reason
counters with `ran` as an explicit denominator. Do not patch the drain gap
before measuring dirty-buffer counts at release — copying the 9-step pipeline
wholesale risks turning a correctness gap into a the derived-budget rule (timeout) failure on
mass-unmount rows —
[[technique-audit-by-primitive-every-caller-of-the-thing-that-must-not-be-called-unprepared]],
full unmount-path detail in
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.

## sess482 — fixing a vacuous probe can invert the vacuity instead of removing it

sess481 fixed the vacuous `P165-AFFINE-STALE` probe (`d_time=0` on 100% of
lines) by narrowing to `d_time && d_time != epoch`, and recorded that a future
zero on this predicate would be "the first real evidence" the affine
dentry-revalidation fast path never blesses a stale binding. It would not
have been: `d_time`'s one writer is the coordinated-validation tail that the
affine fast path *returns before reaching*, so an affine regular-file dentry
never gets `d_time` set for its entire life — the narrowed predicate is
structurally blind to exactly the population the defect names. the design-consult rule caught
an overstatement in the write-up too: not *unsatisfiable* (a dentry can carry
a nonzero `d_time` from `d_splice_alias`/reincarnation/`d_move`), just *blind
to this population* — the defensible and the true claim differ, and the
stronger one would have handed a reviewer a real counterexample. Generalized
rule: a probe fix is verified by showing the new predicate CAN fire on the
population at risk, not by cleaner output or a lower log volume — trace every
field in the predicate to its writer and check that writer is reachable from
the path under test. Replacement: `mxfs.affine_audit_pct` (0.66.0) diverts a
sampled fraction of affine blessings into the coordinated path that already
computes the true verdict, counts `-ENOENT` apart from other errnos, and
avoids RCU entirely because `mxfs_drevalidate` bails `-ECHILD` before
`dget_parent()` —
[[trap-fixing-a-vacuous-probe-can-invert-the-vacuity-not-remove-it]],
mechanics and hard gates for the audit build in
`docs/history/docs/history/docs/history/compiled-sess476-482-sb-lock-vacuous-pass-campaign.md`.

## Ledger metric: closed:found has never exceeded 1

Re-measured sess482 on a now schema-clean, natively-dated ledger (201/201
parse, week-by-week cumulative-open matches `open_defects.sh`'s 84 exactly):
whole-history closed:found = 0.582, and no single ISO week has exceeded 1.00
(W35 came closest at 0.97). At a sustained 0.58 the open queue diverges — more
sessions does not approach the zero-open bar. The trend, not just the level,
matters: W33→W35 is 0.41→0.60→0.97, real convergence toward break-even, not
stagnation (W36 is a partial week, excluded from that read). 65% of open
records are `critical`, which means severity carries almost no ordering
information at that skew; only 4 of 84 open records are untouched 30+ days —
the queue is worked, discovery is simply outpacing closure —
`docs/cost-audit.md`.
