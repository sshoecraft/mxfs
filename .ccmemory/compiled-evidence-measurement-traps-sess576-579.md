---
name: compiled-evidence-measurement-traps-sess576-579
description: sess576-579 + 2026-09-10 triage: 11 evidence/measurement-integrity traps — asymmetric guards, saturated counters, weak-branch predicates, PR evidence…
metadata:
  type: project
tags: [compiled, measurement-integrity, harness, fencing, investigation-methodology, dlm]
---

# Evidence and measurement-integrity traps, sess576-579

Eleven traps/techniques from investigating D-0496, D-0912, D-0932, D-0950, the
fencing/unmount paths, and one 2026-09-10 memory-store sweep. Common thread: a
check, probe, or piece of evidence looked sufficient and was not — the gap was
a direction nobody reasoned about, a branch with weaker evidence than its
sibling, a counter that had already saturated, or a repair sitting exactly
where the measurement needed to happen.

## Fencing evidence: asymmetric guards and evidence categories

**A guard written for "not myself" leaves "not my live peer" open**
(sess576). SCSI PR keys are derived per-boot from `{host_uuid, boot_uuid,
fs_uuid}`, so two incarnations of one host in one kernel share a key.
`P238-FENCE-OWN-KEY` in `dlm/v5_mount.c` correctly refused to preempt the
fencer's *own* previous incarnation (`vkey == ctx->pr_key`) — but a peer
fencing a dead incarnation whose host already remounted has `vkey` (victim's
key) != `ctx->pr_key` (fencer's key), so the guard never fires and the P&A
lands on the live successor. Same hazard, mirrored, unguarded — and the
existing guard's own comment ("would preempt ourselves") reads as if the
general problem were handled, which is exactly why it was missed. The fix
excludes by **node id**, not by liveness alone: a successor on the victim's
host gets a different node id via the per-mount uuid, so a legitimate fence
still fires even before the victim's record is marked not-live. General rule:
when a predicate names "self" — own key/slot/incarnation/node — ask what it
looks like with any other live member substituted, and enforce at the
primitive all call sites funnel through, not at the one call site that showed
the bug. See [[trap-a-guard-written-for-the-self-direction-leaves-the-symmetric-peer-direction-open]].

**READ KEYS does not say WHICH nexus holds a key; READ FULL STATUS does**
(surfaced by design consult on D-0950). A ledger record's root-cause chain was
plausible but not established by its own cited evidence. Three collapses to
watch for when reading PR state: (1) "mounted node lost its own registration"
has four distinct causes — legitimate fence of the active incarnation
(possibly a false-positive death call), a stale/misauthorized fence, an
unregister on another path, or genuine target-side state loss — discriminable
only by correlating the completed PR OUT (issuer, action, RK/SARK,
type/scope, status, sense) against the frozen victim incarnation, never
inferred from one flag; (2) `P302-PR-KEY-RETAINED-FENCE-TARGET` says the
unregister was *skipped*, not that a fence target exists; `umount rc=0` with
`log_shutdown=1` is not a contradiction — detach can be clean while the slice
stays durably dirty; `holder_key=0x0` under an all-registrants reservation is
expected, not evidence of a foreign holder. General shape: never let "key we
selected", "registration observed", "registration proven on our own nexus",
"completed fence", and "durable certificate of that fence" substitute for one
another. See [[trap-read-keys-does-not-say-which-nexus-holds-a-key-and-lost-registration-has-four-causes]].

## Harness/probe traps (sess578, one D-0912/D-0932 campaign)

**A cumulative dmesg count is worse as a *selection* step than as a verdict**
(D-0912). `tests/tcp_lockreq_blackhole.sh` chose its target inode by counting
`dmesg | grep -ac` hits for a fault probe that only fires on the remote-master
send path. A module swap does not clear the kernel ring, so the next run
inherited 15 stale hits, selected an inode that was now *locally* mastered,
and the fault could not fire — nine PASSes, including the anti-vacuity gate,
on a run that never touched the code under test. Fix: mark the log at run
start, scope every count to the marker (`awk '/$MARK/{f=1} f'`, not
`sed -n "/$MARK/,\$p"` which needs escaping), and gate vacuity against a
baseline sampled immediately before the measurement, never against zero —
setup phases fire the same probes. Second bug in the same script: an `ssh`
inside a `while read` loop reading the same stdin swallowed the remaining
candidates; use `done 3<file` / `read ... <&3` and `</dev/null` on the ssh.
See [[trap-a-selection-step-keyed-on-a-cumulative-dmesg-count-picks-the-previous-runs-target]].

**A budgeted probe must carry its own true total on every line** (same
D-0912 lap). A 16-line print budget on `P912-QACK-RX` is correct — an
unbudgeted probe floods the ring — but printing stopped at n=16 while
receipts kept arriving for another 176s, and "ten receipts, about one per
re-send" was nearly published as fact. What actually proved continuation was
an unrelated derived assertion (`receipted=1` stamped against a 15s
staleness window). Rule: print a running total (`n=%d rx=%llu`) on every
budgeted line, so a truncated sample is self-describing; when reading
someone else's probe, check the source for a budget before trusting a line
count as an event count — `n=` values stopping at a round number (16, 20, 64,
200) are the tell; prefer a derived assertion over a raw count wherever one
exists. See [[technique-a-budgeted-probe-must-carry-its-own-true-total-on-every-line]].

**Co-occurrence of two probes is not evidence they interacted** (D-0932). A
check of the form `event_A_count >= 1 && event_B_count >= 1 → FAIL` asserts a
relationship it never measured. Here it fired on a lap where an assertion two
lines earlier had already established the hypothesized precondition
(`RETIRE_PENDING`) was absent, the "resumed" worker issued nothing
(`proves_excl=0` — waking is not acting), and an in-node guard had already
refused the action five times — the exact protection the hypothesis assumed
missing. Rule: count the violation itself, not its ingredients; a FAIL
message must not narrate a mechanism the lap's own output already
contradicts; when an earlier assertion in the same lap has failed, later
assertions dependent on that state are unscoreable, not failing — consider
VACUOUS. Same lap also bounded an unmount at 90s against a 300s injected
hold ("a bound that races an injected delay measures the injection, not the
system" — derive it from the injection, `HOLD_MS/1000 + slack`), and when the
unmount blocking turned out to be the *correct* safety behavior, the right
move was to assert the safe property directly rather than delete the test.
See [[trap-co-occurrence-of-two-probes-is-not-a-race-waking-is-not-acting]].

**A clean unmount blocks on this node's own parked fence/recovery work**
(measured 3x, one build, two knobs). `put_super` does not return while a
node has a fencing attempt or recovery purge parked — a safety property, not
a stall: a node must not vanish leaving its own unresolved work on the
platter. Two consequences: no clean departure can strand its own descriptor
(only a crash can — "descriptor whose holder departed cleanly" is
unreachable by unmount), and a bound that races the injected hold measures
the injection (same lesson as above, independently rediscovered). Asymmetry
worth remembering: a departing recovery owner publishes
`RETIRE_PENDING`/`P304-RETIRE-PENDING-RELEASED` and the slot goes
`flags=RETIRE_PENDING`; a departing fencing prover publishes nothing — its
retire worker retries 3x, is refused by its own parked worker each time
(`P304-FENCE-PROVE-BUSY`), and exits leaving the slot `ACTIVE`, so peers must
fence a node that left normally. `recov_desc_names_node` compares only
`d->victim_node`, so the purge-freeze gate covers descriptors naming a node
as victim, never as holder. See [[technique-a-clean-unmount-waits-for-this-nodes-own-parked-recovery-or-fencing-work]].

**A suite detector executes on the test node, which has no ssh credentials
for its peers.** `tools/mxfs_rig_tag.sh` fell back to ssh-reading a peer's
sysfs to identify the physical rig; that works from clyde (which holds
`~/.config/mxfslab/secrets`) and fails silently on a node, which holds none —
verified absent at `/root/.config/mxfslab/secrets` on test1. A detector
calling such a helper reads the fallback's "cannot determine" as a
legitimate unknown and the cell shows SKIP with the wrong stated reason.
Fix: read local sysfs first, ssh only when the fact is not present locally.
General placement rule for a detector helper: on-node facts (sysfs, /proc,
mounts, dmesg, the LUN) read directly; dev-host facts (repo, cluster marker,
build artifacts) reach over the `/src` NFS mount nodes already have; a
peer-node fact is unreachable from a detector — record it in the cluster
marker at prep time instead. Verify a new helper by running it *from* a node
(`tools/mxfs_sshpass.sh test1 ...`), not just from clyde.
See [[trap-suite-detectors-run-on-the-nodes-where-no-ssh-credentials-exist]].

## Locality and predicate-strength traps (sess579, design)

**Which node masters a DLM resource is a hash of the resource id — a
two-node lap that does not establish locality measures a coin flip.**
`live_holder_wait.sh` took whatever inode `open()` happened to create; one
lap drew a remotely-mastered inode (238 blocking notifications at the
holder), the next drew a locally-mastered one (237) — indistinguishable from
"the fix did nothing," scored 9/9 PASS while exercising the wrong path
entirely. Worse: the blocking notification fires from the resource's
**master**, not the holder, so counting on the holder works by accident when
remote and returns a silent, budget-passing 0 when local. Fixes: establish
locality via a probe that only fires on the path being tested (here,
`dl_drop_lockreq_ino` sits on the remote-master send path only) and abort if
it can't be gotten; derive which node to count on from established locality,
never from the H/W role label; gate against zero explicitly when an
instrument can only read 0 by pointing at the wrong object.
See [[trap-which-node-masters-a-resource-is-a-hash-so-a-two-node-lap-must-establish-locality]].

**A predicate whose two branches demand different evidence is itself the
defect.** `mxfs_dlm_resource_wait_is_live()` gates whether a stalled acquire
keeps waiting: the local-master branch walks the holder chain
(`holders > 0 && live`, first-hand state); the remote-master branch is
`node_live_cb(master)` — membership alone. On TCP the weak branch licensed an
**unbounded** wait: with one `LOCK_REQ` dropped at the sender, `open()`
blocked 495s (2.7 acquire budgets) with no error, shutdown or escalation
while the peer served its own reads in 5ms. General move: when a predicate
branches on *where the authority lives*, diff the branches' evidence
strength explicitly and ask what a branch with only a liveness signal does
forever if it answers wrong. Fix that worked: the master sends an acceptance
receipt on queuing (previously silent, indistinguishable from a lost
request); the requester requires liveness AND a fresh receipt, with the
staleness window derived from request cadence, never from drain duration
(any drain length keeps receipts flowing). Refuted by design consult: driving
death/fence/recovery off an unanswered request, because a requester cannot
distinguish its own broken transmit from a broken peer — this campaign's own
measurement had the fault on the requester's side. Also refuted: a blanket
error return from acquire — most callers (writeback, inactivation, rolling
transactions) have no safe error boundary; failure must be opt-in per call
site, scoped per-task (not per-inode, or two threads on one inode read each
other's verdict), only where nothing is dirty and no transaction is open —
`open()` qualified, already had a fail-closed `-EIO` path.
See [[technique-a-predicate-whose-two-branches-demand-different-evidence-is-the-defect]].

## Repair-at-the-measurement-point (sess577, D-0496)

D-0496 (directory LEAF hash index diverges from DATA after death+replay)
resisted rooting for days. Its record named two masks
(`mxfs_dir2_datascan_lookup`, `mxfs_dir2_leafless_removename`, both gated on
`dir_datascan_heal`) and every experiment disabled that knob to get a
non-vacuous lap. A **third** repair on a different knob went uncounted:
`mxfs_dir_rebuild_leaf_from_data`, fired from `xfs_dir_createname` gated on
`MXFS_IF_DIR_LEAF_STALE` (armed once per cross-node tenure, consumed before
that tenure's first mutation, default-on via `dir_leaf_rebuild`), sits
exactly at the point an incoherent acquisition would be observable — the
leaf as received from handoff, before any local mutation — and silently
overwrote that evidence, reporting only its rebuilt count. Lesson: hunting a
producer that "never reproduces," enumerate every repair path that can touch
the object, not just the ones the defect record already names, and ask
explicitly whether a repair sits at the exact point the measurement would
need to be taken. Fix shape: don't remove the repair (changes behavior, risks
what it prevents) — make it report what it repaired: snapshot pre-repair
state, diff against post-repair, emit both outcomes. Landed as
`P496-ACQ-DIVERGE`/`P496-ACQ-CLEAN` in 0.79.0. Caveat: first run (2
nodes/TCP) got 36 censuses matching 36 repairs, zero divergence, but 81
further rebuilds declined on directory format (single-leaf only) and the
diff ran in-core, not against platter — a clean census under those limits is
a bounded negative, not a disproof.
See [[trap-a-repair-sitting-at-the-measurement-point-destroys-the-evidence-it-would-have-produced]].

## Tooling sweep verification (2026-09-10 memory triage)

Unrelated to the MXFS rig, same failure family: a sweep whose own output is
internally consistent with success. Two silent misses in a 2,800-file memory
sweep, both caught only because a second, independent check asked the
opposite question afterward. (1) Filename and frontmatter `name:` disagreed
on 27 of 2,801 files; anything keyed on filename alone (a move plan, a
delete-by-name) silently skipped those rows with no error — reconcile both
directions (rows with no file, files with no row), never trust one as the
inventory. (2) `path.lstrip("./")` strips *any* leading `.`/`/` characters,
not just the literal prefix, so `./.claude/awareness/x.md` became
`claude/awareness/x.md` — nonexistent — and a rewrite pass silently skipped
every dot-directory (116 citations left dangling across 7 docs) because it
used `if not os.path.exists(path): continue` with no warning. Use
`path[2:] if path.startswith("./")` and make a skipped path print itself.
General shape: a sweep that cannot fail loudly needs an independent
verifier that does not reuse the sweep's own path/name handling. Also:
collapsing `.md.md` to `.md` via one non-repeating regex substitution is not
idempotent (`.md.md.md` → `.md.md`) — replace `(?:\.md){2,}` in one pass, or
loop to a fixed point.
See [[trap-a-sweep-keyed-on-one-name-and-a-path-scan-that-eats-dot-directories]].
