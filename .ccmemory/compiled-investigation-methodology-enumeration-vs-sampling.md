---
name: compiled-investigation-methodology-enumeration-vs-sampling
description: sess481-577: enumeration-vs-sampling investigation traps — audit by primitive/invariant/funnel/choke-point, truncated samples, vacuous probes, confou…
metadata:
  type: project
tags: [compiled, methodology, investigation, measurement, rule4, rule6, traps, technique]
---

# Defect-investigation methodology: enumerate, don't sample; measure, don't infer

Two families of failure recur across sess481-577 whenever a defect is chased
by reading code or by running a harness rather than by direct instrumentation
of the actual population at risk. Family one: a conclusion drawn from a
*sample* (a truncated table, one file, one call site, a fixed-order sweep) is
silently generalized to the *population* (every row, the whole tree, every
caller, every value of a confound) without the enumeration that would justify
it. Family two: an instrument (probe, gate, control arm, parser) that looks
like it measured something in fact measured nothing, or measured the wrong
thing, and the failure is invisible because it reads as a clean or plausible
result. Both families cost a full lap or a wrong ledger entry before being
caught; the fix in every case was to go from "I read/ran/looked and saw X" to
"I enumerated the population and X holds for N/N of it."

## The positive technique: audit by enumeration

Four instances of the same working method, each applied to a different unit
of enumeration:

- **By primitive.** Fix defects by the *scenario* being debugged and the
  hardening lands only on the caller under investigation; siblings are never
  brought along, and nobody notices because the fixed path is the one everyone
  looks at. Instead: pick a primitive with a stated precondition
  (`mxfs_v5_dlm_ag_unlock` — no on-disk DLM unlock without a completed drain
  pipeline), enumerate *every* caller, diff what each does before calling it.
  Found the cooperative-release path had the nine-step drain pipeline and the
  unmount path had one of nine — a live candidate for a defect whose mechanism
  had been unknown for twelve days
  ([[technique-audit-by-primitive-every-caller-of-the-thing-that-must-not-be-called-unprepared]]).
  Same session, companion finding: an oracle that has never once reported a
  mismatch across hundreds of evidence directories can be silently exiting
  early on four different conditions, none of them counted — a zero from an
  instrument that may not have run is not evidence of anything; count `ran` as
  the denominator before trusting a clean sweep.

- **By stated invariant.** Find an invariant the code states about itself,
  usually in a field-declaration comment ("bumped every time this node LOSES
  the inode's DLM grant"), enumerate every site that must honour it, diff the
  sites against each other — conformance is normally byte-identical, so the
  outlier is unmistakable. Found 9 of 10 NL-transition sites bumping an epoch
  counter and one silently not. The audit proves the invariant was *violated*;
  it does not prove the violating branch *executes* — a printk count is not a
  denominator unless the branch's own precondition is also counted, so file
  the fix as landed-and-unverified until it is
  ([[technique-audit-a-stated-invariant-against-every-site-that-must-honour-it]]).

- **By funnel.** A leak with 11+ clean laps and no reproduction is bounded, not
  chased, by proving its deallocator has exactly one caller, enumerating that
  caller's own call sites (here four, one per `why` tag), and checking each
  against the invariant. Three of four were covered by construction or by an
  upstream guarantee; the fourth returned nothing — the hole, found without the
  rig. This also explained *why* eleven clean laps had never found it: the
  `put` route needs a dirty item outside the AIL, gated by `XFS_LI_ABORTED`,
  set only on shutdown paths, and every lap had been a healthy mount. An
  `ASSERT` that is compiled out in the shipping build is not a guard, and
  reproducing the real route needs concurrency (two transactions racing a
  brelse), not just a shutdown
  ([[technique-enumerate-the-single-free-funnel-instead-of-hunting-the-leak]]).

- **By choke point.** An invariant enforced at N callers has N chances to be
  forgotten — 7 of 8 release wrappers had the "no release once poisoned" gate,
  the 8th's TCP arm did not, and it was found only by reading the file after
  the damage had already propagated through a refused replay and a quarantined
  AG. The fix is not to keep auditing callers by hand: find the 1-2 primitives
  every caller funnels through and ask the question there via an oracle
  callback, and — critically — the choke point must *log*, not refuse, because
  the same call can be legitimate from one caller (a survivor purging a dead
  peer's slots) and a defect from another; the wrapper enforces, the choke
  point names the site so the disposition is made per call
  ([[technique-ask-the-invariant-at-the-choke-point-not-at-each-caller]]).
  Same underlying idea, applied to evidence rather than to code: when a
  producer "never reproduces," enumerate *every* repair path that can touch
  the object, not only the ones the defect record already names — a third,
  unnamed, default-on repair was sitting exactly at the point the producer
  would have been observable, and it consumed the measurement instead of
  merely masking the symptom. The fix was not to remove the repair (behavior
  change, risk) but to make it report a pre/post diff of what it repaired, so
  the repair count becomes free coverage accounting
  ([[trap-a-repair-sitting-at-the-measurement-point-destroys-the-evidence-it-would-have-produced]]).

## Negative claims need the same rigor as positive ones

"X is not implemented" / "nothing calls Y" is a claim about the *whole tree*
and was made instead from one file: a ruling said "validate the platter dinode
before dialloc dirties the transaction," `xfs_create` had no such read, and the
conclusion "containment was never implemented" went into two ledger records
with a confident file:line citation. It was wrong — the validator lived inside
`xfs_dialloc` itself, the only place it *could* live, because the candidate
inode number the validator checks does not exist until dialloc picks it. The
phrase "before dialloc dirties the transaction" was mesread as "before the
call to dialloc" when the operand's existence tied it to "inside." A one-line
tree-wide grep would have found it in seconds; grepping one file only found
what the session happened to already be reading in
([[trap-absence-in-one-file-is-not-absence-in-the-tree-containment-was-implemented]]).

## Sampling and distribution-blind measurement

- **A truncated report is a sample, not a census.** A log-sweeper returned 80
  of 647 rows (head/window/tail); every shown row of one tag had the same
  field value, and that got folded with a total count into "all 53 releases
  share this value" — a hypothesis, a scout dispatch, and a written memory
  followed. The omitted middle held the counterexamples (36 vs 17 split).
  Position-selected rows carry zero information about a field's distribution;
  any "every row has X" / "no row has Y" claim from a capped report is
  unsupported until a full-population histogram (one `grep -c`) is run,
  exactly the discipline RULE 10 already requires of a subagent report's own
  negatives
  ([[trap-a-truncated-subagent-table-is-a-sample-never-generalize-a-field-from-the-shown-rows]]).

- **A ratio-to-a-statistic-of-itself detector goes blind exactly when it
  matters most.** A "≥10× the median" spike detector reported *fewer* spikes
  as load rose, while 2+ second operations were appearing at those same loads
  — because the median it divided by had itself degraded, so a uniform shift
  of the whole distribution shrank every ratio below threshold. Before
  thresholding anything as a ratio to a same-sample statistic, ask whether the
  failure being hunted can move the denominator; if so, use an absolute
  budget (this project already derives one per criterion from native XFS) or
  a baseline fixed outside the run under test, and never let a verdict line be
  the *only* thing a detector emits — the raw per-index means, printed
  alongside, are what caught this
  ([[trap-ratio-to-median-detector-goes-blind-when-the-baseline-is-what-degraded]]).

- **A fixed-order parameter ladder on un-reset state measures elapsed time as
  well as the parameter.** Sweeping F (files/node) 8→128 in one pass produced
  a clean monotone curve that "disproved" two hypotheses; a review found the
  points also ran in increasing elapsed time on a never-reprepped filesystem,
  so "cost rises with F" and "cost rises with how long the test has run" fit
  the identical numbers. Fix: run the ladder forward then immediately backward
  on the same state — if F drives it, the F→cost mapping repeats; if time
  drives it, the mapping inverts. Same review also flagged: with closed-loop
  clients, the outstanding-work variable is the client count P, not the sweep
  variable F, so "cost rises with outstanding work" while sweeping F was
  simply the wrong claim; and a censored arm's mean (guard fired, 3611 of 4096
  samples returned) is a lower bound, never "the mean" — publish n per point
  ([[technique-run-the-ladder-backwards-a-fixed-order-sweep-is-confounded-with-elapsed-time]]).

## Instruments and gates that report success while measuring nothing

- **An anti-vacuity gate keyed on a failure artifact cannot score a pass.** A
  discriminating A/B's freshness check kept re-checking for a new evidence
  directory that is written only when the row *fails* — so the two legs
  expected to pass (and which did, 32/32, with full captured output already
  sitting on disk) were discarded as "not scored," inverting the experiment's
  own stated prediction. The general check for any liveness/anti-vacuity gate:
  does the key it watches for exist on the outcome you are hoping for? A gate
  only ever exercised against failures has never actually been tested
  ([[trap-anti-vacuity-gate-keyed-on-a-failure-artefact-refuses-to-score-a-pass]]).

- **Fixing a vacuous probe can invert the vacuity instead of removing it.** A
  probe found vacuous (`d_time=0` on 100% of lines, discriminating nothing)
  was narrowed to `d_time && d_time != epoch` and the ledger recorded that a
  future zero against a large denominator would be "the first real evidence
  the vector does not occur." It would not have been: `d_time`'s one writer is
  unreachable from the fast-path exit the named population always takes, so
  the narrowed predicate is blind to exactly the population at risk — a
  confident, plausible, *wrong* negative, worse than the original noise
  because a zero reads as a finding. The verification a probe fix actually
  needs: trace every field in the new predicate to its writer and confirm that
  writer is reachable from the population being sampled, not just that the
  fix compiles or the log quiets down
  ([[trap-fixing-a-vacuous-probe-can-invert-the-vacuity-not-remove-it]]).

- **Cumulative vs. last-value probe fields cannot be divided against each
  other**, and a subtracted residue is not a measurement of whatever you
  suspect fills it. One session did both: named a leftover 25.8ms/attempt
  residue "slot I/O service time" with no direct probe behind the label (the
  residue in fact contained an entirely uninstrumented backoff sleep), then
  "refuted" it by dividing a cumulative probe count into a last-value field
  that only ever holds the most recent sample — meaningless division that
  happened to survive by luck. The checklist before dividing any two probe
  fields: is each cumulative (`+=`) or per-iteration (`=`) by its own
  assignment site; does the denominator count the same episodes as the
  numerator; does a direct probe for the suspected mechanism already exist
  (often it does, already shipping); if the answer is a residue, print it
  labeled as a residue, never as the mechanism
  ([[trap-check-cumulative-vs-last-value-before-dividing-probe-fields]]).

- **Re-running a create workload on a mount the previous failed row already
  populated measures overwrites, not creates** — every `dd oflag=sync` became
  an O_TRUNC of an existing inode, and the create-cost probe logged 1-2 orders
  of magnitude fewer lines than the planned population, which is the tell:
  read the probe's *count* against the planned population before trusting any
  per-sample statistic derived from it
  ([[trap-rerunning-a-create-workload-on-the-same-mount-measures-overwrites-not-creates]]).

- **A crash-durability control built on a one-block directory cannot lose
  anything**, because every create re-logs the whole block and the AIL push
  from the *last* surviving log item writes every entry, protected or not —
  so a buggy and a fixed build both reported `missing=0`, a non-discriminating
  pair that would have "verified" the fix vacuously. The shape that actually
  puts a block's last modification at risk needs a *different* block
  committed-unwritten with nothing re-logging it afterward (multi-block leaf
  format, alternating unlink/create across blocks). Before trusting any
  crash/durability control: state which block's last write is unprotected and
  show the census proving the crash landed after that write, and count
  reappeared-after-unlink as a loss too, not just missing files
  ([[trap-a-one-block-directory-crash-control-cannot-lose-the-last-create-relogs-the-whole-block]]).

- **A second, "tolerant" parser for a format the producer already parses is a
  standing bug**, caught here only by luck. A hand-written parser for
  `OP <index> <duration_ms>` lines took the first numeric field after `OP` —
  the index, not the duration — and produced a clean, plausible, wrong
  statistic (mean 4ms against a previously measured 193ms for the identical
  arm); it was only visible because at F=8 the coincidental max equaled F
  itself. Rule: copy the producer's own three-line parse verbatim, never write
  an "equivalent" one; sanity-check any new parser against a number already on
  record before reading anything else from it; and treat any measurement that
  numerically equals an experiment parameter (n, F, a loop bound) as a
  fingerprint of reading a counter instead of a measurement
  ([[trap-never-write-a-second-parser-for-a-format-the-producer-already-parses]]).

## Harness sequencing that fabricates the population it measures

- **A chain that reboots, fences, or unmounts nodes must re-establish fleet
  readiness before the next stage touches all of them.** A chain aborted
  twice on "armed on only 30 of 32," reading as two dead nodes; both were
  live, and the whole fleet was unmounted at that instant because the
  chain's own prior stage (`node_death_replay`) was still bringing nodes
  back. A row PASSing does not mean its nodes are back — `run.sh` scores
  the row, not the fleet's recovery. Fix: a positive readiness gate (ssh
  reachable *and* `/mnt/shared` mounted, polled to a derived ceiling) before
  arming anything cluster-wide, not an inference from the previous stage's
  verdict
  ([[trap-arming-a-fleet-that-is-still-rebooting-from-the-previous-lap]]).

- **Two bash shell facts, each burned a rig lap.** `( list ) &` inside a
  non-interactive shell double-forks — `$!` is a wrapper whose *child* runs
  the list and opens any fds the list opens, so a count or fd-check keyed on
  `$!` alone undercounts; sum `$!` and its `/proc/.../task/$!/children`.
  Separately, `a && b && ( list ) &` backgrounds the *entire* AND-list,
  including setup steps like `rm -f flag fifo && mkfifo fifo` — on nodes not
  freshly rebooted between legs, a stale flag file from the prior leg let the
  foreground proceed instantly, opened a fifo the backgrounded setup then
  unlinked and recreated, and both sides waited forever on different fifos
  with no process left to blame — "hung" with nothing in the hang capture
  means the harness, not the kernel. Fix: write setup as its own statement
  before backgrounding the list, and verify what a node command *did* via
  `/proc` or a read-back, never what it printed it intended
  ([[trap-background-subshell-double-fork-and-and-list-precedence-in-ssh-node-commands]]).

## The shape, again

Every entry above is the same question, asked at a different unit of
evidence: is this claim backed by an enumeration of the whole population it's
made about (every caller, every site, every row, every value of the confound),
or by a sample that happened to be in view? And does the instrument reporting
the result — probe, gate, parser, control arm, readiness check — actually
observe the population at risk, or does it silently exit, divide the wrong
fields, re-log over the evidence, or arm before the population it's counting
has stabilized? The fix is never "trust the read/run harder" — it is either
completing the enumeration (grep the tree, not the file; every caller, not the
one being debugged) or adding a denominator/count that lets a future zero be
told apart from an instrument that never had the chance to fire.
