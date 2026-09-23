<!-- s71 design-consult ruling (Astra): the cold structural audit's CLEAN is a release claim only when a coverage witness passed; the witness is transition counters per node and AG plus a retained cohort, recorded by a dedicated stress row, never inferred from a final platter or row wall times -->
# s71 design-consult ruling — the audit gate's allocation-coverage witness

Consulted for `D-THE-CLUSTERED-STRUCTURAL-AUDIT-GATE-DOES-NOT-ESTABLISH-THAT`
with the row's shape (chk_clean: every node unmounts, rank 1 runs chk_mxfs -v,
verdict CLEAN/CORRUPT/INDETERMINATE, everyone remounts), the measured record
(icount 64 after format, 192 after one workload row — the whole evidence the
volume was written), what the checker prints per AG, and what the module
exposes (a few dialloc debug counters, no carve/free/finobt counters).

## The ruling

**The release verdict is conjunctive: CLEAN = the structural audit passed AND
the allocation-coverage witness passed.** The two results are kept apart in
the artifact.

Recommended shape: **a dedicated allocation-stress row immediately before the
cold audit, small kernel event counters scoped by node and AG, and a final
platter-derived witness.** The stress row proves that transitions and
interleaved allocations occurred; the cold audit proves that the resulting
on-disk state satisfies its checks. Neither substitutes for the other.

## What a platter witness can and cannot establish

A post-format/final comparison is a lower bound, never the record:

| observation | establishes | does not establish |
|---|---|---|
| AGI count grew | net inode capacity grew in that AG | gross carves, the allocating node, carve/free cycles |
| AGI count unchanged | no net change | that the AG was untouched |
| final finobt non-empty | free capacity is represented at the cold point | that the finobt changed during the workload |
| final freecount > 0 | some capacity is free | that an inode was freed: a new chunk already holds free inodes |
| final chunk count fell | net removal | gross removals, timing, node |
| final trees consistent | the final state is consistent | that transient states were |

`C_final − C_baseline = gross carves − gross frees`, not "chunks carved".
Under sparse inode chunks, derive chunk accounting from inobt records and
their hole masks, never AGI count / 64. A platter-only design may claim
only "the checker examined this much allocated inode backing and finobt
state after the workloads".

## The concurrency claim, precisely

Row start/end wall times are NOT an overlap witness: setup, barriers, sleeps
and teardown overlap while allocation is sequential. Three claims are
distinct: (1) concurrent activity somewhere on the volume, (2) interleaved
allocation by both nodes in the SAME AG, (3) simultaneous outstanding
requests contending for an AG lock. **The row requires (2).** Disjoint-AG
allocation is breadth, not shared-AG allocator/DLM interaction. Never
require simultaneous AG-lock ownership (impossible by design) and never
claim contention unless a remote-owner wait was measured.

The low-volume overlap witness: per node and AG, during a named
free-running allocation phase, record the committed carve count and the
timestamps of the first and last committed carve. Require, in at least one
shared AG, at least two carves by each node and overlap of the first-to-last
spans beyond the timestamp uncertainty:

    min(last_A_lower, last_B_lower) − max(first_A_upper, first_B_upper) > 0

This rules out "all of A's carves, then all of B's". Timestamps must be
calibrated with a recorded error bound (uncalibrated wall clocks and driver
receive times are not event times). There is no universal "overlap ≥ x % of
wall" threshold: the floor is positive overlap beyond uncertainty, backed by
actual allocator events; duration and volume are stress settings, not
non-vacuity prerequisites.

## Instrumentation

Monotonic counters keyed by filesystem incarnation, module incarnation,
node and AG; before/after snapshots per workload phase (no reset needed):

    chunk_carves, chunk_releases
    finobt_inserts, finobt_deletes, finobt_updates
    finobt_full_to_partial   (an EXISTING full chunk gains a free inode)
    finobt_partial_to_full   (an EXISTING partial chunk becomes full)
    first_carve_time, last_carve_time   (scoped to the measured phase)

The reason-specific finobt counts stop "finobt changed" being satisfied by
inserting a newly carved chunk and later deleting it.

**Semantics outrank interface.** Count SUCCESSFUL metadata transitions —
never allocator entry, retries, reservation attempts, DLM acquisitions,
unlink requests or deferred-free scheduling. A carve counts when the new
backing and its inode-tree state were published by the transaction; a
release counts when the backing was returned through the free-space
operation including required deferred work, not when the last name went
away; an aborted transaction never counts. Attribute to the node executing
the transition (deferred work may not be the node that issued the create or
unlink). A per-node scalar is insufficient: export a per-AG vector through
an interface that gives consistent snapshots. DLM acquisition counts are no
substitute (locks are acquired without allocation). Counters are
filesystem-specific, or the test proves no other filesystem contributed.

## The release floor (non-vacuity, not stress adequacy)

| assertion | floor |
|---|---|
| same-AG clustered carving | one AG with ≥ 2 committed carves from EACH node in the phase |
| measured overlap | those carve spans overlap beyond timestamp uncertainty |
| multi-AG breadth | a committed carve in at least one further AG, by either node |
| chunk reclamation | ≥ 1 committed chunk release during the stress row, before unmount |
| finobt lifecycle | ≥ 1 existing-chunk full→partial AND ≥ 1 partial→full |
| non-empty audit input | in each covered AG, ≥ 1 stress-created inode retained in allocated backing |
| final finobt coverage | in each covered AG, ≥ 1 genuinely partial chunk represented in the finobt |
| structural completeness | every mandatory checker pass completed; no skipped AG, no missing required output |

All counts recorded per node and AG, zeros included. Reclamation and finobt
floors are filesystem-wide claims. The stress row: (1) a shared-AG
allocation burst with both workers continuously allocating; (2) fill chosen
chunks, free chosen inodes, refill them; (3) delete a disposable cohort and
WAIT for release evidence (unlink, close and sync do not establish release —
observe the counter; a retention policy that prevents release fails the
assertion, never waives it); (4) leave a retained, partially used cohort in
the covered AGs. AG steering is a workload technique; **actual AG
attribution decides the assertion** (a directory's placement is not
evidence). The retained cohort's inode numbers and AG/chunk identities go in
a manifest OUTSIDE the audited filesystem; the cold checker confirms their
inode bits remain allocated and the chunk/finobt relationships were checked.

## Where it is recorded

One sealed witness artifact owned by the driver, populated in stages:
post-format baseline (machine-readable per-AG AGI count/freecount, inobt
record count and totals, allocated backing totals, finobt record count and
free total, plus the raw checker output); the stress row (run, filesystem
and format incarnation, phase ids, nodes and module incarnations, counter
snapshots and deltas per node and AG, carve timing with clock-error bounds,
actual AG attribution, retained-cohort manifest, every threshold result;
the ending snapshot taken after deferred work and BEFORE unmount, with
unmount-tail activity collected separately and never credited); the cold
audit row (verifies the witness belongs to this incarnation and the
immediately preceding stress row, verifies every node unmounted, runs the
checker, appends the final per-AG platter state and cohort verification,
evaluates the combined verdict; refuses a stale or mismatched witness). No
workload may touch the filesystem between the stress row and the cold
check. The authoritative witness is never only RESULT text, kernel logs or
MQTT. Never reconcile a stress-row counter delta against a post-format
platter delta as one interval: earlier rows contribute to the latter.

## Verdicts

    structural: CLEAN | CORRUPT | INDETERMINATE
    coverage:   PASS  | INSUFFICIENT | UNKNOWN
    release:    CLEAN | CORRUPT | VACUOUS | INDETERMINATE

CORRUPT whatever the coverage; CLEAN only when structural CLEAN and coverage
PASS; VACUOUS when structural CLEAN but complete measurements show a floor
unmet (zero releases with valid counters; disjoint carve spans);
INDETERMINATE when required evidence is missing or untrustworthy (counters
reset mid-way without a ledger; missing cross-tree output). **Only release
CLEAN passes the gate**; insufficient coverage is never a warning on a pass.

## Hazards by shape

Final platter only: net-vs-gross, invisible cycles, inherited finobt
occupancy, no node attribution, prior rows contaminate. Row wall-time
overlap: barrier/setup overlap mistaken for allocation overlap, incomparable
clocks. Per-node global counters: exclusive different-AG allocation passes.
Per-AG counters without timing: sequential nodes pass. Per-AG DLM counts:
acquisition is not mutation, commit or contention. Counters without precise
semantics: retries, aborts, deferred work, reloads and unrelated mounts
fabricate a witness. Stress without retained state: the audit examines
almost none of the transitions' output. Retained state without transition
evidence: no lifecycle or concurrency claim. Work inside the audit row:
conflates generation, evidence and checking.

The resulting claim as first ruled: both nodes made interleaved committed
inode-chunk allocations in a shared AG; allocation reached another AG; chunk
reclamation and the named finobt transitions occurred; the subsequent cold
checker completely validated the final structures including the retained
workload state. It does not claim lock contention, transient-state
correctness, crash recovery, btree split/merge coverage, or correctness
under every workload.

# s73 re-scoping — the floors the allocator's design makes unreachable

The witness was implemented and measured, and three floors above were found
to demand what the module is designed never to do. Consulted again with the
allocator read from the source; the ruling below corrects the gate's
specification. It is not a waiver of failed coverage: the verdict is still
release CLEAN = structural CLEAN AND the (revised) witness PASS, and the
existing-chunk finobt transitions, the retained cohort and the final
partial-chunk floors stand.

**The design facts.** On a multi-node mount every regular file and every
directory is allocated from this node's own affine AG (slot mod AG count),
whatever the parent's AG — the fix for two nodes' inodes sharing one inode
cluster buffer, whose flush clobbered the peer's inode. A strict partition
(a node owns agno mod stride == slot mod stride, stride the on-disk node
count folded to the AG count) keeps a node out of every other AG; a final
RELAXED pass drops ownership only when the node's whole stride is genuinely
full with no cluster contention seen. Two nodes carving in one AG is the
recorded precondition of the cross-node inobt double-allocation. A
clustered mount never deletes a fully free inode chunk: a sole survivor once
returned 187 chunks' blocks to the free pool and a directory's data landed
on a live inode cluster; no membership predicate can answer "has another
node ever written this volume", so the guard fails closed and the chunk
stays in the inobt, its inodes reused by later creates.

## A. Partitioned, overlapping allocation — replaces same-AG carving and its overlap

Floor: every node's mount was multi-node under one common stride; every
committed carve respects the carving node's configured ownership; every AG
carved during the whole row has exactly one carving node; in the
free-running phase each node commits at least two carves in its own affine
AG; the nodes' phase-1 carve spans overlap after the measured offset, its
error bound and a drift allowance over the span; no RELAXED
ownership-dropping pass occurs in the row; and after every node unmounted,
the cold audit reconciles the superblock icount/ifree with every AGI and
its inode records.

Hazards: ownership is the CONFIGURED stride, never the count of live
nodes; the events are phase-specific committed carves, never mount-lifetime
totals; overlap must stay positive under the admissible clock mappings, not
merely at the estimated offset; overlapping spans show overlapping
allocation workloads, not simultaneous execution of one metadata mutation
and not the absence of a lock; carve exclusivity says nothing about
allocation from existing chunks, peer-inode freeing or inode-buffer
coherence; audit before anything can normalise the accounting.

Permitted claim: "Both nodes performed overlapping free-running inode-chunk
allocation in their respective affine AGs. Every observed carve respected
the configured ownership partition, no AG was carved by both nodes, and
final on-disk inode accounting reconciled across all AGs. This establishes
partitioned allocation coverage, not shared-AG carving coverage."

## B. Empty, retain, reuse — replaces the positive chunk release

Floor, on EVERY node: at least one identified chunk fully occupied by an
attributable disposable cohort (chunk identity, usable inode count, cohort
membership recorded — "the cohort holds a chunk's worth of files" is not
enough); fully emptied by committed inode frees, established by a live
observation of the inode btree (an unlink is not a free: open references,
deferred inactivation and delayed work must have resolved, and a fixed
sleep does not establish that); retained with a zero committed-release
delta on every clustered mount throughout the row; reused as an existing
chunk by subsequent production allocations, bounded — other free chunks may
legitimately win selection, so "the first create must pick the target" is
never required, and failing to observe reuse within the bound is a coverage
failure, not allocator corruption; and at the cold checkpoint each target is
still a whole inobt record whose free mask and freecount match exactly the
accounted occupants, whose blocks are absent from free space, and whose
finobt entry is correct.

"Releases must be zero" is a legitimate invariant assertion when it sits
beside the positive evidence that a chunk became fully free, stayed an inode
chunk and was reused; it is not branch coverage of the deletion guard (that
needs an observed guard evaluation on a deletion candidate, which this
floor does not claim). Reusing one inode from a fully free chunk does not
establish the existing-chunk partial→full transition; that floor stays
independent, and the required partial chunks are still left for the
checkpoint.

Permitted claim: "The workload fully emptied at least one identified inode
chunk, retained it without any observed committed clustered chunk release,
and subsequently reused its inode space in place. The cold audit confirmed
retained chunk ownership, correct freecounts and finobt state, and no
chunk/free-space aliasing. This tests retention and reuse, not successful
chunk deletion."

## C. Chunk deletion without a DLM — outside this gate

No positive chunk-deletion floor belongs in the two-node clustered witness.
A separate never-clustered regression test is the place for it (a
demonstrably never-clustered image, a genuine committed deletion, the record
gone and the blocks back in free space at a controlled checkpoint,
structural CLEAN), and its PASS never satisfies a clustered lifecycle
requirement. `!mp->m_mxfs_dlm` describes the present mount, not the
volume's history; a lone survivor on a DLM mount is still clustered; a
no-DLM read-write mount is never an innocuous cold-audit step on the
clustered image; moving a once-clustered volume into no-DLM operation is a
separate safety obligation the gate's name does not exclude.

Permitted claim: "The two-node clustered gate does not exercise successful
inode-chunk deletion without DLM. No claim about that path, or about
clustered-to-nonclustered mode transitions, follows from this PASS."

## D. Owned-AG spill and wrap — omitted, and the claim says so

The bounded affine witness may omit spill if its claim excludes spill and
wrap. Including spill would need a supported geometry giving the node
another owned AG, a naturally reached state in which the affine AG cannot
satisfy the allocation while another owned AG and the inode budget can, an
observed production spill and committed carve there, continued ownership
compliance and no RELAXED fallback; a wrap claim needs the traversal itself
observed. A force-spill knob is white-box branch testing and never
establishes that production conditions reach the branch; the RELAXED pass
stays a separate release hazard that a narrow gate excludes from its
evidence without establishing safe exhaustion handling.

Permitted claim: "This witness covers affine allocation under
non-exhaustion conditions. It does not cover owned-AG spill, partition
wrap, or RELAXED ownership-dropping fallback."

## The gate claim once the revised floors pass

"On the tested two-node TCP-DLM configuration, the cold structural audit
was CLEAN and the revised allocation witness passed. The run covered
overlapping partition-respecting chunk allocation, the required
existing-chunk finobt transitions, retained cohorts and partial chunks, and
an observed empty–retain–reuse lifecycle with zero committed clustered chunk
releases. Final on-disk inode accounting reconciled. Coverage of spill,
exhaustion fallback, successful no-DLM chunk deletion, and membership or
mode transitions is excluded unless separately reported."
