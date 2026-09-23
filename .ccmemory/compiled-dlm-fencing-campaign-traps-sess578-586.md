---
name: compiled-dlm-fencing-campaign-traps-sess578-586
description: sess578-586: D-0932/0945/0955/0957/0958/0959 DLM/fencing/join campaign — design rulings plus the measurement-integrity traps that produced false verd…
metadata:
  type: project
tags: [compiled, dlm, fencing, measurement-integrity, harness, join, tcp]
---

## Topic

The 2-node TCP DLM/fencing/join-membership correctness campaign, sess578-586,
covering defects D-0932 (per-LUN PR gate), D-0945 (poison-gate timing),
D-0955/D-0957 (sole-survivor ownership + inode-cluster reallocation), D-0958
(remote-acquire abandonment), D-0959 (first-join freeze), and D-0953
(departure-worker teardown). Interleaved with the design work is a chain of
measurement-integrity traps: nearly every false verdict in this campaign came
from treating an absence, a truncated count, or a co-occurrence as if it were
a proven fact.

## sess578 — co-occurrence is not causation (D-0932)

[[trap-co-occurrence-of-two-probes-is-not-a-race-waking-is-not-acting]]: a
check of the form `event_A>=1 && event_B>=1` scored "two actors under one
attempt" when neither actor had acted — `RETIRE_PENDING` was never published
(an earlier assertion already said so), the resumed worker issued nothing,
and an in-node guard had already refused the double-issue five times. Count
the actual violation (the old prover proving exclusion under a term a
takeover already raised), never the ingredients. When an earlier assertion in
the same lap already failed, later assertions built on that state are
unscoreable, not FAILing — consider VACUOUS. Separately: a bound shorter than
the injected delay it must outlast measures the injection, not the system;
derive timeouts from the injection's own duration plus slack.

## sess579 — master locality must be established, not assumed

[[trap-which-node-masters-a-resource-is-a-hash-so-a-two-node-lap-must-establish-locality]]:
which node masters a DLM resource is a hash of the resource id, so a harness
using whatever inode a create() happens to return silently coin-flips between
the remote-master (wire) and local-master (no wire) code paths across laps —
one session scored 9/9 PASS while measuring the untested path, and a budget
gate of `fires<=budget` passed on a zero produced by counting on the wrong
node (the master fires the blocking notification, not the holder). Fix:
establish locality first-hand per lap (arm a probe that only fires on the
remote path; its firing proves remote, its silence proves local — never the
reverse), derive which node to count on from the established locality rather
than from role names (H/W), and gate against zero explicitly.

## sess580 — PR-gate obligation set, and four measurement traps in one day

[[trap-a-per-lun-exclusive-reservation-has-more-than-one-recovery-depending-on-it]]
(D-0932, architecture): one SCSI PR reservation per LUN can have two
recoveries running under it at once — a node returning alone must both
recover its own prior incarnation and fence the peer that had been recovering
it. `v5_gate_restore()`'s comment assumed singular cardinality; the first
recovery to complete restored WE-AR and stranded the second, which then
correctly refused to replay anything forever, so the sole surviving node
never mounted. Fixed with an explicit dependent set (register from the same
evidence that lets a recovery proceed; release own dependency on completion;
restore only when the set empties — never on a timer). Wrong fixes considered
and rejected: relaxing to accept WE-AR, comparing against the certificate's
original prover key, or a bare refcount — none can say which recovery pins
the gate. Two things still owed: the purge must be generation-safe (name
which journal generation/records it deletes), and control-plane publication
(grant-release/completion messages) needs fencing too, not just the
reservation check.

[[trap-master-assignment-moves-across-a-module-reload-so-locality-is-per-epoch]]:
which node masters an inode is re-decided when the cluster re-forms, so a
locality established before a `module_swap_deploy.sh` is void after it — same
inode mastered by test2 pre-swap, test1 post-swap. Re-establish locality
inside the lap that uses it, never carry it across a deploy. Compounding trap
in the same harness: a probe that calls a candidate "local" when a
remote-path drop knob does not fire is reading absence as an answer — fixed
by making both branches first-hand (holder takes a conflicting grant, waiter
reads, whichever node LOGS the blocking notification is the master; both-or-
neither is UNDETERMINED, skip it). Also scope every notification count by
`ino=$ino ` with the trailing space (`ino=140` matches `ino=1400` without it),
and never compare `pr_warn_ratelimited` line counts across laps as if they
were event counts.

[[trap-a-design-consults-hazard-ranking-is-hypotheses-not-findings-measure-before-redesigning]]:
a consult ranked a shared-acquisition-record key #1 and urged a redesign;
instrumented, it showed 114 collisions per 240s wait at zero cost (sharing is
what makes N waiters cost the holder one notification stream instead of N),
and the recommended fix would have reintroduced the exact defect being fixed
(the remote master's lookup keys on (resource, sending node), so a per-task
identity fails its re-send lookup). Two other consult-ranked hazards were
never observed (counters both 0), and the thing that actually produced a
wrong result that session — a harness probe reading silence as locality —
was never on the consult's list, because it wasn't shown the harness. Take a
consult's ranking as a list of things to instrument, not a work order; prove
the instrument can fire before trusting its silence; run controlled pairs
(one variable differing) so the delta is attributable.

[[trap-never-derive-a-count-from-a-capture-you-have-not-proven-non-empty]]: an
ssh helper (`rs() { timeout ... $SSH ... 2>/dev/null | filt; }`) swallows the
remote command's stderr inside the helper, so a caller's own `2>&1` redirect
is a no-op and a failed remote command produces a zero-byte capture. A
`grep -c` over that empty file reported "0 descriptors standing" as a FAIL
about MXFS, when the real cause was the judge node having no NFS mount yet
(freshly booted) so the dump tool couldn't even run. Fix: put `2>&1` inside
the remote command; assert the capture matches an expected non-empty SHAPE
before counting (an error message is non-empty too); on failure exit
ABORT/INFRA, never FAIL/VACUOUS — a zero from a broken instrument and a zero
from a clean system are the same number.

[[trap-a-set-built-from-validation-holds-nothing-for-an-obligation-not-yet-started]]
(sess580/581, D-0932 continuation): a consult said "account for all
outstanding obligations, not merely currently running threads"; 0.82.4 built
the dependent set from recoveries that had validated exclusion (the running-
threads half only) and shipped — the next lap failed identically because a
recovery certified under the gate but not yet claimed by the mount barrier
registered nothing. A set populated at "I have started" cannot answer "is
anything owed" — register from where obligations live durably (the on-platter
recovery descriptors), pin an in-memory set BEFORE the action for windows the
durable state can't see, and when a consult names two halves, verify both
were actually built before marking the record fixed.

## sess581 — a budgeted probe's line index is not an event index

[[trap-the-nth-printed-line-of-a-budgeted-probe-is-not-the-nth-event]]:
`P912-DROP-LOCKREQ` prints only its first 8 hits and every 64th after; a
harness took the (baseline+1)-th printed line as "the first armed drop" and
actually read the 64th event, scoring latency as -8s against a correct build.
When a detector reports its own measurement inline (`unanswered_ms=`,
`bound_ms=`), score that field — it's on the code's own clock and independent
of which other lines happened to print.

## sess582 — timing windows, per-load counters, incarnation awareness

[[trap-a-cause-reproduced-outside-its-timing-window-lands-in-the-second-defence-and-reads-as-unreachable]]
(D-0945): a positive control disabled the poison gate and reproduced the
cause, but the release reached the master 0.2s after the fence had sealed, so
the next line of defense (`P-TAUTH-SEALED-RELEASE-REFUSED`) absorbed it and
the naive read was "gate off, no harm, gate unnecessary." Before scoring a
control: measure the window the primary defense exists to close (both nodes'
timestamps), put the actor inside it deliberately (force the reclaim rather
than wait for a periodic worker), prove it landed inside the window with a
second-line counter of zero plus a direct effect, and report which line of
defense actually answered.

[[trap-a-per-load-counter-read-from-the-per-boot-ring-and-the-mount-line-that-anchors-it]]:
`dmesg` is a per-BOOT ring; MXFS probe counters and print budgets are per-
LOAD (static, reset on insmod). Reading a budgeted probe against the whole
ring after a same-boot module reload gave two false FAILs — a filler
workload spent a 96-line budget, so later arms measured against a silenced
probe; and a whole-ring "pre" (1115, previous load) vs "post" (8, this load)
census read as a -1107 loss. Anchor every per-load read on the mount line
every mount prints first (`MXFS-MEMBERSHIP local=<id> active_count=1`):
`dmesg | tac | sed '/MXFS-MEMBERSHIP .../q' | tac`. A same-load remount moves
the anchor without resetting the counter — under-counts, never produces a
false PASS.

[[trap-a-changecount-regression-probe-must-be-incarnation-aware-and-the-root-cluster-passengers-are-the-rt-inodes]]
(D-0955): `mxfs_dino_clobber_probe` flagged "memory changecount below
platter" as a revert on slots where a sole survivor had simply allocated a
new file over a departed peer's freed inode number (changecount restarts at
1 with a fresh random generation on new allocation — that's the allocator
working, not a clobber). The regression predicate needs the incarnation: same
generation and behind, or platter holds the freed successor at
generation+1 of the live image still held. Separately, "6 unauthorised
passenger slots" in the root inode cluster were the mkfs-created realtime
bitmap/summary inodes (`ino 129`/`130`), never in core, unchanged since mkfs
— present in any root-cluster workload; read per-slot lines, never the sum,
before calling a passenger a peer's inode. An "unauthorised" count and a
"stale" count are different instruments; only an incarnation-aware platter
compare answers "stale."

## sess583 — sole-survivor ownership protocol (D-0955/D-0957)

[[trap-a-ruling-that-says-take-path-x-exactly-as-multi-node-assumes-every-premise-of-x]]:
a consult ruled a sole survivor should take
`mxfs_submit_partial_inode_write()` exactly as under multi-node membership.
Landed alone, it stranded a freshly created directory (799/800 creates
failed, permanent ESTALE) because the partial path's authority rule
(logged-at-NL means "released to a successor") assumes grants exist, and on
single-node membership `mxfs_dlm_ilock_begin` bypasses the DLM entirely —
every logged directory sits at NL without a token, so the "same as
multi-node" rule refuses all of them. The ruling's premise (grants exist) was
false for the exact state it was ruling on. Corrected shape: a sole survivor
must run the real ownership protocol (take grants from the master, i.e.
itself) so multi-node invariants apply unchanged; only true
`mxfs_v5_dlm_never_multi()` state may modify/publish without a grant. Before
landing "take path X as under condition Y," enumerate X's preconditions in
code and check each against the state being ruled on. Also: an A/B harness
that alternates a fixed arm with the pre-fix arm lets the control rescue the
treatment's omissions (whole-write landed what partial-write dropped) —
verifying an omission needs an all-fixed-path campaign; sum the workload's
own error counters into the verdict, not just probe silence; positive
durability evidence is a cold-cache readback from another node, never the
absence of a clobber line (an omission bug fires no clobber probe on bytes
never written).

[[trap-platter-live-memory-free-different-gen-is-not-a-revert-unless-the-slot-is-unheld]]
(D-0955/D-0957): the clobber probe's "platter LIVE, memory FREE, different
gen = live revert" class fired three false positives in one session: a
96-byte detail buffer truncated the generation mid-number (fixed: 160
bytes); a free bumps the generation by exactly one, so platter-gen-behind-by-
one-with-memory-free is the node's own free landing, not a regression; and
tight-mode free/reallocate twice in one round with no sync produces images
identical to a real peer-clobber. The discriminator is tenure, not images: an
in-core inode held at EX/PR was reloaded from platter at grant time, so
everything since is provably ours (own-churn); a slot at NL or not in core
keeps the live-revert classification. On a pre-0.83.3 sole survivor every
inode sat at NL (no grants under the single-node bypass), so this
discriminator was blind there and every own-churn write misread as a revert.

## sess584 — first-join freeze design (D-0959)

[[trap-a-join-time-flush-that-races-the-local-workload-and-answers-with-a-shutdown-is-the-data-loss]]:
the incumbent's `peer_joined` flush ran 5 rounds of log-force + AIL-push +
cache invalidation on a protocol thread against its own live create/append
workload, never converged (buffers kept getting re-dirtied), and the fifth
round force-shut the filesystem down — losing every appended byte in 32 files
and 34 directories' worth of entries, including the peer's own already-synced
adds. Log force + AIL push do not write file data; a drain that must make
state visible to a peer needs `sync_filesystem`/`freeze_super` semantics.
Fixed in 0.83.4: `freeze_super(FREEZE_HOLDER_KERNEL)` on the incumbent, views
dropped and reinstalled under the freeze, thaw, all on a per-ctx join worker
with the peer registered only after prepare succeeds; a settle gate covers PR
and fails closed while a live member's beacon carries another view. A retry-
bounded flush racing the workload it flushes cannot converge — the answer to
"not converged" is "stay unadmitted, retry," never a shutdown; join taking
too long is not corruption. Design ruling: no grant of any mode (PR included)
to the newcomer until positive readiness, never a timer — a shared read
served early is a stale base for a later EX with no BAST able to fix it,
since the incumbent held nothing.

[[trap-a-join-lap-that-lets-the-incumbent-re-touch-its-objects-after-the-flip-measures-nothing]]:
three earlier join laps read clean because the incumbent's modification loop
touched every object again after the membership flip, so the first post-flip
write went through a real re-acquired grant instead of exercising the never-
multi-dirty-at-flip hazard. The lap that finally reproduced spread writes
round-robin over 96 untouched-after-flip objects and detected the flip from a
persistent `cat /dev/kmsg` reader (byte offset after a kmsg mark), because a
per-iteration `dmesg | sed | grep` on a 16MB ring costs over a second and the
resulting detection lag itself let a re-acquire happen under a real grant. On
a never-multi mount xfsaild lands a hot dir block every ~12ms, so only the
last tens of ms of metadata are dirty at any instant — a "dirty at the flip"
repro needs continuous modification up to the flip and zero re-touch after
it. Also: a name-prefix count collided with fixture names (`^b` matched both
seed and payload names; use `^b[0-9]`), and an `Edit` that dropped the
trailing space between a grep pattern and its path made grep read stdin and
silently return 0.

## sess585 — remote-acquire abandonment ruling (D-0958), probe scope

[[ruling-remote-acquire-abandonment-protocol-status-cancel-fallible-boundaries]]:
consult verdict on bounding a remote inode acquire whose live master never
answers. For a caller that cannot unwind (dirty transaction, writeback,
inactivation) there is no safe bounded completion under persistent request
loss — only wait-with-exclusion-preserved, transport repair, or an audited
unwind point; never membership escalation from the acquire path. Shipping
order: (1) acquisition lifetime keyed on a logical `acq_seq`, not on the
existence of a pending entry, so a grant landing between attempt windows is
adopted, not bounced; (2) exact terminal CANCEL with a per-(sender,
owner_inc, acq_seq) tombstone at the master, ack'd, DLM-owned cleanup; (3) a
status lookup (QUEUED/GRANTED/NOT_FOUND/NOT_MASTER/RECOVERING) where
NOT_FOUND means CONFIRMED_ABSENT via one ordered ingress, never "lost at
sender"; (4) nonce history sized to allowance × rate; (5) an explicit error-
returning acquire interface for audited call sites, checked at acquisition
not at syscall exit; (6) fatal-signal handling only on converted paths,
abandonment arbitrated atomically against installation; (7) transport repair
as a separate rate-limited subsystem with no membership/authority side
effects. Do-not-ship list: `current->journal_info == NULL` as a generic
failure permission, GRANTED re-delivery while the no-pending-entry bounce
rule stands, a CANCEL that only deletes a currently-visible waiter, K
consecutive NOT_FOUND presented as fact. K and the silence bound are policy —
never derive them from drain duration, holder I/O latency, membership
timeouts, or a test's window.

[[trap-a-locality-probe-scoped-to-low-inode-numbers-goes-blind-on-an-aged-filesystem]]:
`P7S-BAST-FIRE` (dlm/dlm.c fire_bast_records) prints only for `ino<=256` —
fine on a fresh filesystem's low inode numbers, silently blind on an aged one
(candidates 3713+ after a module swap). All eight candidates read
`master=undetermined` and the lap concluded, falsely, "none of the eight is
remote-mastered" — a hash conclusion produced by a silent instrument. The
same silence would make any locality self-check pass vacuously above ino 256.
Before scoring on a probe line, check its print CONDITION (inode scope,
budget, ratelimit), not just its existence. Fixed 0.84.0 with an explicit
`dbg_probe_ino` knob that makes the probe honor a named target regardless of
inode number.

## sess586 — departure-worker teardown ruling (D-0953), control-arm and knob discipline

[[ruling-departure-worker-teardown-cancel-between-pages-unbounded-join-no-quarantine-by-deadline]]:
consult verdict on the UAF panic where unmount ignored the departure worker's
30s join timeout mid-takeover and destroyed the engine under it. Cancel only
between page-transaction boundaries (prepare→activate→mark-MINE→purge→import
or PREPARE+FROZEN handoff); never propagate -EINTR into a page's substeps.
Untouched pages under a dead authority are safe to leave frozen (sweep-
recoverable); PREPARED-but-not-activated is safe only if something completes
it while the target is live; ACTIVE-before-purge/import is the dangerous
window — finish it, never unwind it. Normal unmount joins the worker with NO
bound (precedent: unmount already waits unbounded for its own parked
fence/recovery work) — keep 30s only as a diagnostic line, never as license
to continue destruction; a wedged LUN hanging unmount is recoverable, a UAF
is not. Quarantine is valid only holding the ENTIRE dependency closure
(engine, tables, ledger, device refs, I/O completions, slot map, transport
buffers/handlers, mutexes, mount ctx) — module pinning protects code, not
objects — and must also block stale-incarnation ledger writes after the PR
key is relinquished, or a UAF fix becomes a ledger-corruption bug. "Begin
departing" must close admission at every takeover entry point (worker,
orphan sweep, on-demand, receive-side handoff), not just the worker, with
own-authority freeze/handoff enumeration running strictly after that join.
Frozen pages after an interrupted pass are a liveness hazard for a survivor
that stays mounted (mount-settle sweep alone is not enough) — trigger a sweep
on every processed membership-change departure, not just "someone might
remount."

[[trap-a-control-arms-expected-behaviour-written-from-reasoning-hides-the-second-defence]]
(D-0958): a control arm's header asserted, from code-reading at design time
and never measured, that a master's undelivered grant without LOCK_CANCEL
"blocks the writer 40s forever." Measured: it blocked 10s then completed,
because a pre-existing second defense (`bast_notify`'s phantom-reconcile: two
no-mirror blocking notifications inside 15s on a TCP mount queue a
mirror-bypassing release) retired the orphan independently. The control
FAILed two checks that were fiction, not a broken control — "fixing" it by
widening or dropping those checks would have hidden that the pre-fix system
was already bounded at 10s. A control arm's assertions must name the specific
old mechanism they measure and report the wall clock, never an invented
duration; the treatment arm must also assert the second defense did NOT fire,
or a lap where both retire the grant proves nothing about which one the
write actually waited on. Run a control arm once before shipping its checks.

[[technique-a-test-knob-a-harness-selects-by-must-expose-a-counter-that-resets-on-write]]:
third occurrence of the budgeted-probe-line trap (after
[[trap-the-nth-printed-line-of-a-budgeted-probe-is-not-the-nth-event]] and
the sess580 selection-step variant) — a candidate search counted
`P912-DROP-LOCKREQ` lines (budgeted: first 8 + every 64th, per module load)
to find a remotely-mastered inode; once the budget was spent by an earlier
lap, later laps read every candidate as "locally mastered" and aborted, and
one lap only found a target because a hit happened to land on the 64th
event. Fixed at the source (0.84.2): make the drop counters readable module
parameters (`module_param_named(..., atomic.counter, int, 0444)`), and make
the arming knobs `module_param_cb` with a set-callback that resets both the
counter and the print budget on every write (arm or disarm) — the reset must
happen in the WRITE path, never lazily at next send, or a candidate that
triggers no send at all inherits a stale count. General form: any knob a
harness selects targets by must expose a per-arm counter reset at arm time.

## Recurring failure modes across the campaign

- **Absence read as an answer.** A probe's silence was repeatedly taken as a
  finding rather than checked for cause: drop-knob silence as "local"
  (sess580), print-scope silence on an aged fs as "undetermined" (sess585),
  an empty capture as "0 descriptors" (sess580), a whole-ring census across a
  module reload as "loss" (sess582), a zero-count budget gate as "pass"
  (sess579). The fix is always the same: prove the instrument can fire before
  trusting its silence, and make both branches of a binary determination
  first-hand.
- **Print/count budgets misread as event counts.** Recurred three times
  (sess581, sess580, sess586) on the same class of rate-limited probe; ended
  only when the probe itself was changed to expose a resettable counter
  rather than asking harnesses to reconstruct counts from truncated log
  lines.
- **Ruling/consult premises not checked against code state.** A consult's
  "take path X as under condition Y" (sess583) and its hazard ranking
  (sess580) were both correct reasoning applied to an incomplete picture of
  the codebase; the fix in both cases was measuring against the actual code
  paths and call-site reality before acting, not trusting the ranking or the
  analogy.
- **Harness state contaminated by re-touching or re-forming.** A join lap
  that let the incumbent re-touch objects after the flip (sess584), and
  master locality carried across a module reload (sess580), both measured a
  different mechanism than intended while reading as clean.
- **Timing windows treated as instantaneous.** A cause reproduced outside its
  defense's timing window (sess582) and a control arm's expected duration
  taken from reasoning instead of measurement (sess586) both required
  measuring wall-clock windows on both nodes rather than reasoning about
  ordering.
