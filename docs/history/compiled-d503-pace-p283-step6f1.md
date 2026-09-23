<!-- D-503 shared-dir create pace collapse (sess295-304, DISPROVED/harness IO), P283 proof-cert audit fix (sess305-306), step-6 F1 deferred-release design… -->
D-503 pace-collapse campaign (sess295-304), the P283 proof-certificate audit defect it
surfaced (sess305-306), and the step-6 F1 deferred-release enforcement design it fed into
(sess307, sess309). All ccloop c7ee71c6, 0.11.507→0.11.511, 2026-08-15.

## D-503: 32-node shared-dir create pace collapse (dir_reuse_coherency / crash_consistency)

sess294's timeline led into sess295's RULE-4 refutation: "holder sat on EX through 1-2 BAST
retries" was a misread of P34 dur_ms — P291-EXWIN showed continuous fair rotation (median
handoff 309ms, per-node wins 22-51, even). Real mechanism: 32 nodes × 50 O_SYNC creates into
one shared dir, ~8 tenures/node × ~6 creates/tenure, tenure ≈300ms (MHT bound + 15ms batch
grace); under collapse each rotation queues 31×300ms → matches observed 24-33s phases.
`docs/rulings/503-convoy-quantified-gpt-ruling-fix-order.md` got the first GPT
RULE-5 ruling: instrument the full mint/nom handoff timeline before any fix, candidate fixes
B (nominee-only fast-retry ladder after nudge) and D (bounded background-release sweep
pacing), plus a note that "shape A" (wall-clock tenure extension) is a no-op since tenure was
already at MHT.

sess296 landed step-1 instrumentation (0.11.507): P297-TKT per-wait wake/miss attribution
(wake=1 nudge / 2 poll / 3 oversleep-past-swallowed-nudge), P70-BP tenure decomposition
(fo_ms=grant→first-op, lo_ms=last-op→release). Key prior: MXFS_CAW_DEFER_POLL_MS=250ms
matched the observed 225-330ms nom-adopt latency, motivating the swallowed-nudge hypothesis.
`docs/history/docs/history/docs/history/compiled-d503-pace-p283-step6f1.md`

sess297 measured .507 fleet-wide: swallowed-nudge DISPROVEN (wake=3 exactly once in 7417
waits). The real cost was the adopt-path tail: nom→sighting med 3ms but sighting→adopt med
1801ms/p90 2981ms — nominee sees the ticket, then stalls claiming it. This refuted fix B (no
sleep to shorten). P70-BP showed fo_ms med=1 (adoption setup cheap), marginal ~10ms/op —
contradicted sess295's fixed-300ms-tenure picture. dir_reuse_coherency FAILED on pace alone
(7 rounds/100s vs MIN_ROUNDS=8) even though crash_consistency PASSED.
`docs/history/docs/history/docs/history/compiled-d503-pace-p283-step6f1.md`

sess298 proved the root via P298-ADOPTCENSUS (0.11.508, 1545 fleet lines): every slow (>800ms)
EX grant on the hot dir arrived via releaser direct-handoff (adopt), never self-promote
(caw_try=0), and the ticket (yield_to) got re-pointed away an average 2.5×/wait — only 44%
of waits ever saw themselves named. Mechanism: `caw_pick_next_ex_waiter` picks the next EX
waiter relative to the CURRENT releaser's own slot — memoryless — so every intermediate
releaser in a PR-drain chain overwrites yield_to with its own pick, starving whichever waiter
isn't lucky enough to be nominated by the LAST releaser. GPT ruling = fix C: state-relative
selection keyed off `last_ex_slot` (advances only on committed EX grant, never at nomination)
+ a sticky standing ticket that ordinary PR-drain releasers must not overwrite + mandatory
PR→EX atomic conversion when the standing nominee is the sole remaining PR holder (deadlock
guard) + stale-clear only on demonstrated invalidity (dead/canceled/fenced), never plain age.
`docs/rulings/sticky-ticket-round-robin.md`

sess299 implemented fix C in dlm_caw.c only (0.11.509): `caw_standing_ex_resv`/
`caw_last_ex_bit` helpers; nomination now prefers the standing reservation, else streak_yield,
else the state-relative pick; PR-batch admission sets yield_to from ex_resv without
overwriting; direct-handoff condition extended to cover sole-PR-nominee with an atomic
holders_pr→holders_ex conversion; wait-loop and initial-acquire stale-clears require
age≥5s AND ticket-target no longer waiting; waiter-cancel clears its own yield_to bit
immediately. last_ex_slot advance and upgrader-priority bypass left as already-conforming.
`docs/history/docs/history/docs/history/compiled-d503-pace-p283-step6f1.md`

sess300 verified fix C on the rig: full accumulation board green, collapse chunk PASS first
try (dir_reuse 112s/120s, 58/58), P298-ADOPTCENSUS window comparison .508→.509: tkt_lost
1.51→0/wait (zero fleet-wide), p99 21.4s→8.7s, clean-run max 3.0s. Starvation component of
D-503 FIXED AND VERIFIED at the mechanism level. But a residual surfaced: reproducible 4/4
back-to-back pace degradation (idle recovers to PASS in ~3min, immediate rerun FAILs at 6-7
rounds) with EX-wait census barely moving between the two conditions — DLM exonerated. Node
`/proc/fs/mxfs/stat` sampling showed no local backlog; the lead was clyde nvme write behavior
during a post-FAIL evidence harvest that writes GBs to the host.
`docs/history/docs/history/docs/history/compiled-d503-pace-p283-step6f1.md`

sess301 reproduced 5/5 and refuted three of sess300's residual hypotheses with direct
measurement: clyde nvme sustained-write GC (flat awaits, no in-run climb), harvest dirty
backlog (inter-run gap quiet), and node-side block IO (test1 sda awaits flat in both runs).
Finer-grained phase decomposition showed the "uniform slowdown across phases" claim was
wrong: wrbar/presync/rm phases grow round-over-round, dc/sync1/verify/ls stay flat — and
run2 starts already elevated on the growing phases. New lead: CAW slot-table tombstones
(open-addressing, linear-probe, TOMBSTONE on delete) — idle dump showed 18,645 TOMB of 65536
slots (28% occupancy), theorized to lengthen find_slot probe chains every round with no
observed TOMB→EMPTY sweeper.
`docs/history/docs/history/docs/history/compiled-d503-pace-p283-step6f1.md`

sess302 refuted the tombstone lead by code inspection alone: no code path anywhere converts
TOMB→EMPTY (only mkfs zeroes), so probe-chain length is monotone non-decreasing over disk
lifetime — a run after 3min idle starts from the same-or-worse table as the failing b2b run2
and still PASSES, which is the opposite of what the hypothesis predicts. Also refuted:
single straggler node (create durations uniform fleet-wide every round) and test1-local
backlog at run2 start (all counters flat 20s before run2, which is slow anyway). Real signal
isolated: **presync** (the post-wrbar `sync` call in dir_reuse_coherency.sh) steps from 0.6s
to 2.6-3.8s starting at run1 round 4 and never recovers within the run; run2 starts already
at that plateau. Hypothesis for next session: AIL/dirty-metadata backlog from 32 simultaneous
post-barrier syncs contending over DLM cluster-buf/AG locks (recalling a sess18 comment about
inodegc backlog draining over 60-120s).
`docs/history/docs/history/docs/history/compiled-d503-pace-p283-step6f1.md`

sess303 refuted the AIL/dirty-metadata hypothesis directly (AIL depth ≤16 blocks and grant
heads flat on every node through the full PASS/FAIL/idle/PASS cycle) and instead proved the
cause was HARNESS-INDUCED, not mxfs: a null-mxfs synthetic repro (`tests/drc_synth_sync.sh` —
17MB writes to node root fs + sync(1), zero mxfs ops) reproduced the exact settled/b2b/idle
timing triad. Mechanism: `dir_reuse_coherency.sh` was dumping the full 16.9MB dmesg ring to
`/root` every round on every node (540MB/round fleet-wide), forced through the qcow2→nvme0n1
host disk that also hosts all 32 VM images AND the SCST LUN backing store — suspected NVMe
pseudo-SLC write-cache exhaustion (~3-4GB fast-write budget, ~3min recovery, matching the
idle-recovery constant). Prescribed closure: move the dmesg snapshot/stream from `/root` to
`/dev/shm` and re-run b2b, predicting PASS+PASS.
`docs/history/docs/history/docs/history/compiled-d503-pace-p283-step6f1.md`

sess304 executed that closure and **CLOSED D-POSTLOAD-SYNCWRITE-PACE-COLLAPSE-503 DISPROVED**:
moved the per-round dmesg snapshot and the DRC_STREAM follow target to tmpfs in
`dir_reuse_coherency.sh`, updated all downstream consumers to search both paths, then ran
back-to-back `dir_reuse_coherency` ×3 with no idle gap — PASS/PASS/PASS (107/108/109s), where
run2 had failed 7/7 deterministically before. The create-phase +1.5s/round term vanished too
(same host-collapse mechanism). Net: fix C is a real, verified DLM fairness fix; the residual
that looked like a lingering D-503 symptom was entirely the test harness's own IO pattern
saturating the shared host disk, not an MXFS defect.
`docs/history/docs/history/docs/history/compiled-d503-pace-p283-step6f1.md`
Ops notes from this arc: `make clean` deletes `tools/` binaries — always `make tools` before
`prep_cluster` or prep fails "mkfs tool not found". `tools/mxfs_sshpass.sh` takes a bare
hostname (it prepends `root@` itself); `root@testN` fails rc=5.

## P283-RELCERT-CAS-UNPROVED: proof-certificate audit defect (sess305-306)

Investigating fleet dmesg from the D-503 board (no new build needed), sess305 proved the root
of all 33 observed `cas_unproved` events on 0.11.509 (752,428 release attempts): two
concurrent `mxfs_dlm_bast_process` release pipelines from different kworkers legitimately
race on the same hot shared-dir inode (duplicated P51-REL/P147-PREUNLOCK/P6H-HANDOFF with
identical gen/slot/epoch) — both run the proof, but the later stamper reads the peer's
RELEASING state, and the single shared scalar `i_mxfs_rel_state` cannot represent two live
instances at once. This is a legal outcome of the two-slot demoter design, not a correctness
bug — the AUDIT was unsound, not the release. GPT ruling: move proof authority to a
**per-instance, tenure-bound proof certificate** (cert gains `proved` + `rel_gen`), add
`cas_noproof_v2` as the real gate metric (own cert unproved), demote `i_mxfs_rel_state` to
diagnostic-only, reject both pipeline-serialization and a CAS-window mutex as fixes (liveness
risk), and enumerate 7 invariants a legal concurrent-dup-release must satisfy (only the CAS
winner publishes; losing completion must not reset winner state; CAS covers full tenure
identity; etc.) — any unproven invariant becomes its own defect.
`docs/rulings/p283-per-instance-proof-cert.md`

sess306 implemented and verified the ruling (0.11.510): `mxfs_release_cert` gained
`proved`/`rel_gen`; both PROVED exits of `mxfs_relbar_close_or_defer` (anchored and noanchor
arms) now stamp `proved=1`; `cas_noproof_v2` counts `cas_attempted && !proved`; legacy
`cas_unproved` kept as silent diagnostic. 3× `dir_reuse_coherency` on the rig: PASS 32/32
every time, and over ~124k release attempts **cas_noproof_v2=0 on all 32 nodes** while legacy
cas_unproved still ticked 4 times — exactly the predicted A/B (legacy audit false-alarms on
the known aliasing overlap, v2 stays clean). Opened a new ledger entry
D-DUP-RELEASE-HANDOFF-INVARIANTS-UNVERIFIED (high) because invariant 4 was found literally
violated in this same run (loser's `relcert_finish` writes ACTIVE over the winner's RELEASING
— currently telemetry-only, no correctness impact yet proven).
`docs/history/docs/history/docs/history/compiled-d503-pace-p283-step6f1.md`

## Step-6 F1: deferred-release enforcement (sess307, sess309)

With steps 1-5 landed as telemetry, sess307 obtained the RULE-5 ruling for step 6 — making
deferral of a release actually happen instead of just being counted. Defer predicate:
`still_dirty || proof_failed || tripwire` — explicitly NOT the F2 ticket-absent/NO_DOMAIN
case (that's step-7 persistence-domain policy, snapshotted at mount so a runtime
`fua_disable` flip can't change requirements mid-tenure). One knob `release_proof_enforce`,
default 1 on the verification board (a near-zero observed rate means enforce-off verifies
nothing), load-time/read-only. Design: an ICLUS per-cluster delayed worker with states
{ACTIVE, DEMOTING, WEDGED, RELEASED} and a `release_epoch` ABA guard; immediate first retry,
~25ms→1s backoff with jitter; enters the normal busy-serialized release path (no second CAS
path) — drain, log-force if pinned, targeted AIL push, retry durability, keyed proof, CAS
only on full proof; disarms only on successful CAS, explicit cancel (epoch++), or safe-sync
teardown, never on apparent state change alone. Admission closure required: new ops park on
a waitq while DEMOTING, wake on release-done/valid-cancel/wedge. Bounds: 60s no-progress or
300s total DEMOTING → WEDGED (progress = obligation/inflight decrease, unpin, dirty→clean,
proof-phase completion — NOT mere seq/gen change or another BAST). On wedge: pin the resource,
refuse it in `release_all` at teardown (so unmount can't silently drop a wedged grant), force
shutdown once, let peer fencing take over. `-EDEADLK` stale-selfclear gets no exemption from
any of this.
`docs/rulings/step6-f1-deferred-release-enforcement.md`

sess309 landed build 1 (0.11.511) implementing items 1-10 of the sess308 map:
`mxfs_release_proof_enforce` (0444); `mxfs_iclus_disk_release` changed to take `ic` as a
parameter instead of an internal lookup (the old lookup could race `purge_all`'s unhash and
silently disable the defer gate mid-teardown); defer gate fires after tripwire eval on
{oblig_cas, proof_failed, tripwire}, with `cas_attempted` set only after the gate so a
deferred cert correctly reads `cas_attempted=0`; `mxfs_iclus_defer_arm` tracks episode state
under `ic->lock`, backoff work queued under the same lock (closes a schedule-after-cancel
use-after-free race against purge_all's no_retry-then-cancel_sync); a refinement beyond the
sess308 map — a FAILED CAS under enforcement must NOT reopen admission (old code set ACTIVE
unconditionally), because the worker's granted-only covered_active sweep is only sound while
DEMOTING blocks new grant stamps for the whole episode; wedge pins the grant via
`mxfs_v5_dlm_iclus_pin`→`mxfs_dlm_caw_pin_resource`, and `release_all` now refuses pinned
slots; `release_done_locked()` centralizes success bookkeeping including the release_epoch
bump and episode reset — without that reset, a stale `defer_started_j` would instantly wedge
the very next episode against the 300s total bound. Deliberately deferred to "build 2": the
relbar proof-failed flip into the defer/strand channel and per-release_epoch selfclear
suppression. Not yet deployed to the fleet; fault-inject verification (relgate_fault stages
7/9/10) still owed, plus a design question on how to hold a proof failure open long enough to
exercise the wedge path.
`docs/history/docs/history/docs/history/compiled-d503-pace-p283-step6f1.md`
