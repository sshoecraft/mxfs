<!-- sess89-94: fence-certificate+recovery-takeover dead-code discovery, GPT rulings, wiring, rig verification (0.11.420-427); token-v2 wire shipped. -->
# sess89-94 — the fence-certificate / recovery-authority campaign

One continuous arc: starts by proving large parts of the recovery/fencing
subsystem are dead code, ends with the fence-evidence channel wired, rig-verified,
and its remaining unsoundness (a fenced node can re-register) formally ruled on by
GPT. Runs 0.11.420 → 0.11.427.

## sess89 — own-crash reclaim is dead; withdrawn-slot steal hazard refuted `docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`

Build 0.11.420. Fleet measurement over every node's dmesg history: **0 of 91**
disklock claims were "own-stamp reclaim" — `node_id` is drawn fresh
(`uuid_to_node_id(get_random_bytes)`) at every mount, nothing persists it, so
pass-1's `node_id == local_node` match never fires. Two consequences: (1)
`xlog.c`'s "required own-crash recovery path" never runs — every mount depends
entirely on a **survivor** replaying its slice; the whole-cluster-crash /
no-survivor case has no proven replayer. (2) `MXFS_RECOVERY_SUPERSEDED` is
unreachable dead code — `recovery_begin`'s `cur->node_id != victim` gate always
fires first.

A code-reading hypothesis (withdrawn slot k<32 gets stolen by a remount ahead of
free slots) was REFUTED by measurement: `withdraw_slot_reclaim_probe.sh` showed
the GUARD lands 1.26s after WITHDRAWN, well inside a ~12s remount, so pass-2's
GUARD skip holds and the remount correctly takes a free slot. 100/100
fsync-acknowledged files survived.

Owed: full 32/caw board (not run in 3 sessions), the no-survivor case, RULE-5
consult on fixing dead pass-1.

## sess90 — board green; crash_consistency FAIL localized to a contention STATE, not inherent pace `docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`

Board: 23 PASS/3 FLAKY/1 POLICY/1 FAIL — proto_gen 3 did not regress it.
`crash_consistency` FAILed (3rd occurrence): new tool `cc_phase_attrib.sh`
localized it to the O_SYNC `datawrite`/`md5write` phases (56s/48s max vs 90s
budget), and showed `NO_TERMINAL_RECORD` is a barrier artifact (15/32 nodes
reached done, 17 stalled at dropcaches) not a capture bug. Two hypotheses
REFUTED by measurement: inherent shared-dir create pace (standalone rerun: 2s
max, 28x faster) and rsync_paired adjacency (back-to-back run passed at higher
hostload than the failure). Kernel evidence: failing node had 14750 vs 8280 mxfs
kmsg lines for identical work, dominant inode = shared `.crash_consistency` dir,
root inode in a suppressed-BAST storm — a starvation signature, not uniform
slowness. Next-session plan: bisect the in-board prefix to find what state makes
it reproduce.

## sess91 — three parallel threads: recovery entry points, incarnation equality, token-v2 recon

**Dead-code census, corrected upward** `docs/history/docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`:
5 of 7 recovery-descriptor entry points (`recovery_takeover`, `recovery_claim`,
`recovery_fence_intent`, `recovery_fence_certify`, `recovery_fence_takeover`)
have zero callers — only `recovery_begin`/`recovery_advance` are live. Measured
consequence: an elected replayer that dies mid-recovery wedges forever (survivors
defer to a phantom `P234-RECOV-OWNED` owner) — filed `D-RECOVERY-TAKEOVER-UNREACHABLE`.
Second consequence: `recovery_begin` writes `stage=FENCED` directly with
`fence_kind=NONE`, bypassing the intent/certify path entirely, so the in-tree
comment "the ONLY way to reach FENCED is fence_certify()" is **false in the
shipped build** — this is why `D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION` and
`D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION` survived the earlier sess74-76
campaign: the certificate was designed and never invoked.

**Incarnation equality wedge, found and fixed same session**
`docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`: new probe
`incarnation_mismatch_probe.sh` reached the monitor's EPOCH-CHANGE arm (a
different, reachable route than the unreachable pass-1) and proved the
incarnation predicate **discriminates** for the first time ever on the rig
(`P237-RECOV-INC-MISMATCH`, refused correctly). But the follow-on round exposed
a NEW critical: `inc_eq(0,0)` is false (by design — zero is never a wildcard for
cross-source comparison), yet `recov_auth_holds` compares `victim_epoch` this way
even when auth was issued **verbatim from the same descriptor** that has
`victim_epoch=0` — so the owner fails its own authentication and every advance
returns `-EBUSY`/`P234-RECOV-NOTOURS` forever, freezing the slot and the dead
node's CAW grants. GPT ruling (verbatim, binding): unknown may equal unknown only
as part of a *descriptor identity* comparison, never as independently-sourced
incarnations; `recov_auth_holds` also never checked `victim_slot` despite
`recov_auth_issue` copying it (stale-auth-vs-wrong-slot hazard, not
zero-specific). Fix: a second comparator `recov_tok_eq()` for descriptor-token
identity, separate from `inc_eq()` for cross-source proof.

**Reachability of zero-epoch descriptors, corrected downward**
`docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`: an earlier over-claim
("every lease-detected death is a first-class zero-epoch path") was refuted by
measurement — fleet-wide, zero lease-detected deaths ever occurred (lease
timeout 600000ms vs disklock monitor's ~62s, monitor always wins). The actual
producer is the monitor **downgrading** a known nonzero cached incarnation to 0
on a stale/torn sector read (filed `D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO`).
Also found: the `lease_timeout_ms` module param does NOT set the lease timeout
(only feeds the disklock dead-timeout) — a naming trap fixed in sess93.
Method note: "a path is documented as intended" is not evidence it executes;
grep the fleet logs and check both competing timeouts before writing a
reachability claim.

**Token-v2 edit inventory** `docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`:
step 5.2 (authority token v2, `D-FOREIGN-REPLAY-UNGATED-IMAGES`) unblocked once
`D-MOUNT-INCARNATION-CONSTANT-ZERO` closed (incarnation is now real/nonzero per
mount). v1 cannot gate apply/skip (32-bit resource, no victim binding, memset-0
owner_boot) — must stay report-only. v2 wire (40B BE, from the sess83 ruling)
plus a mandatory status enum (VALID/NOT_REQUIRED/UNPROVEN/MISLABELLED/MIXED/
INCOMPLETE/WRITE_AUTH/UNSUPPORTED/MALFORMED) replacing the six-way overload of
`class==NONE`. Trap documented: the CIL shadow-buffer size macro must stay
single-sourced between size-estimate and emission sides or it silently
corrupts — redefine the one existing macro to `sizeof(v2)`, never add a second.
Three items explicitly deferred past 5.2: capture at DIRTY/JOIN time (not
format time), MERGE semantics (not last-writer-wins), and provenance SNAPSHOT
with the CIL image (relogging must not mutate an earlier checkpoint's
provenance).

**sess91 outcome, 0.11.421** `docs/history/docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`:
2 defects CLOSED FIXED AND VERIFIED (`D-MOUNT-INCARNATION-CONSTANT-ZERO`,
`D-RECOV-AUTH-ZERO-VICTIM-EPOCH-WEDGE`) via an A/B that flipped
`P234-RECOV-NOTOURS`/`P234-COMPLETE-REPLAYEDFAIL` from 7→0 and
`P163-RECOVERY-COMPLETE` from 0→1 on identical injection. 3 defects filed:
`D-RECOV-ADVANCE-UNBOUNDED-RETRY` (critical — 11 quiet retries over 12min with
no bound/backoff/escalation), `D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO` (high),
`D-RECOV-ZERO-EPOCH-DESCRIPTOR-AUTHORITY-UNPROVEN` (high). Board: 27/27
functional PASS. Ledger 20→22 open.

## sess92 — the fence-evidence wiring recon: the whole subsystem never executed `docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`

Corrects sess91's census: it is **7** dead entry points, not 5 — missed the two
most important, `recovery_replay_authorized` (THE central gate, 0 callers) and
`recov_cert_proves_exclusion` (called only by two other dead functions). The
entire fence-certificate + exclusion-gate subsystem — the earlier sess74-76
campaign's design, wire format, and proto_gen bump — never executed; only
`recovery_begin`/`recovery_advance` run. Also caught stale ledger text:
`D-PR-FENCE-PREEMPT-WITHOUT-ABORT` was marked "not yet fixed" but had actually
landed and been rig-verified in sess71/73 — only its item 4 (prove an in-flight
write is excluded) remained open.

Traced the live flow: fence is computed/logged/discarded, slot resolved AFTER
the fence, descriptor written AFTER replay (a post-hoc record, not pre-replay
authority). Established the wiring is tractable: `victim_key ==
(uint64_t)victim_node` is known a priori (no need to split key-reads out of
`fence_node`), and a GUARD slot is already unclaimable by joiners
(`disklock.c:4707`), removing the main expected hazard to reordering fence-before-replay.
Four open questions banked for the RULE-5 consult: single-winner CAS
confirmation, availability policy when no certificate can exist, the source of
epoch for the lease detector's zero, and whether mount-barrier cohort victims
(previous-boot) get the same treatment.

## sess93 — wiring shipped (0.11.422-426), rig-verified, and a critical hole formally ruled unsound

**GPT ruling on wiring** `docs/rulings/fence-evidence-wiring.md`
(binding, supersedes sess74-76 design notes): the shipped flow was unsafe, not
merely unwired — the live path *contradicts* its own invariants. Release unit is
7 things: durable intent before fencing, durable certificate before replay,
claim/takeover of an execution lease, per-destructive-op authorization, an
explicit blocked state, removal of every ungated replay entry point, and
mixed-version/upgrade handling. Key rulings: only the intent-CAS winner may
issue PREEMPT AND ABORT (a losing replayer waits on a coordinator queue, never
speculates, no safety timeout ever authorizes unguarded replay); fail closed
with no unsafe override knob for any non-proving fence result, but MUST validate
fencing capability **at mount admission**, not discover it after a death;
zero-incarnation lease events may only accelerate the disk detector, never
authorize replay directly; MXFS should request+verify APTPL persistence, not
just set the bit. Named the crash hole GPT considers largest unaddressed:
P&A succeeds, key removed, prover dies before certify is durable — the proof
existed only in volatile memory and is lost; takeover does not repair this,
must be documented as a real availability hole. Also corrected 5 specifics in
the proposed wiring (claim the execution lease ONCE, not per-phase; wire
`recovery_takeover` explicitly; retire `recovery_begin` from the live path
entirely, not as fallback; put authorization below the dispatcher at each
destructive primitive; treat `-EEXIST` as a hint requiring re-validation, not
evidence).

**Fence-evidence channel LIVE, 0.11.422** `docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`:
shipped `v5_pr_fence_prove()` (single-winner intent→P&A→certify), the
`recovery_acquire`/`recovery_release` gate holding auth across replay+completion,
both replay dispatch sites gated, `recovery_begin` retired (refuses at entry),
`recovery_slot_status()` classifier. Measured on the rig with no injection —
just killing a node: prover and replayer were **different nodes**
(`test3` proved, `test1` consumed, the sess73 asymmetry the certificate exists
to handle), all 30 other survivors deferred instead of each issuing their own
P&A (proof of the single-winner ruling landing correctly).

**Takeover verified via a real double fault, 0.11.422**
`docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`: killed the victim,
then killed the elected replayer mid-recovery (both `virsh destroy`s driven from
a host-side O_DIRECT poller of the backing store to hit the ~8s window — ssh
round trips are too slow). A third node correctly resumed from `stage=3`
(IMAGES_REPLAYED) rather than re-running earlier work and published. Confirms
this differs from the sess91 phantom-owner injection, which correctly refuses
(a phantom is in nobody's proved-dead set) — real takeover needs an owner *this
node itself fenced*. Closed 3 criticals: `D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION`,
`D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION`, `D-RECOVERY-TAKEOVER-UNREACHABLE`.

**The critical hole, measured** `docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`:
`pr_reregister_probe.sh` at the SCSI layer (MXFS bypassed): PREEMPT AND ABORT a
healthy node → its write is correctly refused → it does
`REGISTER_AND_IGNORE` under a fresh key → **the target accepts it** → its next
write **lands on the platter**. The certificate is true at the instant of P&A
and expires silently after. Only cooperative self-fence
(`mxfs_scsipr_self_check`) stood in the way — useless against a CPU-starved or
partitioned node that hasn't scheduled. No existing criterion could catch this
because every fencing test power-cuts the victim (`virsh destroy`); none leaves
it alive-and-fenced. Filed `D-FENCED-VICTIM-MAY-REREGISTER` (critical),
explicitly kept separate from the two closed evidence-channel defects (they were
about publishing/consuming no evidence at all; this is about how long true
evidence stays true).

**GPT ruling on enforcement options** `docs/rulings/2-fence-enforcement-options.md`
(binding): the measurement **invalidates PREEMPT AND ABORT as a durable host
fence** — it's a point-in-time removal, not revocation of the ability to
re-register; the certificate must be renamed/reconceived as attesting a
*completed eviction event*, not continuing exclusion, unless backed by one of:
(d) target/fabric ACL/session revocation of the victim's stable identity —
sound, but outside a kernel FS module, needs an external fencing agent;
(a) temporary conversion of the WE-RO reservation to single-holder WRITE
EXCLUSIVE for the replay window — conditionally sound in-band option, six strict
requirements (quiesce all cooperating nodes first, no unreserved gap during the
PR transition, still issue P&A for outstanding commands, hold WE through
publication, atomic takeover, restore WE-RO only after); (b) re-verify key
absence before each destructive step — detect-only, cannot close the race, must
BLOCK not continue on detection; (c) periodic P&A and enumerate-unknown-keys —
both **unsound**, give no integrity bound (one accepted write invalidates
recovery) and make the recoverer an unauthenticated membership authority. Also
ruled: in-place foreign XFS log replay has a quiet-write-domain hard
precondition that cannot be satisfied by any check/timeout/wording change;
sound long-term architectures are COW-into-clone+atomic switch, target-enforced
epoch capabilities, or per-node isolated logging — not a local replay change.

**sess93 final state, 0.11.426** `docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`:
version chain 0.11.422 (prover+gate+lease+dispatch gating+recovery_begin
retirement+recovery_slot_status+takeover wiring) → 0.11.423
(`exclusion_holds()` re-check at 4 points) → 0.11.424 (log-ordering honesty fix)
→ 0.11.425 (`RECOVERY_BLOCKED_FENCE` debugfs surface) → 0.11.426
(`lease_timeout_ms`→`dead_timeout_ms` rename fixing the sess91 naming trap, plus
`fence_intent()` now refuses to construct any zero-incarnation descriptor —
`P238-FENCE-ZEROINC` — closing the zero-epoch defect at the source). Board: 26
PASS/0 FAIL. Net session: 6 closed (5 FIXED AND VERIFIED + 1 DISPROVED —
`D-PR-REGISTRATION-NOT-PERSISTENT-APTPL`, refuted by checking the target's
REPORT CAPABILITIES rather than grepping MXFS source, a reusable method
correction: SCSI-level behavior needs SCSI-level evidence), 7 filed. Ledger
23→24 open — count rose because wiring a dead safety mechanism exposed what it
still lacks, called out explicitly as the honest direction rather than a
regression. Harness fix banked: `showstat.sh` now excludes `win_src=none` runs
from the FLAKY tally — a scanner chunk that ran without its data-producing
criterion in the same chunk scanned zero lines and cannot convict.
Duplicate/consistent with `docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`,
which additionally records the `RECOVERY_BLOCKED_FENCE` debugfs record shape
(reason=EXCL_LAPSED, victim/fence/ownership/timing fields, first_ms stamped
once and kept — not restamped per retry, so operators see true blocked
duration) and the four reusable probes shipped this arc: `fence_evidence_probe.sh`,
`recov_takeover_doublefault_probe.sh`, `pr_reregister_probe.sh`,
`excl_lapse_probe.sh`.

## sess94 — token v2 shipped, 0.11.427, rig-verified `docs/history/docs/history/compiled-sess89-94-fence-certificate-recovery-authority-campaign.md`

Executes the sess91 edit inventory + sess83 ruling. Wire, status enum, and
size-macro fix landed exactly as planned. New: `mxfs_disklock_mount_identity()`
returns {slot, node_id, incarnation} all-or-nothing — trap avoided by NOT using
`ctx->node_slot` (0 is both "unclaimed" and "legitimately slot 0", ambiguous);
uses disklock's `local_slot` (-1 until claimed) instead. Capture failure
dominates classification: an identity-unavailable token is forced to
class=NONE/status=INCOMPLETE rather than allowed to look like proof. Rig
measurement on a real node death: every token carries `v=2`, nonzero
`oepoch` (impossible before this campaign closed the incarnation-constant-zero
defect), correct slot/node cross-check, and the status field discriminating
VALID vs MISLABELLED. Producer-side: `incomplete=0` over 16384 tokens (identity
capture never failed) but `mislabel=4770` (29%) — the AG grant shadows the
inode grant at format time for the inode-authority population (dir/attr/bmbt
blocks), which becomes step 5.3's actual problem statement. proto_gen NOT
bumped: both mixed-version read directions are safe by construction (length
check + explicit version test fails closed); the bump is deferred to 5.4
enforcement. Still owed on the parent defect: capture-at-dirty-time, merge
semantics, provenance snapshot with CIL image — none change what changed here,
only where/how it's filled, so this wire does not need to be redone.

## Threads still open at the end of sess94

- `D-FENCED-VICTIM-MAY-REREGISTER` (critical) — needs the WE-gate or fabric
  revocation design from the sess93 ruling, no code yet.
- `D-RECOV-ADVANCE-UNBOUNDED-RETRY`, `D-MIXED-VERSION-UNGATED-REPLAY`,
  `D-FENCE-CAPABILITY-UNVALIDATED-AT-MOUNT`, `D-FENCE-CRASH-MATRIX-UNTESTED`,
  `D-PR-FENCE-PREEMPT-WITHOUT-ABORT` item 4 (in-flight write exclusion proof).
- Step 5.3 (foreign-replay authority): fix the AG-grant-shadows-inode-grant
  mislabeling found by the 5.2 measurement.
