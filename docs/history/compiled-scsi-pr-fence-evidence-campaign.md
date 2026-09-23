<!-- sess68-76+378: PR-fence takeover/evidence-channel design, PREEMPT AND ABORT landing, descriptor v2, and the upstream dm bug that silently defeated it. -->
# SCSI-PR fencing: PREEMPT AND ABORT, the fence-evidence channel, and the upstream dm bug that silently defeated it

Chronology of the campaign to make MXFS's peer-death recovery actually prove
I/O exclusion before replaying a dead node's journal slice, sess68-76 (design
+ landing) and its sess378 epilogue (root-cause of why it never worked on the
rig despite "verification").

## sess68 — takeover predicate refuted, ordering rules set

``docs/rulings/takeover-evidence-refuted.md`` (0.11.411).
GPT design-consult ruling on the not-yet-written recovery coordinator, before it got
written from a wrong premise:

- **Refuted**: "sector no longer carries `{owner_node,owner_epoch}` as ACTIVE"
  is not proof of takeover-safety. `node_id` is an identity, not an I/O
  capability — descriptor CAS does not stop an in-flight SCSI write or a
  still-running replay worker. Sector state is admissible only as
  *retirement evidence*, and only when the producing transition has a
  documented ordering guarantee (clean release as the FINAL act after
  stop-acquire → cancel/join workers → stop refresh → drain I/O → durable
  zero; or a completed fence). Bad magic/CRC failure is never retirement
  evidence — fail closed.
- Real bug exposed: `!mxfs_disklock_slot_live(owner_slot)` is indexed by
  SLOT not incarnation — once a slot is reclaimed by a new live node it
  reads live again and takeover wedges forever; unconditionally true for
  our own slot too.
- Mount barrier must acquire (register + start refresh) BEFORE inline
  replay, not after — otherwise replay can run concurrently with an
  existing owner. Refresh must never be hook-gated once owned; acquisition
  may be.
- Rediscovery backstop (all-slots scan) is right but incomplete: if every
  witness reboots before any `begin()`, a stale ACTIVE sector is orphaned
  forever with no fencer — needs an explicit orphan-discovery/fencing
  path, not silent treat-as-dead.
- Every stage effect is at-least-once, not just takeover: a crash *during*
  a stage (not just before dispatch) can leave the effect done but the
  stage record not advanced (e.g. FENCED writes half the images and dies).
  Needs durable per-item progress, not one coarse stage bit, for images,
  obligations, AND grant release.
- Conclusion: the retirement-evidence mechanism needed is most likely a
  durable fencing TOMBSTONE — consult GPT on wire format before writing it.

## sess69 — advisory-PR fail-closed ruling; a real shipped defect fixed

``docs/rulings/advisory-pr-fail-closed-fenced-is-false.md``
and ``docs/history/docs/history/docs/history/compiled-scsi-pr-fence-evidence-campaign.md``
(0.11.412).

GPT ruling, given the (later-corrected) premise that the rig's PR is
advisory (shared I_T nexus): **no safe automatic recovery exists under
advisory PR — fail closed.** Headline finding: the defect is bigger than
takeover — it also applies to *initial* recovery of a victim, because
replaying V's journal while V can still write is unsafe regardless of who
is replaying. `FENCED` stage as shipped is a **false claim**:
`mxfs_scsipr_fence_node()` returns 0 for "fenced, never there, OR advisory
topology" and the caller cannot distinguish them, so on advisory hardware
"fenced" was recorded with zero exclusion ever obtained. Descriptor CAS
serializes the record, not bulk writes to unrelated LBAs — plain
compare-and-write on the target block is insufficient exclusion.
Implementation order handed down: P0 stop recording false fencing (typed
outcomes, block replay without proven exclusion) → P1 separate victim/owner
exclusion invariants in the wire format → P2 safe refresh/takeover → P3
per-image progress → P4 decide the supported liveness contract per
hardware class.

Same session, a **separately found, independently real** shipped defect:
`mxfs_disklock_purge_node()` published its zero by plain
read-modify-write with no interlock, and 6 call sites (2 run on every
survivor at peer death) made concurrent purge the normal case, not exotic
— losing interleaving could resurrect a destroyed live grant, or (worse)
erase a *live* node's heartbeat record and get it declared dead and
fenced/replayed while still writing (split-brain). A second, independent
hole: the freeze gate was evaluated on a pre-scan read, not re-derived at
publish time, defeating it. Fixed via `mxfs_pal_bdev_compare_and_write()`
of the exact validated image with bounded retry, and the freeze gate
re-derived on the CAS'd image. First rig cycle in 11 versions (0.11.402
had gone unboarded that long) — green: `fence_during_write` 32/32 17s/60s,
`crash_consistency` 204/204 86s/90s, `dir_reuse_coherency` 93/93 107s/120s.
Method lesson: when the unboarded backlog is deep, board first — verifying
what exists beats landing one more increment on an unverified base.

Also found: the recovery coordinator was never wired — `recovery_refresh`,
`recovery_read`, `recovery_takeover` are called from nowhere; only
`begin`/`advance` are live, so an owner dying between `begin()` and
`GRANTS_RELEASED` freezes the victim's slot and its grants forever — a
regression vs 0.11.401, introduced when the descriptor went live without
its takeover driver.

## sess70 — the advisory-PR premise was WRONG; real defect identified

``docs/history/docs/history/docs/history/compiled-scsi-pr-fence-evidence-campaign.md``
(still 0.11.412, no code).

Correction that invalidates the sess69 ruling's premise: the "advisory PR,
shared nexus" finding came from the OLD tcm_loop rig. The current rig is
SCST iSCSI with each VM its own initiator — measured directly: 33 distinct
keys / 64 entries at 32 nodes×2 paths (one unique key per node), a real
WE-RO reservation held, no stale-key accumulation across `virsh destroy`.
**Per-node PR is ACTIVE here.** sess69's "fail closed, no safe recovery"
does not apply on this hardware; P0 is a typing/gating job, not a
capitulation.

The real defect, found by reading the PAL call: `pal/linux/kern.c` issued
PR OUT service action **0x04 (PREEMPT)**, never **0x05 (PREEMPT AND
ABORT)** — the `abort` bool was hardcoded `false` since v0.11.80. Per
SPC-4, PREEMPT removes the registration but does not abort the victim's
in-flight task set; PREEMPT AND ABORT does and does not complete until
those tasks are aborted. Both recovery criteria kill the victim mid-write,
so the victim's task set is non-empty by construction — the delta is
exactly the in-flight window. Confirmed the target supports 0x05 via
direct `sg_persist --preempt-abort`. Also found: no heartbeat-loss
self-fence exists at all (a heartbeat-dead but disk-alive node keeps
writing); the entire replay-exclusion predicate collapses to
`fence_node()==0`, which has 4 distinct `return 0` paths (real fence,
`-EOPNOTSUPP`, advisory-topology count check, already-absent) that the
caller cannot distinguish; the mount-barrier cohort replay path has *no*
fence predicate at all. Four defects ledgered:
`D-PR-FENCE-PREEMPT-WITHOUT-ABORT`, `D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION`,
`D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION`, `D-PURGE-NONATOMIC-PUBLICATION`
(fixed, verification owed). Method note: `sg_persist` against
`/dev/mapper/mpatha` settles PR questions cheaply — don't re-derive from
stale tree comments.

## sess71 — PREEMPT AND ABORT + typed fence outcome land; GPT protocol ruling

``docs/history/docs/history/docs/history/compiled-scsi-pr-fence-evidence-campaign.md``
(0.11.413, built, NOT deployed).

GPT design-consult ruling on the corrected premise: **key-absence alone is not
exclusion proof** — it proves only new writes are rejected, not that the
accepted task set drained, that the victim can't re-register, or that
every victim nexus was covered. PR generation is dating evidence only,
never a gate (not atomic, not a lease). Winner protocol required:
serialize per victim/epoch → one fencer issues 0x05 → waits for completion
→ verifies status/reservation → durably publishes evidence the victim
cannot modify → only then may the elected (possibly different) node
replay; losers consume that evidence, never re-derive it. Never map a
losing 0x05 RESERVATION CONFLICT to success. One 0x05 covers both
multipath registrations if they share the victim's SARK. 0x05 can time
out under deep queues — on timeout, exclusion is UNKNOWN, never inferred
later from an absent key.

Landed: `mxfs_pal_scsi_pr_preempt(..., bool abort)` plumbed end to end;
RESERVATION CONFLICT now returns `-EBUSY` not 0 (the load-bearing lie);
new `mxfs_pal_scsi_pr_read_reservation()`; `enum mxfs_fence_kind` with
`mxfs_fence_kind_proves_exclusion()` true only for `PREEMPT_ABORT_DONE`;
`mxfs_scsipr_fence_node()` now requires a held WE-RO reservation, issues
0x05, and re-verifies victim-gone/own-key-present before claiming success.
Caught and fixed a **number-space trap**: Linux `pr_read_reservation`
returns the block-layer `enum pr_type` (WE-RO = 3) while the SCSI wire
value used elsewhere is 5 — comparing them directly would fail closed on
every fence, silently. Structural notes for the next steps: `recovery_begin()`
runs at replay-COMPLETION time, not fence time — GPT's protocol needs
evidence published BEFORE replay, so it must move; the fence winner and
the elected replayer (`lowest_live_slot`) are different nodes in general,
so the durable evidence channel is mandatory before gating dispatch (gate
too early and recovery stalls outright, since the usual replayer is a race
loser).

## sess72 — PR key-view truncation: a new critical defect, found and fixed

``docs/history/docs/history/docs/history/compiled-scsi-pr-fence-evidence-campaign.md``
(0.11.414, deployed to all 32 nodes).

Closed both sess71 open risks with direct rig evidence: `dm_pr_read_reservation`
exists in 6.8, and a WE-RO reservation is genuinely held. `READ FULL
STATUS` audit confirmed one 0x05 removes both multipath registrations for
a shared key.

New defect: registrations are per-I_T-**nexus**, not per node — the 32-node
rig holds 64 descriptors (2 paths/node). Every PR consumer sized its key
buffer as `keys[MXFS_MAX_NODES]` (64), so the fleet sat at exactly capacity
with zero headroom and both PAL backends truncated **silently**. Because
every consumer decides from key *absence*, a truncated view read as
"absent" — `mxfs_scsipr_self_check()` freezes a HEALTHY node on
`own_present==false`, and its topology escape hatch (`count>=live_members`)
cannot catch truncation because a saturated count satisfies it maximally.
Reachable via any stale unregistered descriptor, a third path, or a 33rd
node. Fixed: resized to `MXFS_MAX_NODES * 8` (512, sized by nexuses not
nodes), added a `total` out-param so truncation is detectable, new
`-EOVERFLOW`/`P-PR-VIEW-TRUNC`, new `MXFS_FENCE_KIND_VIEW_TRUNCATED`, all
four consumers converted, `self_check` explicitly never self-fences on a
truncated view. Also noted: `local_key = (uint64_t)node_id` changes across
remounts of the same node (it's per-incarnation) — `victim_key` in
`fence_node()` is only correct if the caller passes the victim's *current*
incarnation id (deferred, not yet load-bearing).

## sess73 — PREEMPT AND ABORT verified on the rig; prover ≠ replayer exposed

``docs/history/docs/history/docs/history/compiled-scsi-pr-fence-evidence-campaign.md``
(0.11.414).

`tests/pr_fence_evidence.sh` against a hard `virsh destroy`: one node
(test9, of 32) produced `PREEMPT_ABORT_DONE(16) proves_excl=1` with a
verified post-state (victim absent, own key present) — the the zero-defect bar
verification target for the sess71 change, met. Distribution: 1 winner /
30 losers (`KEY_ABSENT_UNPROVEN`), as designed.

But this exposed the next defect directly: the elected **replayer**
(`lowest_live_slot`, here test1) dispatched foreign replay 22ms after its
own fence attempt returned `proves_excl=0` — the node that proves
exclusion and the node that replays are structurally different, and the
prover's evidence is never published for the replayer to consume. This is
`D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION`, now precisely characterized in
shipped code (confirms sess72's warning against gating dispatch before an
evidence channel exists).

Two harness traps that had fabricated a wrong root cause and cost a rig
run: (1) `pr_fence_evidence.sh` polled only 8 of 32 nodes, guaranteed to
usually miss the single winner — "no winner" was misread as target-side
reaping; fixed to poll the whole fleet and assert exactly 1 prover. (2)
`tools/mxfs_secrets.sh`'s bare `case "${1:-passfile}"` at file end killed
any script that *sourced* it with positional args (sees the caller's
`$1`), dying silently before its first echo; fixed to dispatch only when
executed directly. SCST source (`scst_pr_unregister()` reachable only from
PR OUT handlers) confirmed no session-teardown path removes registrations
on this target — a key disappearing means somebody preempted it, not the
target reaping it. GPT ruling (same session): `victim absent + WE-RO held
+ own key present + count>=live` is refuted as sufficient — it's a
write-admission observation, not a task-drain proof; required gate is
disjunctive (P&A success OR authoritative drain cert OR LU reset OR
session drain), and correctness must not depend on winning a race against
target-side cleanup.

## sess74 — GPT ruling on the fence-evidence channel design: architecture approved, 6 blockers

``docs/rulings/fence-evidence-channel-6-blockers.md``

Design: descriptor v2 carries a fence certificate, published by the PROVER
into the VICTIM's own HB sector at fence time, initially **UNOWNED**, later
claimed by the elected replayer, replay gated on
`mxfs_fence_kind_proves_exclusion()`. **Approved as architecture**; the
naive "publish only after P&A completes" path is not. "Claiming an unowned
recovery lease is not takeover" ratified as a new disklock.h rule —
`owner_node==0` must be impossible for a real node; UNOWNED is a distinct
state, not "abandoned owner".

Six release-blocking requirements: (1) durable FENCING intent written
BEFORE the P&A; (2) an authoritative fallback for the prover-dies-after-
P&A-before-durable-certificate window; (3) refuse RW clustered operation
on unqualified PR/topology, not a knob; (4) centralized replay AND
stage-transition enforcement, at every destructive dispatch site
(including sector zeroing/final publication), not just two call sites;
(5) cluster-wide version gating; (6) full audit of every ACTIVE/non-ACTIVE
consumer of descriptor state.

Lost-prover window (Q2): the mitigation (intent record) is necessary but
NOT sufficient — "intent + prover died + key absent ⇒ P&A completed" is
unsound in general (depends on target-specific reap semantics, only rig
evidence not proof). Sound recovery requires performing and certifying a
*new* accepted exclusion/drain operation, with permanent quarantine the
only safe fallback where none exists. Explicitly **prohibited**:
re-registering the victim's key on our own nexus then preempting it (that
only proves we removed our own fabrication); PR OUT CLEAR alone.

Q3: UNSUPPORTED/ADVISORY_TOPOLOGY may never be classified as fenced, even
generalized beyond the original rig — a timeout is a suspicion, not proof,
and reactive shutdown happens only after a write already failed. RW
clustered mount must refuse without a positively-qualified exclusion
mechanism.

Q4 (gate placement): the two originally-proposed call sites are not
enough — gate must sit inside `recover_foreign_slice()` before the first
replay I/O, on the IMAGES_REPLAYED transition, on every destructive
victim-manifest path, and on sector zeroing/final publication.

Author's own claim refuted: "a v1 reader sees version mismatch and fails
closed" is wrong given the shipped ordering (replay-then-check-at-
completion) — a v1 node can replay first and only hit the conflict
afterward. Requires cluster-wide PROTO_GEN gating, not per-slot version
checks. Certificate content must bind target/LU identity, reservation
type/scope, prover identity+incarnation, the exact service action, and a
post-state re-read — command completion into a volatile target cache is
not durability. Wire layout for v2 sketched (120B descriptor, cert fields
at offset 76-116).

## sess75 — descriptor v2 wire + version gate land; C side not written

``docs/history/docs/history/docs/history/compiled-scsi-pr-fence-evidence-campaign.md``
(0.11.415, built, **do not deploy** — half-landed protocol change).

`MXFS_PROTO_GEN` 1→2 as the hard prerequisite (the C7 sb-incompat-bit +
envelope + HB-feature-block vergate now excludes v1 recovery code
cluster-wide, closing the sess74 version-mismatch hole). A v1-formatted
volume now refuses to mount; rig re-mkfs covers this, `chk_mxfs
--upgrade-protogate` is the offline path. Descriptor 80B→120B
(`MXFS_RECOV_DESC_VERSION` 2), certificate fields written once at
FENCING→FENCED and immutable after (`fence_kind`, `fence_resv_type`,
`fence_victim_key`, `fence_prover_epoch`, `fence_stamp_ms`,
`fence_prover_node`, `fence_pr_gen` — diagnostic only, never a gate —
`fence_term`, the FENCING-attempt term, kept a **separate type**
(`mxfs_recov_fence_auth`) from the execution lease so one can't be passed
where the other is required). Stage ladder renumbered with FENCING
inserted before FENCED; FENCING authorizes nothing.
`MXFS_RECOV_OWNER_NONE 0` makes UNOWNED a real distinct state. Five API
functions declared in disklock.h (bodies not yet written):
`recovery_fence_intent`, `recovery_fence_certify`, `recovery_claim`,
`recovery_replay_authorized` (the central gate), `recov_cert_proves_exclusion`.

Caught a **stale-build trap**: a second incremental build after editing
`mxfs_super.h` produced the identical srcversion — suspicious per the
"make clean before rebuild for multi-file changes" lesson; flagged as
unverified going into sess76 (confirmed real there).

## sess76 — fence-evidence channel C side lands; prover wiring still owed

``docs/history/docs/history/docs/history/compiled-scsi-pr-fence-evidence-campaign.md``
(0.11.416, **do not deploy** — same reason, nothing publishes a
certificate yet, so deploying now fail-closes every replay into a hang,
not a working FS).

Confirmed the sess75 stale-build suspicion was real: `make clean && make
modules` moved the srcversion; the incremental build had NOT picked up
`MXFS_PROTO_GEN=2`. All five declared bodies landed plus a sixth
(`recovery_fence_takeover()`, for the prover-died-with-intent-durable
case: bumps `fence_term`, lets a successor retry its OWN P&A rather than
inferring the dead prover's result — per the sess74 Q2 unsound-inference
ruling). `fence_intent` gained a `victim_key` param recording the
*intended* key at FENCING; certify overwrites it with the key actually
removed and **refuses a mismatch** (key-drift check). Closed a hole found
while wiring: `recovery_advance()` previously let a caller with
`auth==NULL` (the prover, during FENCING, degrades to owner-identity)
advance its own intent straight to FENCED with `fence_kind` still NONE —
manufacturing a false fence; now refuses any target stage ≤ FENCED without
proof.

Left exactly here: the prover still needs wiring inside
`v5_pr_fence_dead_node_rc()` (not at its four call sites — whichever
fencer's P&A wins first consumes the victim's key, so any path skipping
intent/certify permanently strands that slice), then
`recovery_begin()` replaced by `recovery_claim()` and the claim+gate moved
before replay at both dispatch sites, then the RW-mount-without-qualified-
exclusion refusal (blocker 3) and the `get_slot_node_id()` non-ACTIVE-
returns-0 fix (blocker 6).

## sess378 — root cause of why it never actually worked: an upstream dm bug

``docs/history/docs/history/docs/history/compiled-scsi-pr-fence-evidence-campaign.md`` (0.14.11,
measured ~6 weeks after sess76, 32/caw production LUN).

Direct measurement (target-side SCST trace + MXFS log, same instant) proved
the fence channel built across sess68-76 had been **certifying a lie the
entire time it ran**: MXFS logged `PREEMPT_ABORT_DONE proves_excl=1` and
"exclusion is PROVED and durable" while the target's own CDB parser logged
plain `Preempt:` (service action 0x04), never `Preempt and abort:` (0x05).
Root cause: `/src/linux/drivers/md/dm.c`'s `dm_pr_preempt()` builds a
`struct dm_pr` with a designated initializer that never assigns `.abort` —
grep confirms the field is declared, read once downstream, and assigned
nowhere — so on **every** dm-multipath device, PREEMPT AND ABORT silently
downgrades to PREEMPT, regardless of what the caller requested. MXFS's own
stack (scsipr.c → PAL → kern.c) correctly plumbs `abort=true` all the way
down; the drop happens inside `ops->pr_preempt()`, which is dm's, because
MXFS opens `/dev/mapper/mpatha`.

Quantified why it matters: an A/B against the shipped vdisk_fileio target
handler measured the actual write-vs-fence-completion ordering. 0x05 blocks
in-kernel until the victim's command drains (~12.3-12.5s observed), so the
write is provably ordered before the fence completes. 0x04 returns in
~0.2ms and the victim's write can land **12 seconds after** the fence was
already certified as proving exclusion — precisely the corruption window
the entire sess68-76 campaign was built to close, still open.

Why 15+ sessions of green boards never caught it: the SCSI-PR fence has
**zero board coverage**. `fence_during_write` is a negative test (asserts
zero fences happen during a write storm — it never kills anything);
`crash_consistency`'s own header states a true node-kill + foreign-replay
needs host-side orchestration the in-guest harness doesn't have. A prior
session's claimed re-verification of the certificate path never actually
exercised a fence. `tests/fence_stage3_real.sh` (new, sess378) is the only
harness in the tree that does.

Fix is explicitly not "patch the kernel" (the zero-defect bar: another system's bug is
never license to keep one, and the customer's kernel isn't MXFS's to
dictate). MXFS already has the primitives to bypass dm entirely: raw SCSI
CDB passthrough (`scsi_execute_cmd`, both DRV_IN/DRV_OUT) and a stacked-
device resolver (`mxfs_bdev_to_sdev()`) that already walks a dm bdev down
to the underlying `scsi_device`. SCST ground truth confirmed one raw P&A
of the victim's key aborts both of its multipath nexuses (registrant-key
based, not per-path), so a single raw issuance suffices.

## Net state at sess378

The intended protocol (typed fence outcome → durable intent → certify →
unowned claim → gated replay) is fully designed and landed in the
descriptor/API layer (0.11.413-416). The one link the whole chain depends
on — that a certified `PREEMPT_ABORT_DONE` actually drains the victim's
in-flight I/O — was false on this rig the entire time, undetected because
the fence path itself was never under board coverage. The path forward is
bypassing dm's PR OUT for raw SCSI CDB issuance so `abort=true` reaches
the target as service action 0x05 in fact, not just in the MXFS-internal
type system.
