# DLM_PLAN_REVIEW.md — GPT verification of the NET2 plan

> Consult of record, 2026-07-17 (gpt-5.6-sol). Input: `DLM_PLAN.md` +
> `new_dlm.md` verbatim, plus the 15-item verified errata from the same-day
> line-by-line tree re-scan against 0.10.120 (see ccmemory
> `net2-plan-rescan-errata-0.10.120`). Prior consult context (2026-07-12
> "don't build NET2 to fix CAW") was disclosed; this consult addresses the
> different question: NET2 as the legacy-TCP-transport replacement.
>
> Bottom line: **build NET2, but reject "one pass."** Smallest version first:
> reliable, incarnation-qualified, effect-idempotent midcomms over DIRECT peer
> links (keep the full mesh), mandatory fence-before-reclaim, XFS drain
> pipeline unchanged. Overlay / 1024-shard replication / PR delegations / CAW
> envelope are separately-justified later stages — envelope deferred
> indefinitely. Amendments A1–A24 below are to be folded into DLM_PLAN.md
> before any implementation.

---

The full reply follows verbatim.

---

# 1. Verdict and right-sizing

## Verdict: sound principles, but **no-go as an executable implementation plan**

The fundamental safety model is correct:

- reliable, idempotent application-level delivery;
- disconnect is never RELEASE;
- fencing before reclaim;
- no incompatible grant before drain-and-release or fence-and-recovery;
- mount-time transport selection;
- preservation of the XFS drain pipeline and generation-qualified release.

However, the proposed first implementation combines five difficult distributed systems projects:

1. reliable midcomms;
2. routed overlay;
3. authoritative membership/fencing;
4. 1024 independently replicated lock shards with elections and reconfiguration;
5. CAW delegation/envelope semantics.

That is not right-sized for the demonstrated problem or the current 2–32-node test environment. Several parts are also under-specified enough to be unsafe, particularly membership authority, shard reconfiguration, generation persistence, and recovery ordering.

**Recommendation:** approve NET2 as a direction, but reject "one pass." First build a reliable direct-mesh NET2 transport with effect-level idempotency and mandatory fence-before-reclaim. Retain wholesale freeze/purge initially if necessary for safety. Measure before adding overlay or replicated shards.

---

## Routed overlay versus reliable full mesh

A 64-node full mesh is:

- 63 peer connections per node;
- 2,016 TCP connections cluster-wide;
- currently roughly 63 receive threads per node because of the implementation model.

That is undesirable, especially with 32–64 VMs sharing one host, but it is not by itself a demonstrated architectural wall. The proven defects are lost state transitions and whole-table purge on membership change. The claim that the mesh "walls at ~16" is not supported by the validation history given here.

A direct mesh also has important first-version advantages:

- one hop;
- no relay queues;
- no TTL/routing convergence;
- no stale-view relay behavior;
- no dependence on alternate-path correctness;
- simpler backpressure and diagnostics;
- easier loss/dup/reconnect fault injection.

The per-peer-thread cost can also be attacked independently by multiplexing sockets over a bounded worker set, if PAL permits equivalent kernel/user-mode implementations.

### Recommendation

- **Keep full mesh for the first NET2 landing.**
- Make midcomms independent of topology so an overlay can be inserted later.
- Add the overlay only after a 64-node or faithful emulated test shows that connection/thread count—not retransmission, purge, freeze, or host oversubscription—is the failing limit.
- Do not fork the legacy "do not tear down on send timeout" policy. Once messages are retained for retransmission, a wedged link should be reconnectable without losing the logical session.

The overlay is a reasonable later optimization, not a correctness prerequisite.

---

## 1024 shards and three-way replicated logs

Virtual buckets are sensible for indexing, load accounting, and limiting recovery scope. A complete 1024-group replicated-log service with elections, log transfer, quorum commits, membership reconfiguration, and volatile kernel-resident state is much larger than the plan acknowledges.

The current shard design is not yet equivalent to Raft or another defined consensus protocol. In particular, it lacks complete rules for:

- old-to-new replica-group reconfiguration;
- joint quorums during a membership epoch change;
- durable vote/term behavior across reboot;
- state transfer before a new replica participates in quorum;
- log truncation and snapshotting;
- simultaneous membership and shard-leader changes;
- replica loss followed by incarnation/slot reuse;
- total replica-state loss;
- proving generation high-water after all replicas restart.

"HRW chooses a new top three" is mapping, not safe consensus reconfiguration. Independent old and new groups can each obtain a 2-of-3 quorum unless overlap and transition rules are explicit.

### Simpler first implementation

Use the current hash-master model behind reliable midcomms, adding:

- incarnation-qualified, request-ID-qualified operations;
- duplicate ACQUIRE/RELEASE/GRANT handling;
- generation-qualified releases;
- mandatory fencing before dead-holder or dead-master recovery;
- explicit freeze during uncertain recovery;
- resource/bucket indexes so later recovery need not scan or purge unrelated state.

Initially retaining a whole-table purge after fencing is acceptable if it is safe and meets the test budget. It is preferable to an unsafe "incremental remaster."

Incremental remaster after an ungraceful master death is not free: if master state was unreplicated, surviving live holders may be unknown. Safe choices are:

- replicate the affected ownership state;
- freeze and perform a recovery barrier involving every possible holder;
- or conservatively purge/recover a broader scope.

Do not reconstruct ownership merely from client claims.

If purge/recovery latency then fails criteria, add replication in a second stage. A fixed-epoch primary/backup design may be sufficient before implementing autonomous hot-shard migration. If full three-way consensus is retained, specify it as a complete protocol rather than "Raft-style."

---

## PR delegations

Defer renewable PR delegations.

Ordinary multi-holder PR fan-out is required lock functionality. A renewable local delegation is a separate cache-consistency protocol involving:

- delegation expiry and clock semantics;
- revocation races;
- node restart;
- lost revocation;
- local users admitted concurrently with revocation;
- proof of local quiescence before EX;
- failover reconstruction of delegation state.

It does not address the initial correctness failure and should not be in the first trusted release.

Hot-shard migration should also be deferred until static leadership is correct and measured. It cannot improve serialization of one hot resource.

---

## CAW envelope mode

Defer envelope mode indefinitely until pure NET2 and safe CAW BAST wakeups have separately soaked.

Envelope mode is not a fallback for unreliable CAW. It depends on CAW for the authoritative envelope transition and adds a second ownership model. The current envelope record is already stale relative to the real CAW slot semantics and would regress:

- `yield_to`;
- `yield_set_ms`;
- `ex_grant_streak`;
- `waiters_ex`;
- `dir_block0_fsb`;
- `dir_block0_gen`;
- tombstone-on-final-unlock;
- `is_free` atomic `dir_epoch/last_ex_slot` reset;
- grant observation/orphan-clock behavior.

The failed separate post-hoc free-reset CAS is a strong warning: an envelope design cannot casually checkpoint fields with extra synchronous disk operations.

**Cut order:**

1. CAW envelope mode.
2. Renewable PR delegations and hot-shard migration.
3. Routed overlay.
4. Full 1024-shard three-replica election service, unless measurements prove purge/failover is the next wall.
5. Novel disk-backed membership epoch ledger, unless its authority and non-CAW implementation are first resolved.

Do not cut reliable midcomms, effect idempotency, fencing gates, or generation-qualified recovery.

---

# 2. AMENDMENTS — concrete changes required in `DLM_PLAN.md`

The following should be folded into the plan before implementation.

## A1. Replace the "single pass" policy

**Sections affected:** document preamble, §11, and the conflict with `new_dlm.md`.

Replace:

> Implemented in one pass — there are no phases.

With:

> NET2 is implemented and enabled in separately test-gated stages. Each stage must preserve the drain/release invariant, build in kernel and user mode, and pass its written RULE-0 budget before the next stage is enabled. Later components must not be required for correctness of an earlier stage.

Initial order:

1. reliable direct-mesh midcomms plus effect-idempotent lock operations;
2. mandatory fence-before-reclaim and scoped freeze/recovery;
3. optional CAW reliable BAST wakeups;
4. incremental recovery/indexing;
5. overlay only if mesh measurements fail;
6. replicated shards only if recovery/availability criteria require them;
7. delegations;
8. envelope last.

---

## A2. Correct the description of the existing wire header

**Sections affected:** §1 and §6.

State that `struct mxfs_dlm_msg_hdr` is exactly 32 bytes:

- `magic u32`;
- `version u16`;
- `type u16`;
- `length u32`, total message length including the header;
- `seq u32`, currently inert;
- `sender u32`;
- `target u32`;
- `epoch u64`.

There is no inner `payload_len`. Receivers frame the inner message using `hdr.length`.

The inner wire already carries:

- membership/lease epoch in `hdr.epoch`;
- `grant_gen`, `dir_epoch`, and handoff in grant responses;
- `grant_gen` in RELEASE.

The plan must distinguish at least:

1. membership epoch;
2. per-resource `dir_epoch`;
3. shard term/mapping epoch, if shards are retained.

They are not interchangeable.

---

## A3. Do not use the inert inner `seq` as NET2's operation identity

**Sections affected:** §6, §7.A, §8, R7.

The current producers do not provide a trustworthy unique `hdr.seq`. NET2 must allocate an independent operation/request ID at the NET2 boundary.

Every mutating lock operation must carry an explicit identity such as:

- source slot and incarnation;
- request ID;
- resource ID;
- membership/mapping epoch;
- shard term, if applicable;
- expected grant generation where relevant.

Midcomms duplicate suppression is only a delivery optimization. Lock handlers must persist or retain enough completed-operation state to return the same result for duplicate ACQUIRE and RELEASE.

---

## A4. Correct the resource-ID model

**Sections affected:** §4, §7.B, hashing descriptions.

`struct mxfs_resource_id` is:

```c
{ volume, ino, offset, ag_number, type, pad[3] }
```

It has no generation or incarnation field. Node incarnation, request identity, term, and membership epoch must remain operation metadata and must not be inserted into the resource key.

Hashing and equality must use canonical zeroed padding. Preserve the existing whole-struct initialization behavior of `make_inode_resource()` and `make_ag_resource()`.

---

## A5. Move the message-size constant before NET2 reuses it

**Sections affected:** §6 and file inventory.

`MXFS_PEER_MAX_MSG_SIZE` is currently private to `peer.c`. Move or duplicate it into an explicitly shared protocol header before NET2 references it. Add static assertions for:

- inner header size;
- outer header size;
- maximum frame size;
- packed/aligned representation.

Specify wire byte order. Do not rely on native C struct layout across kernel/user builds or architectures.

---

## A6. Replace the incarnation algorithm

**Sections affected:** §5 and membership protocol.

Do not derive incarnation ordering from `mxfs_pal_time_ms`. It is boot-relative, resets across reboot, and is not cross-node comparable. A 16-bit folded boot timestamp is also too collision-prone for a safety identity.

Use one of:

- a persistent per-slot monotonic incarnation stored in authoritative shared state;
- or a sufficiently large random boot nonce, with equality rather than "newer/older" ordering;
- preferably both persistent generation and random nonce.

If the wire retains `u16`, define collision handling and refuse unsafe slot reuse. Prefer widening the incarnation field. A received different incarnation means a distinct session; the protocol must not infer that it is "newer" merely from a boot-relative timestamp.

---

## A7. Separate version negotiation from legacy compatibility

**Sections affected:** §6 and §8.

Do not blindly bump the existing inner `MXFS_DLM_VERSION` if that prevents the promised legacy fallback. Define:

- a NET2-specific outer protocol version;
- a capability advertisement that legacy nodes safely ignore or reject;
- mount/form/join behavior for mixed capabilities.

Fallback cannot occur independently after the transport is fixed. The forming cluster publishes one transport/feature set; joiners either conform or fail the join.

---

## A8. Revise the first topology to direct mesh

**Sections affected:** §3, §4, §7.A, §11, §13.

The first NET2 implementation should use direct peer links with reliable sessions. Keep the routing API abstract so overlay support can be added later.

Do not copy legacy `peer.c`'s keep-socket-up policy unchanged. With a retransmit ring, a transient or wedged link may be closed and reconnected without losing the logical session.

If the overlay remains in the future plan, add explicit protocols for:

- membership-view transition while frames are in flight;
- handling RELEASE/ACK from the preceding epoch;
- relay queue backpressure;
- route loops and TTL exhaustion;
- duplicate delivery over multiple paths;
- safe link retirement;
- absence of a node-disjoint path in small or partitioned views.

Do not simply drop every old-epoch frame at relays: a release initiated before an epoch transition may be essential for progress. Define an epoch-drain/bridging rule that cannot mutate new-epoch state incorrectly.

---

## A9. Fully specify flow control and priority behavior

**Sections affected:** §7.A and R6.

Define:

- send and receive window sizes;
- retransmit-ring bounds;
- SACK width and behavior beyond 32 gaps;
- ACK generation and delayed-ACK timers;
- ACK retransmission/piggyback behavior;
- maximum retry age;
- sequence wrap handling;
- memory accounting per peer and per mount;
- response to a full FENCE or REVOKE queue.

"Hard error" is not a safety policy. Queue exhaustion for control, BAST, RELEASE, or RELEASE_ACK must cause a defined fail-closed action—such as freezing the affected scope—and must never silently discard the transition.

Priority scheduling must reserve capacity, not merely use strict ordering. In particular:

- new BAST traffic must not indefinitely prevent already-completed RELEASE/RELEASE_ACK;
- retransmissions must not starve first transmissions;
- fencing traffic must not share a bounded resource whose exhaustion is caused by lock traffic;
- GRANT traffic must have a bounded minimum service rate.

Consider separate subqueues for BAST, RELEASE, and RELEASE_ACK rather than one REVOKE class.

---

## A10. Rewrite shard consensus as either deferred or complete

**Sections affected:** §7.B, R3, R8, §14.

If replicated shards are deferred, mark them explicitly non-MVP.

If retained, replace "Raft-style" with a complete protocol specifying:

- persistent or epoch-fenced term/vote semantics;
- commit index and log matching;
- append conflict/truncation;
- snapshots and memory bounds;
- leader completeness;
- state transfer;
- old/new replica-set joint consensus;
- when a transferred replica may vote or acknowledge;
- membership epoch changes during election;
- reboot of all three replicas;
- total replica-state loss;
- interaction between HRW mapping and committed configuration.

An HRW result is only a desired placement. It must not immediately become the voting configuration.

Pending waiter queues, dedup results, pending revocations, fairness state, and generation high-water must either be replicated or explicitly reconstructed without violating safety/fairness.

---

## A11. Define grant-generation width, wrap, and nonzero behavior

**Sections affected:** §7.B, §8, §9, R3.

NET2 must always return a nonzero `grant_gen`. Existing XFS code uses `grant_gen == 0` as a CAW-style discriminator in addition to `transport_caw()`.

Document the actual seam and wire widths. If the XFS-visible token is 32 bits:

- reserve zero;
- specify wrap handling;
- do not rely on a simple `>` comparison across wrap;
- freeze or force a new safely distinguished epoch before reuse.

A new shard leader may not set the next generation from only its local log unless quorum history proves that high-water complete.

---

## A12. Preserve both BAST callback families and all seam entries

**Sections affected:** §8.

NET2 must invoke both existing notification paths:

- `mxfs_dlm_bast_notify`;
- `mxfs_dlm_ag_bast_notify`.

Update all eight current `mxfs_v5_dlm_*` branch-shaped seam entries and any associated accessors. Include:

- real `grant_gen`;
- `dir_epoch`;
- handoff;
- granted mode;
- generation-qualified unlock;
- the dedicated `mxfs_v5_dlm_inode_unlock_free()` behavior.

For CAW-safe hybrid modes, `mxfs_v5_dlm_transport_caw()` must continue to return the semantics required by CAW's restartable epochs. Pure NET2 must take network monotone-comparison paths and must never emit generation zero.

---

## A13. Correct the transport-selection description

**Sections affected:** §8 and §14.

The v5 seam does not perform CAW probing or AUTO fallback. It receives `opts->transport`, with the existing force override and validation. AUTO is resolved by the caller/mount layer.

Add `NET2=3` without implying that `v5_mount.c` automatically probes and falls back. Define the force-transport value separately and preserve mount-time immutability.

A "CAW plus NET2 wakeup" feature should be represented as CAW transport plus a negotiated auxiliary capability unless there is a compelling reason to expose a fourth XFS-visible transport semantic.

---

## A14. Replace the membership-epoch authority design

**Sections affected:** §7.C, §7.D, §7.E, R4, R9.

The proposed CAW-written epoch ledger is incompatible with NET2's main fallback goal if CAW is unavailable or unreliable. It also creates a new authoritative membership source beside lease/disklock without defining precedence.

The plan must name exactly one authority for:

- committed member mask;
- fenced mask;
- slot/incarnation binding;
- replay election eligibility;
- shard mapping epoch.

Existing sources should have explicit roles:

- lease multicast: observation/hint;
- direct probe: observation/hint;
- disk heartbeat: storage-reachability observation and existing self-fence input;
- committed membership service: authority;
- fencing confirmation: prerequisite to exclusion/reclaim.

For CAW-unavailable installations, the authority cannot depend on SCSI CAW. Specify an alternative such as a properly defined network consensus service with a storage/power fence authority or an external cluster manager. A shared-disk record may only be used if its atomicity is supported on the target hardware independently of the unreliable CAW operation.

Do not claim "no layout growth" while carving an unspecified reserved-sector ring. Give exact offsets, compatibility/versioning, atomic update protocol, tooling, and failure behavior.

---

## A15. Give NET2 its own freeze state and stamp

**Sections affected:** §7.C, §7.E, §8.

The existing `last_memb_change_ms` and `mxfs_memb_settle_ms` plumbing are inside the legacy TCP engine. NET2 must own its own timestamps, masks, reason codes, and freeze scopes.

Do not claim that CAW already consults the TCP `memb_settle` gate. If CAW is to consume a common freeze module, add and verify an explicit CAW integration point.

The 20-second timer must not become an unconditional NET2 grant freeze. Define:

- which operations are blocked;
- whether compatible reads continue;
- maximum decision deadlines;
- error surfaced when the deadline cannot be met;
- how the behavior fits each RULE-0 test budget.

Timer expiry alone may never authorize reclaim.

---

## A16. Add the missing recovery generation-advance step

**Sections affected:** §7.D, §9, R3, §13.

The existing lease-expire callback does not advance resource generation on reclaimed slots. NET2 must implement or prove unnecessary an explicit step.

Required ordering is:

1. freeze affected grants;
2. confirm storage fencing of the victim;
3. commit the membership epoch excluding the victim;
4. perform required dead-node purge and foreign-slice journal replay;
5. invalidate/reconstruct replicated or local lock state;
6. advance the appropriate resource/slot generation;
7. publish recovery completion;
8. unfreeze.

Define "advance generation" separately for:

- pure NET2 records;
- CAW slots;
- envelope slots, if ever implemented.

No grant may be issued between replay and generation advancement.

---

## A17. Integrate foreign-slice replay, evict ring, MDS, and disk self-fencing

**Sections affected:** §7.C, §7.D, §9.

The committed NET2 view must be the input to foreign-slice replay election. Do not allow the lock membership service and `mxfs_disklock_lowest_live_slot()` to elect different recovery owners.

State explicitly:

- the evict ring remains a non-authoritative invalidation-hint mechanism;
- it does not release locks or establish membership;
- the disklock generation/re-mkfs self-fence remains active beneath NET2;
- MDS/disklock slot 0 remains unchanged unless separately redesigned;
- the `ever_multi` single-node-regression latch remains enforced;
- runtime disk dead-timeout remains an observer threshold, not proof of fencing.

---

## A18. Correct fencing claims

**Sections affected:** §7.D and R4.

A DLM/CAW slot-generation change is not automatically a storage fence for pure NET2. A partitioned kernel may retain LUN access and continue using previously granted NET2 state without issuing another CAW.

A valid fence must prove the victim cannot issue any shared-LUN I/O through any path. For SCSI PR, specify:

- per-node key ownership;
- reservation type;
- multipath behavior;
- preempt-and-abort or equivalent semantics;
- confirmation on all relevant paths;
- behavior on key reuse and restart.

Do not assume `scsipr_unregister` is a self-fence unless the reservation mode proves that unregister removes the node's storage access.

Fence callbacks must be incarnation-qualified; a late fence completion for an old incarnation must not fence or mark dead a replacement incarnation.

---

## A19. Correct the port registry and migration

**Sections affected:** §14 and port-registry work.

Current effective assignments are:

- 7600: DLM;
- 7601: discovery;
- 7602: legacy-path lease fallback and CAW BAST, currently colliding;
- 7603: v5 lease literal;
- 7604: unused;
- 7605: unused and available for NET2 membership.

Do not simply change `MXFS_LEASE_PORT` from 7602 to 7603. That silently changes legacy behavior.

Adopt explicit names such as:

- `MXFS_DLM_PORT 7600`;
- `MXFS_DISCOVERY_PORT 7601`;
- `MXFS_CAW_BAST_PORT 7602`;
- `MXFS_LEASE_LEGACY_PORT 7602`;
- `MXFS_LEASE_V5_PORT 7603`;
- `MXFS_NET2_MEMBERSHIP_PORT 7605`.

Then define a versioned migration to one canonical lease port, including compatibility behavior. Remove literal ports only after that decision.

---

## A20. Update CAW safe-mode BAST semantics

**Sections affected:** §7.F and §8.

Reliable NET2 BAST is an accelerator only. CAW disk state remains authoritative.

The waiter must retain:

- bounded disk polling;
- timeout/reconnect behavior;
- fallback to the existing hint path where negotiated;
- safe behavior if NET2 membership is unavailable.

A lost or unavailable network wakeup must not prevent eventual observation of the disk transition. Coalescing must preserve every affected resource/AG identity.

The plan should account for current CAW grant metadata, grant sequence counter, real granted-mode accessor, and orphan-clock table where they affect owner/waiter observation.

---

## A21. Rewrite or remove the envelope state model

**Sections affected:** §7.F, §9, R2, R11.

If envelope remains documented, its replicated state must include or faithfully derive:

- holder masks by mode;
- generation;
- `dir_epoch`;
- `last_ex_slot`;
- handoff;
- `yield_to`;
- `yield_set_ms`, using cross-node-comparable real time where required;
- `ex_grant_streak`;
- `waiters_ex`;
- `dir_block0_fsb`;
- `dir_block0_gen`;
- tombstone state;
- free/reset semantics;
- pending waiter and pending revoke state.

Envelope release must match current `mxfs_dlm_caw_unlock_gen(ctx, resource, expected_gen32, is_free)` semantics. For final free unlock, tombstoning and `dir_epoch/last_ex_slot` reset must be part of the same authoritative CAS image. Do not add a separate post-hoc synchronous reset operation.

Because this substantially expands the protocol and affects proven performance, envelope should remain disabled and preferably be removed from the initial implementation plan.

---

## A22. Correct the preserved drain-pipeline names

**Sections affected:** §7.B, §9, §13.

Use the current sequence:

1. `mxfs_dlm_ag_drain_meta_buffers`;
2. `mxfs_dlm_ag_drain_alloc_buflist`;
3. `mxfs_dlm_ag_drain_inode_buffers`;
4. block-device flush in `mxfs_dlm_ag_bast_work_fn` Phase 2/2b;
5. generation-qualified unlock.

Retain:

- `p_rel_gen` capture before NL;
- mid-drain abort;
- `unlock_gen(p_rel_gen)`;
- `-ESTALE` re-arm of BAST.

---

## A23. Update PAL statements

**Sections affected:** §10.

The core can use existing:

- `mxfs_pal_spinlock_*`;
- `mxfs_pal_time_ms` for local monotonic deadlines;
- `mxfs_pal_time_real_ms` only where cross-node wall-clock comparison is deliberately required.

Do not compare boot-relative monotonic timestamps across nodes.

The only genuinely new PAL hooks remain watchdog and external fencing agent hooks, but their cancellation, incarnation qualification, callback lifetime, and kernel/user-mode semantics must be specified.

---

## A24. Add an explicit dual-build/wire-lifetime section

**Sections affected:** §6, §10, §11, §13.

Require:

- explicit endian conversion;
- no native-struct wire serialization;
- identical size/static assertions in kernel and user mode;
- bounded allocations;
- no sleeping in atomic context;
- callback lifetime safety during unmount/module unload;
- deterministic thread shutdown;
- lock-order documentation;
- PAL condition/timer behavior tests;
- no kernel pointer or address used as an operation identity;
- equivalent fault-injection behavior in the user-mode harness.

---

# 3. Design holes not adequately covered

## 3.1 Two membership authorities

The largest architectural hole is the relationship among:

- existing lease membership;
- disklock heartbeat/liveness;
- NET2 voter membership;
- shard replica membership;
- replay election;
- SCSI PR fencing state.

"Three observers, one authority" is a good phrase, but the plan does not actually establish one authority. It introduces a new epoch record while existing callbacks still purge, replay, declare death, and self-fence.

Every consumer must use the same committed tuple:

```text
{membership_epoch, member_mask, slot→incarnation bindings, fenced_mask}
```

Observer disagreement causes SUSPECT/freeze, not independent state transitions.

The membership service must also avoid circular dependence:

- shard service needs membership to choose replicas;
- membership ACKs are sent over NET2;
- NET2 routing depends on membership;
- fencing may depend on disklock membership;
- recovery election depends on a live-node calculation.

A bootstrap and degraded-path protocol is required.

---

## 3.2 CAW dependency in the CAW-unavailable fallback

The epoch ledger currently requires a CAW write, even though pure NET2 is intended for hardware where CAW is unsupported or unreliable. This materially invalidates the proposed membership mechanism for one of NET2's two main product cases.

The plan needs distinct supported configurations:

1. **CAW capable:** CAW authoritative locks, optional NET2 BAST.
2. **CAW unreliable but storage fencing available:** pure NET2 with network/external membership consensus and PR/watchdog/external fence.
3. **No reliable storage fence:** mount may operate, but ambiguous failure must produce a bounded, visible frozen/error state; automatic recovery is prohibited. Prefer refusing clustered NET2 mount unless this posture is explicitly requested.

---

## 3.3 Shard state versus foreign-slice replay

A new leader cannot resume from replicated holder state merely because the old holder was fenced. Journal replay and metadata invalidation may still be required.

Conversely, foreign-slice replay must not begin under a different view from the shard service. Required barriers are:

```text
fence confirmed
  → membership exclusion committed
  → replay owner committed
  → replay completed
  → lock records/generations repaired
  → shard activation
```

A shard election may occur earlier for bookkeeping, but it must remain recovery-frozen.

---

## 3.4 Freeze can become a test-visible outage

A 20-second freeze is already long compared with many native-XFS-derived budgets. Adding resource, shard, filesystem, membership-settle, election, fence, and recovery freezes can make ordinary membership churn fail every performance test while remaining "correct."

The plan needs:

- reason-coded freeze counters;
- start/end timestamps;
- maximum allowed duration per reason;
- scope;
- affected operation classes;
- bounded failure returned to callers if resolution exceeds the test budget.

A no-fence partition cannot wait forever in a test. It should enter a stable frozen state and return a defined error or administrative status within budget. "Freeze forever" is safe but not testable availability behavior.

Routine join/leave should not impose a 20-second filesystem-wide EX freeze if the old member held no relevant lock and the view change is cleanly committed.

---

## 3.5 Priority inversion remains possible inside the high-priority class

BAST, RELEASE, RELEASE_ACK, and retransmission are grouped together, but their dependencies differ:

- BAST initiates drain.
- RELEASE reports drain completion.
- RELEASE_ACK allows the old holder to retire state.
- A waiter may generate more BASTs while prior releases are queued.

A BAST storm can therefore delay the very RELEASEs needed to make progress. Reserve queue entries and scheduling quanta separately for completed RELEASE and RELEASE_ACK traffic. These should generally outrank repeated BASTs for the same resource.

Control-plane traffic should not rely on a lock-plane relay queue merely because it has priority zero.

---

## 3.6 Security and message authenticity

The plan uses a 32-bit cluster UUID hash and unauthenticated network messages for grants, membership, and fencing requests. Even on a trusted storage LAN, accidental cross-cluster traffic or stale test networks are realistic.

At minimum:

- use the full cluster UUID or a collision-resistant identifier in session establishment;
- authenticate the handshake and fencing/control messages, or explicitly state and enforce a trusted-network threat model;
- reject cross-volume and cross-filesystem-generation traffic;
- rate-limit unauthenticated SYN/beacon state allocation.

A spoofed FENCE_DONE is far more dangerous than a spoofed ordinary DLM packet.

---

## 3.7 Volatile replica state and simultaneous restart

If logs exist only in RAM, a power event or same-host VM reset can erase all three replicas simultaneously. "Take max committed log" then has no source.

The design must choose:

- durable shard state;
- a recovery procedure that fences all possible holders and reconstructs from journals/disk;
- or a cluster-wide recovery epoch that invalidates every prior network grant before service resumes.

A new incarnation alone does not invalidate writes from already-running clients unless those clients are fenced or forced through a recognized recovery barrier.

---

## 3.8 Waiter/fairness state is absent

The proposed lock record stores holders and pending revokes but not a complete acquisition queue. After leader failover, retries may rebuild liveness but can violate fairness, reorder an EX behind new readers, or lose CAW-equivalent handoff behavior.

Specify whether waiters are:

- replicated log state;
- client-owned retry state with a deterministic ticket;
- or intentionally discarded on term change, with a fairness reset that is proven safe.

---

## 3.9 Resource lifetime and tombstones

The CAW implementation now tombstones during final unlock and performs free-specific epoch reset atomically. Pure NET2 also needs a resource record lifecycle:

- when a record can be discarded;
- how old duplicate RELEASE/ACQUIRE messages are rejected after recreation;
- whether generation high-water survives record deletion;
- how inode reuse and directory reuse avoid ABA.

A resource ID has no incarnation field, so record deletion cannot discard all history without another fencing token.

---

# 4. Sequencing and minimal first landing

`new_dlm.md` is correct that this work must be staged. `DLM_PLAN.md`'s "one pass" is not credible and would make root-cause isolation nearly impossible.

## Stage 0 — protocol specification and observability

Before changing transport behavior, land:

- shared wire constants and endian helpers;
- request/incarnation identity definitions;
- counters and tracepoints;
- fault-injection controls;
- port registry with deliberate compatibility;
- kernel and user-mode protocol tests.

### Gate

- both builds green;
- wire encode/decode golden vectors;
- malformed-frame fuzzing;
- no Makefile or runtime enablement without approval;
- written RULE-0 budgets.

---

## Stage 1 — reliable midcomms over the existing direct mesh

Implement a new NET2 transport using direct links:

- per-incarnation sessions;
- ACK/SACK/retransmit;
- receive windows;
- bounded queues;
- effect-idempotent lock operations;
- nonzero generation tokens;
- both inode and AG BAST paths.

Keep current hash mastership. Do not add overlay, delegation, or envelope.

Membership changes may initially retain a conservative global freeze/purge, but dead-node reclaim must be moved behind a mandatory fence and recovery barrier before this stage is trusted for failure tests.

### Criteria-visible win

This directly addresses the proven dropped GRANT/RELEASE/BAST defect. It can make the previously leaking legacy-network workloads clean without depending on speculative scaling machinery.

### Go/no-go gate

At 1/2/4/8/16/32 nodes:

- 100% of applicable suite within written budget;
- repeated `tcp_dlm_scaling`, `dir_reuse`, fairness, and stress sessions;
- injected packet loss/dup/reorder;
- zero incompatible overlapping grants;
- zero unacknowledged transition silently discarded;
- every duplicate mutating operation produces the original result or a generation-qualified stale response.

If 32-node direct mesh meets CPU/thread/wall budgets, overlay is not yet justified.

---

## Stage 2 — authoritative fencing and recovery hardening

Create the NET2-owned SUSPECT/freeze/fence state machine and bind all dead-node recovery to confirmed storage fencing.

Initially reuse the existing liveness observations where possible, but eliminate timeout-alone DEAD for NET2. Define one committed recovery view and integrate foreign-slice replay.

### Go/no-go gate

Pass:

- kill mid-drain;
- reboot holder;
- asymmetric partition;
- network-isolated node retaining LUN access;
- failed/late fence completion;
- no-fence configuration.

No incompatible grant may appear before the trace shows:

```text
fence confirmation
< membership exclusion
< replay completion
< generation advance
< unfreeze/grant
```

A timeout or absence of fence hardware must produce a visible frozen result within budget, never a reclaim.

---

## Stage 3 — CAW reliable BAST wakeups

This can be developed after Stage 1 because it reuses proven reliable sessions, but it should not be the first project milestone: CAW is already green and this does not replace legacy TCP.

Keep disk polling as the correctness fallback. Measure whether relaxed polling reduces command load and wall time.

### Go/no-go gate

- CAW suite remains 100% green at 1–32 nodes;
- drop all NET2 BASTs: correctness unchanged, only latency worsens;
- drop UDP hints: reliable NET2 wakeups preserve expected latency;
- disconnect NET2 during waits: bounded disk polling makes progress;
- command-rate and wall-time improvement is measured against CAW without NET2.

---

## Stage 4 — incremental recovery or replicated buckets

Add only if Stage 1/2 fail membership-change budgets because of global purge.

First add resource/master indexes and scoped freeze. If state preservation is required, introduce replicated bucket state with a fully specified fixed-epoch protocol. Do not add hot migration simultaneously.

### Go/no-go gate

- membership changes touch only expected buckets/resources;
- no unaffected resource freeze beyond its budget;
- master death at every commit point;
- no generation regression;
- no loss of live holder state;
- replay and activation ordering proven.

---

## Stage 5 — routed overlay, only if measured necessary

Run a faithful 64-node test or connection/thread stress first. If direct mesh fails because of thread count, first consider bounded socket-worker multiplexing.

### Go/no-go gate

- same correctness matrix as direct midcomms;
- two independent link failures do not lose a logical transition;
- relay saturation does not delay RELEASE/FENCE beyond budget;
- no route loop or stale-epoch livelock;
- overlay materially improves CPU, thread count, or wall time at 64 nodes.

---

## Stage 6 and later

- renewable PR delegation;
- hot-shard migration;
- CAW envelope.

Each should have its own feature bit and default-off soak period. Envelope must not be enabled until all replica-loss, fence, replay, fairness, canonical-directory, and final-unlock-CAS cases pass.

---

# 5. Required verification and fault-injection matrix

The current verification section is a useful outline but not sufficient for a distributed lock protocol.

## 5.1 Midcomms matrix

Inject independently and in combination:

| Fault | Required cases |
|---|---|
| Loss | DATA, ACK, GRANT, RELEASE, RELEASE_ACK, BAST; burst and random loss |
| Duplication | Before delivery, after ACK loss, after reconnect |
| Reordering | Within window, beyond SACK range, across reconnect/path change |
| Delay | Delayed DATA, delayed ACK, delayed old-epoch frames |
| TCP failure | Reset before header, mid-header, mid-payload, after kernel accepted send |
| Backpressure | Full GRANT queue, full BAST queue, full RELEASE queue, stalled receiver |
| Restart | Sender restart, destination restart, slot reuse, stale old-incarnation packets |
| Epoch change | Acquire/release concurrently with view transition |
| Sequence limits | Window boundaries, SACK boundaries, near wrap |
| Malformed input | Bad length, oversized length, wrong target, UUID, volume, epoch, CRC/auth |

### Required evidence

Counters per peer/session:

- unique messages created;
- first transmissions;
- retransmissions;
- ACKed messages;
- duplicate sequences suppressed;
- duplicate operations handled idempotently;
- out-of-window drops;
- stale incarnation/epoch/term drops;
- queue-full events by class;
- maximum queue residency by class;
- session reset/resume count;
- unrecoverable protocol errors;
- freezes caused by communication ambiguity.

Invariants:

```text
delivered_effects <= unique_operation_ids
committed RELEASE removals <= completed drain traces
incompatible grants never overlap
every freed retransmit entry has ACK or explicit session-abort disposition
no RELEASE/GRANT/BAST is silently discarded on queue overflow
```

For duplicate ACQUIRE, logs must show the same pending/granted result and generation. For duplicate RELEASE, logs must show the prior committed result or a defined stale-generation response.

---

## 5.2 Shard failover matrix, if replicated shards are retained

Kill or partition the leader:

1. before append;
2. after local append but before replication;
3. after one replica append;
4. after quorum append but before commit publication;
5. after commit but before GRANT;
6. after GRANT send but before ACK;
7. after holder drain but before RELEASE reaches leader;
8. after RELEASE quorum commit but before RELEASE_ACK;
9. while revocations are pending;
10. during replica-set reconfiguration;
11. during snapshot/log compaction;
12. while an old leader is partitioned and later rejoins.

Partition patterns:

- leader alone;
- one follower alone;
- 2-versus-1;
- old replica group versus new group;
- overlapping old/new groups;
- simultaneous membership epoch change;
- all replicas rebooted;
- two replicas lost permanently.

### Required evidence

- at most one grant-capable leader for a committed configuration/term;
- every grant references a quorum-committed ownership state;
- commit index never decreases;
- generation and `dir_epoch` high-water never decrease;
- old-term operations cannot mutate current state;
- an uninitialized/transferring replica never votes or acknowledges commits;
- pending holder/revocation state survives failover;
- no incompatible grant until all committed holder bits are cleared or fenced/recovered;
- total state loss causes recovery freeze, never empty-table assumption.

Record term, configuration ID, replica set, commit index, resource generation, holder mask, pending revoke mask, and recovery barrier in every relevant trace.

---

## 5.3 Fencing and recovery matrix

### Kill mid-drain

Inject death:

- before drain starts;
- between each current drain phase;
- before block flush;
- after flush but before RELEASE;
- after RELEASE send but before commit;
- after commit but before ACK.

Required result:

- no incompatible grant based on timeout;
- fence confirmation precedes replay;
- replay precedes generation advance;
- generation advance precedes new incompatible grant.

### Partition with continuing LUN access

Test:

- all NET2 links blocked, disk access intact;
- multicast only blocked;
- direct probes only blocked;
- asymmetric A→B and B→A loss;
- minority retains LUN access;
- stale leader retains LUN access;
- multipath with only one path revoked;
- PR key removal delayed or falsely reported;
- old incarnation fence completion arrives after slot reuse.

Required result:

- network quorum alone cannot reclaim;
- victim cannot be declared fenced until all storage paths are revoked;
- minority freezes/self-fences according to policy;
- late fence callbacks are incarnation-qualified and ignored where stale.

### No-fence hardware

Test mount and runtime posture explicitly:

- no SCSI PR;
- watchdog unsupported;
- external agent unsupported;
- fence agent times out;
- fence agent reports failure;
- fence authority disappears during recovery.

Required result:

- no automatic DEAD/reclaim;
- affected resource/shard/FS enters a reason-coded frozen state;
- callers receive the documented bounded outcome within the test budget;
- administrative status clearly identifies the blocking incarnation and missing fence method.

### Existing infrastructure

Also inject:

- disklock `fs_gen` change/re-mkfs detection;
- evict-ring wrap and stale hints;
- disk dead-timeout runtime changes;
- MDS/slot-0 failure;
- `ever_multi` transition back to one node;
- conflicting replay-election observations.

NET2 must not override existing self-fence behavior or treat evict-ring hints as lock releases.

---

## 5.4 Performance and RULE-0 evidence

For every test and node count, record:

- native-XFS baseline;
- computed `2 × native` budget;
- actual wall time;
- freeze time by reason and scope;
- fence time;
- replay time;
- retransmission count;
- queue maximums;
- worker CPU;
- socket/thread count;
- disk command rate for CAW modes.

A timeout is a failure, including a "safe" indefinite freeze. The test may expect a controlled frozen/error result, but that result must occur within a written budget.

Do not tune timeout values until counters identify the blocking state. In particular, do not solve retransmission, election, or freeze failures by lengthening the 20-second settle interval.

---

# Bottom line

Build NET2, but build the smallest version that fixes the proven network-DLM defect:

> **Reliable, incarnation-qualified, effect-idempotent midcomms over direct peer links, with mandatory fence-before-reclaim and the existing XFS drain pipeline unchanged.**

Treat the overlay, autonomous replicated shards, delegations, and especially CAW envelopes as separately justified optimizations. The current plan's safety intent is good, but its membership authority, shard reconfiguration, generation recovery, port migration, and CAW-envelope state model must be corrected before coding begins.
