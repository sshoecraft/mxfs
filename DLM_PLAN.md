# DLM_PLAN.md — NET2 Transport Implementation Plan (v2, 2026-07-17)

> Full implementation plan for **NET2**, the new MXFS DLM network transport
> specified in `new_dlm.md`. v2 supersedes the 2026-07-11 draft: every
> `file:line` anchor was re-verified against the 0.10.120 tree (ccmemory
> `net2-plan-rescan-errata-0.10.120`), the GPT review's 24 amendments
> (`DLM_PLAN_REVIEW.md`) are folded in, and the two components the review
> flagged as under-designed — **shard consensus/reconfiguration** (§7.B) and
> **membership-epoch authority** (§7.C) — are now fully designed.
>
> **Scope: the complete system, implemented in ONE effort.** There are no
> deferred "later stages." The build order (§11) is a dependency ordering
> with in-effort verification gates — each gate is a checkpoint inside the
> same implementation push (build → gate-test → continue), not an exit ramp.
> The only runtime-gated component is CAW envelope delegation, which ships in
> this pass but defaults OFF until its fault matrix (§13.4) passes — that is
> a module/feature switch, not a deferral of implementation.

---

## 1. Context — why this is being built

The current MXFS network DLM (`force_transport=1`, files `dlm/dlm.c` +
`dlm/peer.c`) has two proven structural defects:

1. **Fire-and-forget messaging.** The inner header's `seq` field
   (`mxfs_dlm.h:110`) is inert — no ACK, retransmit, dedup, or sequencing
   anywhere. Loss recovery is requester timeout + full re-request
   (`MXFS_LOCK_ACQUIRE_WAIT_MS=1000`). Sockets are deliberately kept up on
   transient send timeout (`peer.c:914-940`, retry ladder {200,500,1000}ms ×3
   → `-EAGAIN`) precisely because buffered GRANT/RELEASE/BAST are never
   retransmitted — a dropped one is a lost lock transition. Proven root of
   the historical `tcp_dlm_scaling` / `dir_reuse` coherence leaks.
2. **Single unreplicated master + wholesale purge.** Mastership is
   hash-distributed (`mxfs_dlm_resource_master`, master =
   `nodes[hash % count]`, `dlm.c:2621/2636`) but any membership change purges
   the ENTIRE lock table and bumps the epoch
   (`mxfs_dlm_update_active_nodes`, `dlm.c:2650-2775`), and dead-node
   declaration is timeout-only (`v5_tcp_death_worker_fn`, no fencing gate).

The full mesh (63 sockets/recv-threads per node at 64 nodes) is a cost, not a
proven wall — NET2 therefore implements **both** link topologies (§7.A):
direct mesh (default at all currently-validated sizes) and the routed overlay
(selectable, gated by its own matrix), behind one routing abstraction.

NET2 is a **third transport** behind the `mxfs_v5_dlm_*` seam alongside CAW
and legacy TCP. The XFS layer and the Invariant-1 drain pipeline are
untouched. Legacy `peer.c`/`dlm.c` are retained as fallback.

**The single most important safety rule (from `new_dlm.md`):**
> Loss of connectivity, quorum, leader state, or membership certainty must
> stop new grants. It must **never** be converted directly into lock
> revocation. A holder may be bypassed only after it has completed
> drain-and-release **or** has been fenced from shared storage and recovery
> has completed.

### Existing wire reality NET2 wraps (verified)

`struct mxfs_dlm_msg_hdr` is exactly **32 bytes**: magic u32, version u16,
type u16, **length u32 (total, incl. header — receivers frame on this; there
is no payload_len field)**, seq u32 (inert), sender u32, target u32,
epoch u64. The inner wire already carries TWO epoch systems — the
lease/membership epoch in `hdr.epoch` and the per-resource `dir_epoch` (+
`handoff` byte + `grant_gen`) in grant responses; RELEASE carries
`grant_gen` and stale-gen releases are dropped (`dlm.c:4001`). NET2 adds a
third ordered domain (shard term). **These three are distinct and never
interchangeable: membership epoch ▸ shard term ▸ per-resource
dir_epoch/grant_gen.**

---

## 2. Goals / non-goals

**Goals (all in this effort)**
- End-to-end reliable midcomms: persistent incarnations, per-direction seq,
  cumulative + selective ACK, retransmit (over alternate path when overlay
  active), dedup, receive windows, fully-specified bounded flow control,
  priority classes with reserved capacity.
- Dual link topology behind one routing abstraction: direct mesh (default)
  and bounded-degree routed overlay (~O(log N) neighbors), both implemented.
- Virtual shards (1024) with 3-node replica groups, epoch-derived
  configurations, in-epoch terms, replicated snapshot+log state, leader
  election/migration, closed-set recovery barrier — no wholesale purge.
- PR fan-out + renewable PR delegations; hot-shard leader migration.
- Membership plane with ONE committed authority record (MEPOCH, §7.C) —
  observers vote, quorum+fencing commits; works identically with or without
  CAW-capable hardware.
- Fencing tied to SUSPECT→DEAD (method ladder, incarnation-qualified),
  explicit recovery generation-advance, scope-aware budgeted freeze.
- CAW/NET2 hybrid: reliable BAST wakeups (capability, not a 4th transport
  semantic); CAW envelope delegation implemented, feature-gated default-OFF.

**Non-goals (explicit)**
- No live transport switching (Invariant 5). Fixed at mount; joiners conform.
- No on-disk layout growth: `MXFS_CAW_MAX_SLOTS=65536` stays (Invariant 2);
  MEPOCH persistence uses existing reserved bytes in per-node heartbeat
  records (exact layout §7.C) — single-writer sectors, no new regions.
- No kernel API outside `pal/` (Invariant 4). Must build user-mode.
- Legacy TCP transport retained; NET2 negotiated, not forced.

---

## 3. Architecture overview

```
        ┌──────────────────────────────────────────────────────────────┐
        │  XFS overlay (xfs/xfs_mxfs_dlm.c) — UNCHANGED                  │
        │  drain pipeline (Invariant 1), grant_gen/dir_epoch fencing     │
        └──────────────────────────────┬───────────────────────────────┘
                                        │  mxfs_v5_dlm_* seam (v5_mount.c)
        ┌───────────────────────────────▼──────────────────────────────┐
        │  LOCK PLANE          net2_shard.c / net2_lock.c               │
        │  epoch-derived shard configs, terms, snapshot+log, PR fan-out │
        ├───────────────────────────────────────────────────────────────┤
        │  MIDCOMMS            net2_midcomms.c  (sessions, seq/ack/retx)│
        │  ROUTING ABSTRACTION net2_overlay.c   (mesh + overlay provider)│
        │  LINK                net2_link.c      (TCP neighbor links)    │
        ├───────────────────────────────────────────────────────────────┤
        │  CONTROL PLANE (reserved sockets/threads/priority)            │
        │  net2_membership.c  net2_epoch.c  net2_fence.c  net2_freeze.c  │
        ├───────────────────────────────────────────────────────────────┤
        │  DISK HYBRID   net2_bast.c   net2_caw_envelope.c (default off)│
        └───────────────────────────────────────────────────────────────┘
```

**Reliability boundary is the end-to-end NET2 session, not the TCP link.** A
link dropping is a routing event; with a retransmit ring, a wedged link is
CLOSED AND RECONNECTED without losing the logical session (this deliberately
departs from legacy peer.c's keep-socket-up policy — that policy existed only
because nothing was retransmittable). A link event is never reported upward
as node death or an implicit RELEASE.

---

## 4. New file inventory

All under `dlm/`. Object additions to the Kbuild list that carries `peer.o`
**require explicit user go-ahead** (project rule; flag at wiring time).

| File | Responsibility |
|---|---|
| `net2.h` | Public API + identity structs, priority/reliability enums, lifecycle. |
| `net2_wire.h` | Outer header `mxfs_net2_hdr` (64 B), magics, flags, endian helpers, static asserts. Shared protocol constants incl. `MXFS_NET2_MAX_MSG_SIZE` (lifted from peer.c's private `MXFS_PEER_MAX_MSG_SIZE=8192`, peer.c:17). |
| `net2_link.c/.h` | Neighbor TCP links over `mxfs_pal_tcp_*` (fork of peer.c connect/accept/handshake races, lower-slot-initiates); per-link recv thread + prioritized egress worker; reconnect-preserving-session. |
| `net2_overlay.c/.h` | Routing abstraction with two providers: MESH (direct link to dst) and OVERLAY (ring+finger neighbor set, greedy routing, 2 node-disjoint next hops, TTL, relay). |
| `net2_midcomms.c/.h` | Session table (6-tuple + nonces), seq/ack/sack, retransmit ring, receive window + dedup, flow control, reconnect/resume. |
| `net2_shard.c/.h` | Shard configs derived from MEPOCH, terms, snapshot + bounded log, quorum commit, election, state transfer, recovery barrier, migration. |
| `net2_lock.c/.h` | Per-resource lock records, replicated waiter queue + fairness, PR fan-out, renewable delegations, idempotent op handlers + replicated completed-op cache, grant_gen/dir_epoch allocation (nonzero, wrap-managed). |
| `net2_msg.h` | Lock-plane payloads (ACQUIRE/GRANT/RELEASE/RELEASE_ACK/BAST/APPEND/APPEND_ACK/TERM_VOTE/SNAPSHOT/RECOVERY_REPORT). |
| `net2.c` / `net2_ctx.h` | `mxfs_net2_ctx`, seam entry implementations, recv demux. |
| `net2_membership.c/.h` | Observers (mcast/probe/disk votes), SUSPECT/DEAD state machine, incarnation persistence. |
| `net2_epoch.c/.h` | MEPOCH single-decree commit protocol + per-slot HB-record persistence. |
| `net2_fence.c/.h` | Fence request/done (incarnation-qualified), SCSI-PR preempt-and-abort binding, method ladder. |
| `net2_freeze.c/.h` | Scope-aware, reason-coded, budgeted freeze. |
| `net2_bast.c/.h` | Reliable CAW BAST wakeups (capability on CAW transport). |
| `net2_caw_envelope.c/.h` | Envelope delegation (full slot-semantics mirror), feature-gated, default off. |
| `include/mxfs/mxfs_ports.h` | Port registry (§14). |

Shared-code lifts (one copy for CAW + NET2): `resource_hash_raw` /
`resource_equal` (dlm.c:221/240) and `lock_compat[][]` / `is_compatible` /
`recompute_granted_mode` (dlm_caw.c:186/250/278; order EX>PW>PR>CW>CR;
EX/PW popcount>1 = corruption, per `slot_appears_corrupt` dlm_caw.c:398).

---

## 5. Identity & incarnation

**Resource identity is unchanged**: `struct mxfs_resource_id`
{volume, ino, offset, ag_number, type, pad[3]} (`mxfs_common.h:60-67`) — it
has NO generation field and gains none. Incarnation, request id, epoch, term
are **operation metadata**, never part of the resource key. Hashing uses the
whole memset-zeroed struct (preserved behavior of `make_inode_resource` /
`make_ag_resource`, v5_mount.c:1340/1349).

**Node identity** (replaces the v1 boot-time scheme — boot-relative
`mxfs_pal_time_ms` is not cross-node comparable and a folded 16-bit stamp is
collision-prone):

```c
struct mxfs_net2_id {
    uint32_t cluster_uuid_hash;   /* FNV1a; full UUID exchanged in SYN */
    uint64_t membership_epoch;
    uint16_t slot;                /* heartbeat slot 0..63 (MXFS_DISKLOCK_HB_SLOTS) */
    uint32_t incarnation;         /* persistent per-slot monotonic counter */
};
/* per-boot 64-bit random session nonce exchanged in SYN, not per-frame */
```

- **incarnation** is a per-slot monotonic counter PERSISTED in the node's own
  disklock heartbeat record (single-writer sector — Invariant 3 already
  guarantees exclusive ownership): at mount/slot-claim, read own record,
  `incarnation = last + 1`, write back before joining. Survives reboot;
  strictly ordered per slot by construction. u32 on the wire.
- **nonce**: 64-bit `mxfs_pal_get_random_bytes` per boot, exchanged during
  session establishment. Sessions match on equality of
  {uuid, epoch-domain, slot, incarnation, nonce}; a mismatch is a DIFFERENT
  session, full stop.
- Ordering rule: "newer" is decided ONLY by the persisted incarnation
  counter. A frame from (slot S, inc I<current) is stale → dropped. A beacon
  claiming (S, I>current-known) marks the old incarnation DEAD-superseded —
  which still requires fencing before its resources are reclaimed (§7.D).
  Never infer newness from any timestamp.
- 64-bit node masks and slot 0..63 identity are preserved everywhere
  (Invariant 3).

---

## 6. Wire protocol

NET2 **wraps** the unchanged inner `mxfs_dlm_msg_hdr` + body as opaque
payload — the inner dispatch switch (`v5_peer_msg_cb_tcp` body,
v5_mount.c:291-339) is reused verbatim.

```c
#define MXFS_NET2_MAGIC        0x4E455432u  /* "NET2" */
#define MXFS_NET2_WIRE_VERSION 1
/* frame_class */ DATA=0 ACK=1 SYN=2 SYN_ACK=3 FIN=4
/* flags */ RELIABLE(1<<0) ACKREQ(1<<1) RELAYED(1<<2)

struct mxfs_net2_hdr {                /* 64 bytes, little-endian on the wire */
    uint32_t magic;   uint8_t version; uint8_t frame_class;
    uint8_t  priority; uint8_t flags;
    uint8_t  ttl;     uint8_t hopcount; uint16_t payload_len;
    uint32_t cluster_uuid_hash;
    uint64_t membership_epoch;
    uint16_t src_slot, dst_slot;
    uint32_t src_incarnation, dst_incarnation;
    uint64_t seq;     uint64_t ack;
    uint32_t sack_mask;               /* 32 slots past cumulative ack */
    uint32_t msg_id;                  /* NET2-allocated; see below */
    uint32_t pad;                     /* zero; reserved */
};
_Static_assert(sizeof(struct mxfs_net2_hdr) == 64, "net2 hdr");
```

- **Endianness**: all NET2 header/control fields are explicitly
  little-endian; encode/decode helpers in `net2_wire.h` (no native-struct
  serialization). Identical `_Static_assert`s compile in kernel AND
  user-mode. Golden encode/decode vectors + malformed-frame fuzz are part of
  the protocol test (§13.1).
- Framing per link: read 64 B, validate magic/version/payload_len, read
  `payload_len` bytes. `MXFS_NET2_MAX_FRAME = 64 + MXFS_NET2_MAX_MSG_SIZE
  (8192)`. No fragmentation; reject larger.
- **Operation identity (NOT the inner `seq`)**: the inner header's inert
  `seq` is untrustworthy (producers never maintained it) and is left alone.
  NET2 allocates `msg_id` from a per-session counter at the NET2 boundary,
  and every MUTATING lock op additionally carries, in its net2_msg envelope:
  {requester slot+incarnation, request_id u64, resource_id, membership_epoch,
  shard_term, expected grant_gen where applicable}. Midcomms dedup is a
  delivery optimization only; **effect idempotency lives in the lock
  handlers**, backed by the replicated completed-op cache (§7.B) so a
  duplicate ACQUIRE/RELEASE returns its original result even across leader
  failover.
- **SYN/SYN_ACK** carry a TLV block: full 16-byte cluster UUID, volume id,
  fs_gen, boot nonce, feature bits (§7.F), NET2 wire version. Mismatched
  UUID/volume/fs_gen → reject (guards stale test networks / cross-cluster
  traffic). Unauthenticated SYN state is rate-limited per source. Threat
  model: trusted storage LAN; control messages (FENCE_*/MEPOCH_*) are
  additionally bound to the committed voter identities + incarnations —
  a FENCE_DONE from a non-voter or stale incarnation is discarded loudly.
- **Version negotiation**: NET2 capability is negotiated in the NET2
  handshake itself + advertised in discovery beacons — the inner
  `MXFS_DLM_VERSION 1` is NOT bumped (legacy fallback must keep
  interoperating; a v1-only peer simply never speaks NET2). Transport choice
  is fixed at form/join: the forming cluster publishes transport+features;
  joiners conform or fail the join (Invariant 5).

---

## 7. Component designs

### 7.A Link + routing + midcomms (the core engine)

**Link (`net2_link.c`).** One TCP connection per neighbor (mesh: neighbor =
every member; overlay: computed set), forked from peer.c's lifecycle
(lower-slot-initiates, peer.c:661; accept/connect race handling). Per link:
1 recv thread + 1 egress worker draining the priority queues — this removes
`mxfs_peer_send`'s caller-serialization on `send_lock` (peer.c:884).
**Reconnect policy**: on send error/timeout the link may be torn down and
re-established freely — the retransmit ring owns delivery, the session
survives reconnects. Link state changes are routing events only (R1).

**Routing abstraction (`net2_overlay.c`).** `net2_route(dst) → link`
with two providers, selected by modparam `net2_topology`
{0=auto,1=mesh,2=overlay}, auto=mesh until the overlay gate (§13.1b) is
green at scale:
- MESH: link per member; route = direct link; no relays, no TTL.
- OVERLAY: deterministic neighbor set — key members by
  FNV1a(uuid_hash, memb_epoch, slot, incarnation), sort (`mxfs_pal_sort`),
  fingers at ring offsets ±(1,2,4,…2^k), always include successor +
  predecessor, dedup, clamp degree to [6,10]. Greedy closest-not-past
  routing ≤ ceil(log2 N) hops; `net2_route` also returns a node-disjoint
  alternate; retransmits alternate paths. Relays decrement TTL (init 6, drop
  at 0), set RELAYED, re-enqueue at frame priority, are accounted against
  the same egress scheduler, and NEVER generate ACKs.
  **Epoch bridging at relays**: frames from epoch E-1 are relayed/delivered
  for a bounded bridge window (until the local node has observed every
  session from E-1 either resumed in E or FIN/GC'd) — RELEASE/RELEASE_ACK
  initiated before a view transition must be able to complete; only frames
  older than E-1 or beyond the bridge window are dropped. Old-epoch frames
  can never MUTATE new-epoch lock state (handlers reject on epoch) — the
  bridge exists so gen-qualified releases can still be acknowledged.
- View updates (`mxfs_net2_update_view`) recompute neighbor sets; new links
  open eagerly, dropped ones close lazily after their retransmit entries
  drain or re-route.

**Priority classes — five, with reserved capacity (not strict-only):**

```c
enum net2_priority {
    NET2_PRI_FENCE   = 0,  /* fencing / MEPOCH control        */
    NET2_PRI_RELEASE = 1,  /* RELEASE / RELEASE_ACK / their retransmits */
    NET2_PRI_REVOKE  = 2,  /* BAST / revoke                    */
    NET2_PRI_GRANT   = 3,  /* GRANT / ACQUIRE / APPEND         */
    NET2_PRI_DISCOVERY=4,  /* discovery / stats                */
};
```

RELEASE outranks BAST deliberately: a BAST storm must not delay the
completed releases that make progress (review §3.5). Scheduler: weighted
deficit round-robin with guaranteed minimum quanta per class (defaults
FENCE 20%, RELEASE 30%, REVOKE 25%, GRANT 20%, DISCOVERY 5%; strict
preference inside a quantum). Retransmissions ride their class but a
per-class retransmit sub-quantum guarantees first transmissions are never
fully starved by retransmits and vice versa.

**Queue bounds + fail-closed policy.** Defaults {FENCE 64, RELEASE 256,
REVOKE 256, GRANT 1024, DISCOVERY 64} per link. GRANT/DISCOVERY overflow →
`-EAGAIN` backpressure to the caller (acquire latency rises; coherence
completion never does). FENCE/RELEASE/REVOKE overflow is NEVER a silent
drop and never merely "a hard error": the affected peer's session enters
COMM_AMBIGUOUS and the freeze module (§7.E) freezes the affected scope until
the queue drains or membership resolves the peer. Every overflow increments
a reason-coded counter (§13 evidence).

**Midcomms (`net2_midcomms.c`).** Session per
{uuid_hash, epoch-domain, src slot+inc, dst slot+inc} + nonce equality.
Per direction: `tx_next_seq`, `tx_unacked_base`, retransmit ring
(`NET2_TX_WIN=64` segs), flow window; RX: `rx_cum_ack`, 32-bit sack window,
msg_id dedup ring (1024). Fully specified behaviors:
- Receive window = 64 segs; frames beyond window dropped + counted (sender
  is flow-blocked, so this indicates a bug or attack).
- SACK covers 32 past cum_ack; gaps beyond 32 are recovered by cum-ack-driven
  retransmit (sender retransmits base first — go-back within the unsacked
  tail).
- ACK generation: piggybacked on any egress to the peer; standalone ACK after
  a 5 ms delayed-ack timer or 8 pending deliveries, whichever first. ACKs are
  unreliable frames; ACK loss is healed by retransmit + re-ACK-on-dup.
- Retransmit worker: single RT thread, 50 ms tick; RTO 200 ms initial,
  ×2 backoff capped at 2 s. **Max retry age**: after 10 s unacked, the
  session enters COMM_AMBIGUOUS → membership probe escalation + scope freeze
  (never silent abandonment; `MXFS_LOCK_ACQUIRE_WAIT_MS` remains the
  caller-visible backstop for acquires only).
- Sequence wrap: u64 — unreachable in practice; serial-number arithmetic used
  anyway; asserted in the protocol tests.
- Memory accounting: per-session ring + rx buffer caps (≤ 64+64 frames ×
  8256 B ≈ 1 MB), per-mount total cap = members × 2.5 MB; allocation failure
  = backpressure, never drop of queued coherence traffic.
- Restart handling: a new incarnation/nonce = a new session; old sessions
  are frozen, drained for release-bridging (§7.A epoch rule), then GC'd.
  Dedup state for a dead incarnation persists until its epoch exits the
  bridge window (defeats slot-reuse ABA together with §5).

Send API: `mxfs_net2_send(n, dst_id, pri, reliable, msg_id, buf, len)`;
receive delivers `(src_id, payload, len)` to the registered cb. Contract:
at-least-once + dedup hint; handlers are effect-idempotent (§6).

### 7.B Sharded replicated lock service — complete design

**Configuration authority: shard configs are DERIVED from the committed
membership epoch — shards do not manage their own membership.** For
committed epoch E with member_mask M(E): shard s (s = FNV1a(uuid ‖
resource_id) & 1023) has replica set R_E(s) = HRW top-3 over
{E, s, member (slot, incarnation)}; rank-0 is the initial leader. Because E
itself is quorum-committed with fencing (§7.C), **configurations are totally
ordered and exclusive**: every shard message carries (E, term); a replica
accepts APPEND/vote/ACK only for its current committed E. An old epoch's
group cannot form a competing quorum because its members either moved to
E+1 (and refuse E) or are fenced (and cannot be counted). This is the v2
answer to the two-quorums hole: epoch fencing replaces joint-quorum
reconfiguration.

**State model: epoch-fenced volatile state + snapshot/log, with a closed-set
recovery barrier.** Lock state is exclusion state, reconstructible from live
holders + fenced-and-replayed dead ones; it does not need disk durability
(matches GFS2/OCFS2 recovery philosophy). Consequences are handled
explicitly below (all-replica loss, whole-cluster restart).

```c
struct net2_shard {
    uint32_t shard_id;
    uint64_t memb_epoch;            /* committed E this config derives from */
    uint32_t term;                  /* in-epoch term, starts 1 */
    uint16_t leader_slot;  struct { uint16_t slot; uint32_t inc; } replicas[3];
    uint64_t commit_seq;            /* monotonic per (E,term) chain, carried over takeover */
    struct net2_log     *log;       /* bounded ring, window = NET2_TX_WIN */
    struct net2_lock_rec *table;    /* hash of live records */
    struct net2_opcache  *done;     /* replicated completed-op results (per client-inc ring, 64 entries) */
    enum { SH_ACTIVE, SH_ELECTING, SH_XFER, SH_FROZEN, SH_RECOVERY } state;
    uint64_t grant_gen_next;        /* shard-global; nonzero; see wrap rule */
    uint64_t dir_epoch_next;
};

struct net2_lock_rec {
    struct mxfs_resource_id resource;
    uint64_t holders_ex, holders_pw, holders_pr, holders_cw, holders_cr;
    uint64_t grant_gen;             /* current tenure token, never 0 */
    uint32_t dir_epoch; uint8_t last_ex_slot; uint8_t handoff;
    uint64_t pending_revoke_mask;
    uint64_t pr_delegation_expiry_ms;   /* wall-clock: mxfs_pal_time_real_ms */
    struct net2_waiter *waitq;      /* REPLICATED fifo: {slot,inc,request_id,mode,enq_seq} */
    uint8_t  ex_streak;             /* fairness: after 3 consecutive EX grants with
                                       PR waiters queued, grant the PR class (mirrors CAW) */
};
```

Holder semantics identical to CAW: EX/PW single-holder (popcount>1 =
corruption; shared detector), recompute EX>PW>PR>CW>CR.

**Log + commit.** Leader appends `{op, resource, mode, requester{slot,inc},
request_id, grant_gen, dir_epoch, (E,term), commit_seq}`; N2_APPEND to both
replicas; **commit at 2-of-3** (leader + ≥1 ack); only then emit
GRANT / RELEASE_ACK. The waiter queue and completed-op cache mutate ONLY via
logged entries — so fairness order and idempotent results survive failover.
Log entries retire once both replicas ack; a replica lagging past the ring
window receives a snapshot (state transfer) instead. Memory bound:
ring window + snapshot-in-flight per shard.

**Election (within epoch E).** On leader SUSPECT/DEAD (membership signal,
never a mere link drop): remaining replicas vote; candidate must present
max (term, commit_seq) among reachable group members (leader-completeness:
any winner intersects every 2-of-3 commit). Randomized timeouts biased by
HRW rank. Winner increments term, commits an N2L_TERM barrier entry to
quorum, THEN resumes grants. Old-term messages → N2_DENY(STALE_TERM).
**Voting eligibility**: a replica that restarted within E (fresh incarnation,
empty state) may not vote or ack commits until state transfer completes
(SH_XFER → CAUGHT_UP marker logged by the leader). If a shard cannot muster
2 eligible members → SH_FROZEN (freeze scope = that shard's resources) until
the next membership epoch re-derives the config or transfer completes.

**Reconfiguration (E → E+1).** Membership commits E+1 (fencing of removed
nodes already confirmed — §7.C). Per shard whose R changed:
1. Surviving old leader (or, if it died, the surviving old replica with max
   commit_seq — serving as SOURCE only, with no grant authority) freezes the
   shard at commit_seq C.
2. New R_{E+1} rank-0 pulls the snapshot at C (SH_XFER), commits an
   N2L_TERM(E+1, term=1, base=C) barrier to its new quorum, resumes.
3. **Recovery barrier (no old replica survived — total shard-state loss):**
   the shard enters SH_RECOVERY; the new leader broadcasts
   N2_RECOVERY_REPORT(shard) to ALL members of E+1; every member replies
   with its locally-held grants for that shard from its client-side held
   table — each report entry carries the client's stored grant_gen token, so
   reports are gen-stamped, and the claimant set is CLOSED (exactly E+1's
   members) while every non-member is already fenced + journal-replayed
   (their grants are void by §7.D ordering). The leader rebuilds holder
   masks/waiters-empty, sets `grant_gen_next = max(reported)+1024` and
   `dir_epoch_next = max(reported)+1` (slack absorbs unreported in-flight
   grants, which cannot exist for fenced nodes and are re-requested by live
   ones), logs the rebuilt state to quorum, then activates. Reconstruction
   from client reports is safe here precisely because the set is closed and
   fenced — the unfenced-unknown-claimant case cannot arise.
4. Shards whose R is unchanged keep serving through the transition
   (no wholesale purge — the central fix).

**Whole-cluster restart.** All volatile state gone → the newly formed
cluster commits a fresh epoch; at formation, existing mount-time journal
replay of all slices re-establishes disk truth; no prior grants can exist
(every prior holder either released, unmounted, or is fenced+replayed).
grant_gen restarts at 1 in the new epoch: safe because tokens are compared
only within an XFS instance's lifetime (in-core `>` comparisons never span a
remount) and on the wire every op is epoch-qualified, so cross-epoch tokens
are rejected before any gen compare.

**grant_gen rules (XFS contract).** Seam token is u64 via
`mxfs_v5_dlm_inode_grant_gen`. **Never 0** — several XFS sites treat
grant_gen==0 as the CAW-style discriminator (xfs_mxfs_dlm sites at 12279,
13889), so NET2 always allocates ≥1 and `mxfs_v5_dlm_transport_caw()` stays
false → XFS uses the monotone `>` compare paths (the != paths are CAW-only,
for restartable slot epochs). Wrap: u64 does not wrap in practice; the
allocator still asserts and would freeze the shard rather than reuse
(defense in depth). On takeover, `grant_gen_next/dir_epoch_next =
1 + max(committed)` — leader completeness guarantees the max is complete;
in SH_RECOVERY the slack rule above applies.

**PR fan-out + exact release order (Invariant 1).** EX-against-PR: commit
N2L_EX_PENDING → N2_BAST each PR holder (drives the UNCHANGED XFS entries —
both `mxfs_dlm_bast_notify` (inode) and `mxfs_dlm_ag_bast_notify` (AG),
registered at xfs_mxfs_dlm.c:31654/31657) → each holder runs the drain
pipeline and sends gen-qualified N2L_RELEASE → leader clears its bit on
COMMIT → holder set empty committed → grant EX:

```
BAST → stop new local users → mxfs_dlm_ag_drain_meta_buffers
     → mxfs_dlm_ag_drain_alloc_buflist → mxfs_dlm_ag_drain_inode_buffers
     → blkdev flush (ag_bast_work_fn Phase 2/2b)
     → send RELEASE(res, grant_gen) → wait RELEASE_ACK (quorum-committed)
```

NET2 never sends RELEASE on a holder's behalf and never infers RELEASE from
disconnect. Lost GRANT → retry reaffirms the SAME gen from committed state;
lost RELEASE → holder retransmits (liveness, not coherence); stale RELEASE →
gen-qualified drop → `-ESTALE` → holder re-arms BAST (matches XFS release
fencing: p_rel_gen capture at 12120, mid-drain abort 12383-12508,
unlock_gen + ESTALE re-arm 14025-14063).

**Renewable PR delegations.** Leader grants a delegation
{resource, slot+inc, expiry = now_real + 5 s, gen}; the client satisfies
repeated LOCAL PR without network ops until expiry/revoke. Delegations are
logged (replicated) like grants. Revocation = BAST + the client proves local
quiescence (its PR holders drained) before EX proceeds; expiry uses
`mxfs_pal_time_real_ms` (cross-node comparable) with a 1 s skew guard —
an expired-but-unrevoked delegation is still BAST'd before any EX (expiry
only bounds renewal, it never substitutes for revocation — no clock-based
revocation, ever).

**Hot-shard migration.** Same logged term transition as reconfiguration
step 1-2, triggered by leader load (ops/s per shard counter) — an
optimization; never a way to resolve an uncertain holder.

**Held cap.** Client-side held[] honors ctx->max_held (default 32768,
`MXFS_CAW_MAX_HELD`, dlm_caw.h:50). Pure NET2 consumes no disk slots.

### 7.C Membership plane + MEPOCH authority — complete design

**One authority.** The committed MEPOCH record is the single source of truth
for {membership_epoch, member_mask, fenced_mask, slot→incarnation bindings}.
Everything else is an observer or a consumer:

| Source | Role |
|---|---|
| lease multicast (lease.c, port per §14) | observer vote (fast, lossy) |
| NET2 unicast probe (new) | observer vote (asymmetric-partition fallback) |
| disklock slot heartbeat (disklock.c, 62 s default, runtime-settable) | observer vote + storage-reachability signal: a node still advancing its slot is alive on the LUN and NOT timeout-fenceable |
| committed MEPOCH record | **authority** |
| fence confirmation (§7.D) | precondition for any exclusion commit |
| foreign-slice replay election | consumer: replay owner = lowest live slot **of the committed member_mask** (mxfs_disklock_lowest_live_slot retained, evaluated over the committed view) |
| evict ring (disklock HB records) | unchanged non-authoritative invalidation hints; never releases locks, never membership |
| disklock self-fence (fs_gen / generation change) | unchanged, active beneath NET2 |
| MDS = disklock slot 0 | unchanged |
| ever_multi latch | unchanged |

**No CAW dependency.** MEPOCH uses only (a) direct-link NET2 messages at
FENCE priority and (b) plain single-sector writes to each node's OWN
disklock heartbeat record — single-writer by Invariant 3, atomic at 512 B on
all target hardware. Identical protocol on CAW-capable and CAW-unreliable
hardware; the fence LADDER (§7.D) is where hardware capability differs.

**Persistence layout.** Carved from the disklock HB record's remaining
reserved bytes (same pattern as the evict ring; exact offsets fixed at
implementation against `disklock.h`'s current reserved[] with the existing
`_Static_assert(≤512)` guarding):

```c
struct mxfs_mepoch_rec {              /* 44 bytes, LE, in own HB record */
    uint64_t epoch;
    uint64_t member_mask;
    uint64_t fenced_mask;
    uint32_t self_incarnation;        /* §5 persistence lives here too */
    uint16_t voter_slots[3];          /* voters that committed this epoch */
    uint16_t flags;                   /* MEPOCH_F_* incl. version */
    uint32_t crc32c;                  /* over the record */
};
```

Every node republishes the latest COMMITTED record in its own HB slot each
heartbeat. Properties: durable across whole-cluster restart (max valid
record over all slots at formation); disk-visible to partitioned nodes (an
excluded node READS survivors' records and self-fences on seeing itself in
fenced_mask — works with zero network connectivity); no new on-disk region.

**Voter set.** Deterministic from committed state: the 3 lowest slots of
epoch E's member_mask (5 when |members| ≥ 16; the count is itself recorded
in flags so both sides of a transition agree). Epoch E+1 requires a majority
of **E's** voters — that is the reconfiguration rule (single-decree
handoff); E+1's voters then derive from E+1's mask for the next transition.

**Commit protocol (single-decree, per epoch increment).**
1. PROPOSE: the lowest-slot live voter of E (deterministic; the next-lowest
   takes over if the lowest is itself SUSPECT for 2× probe interval)
   broadcasts MEPOCH_PROPOSE{E+1, member_mask', fenced_mask',
   slot→inc table, reason} to E's voters.
2. Preconditions checked by every voter: monotonic (E+1 = E_local + 1),
   fenced_mask' ⊇ fenced_mask, and **for every slot removed from
   member_mask': a fence_done record (incarnation-qualified, §7.D) is
   attached**. Exclusions without attached fence proof are NACK'd —
   quorum without fencing cannot commit an exclusion. Additions (joins) need
   no fence.
3. ACK by majority of E's voters (over direct links, FENCE priority; voters
   persist the candidate to their HB record as PREPARED before ACKing —
   two-phase within the record's flags — so a proposer crash cannot yield
   two different committed E+1 values: a later proposer must adopt any
   PREPARED candidate it finds on disk or among voters).
4. COMMIT: proposer publishes MEPOCH_COMMIT; every member persists the
   record to its own HB slot and multicast-echoes it (lease beacon carries
   the committed epoch number as a hint).
5. Consumers gate on it: shard configs re-derive (§7.B), freeze module
   updates require_epoch, replay election uses the committed mask.

Failure cases: proposer dies mid-round → next deterministic proposer adopts
the PREPARED candidate (read from voters/disk) and completes it. Voter
minority unreachable → no new epoch commits; SUSPECT nodes stay frozen
(never reclaimed) until quorum returns — coherence over availability, with
the freeze visible and budgeted (§7.E). A node that cannot see a voter
majority AND cannot advance its epoch view within
`mepoch_lease_ms` (default 10 s): freeze-FS locally; if it subsequently
reads a committed record excluding itself → immediate self-fence
(scsipr key removal per §7.D + existing fence_notify path).

**Bootstrap (no circularity).** Mount → claim disklock slot + bump persisted
incarnation (§5) → read all HB records → adopt max valid committed MEPOCH.
None found (fresh cluster): the forming node commits epoch 1 with itself as
sole member (a 1-member cluster is its own quorum), then joins are epoch
increments. Membership messages ride DIRECT links (mesh provider) always —
the membership plane never depends on overlay routing, killing the
routing↔membership circular dependency. Discovery (`discovery.c` peer_cb,
invocation at :205) seeds candidate {host, slot, incarnation} for probes and
link establishment; it is a hint, never authority.

**SUSPECT machinery.** ≥2 observers missing (of mcast/probe/disk) →
SUSPECT: freeze conflicting grants for locks the node may hold
(FREEZE_RESOURCE via the shard leaders' frozen_node_mask), probe hard,
consult the disk observer (slot still advancing = alive-on-LUN: do NOT
proceed toward exclusion on network evidence alone; keep frozen). Reconnect
with the SAME incarnation+nonce within grace → ACTIVE, freeze lifted, flap
absorbed. Grace elapsed → FENCING (§7.D). Only fence_done permits the
exclusion commit that makes it DEAD. NET2 has NO timeout-alone death: the
legacy `v5_tcp_death_worker_fn` grace-timeout declare (v5_mount.c:590-622)
is not reused; its NET2 analog raises a fence request and declares only from
the fence_done callback.

**NET2-owned freeze/settle state.** All stamps/masks live in
`mxfs_net2_ctx` — NOT the legacy TCP engine's `last_memb_change_ms` /
`mxfs_memb_settle_ms` plumbing (that is dlm.c/TCP-local and stays untouched
for the legacy transport).

### 7.D Fencing + SUSPECT/DEAD + recovery + partitions

State machine as in v1 with the corrections:

```
ACTIVE → SUSPECT (≥2 observer votes; disk observer consulted)
  SUSPECT → ACTIVE  (same incarnation+nonce reconnect within grace)
  SUSPECT → FENCING (grace elapsed) — raise mxfs_net2_fence_request
  FENCING → DEAD    (fence_done{confirmed} ONLY; no mechanism → FREEZE_FS,
                     remain FENCING; timeout is not a fence)
  DEAD → RECOVERING → reclaimable   (ordering below)
```

**Fence records are incarnation-qualified end-to-end**: request carries
{victim slot, victim incarnation, epoch, method, seq, deadline}; a late
fence_done for an old incarnation is discarded (must not fence or kill a
replacement incarnation).

**Method ladder (`net2_fence_execute`, first success wins):**
1. **SCSI-PR preempt-and-abort** — primary. Keys are per-node
   (`(uint64_t)node_id`, scsipr.c:31). Requirements made explicit: the
   reservation type + PREEMPT AND ABORT service action must revoke the
   victim's access and abort its in-flight commands; confirmation =
   `mxfs_scsipr_read_keys` shows the victim key gone **on every active path
   of the multipath device** (per-path confirmation; one revoked path is not
   a fence). Key-reuse rule: a restarted victim re-registers under a new
   incarnation only after reading MEPOCH and finding itself not-excluded.
2. **CAW epoch fence** — only where CAW is trusted hardware AND the victim's
   access is provably CAW-gated; NOT valid for pure NET2 (a partitioned
   kernel can keep writing without issuing another CAW — a slot-generation
   change alone is not a storage fence). Listed for CAW-transport clusters.
3. **Watchdog lease** — new PAL hook (§10); expiry removes LUN access.
4. **External agent** — new PAL hook (power/fabric).
None available → do not declare DEAD; FREEZE_FS with reason NOFENCE
(bounded, visible — §7.E). Self-fence note: `mxfs_scsipr_unregister` is a
valid self-fence only under reservation modes where unregistration removes
write access — assert the mode at mount; otherwise self-fence = deliberate
key preempt-self + I/O quiesce.

**Recovery ordering (the missing gen-advance step is explicit — the existing
`v5_lease_expire_cb` (v5_mount.c:766) purges + elects replay but advances no
generation; NET2 adds steps 5-6):**

```
1. freeze affected scopes (already held from SUSPECT)
2. fence confirmed (incarnation-qualified)
3. MEPOCH commit: epoch E+1 with victim excluded, fenced_mask |= victim
4. dead-node purge + foreign-slice journal replay (replay owner = lowest
   live slot of E+1's committed mask; existing replay machinery)
5. lock-state repair: shard reconfiguration / recovery barrier (§7.B) —
   victim's holder bits cleared ONLY here, after 2-4
6. generation advance: every resource the victim held gets
   grant_gen_next bump past its tenure (shard-global allocator guarantees
   monotone; for CAW transport the existing slot-generation semantics apply;
   envelope slots per §7.F)
7. publish recovery completion (logged barrier per shard)
8. unfreeze scopes whose require_epoch ≤ E+1 and whose victims ⊆ fenced_mask
```

No grant may be issued for an affected resource between steps 4 and 6.

**Partitions.** An exclusion epoch commits only with voter majority AND
attached fence proof (§7.C step 2) — quorum without fencing is structurally
unable to commit. Minority: epoch-lease stall → freeze-FS; sees itself
fenced via disk → self-fence. Both sides' behavior is bounded and visible
(§7.E), never "pick a side locally."

### 7.E Freeze-on-ambiguity — budgeted and observable

```c
struct mxfs_net2_freeze {
    enum { FZ_NONE, FZ_RESOURCE, FZ_SHARD, FZ_FS } scope;
    enum { FZR_SUSPECT, FZR_ELECTION, FZR_XFER, FZR_QUORUM_LOSS,
           FZR_NOFENCE, FZR_COMM_AMBIGUOUS, FZR_RECOVERY } reason;
    uint64_t frozen_node_mask;  uint32_t frozen_shard;
    uint64_t require_epoch;     uint64_t since_ms, deadline_ms;
};
```

- Blocks: new grants that CONFLICT with the frozen scope. Compatible reads
  and non-conflicting grants proceed. FZ_FS blocks all new grants.
- **Every freeze carries a reason code, start stamp, and deadline; counters
  and a live status surface (per-mount stats + `chk_mxfs` query) expose
  {scope, reason, age} — "frozen" must be a testable, visible state, not a
  silent hang.** Deadlines by reason (defaults): SUSPECT grace 8 s, ELECTION
  2 s, XFER 5 s, RECOVERY 30 s, NOFENCE/QUORUM_LOSS unbounded-but-visible
  (test posture: the suite asserts the frozen status is reported within its
  budget; it does NOT wait for unfreeze on no-fence hardware).
- Unfreeze requires BOTH `memb_epoch >= require_epoch` AND
  `frozen_node_mask ⊆ committed fenced_mask ∪ reconnected` — never a timer.
  Timer expiry ESCALATES (widens scope / raises admin status), it never
  authorizes reclaim.
- Routine join (no conflicting holder) freezes nothing beyond the shard
  config re-derive (measured; the 20 s legacy settle behavior is NOT
  inherited — NET2's equivalents are the scoped freezes above).
- Single source of truth: shard leaders and (for hybrid modes) the CAW grant
  path consult the SAME freeze table via an explicit hook — the legacy
  TCP `memb_settle` gate (dlm.c:1128) remains legacy-only.

### 7.F CAW / NET2 hybrid

**Feature bits** (negotiated at form/join, echoed in beacons + MEPOCH flags;
fail-closed for older impls on envelope volumes):
`MXFS_NET2_FEAT_MEMBFENCE`, `MXFS_NET2_FEAT_BAST_WAKE`,
`MXFS_NET2_FEAT_ENVELOPE`.

**BAST wakeups (BAST_WAKE) — a capability on the CAW transport, not a 4th
XFS-visible transport.** Transport stays `MXFS_V5_TRANSPORT_CAW`;
`mxfs_v5_dlm_transport_caw()` continues returning true (CAW's `!=` epoch
semantics remain correct — xfs sites 16685/16716/18446/22085). NET2 only
accelerates:
- Replace the mcast BAST hint send (`caw_send_bast_mcast`, dlm_caw.c:1509,
  fire-and-forget UDP to port 7602) with reliable
  `net2_send(owner, NET2_PRI_REVOKE, …)`, coalescing per owner while
  preserving every distinct resource/AG identity in the coalesced payload.
- Waiter blocks on condvar wakeup instead of the 100 ms resend loop
  (dlm_caw.c:1748, `MXFS_CAW_BAST_RESEND_MS`).
- Disk poll (`bast_poll_fn` dlm_caw.c:4455) relaxes to
  `MXFS_CAW_BAST_POLL_RELAX_MS` when net2 is up (extending the existing
  adaptive logic at 4628-4632); **bounded polling always continues** —
  a lost/unavailable network wakeup only costs latency, never correctness;
  `bast_recv_fn` (4641) retained as fallback. NET2 membership down ⇒
  behavior degrades exactly to today's CAW.
- Accounts for current CAW machinery where waiters/owners observe state:
  grant_meta cache, grant_seq32 tokens, `mxfs_dlm_caw_granted_mode`,
  orphan-clock table — none are bypassed.

**Envelope delegation (ENVELOPE) — implemented in this pass, ships
default-OFF, enabled only after §13.4 passes.** The shard leader holds the
disk slot as delegation authority; client↔client transitions ride NET2. The
replicated envelope state mirrors the FULL current slot semantics (the v1
struct predated several fields):

```c
struct mxfs_net2_envelope {
    struct mxfs_resource_id resource;  uint32_t slot_index;
    uint32_t disk_generation;          uint32_t delegation_gen;
    uint8_t  envelope_owner_slot;      uint64_t memb_epoch;
    uint64_t net_holders_ex, net_holders_pw, net_holders_pr,
             net_holders_cw, net_holders_cr, pending_revoke_mask;
    uint32_t dir_epoch;  uint8_t last_ex_slot;  uint8_t handoff;
    uint64_t yield_to;   uint64_t yield_set_ms;     /* real-time clock */
    uint8_t  ex_grant_streak;  uint64_t waiters_ex_mask;
    uint64_t dir_block0_fsb;  uint32_t dir_block0_gen;
    struct net2_waiter *waitq;
};
```

Fairness (yield ticket, streak-yield) is enforced by the leader from
replicated state — envelope mode must not regress `caw_fair_handoff`
behavior. Release order (Invariant 1), matching the CURRENT unlock
semantics:

```
net2_envelope_release(env):
  1. revoke every net holder (BAST); pending_revoke_mask = holders
  2. wait pending_revoke_mask == 0        (each RELEASE gen-qualified + committed)
  3. commit empty holder set to shard quorum
  4. mxfs_dlm_caw_unlock_gen(ctx, res, expected_gen32, is_free)  — LAST;
     dir_epoch/last_ex_slot and (on is_free) their reset ride in the SAME
     tombstone CAS image; NO separate post-hoc CAS (the separate-CAS shape
     is a proven perf regression — the shared iSCSI command-rate ceiling)
```

Leader failure: fence old leader (confirmed, incarnation-qualified) → new
leader = shard replica → CAW the slot to a new generation
(delegation_gen++) → replay replicated holder/revoke/fairness state →
reissue revokes / recovery barrier → only then incompatible grants. Total
replica-state loss → the closed-set recovery barrier (§7.B step 3) over the
member mask, or fence-all — the stale disk envelope alone does not identify
sub-holders. Recovery tooling asserts dir_epoch/last_ex_slot were
checkpointed before any release; a live delegation_gen with stale dir_epoch
triggers the barrier, never a silent grant.

---

## 8. Integration seam (verified anchors, 0.10.120)

**Transport registration.** `MXFS_V5_TRANSPORT_NET2 3` (v5_mount.h:29-31
currently CAW=0/TCP=1/AUTO=2) + `struct mxfs_net2_ctx *dlm_net2` in
`struct mxfs_v5_dlm` (v5_mount.c:121). **Reality check folded in: v5_mount
does NOT probe/fallback — transport = `opts->transport` + the
`mxfs_force_transport` override (v5_mount.c:34/830) + validation
(862-867); AUTO is resolved by the caller/mount layer, which gains the NET2
value and its own negotiation there.** Mount-time immutability preserved.

Seam entries gaining a leading `if (ctx->dlm_net2)` arm — all eight verified
present with the two-branch shape, and ALL of them now serve real values on
the CAW branch too (the NET2 arm must match that bar):
`mxfs_v5_dlm_inode_lock` (1360), `_inode_unlock_gen` (1534; honors
expected_gen), `_inode_unlock_free` (1498; is_free semantics),
`_ag_lock` (1940), `_ag_lock_nb` (1993), `_ag_unlock` (2119),
`_inode_grant_gen` (1632; NET2 returns its nonzero u64→u32 token),
`_grant_handoff` (1723), `_dir_epoch` (1748), plus `_granted_mode` (1704)
and the orphan-clock accessors (1655/1666, CAW-only — NET2 returns 0).
NET2 drives BOTH notify families: `mxfs_v5_dlm_set_bast_notify` →
`mxfs_dlm_bast_notify` and `set_ag_bast_notify` → `mxfs_dlm_ag_bast_notify`.
`mxfs_v5_dlm_transport_caw()` (1791) stays `!ctx->dlm && ctx->dlm_caw` —
false for NET2 → XFS takes monotone `>` paths; NET2's never-zero gens keep
the gen==0 discriminator sites on the network path too.

**Callback wiring** (TCP block at v5_mount.c:884-924 as template):
`mxfs_net2_create(&cfg{node_id, uuid, uuid_hash, ports, volume_id, fs_gen,
self_slot, self_incarnation})`; `mxfs_net2_register_recv_cb(n,
v5_net2_recv_cb, ctx)` — the recv cb reuses the existing
`switch(hdr->type)` dispatch body (v5_mount.c:291-339) unchanged;
`mxfs_net2_start`; `v5_refresh_active_nodes` (353) additionally calls
`mxfs_net2_update_view`. Send cb mirrors `v5_dlm_send_cb_tcp` (261) via
`mxfs_net2_send(..., net2_pri_for_type(h->type), RELIABLE, msg_id, ...)`.
BAST cb: replace `mxfs_peer_send` (439) with net2_send(REVOKE, RELIABLE);
keep the local-owner short-circuit (414-421); DELETE the ad-hoc 3-retry/50 ms
loop (408-451) — reliability is the session layer's job. The legacy
deferred-death worker (590-622) is not wired for NET2 (§7.D replaces it).

---

## 9. Preserved invariants & fencing tokens

- **grant_gen**: per-grant monotone, NEVER 0 (§7.B rules; XFS discriminator
  sites documented). Reconstructed to committed high-water on takeover;
  slack rule in recovery barrier.
- **dir_epoch + handoff**: monotone under NET2 (transport_caw()==false ⇒
  XFS `>` compare paths; the `!=` paths remain CAW-only).
- **i_mxfs_ex_grant_seq** (xfs_inode.h:171, stamped at 22007): XFS-local;
  NET2 just delivers EX grants that trigger it.
- **Release fencing**: p_rel_gen capture (12120) / mid-drain abort
  (12383-12508) / `unlock_gen(p_rel_gen)` + `-ESTALE` re-arm (14025-14063)
  work unchanged against NET2's gen-qualified handlers.
- Invariant #1: quorum-committed RELEASE_ACK gates every incompatible grant;
  envelope release order §7.F; recovery ordering §7.D (fence → replay →
  gen-advance → grant). #2: no new disk slots; MEPOCH lives in existing
  reserved HB bytes with the existing 512 B static asserts. #3: slot
  identity + 64-bit masks kept; incarnation (persisted) + nonce added
  alongside. #4: everything through `mxfs_pal_*`; user-mode build mandatory;
  no kernel pointers as protocol identities. #5: transport + features fixed
  at mount; joiners conform.

---

## 10. PAL

Existing surface covers the core — including the post-plan additions the
core now uses: `mxfs_pal_spinlock_*` (pal.h:280-309) and
`mxfs_pal_time_real_ms` (pal.h:520; used ONLY where cross-node wall-clock
comparison is required: delegation expiry, yield_set_ms; all local deadlines
use monotonic `mxfs_pal_time_ms` and are never compared across nodes).

New hooks (all `-EOPNOTSUPP` graceful, Invariant 4), with full lifecycle
semantics specified at implementation: cancellation, incarnation binding,
callback lifetime across unmount/rmmod, kernel+user implementations:
1. `mxfs_pal_watchdog_arm(dev, lease_ms)` / `mxfs_pal_watchdog_pet(dev)` /
   `mxfs_pal_watchdog_cancel(dev)`.
2. `mxfs_pal_fence_agent(node_id, incarnation, action, done_cb, cb_data)`.

Dual-build/wire rules (binding for every net2 file): explicit LE
conversion, no native-struct serialization, identical static asserts both
builds, bounded allocations, no sleeping under spinlocks, deterministic
thread shutdown (create/stop pairs symmetrical to peer.c's), documented lock
order (link → session → shard → freeze; membership taken last), PAL
cond/timer behavior covered by user-mode tests, fault-injection hooks
compiled into BOTH builds.

---

## 11. Build & wiring order — one effort, gated checkpoints

Dependency order within the single implementation push. Each checkpoint is
run before moving on (RULE 0 budgets written per test; a timeout is a FAIL);
nothing below is optional or deferred to a future effort.

1. `net2_wire.h` + `mxfs_ports.h` + identity (§5/§6) + counters/tracepoints
   + fault-injection controls. **Gate**: kernel + user builds green; golden
   encode/decode vectors; malformed-frame fuzz; static asserts both builds.
2. `net2_link.c` → mesh provider → `net2_midcomms.c`. **Gate**: user-mode
   protocol harness passes the §13.1 midcomms matrix (loss/dup/reorder/
   delay/reconnect/restart/wrap); 2-node kernel smoke.
3. Shared-code lifts (compat matrix, resource hash).
4. `net2_shard.c` / `net2_lock.c` / `net2_msg.h` (full §7.B incl. waiters,
   opcache, recovery barrier). **Gate**: §13.2 shard matrix in the user-mode
   harness (12 kill-points × partition patterns).
5. `net2_membership.c` + `net2_epoch.c` (MEPOCH + persistence + observers
   wired from lease/discovery/disklock as votes). **Gate**: bootstrap,
   join/leave, proposer-crash, PREPARED-adoption, whole-cluster restart.
6. `net2_freeze.c` + `net2_fence.c` (ladder, incarnation-qualified;
   recovery ordering with gen-advance). **Gate**: §13.3 fencing matrix on
   VMs (kill-mid-drain at every phase boundary, partition-with-LUN-access,
   no-fence posture visible-frozen within budget).
7. Seam wiring (§8) + transport enum + mount negotiation. **Gate**: full
   suite 1/2/4/8/16/32 on NET2 transport — the tcp-era leak workloads
   (`tcp_dlm_scaling`, `dir_reuse`, `dlm_fairness`, stress) repeatedly clean
   WITH injected loss/dup/reorder; zero overlapping grants; RULE-0 budgets
   (2× native XFS ceiling) met.
8. Overlay provider in `net2_overlay.c` (+ epoch bridging). **Gate**: same
   correctness matrix with `net2_topology=overlay`; two independent link
   failures lose no transition; relay saturation never delays RELEASE/FENCE
   past budget; measured thread/CPU delta recorded. Default stays mesh until
   this gate is green at the largest testable N.
9. `net2_bast.c` BAST_WAKE on CAW. **Gate**: CAW suite stays 100% green
   1-32; drop-all-wakeups ⇒ correctness unchanged (latency only);
   disconnect-NET2-mid-wait ⇒ bounded poll progresses; command-rate/wall
   delta vs plain CAW recorded.
10. PR delegations + hot-shard migration. **Gate**: delegation revoke/expiry/
    restart races in the user harness; fairness preserved across failover;
    no dlm_fairness/dlm_scaling regression.
11. `net2_caw_envelope.c` (feature-gated, DEFAULT OFF). **Gate to flip the
    default**: §13.4 envelope matrix incl. leader-failure at every release
    step, replica loss, fairness parity with plain CAW, and no
    posix_multi/dlm_scaling regression.
12. Makefile/Kbuild additions — **explicit user go-ahead required** (project
    rule) — plus docs/.md per module.

---

## 12. Risk register

| # | Risk | Sev | Mitigation |
|---|---|---|---|
| R1 | Disconnect/SUSPECT misread as RELEASE (Inv 1) | HIGH | Links have no disconnect→lock-layer path; only MEPOCH commits exclusion, only with fence proof; freeze meanwhile. |
| R2 | Envelope CAW-unlock before revokes complete (Inv 1) | HIGH | Single release chokepoint; assert pending_revoke_mask==0; is_free reset rides the same CAS; default-off until §13.4. |
| R3 | gen/dir_epoch regress on takeover | HIGH | Leader-completeness election; committed high-water; recovery-barrier slack; nonzero-gen invariant asserted at the seam. |
| R4 | Quorum-without-fencing exclusion | HIGH | Fence proof is a commit PRECONDITION (§7.C step 2), not a parallel step; minority self-freezes/self-fences via disk-visible fenced_mask. |
| R5 | Double-EX | HIGH | Shared compat matrix; EX/PW single-holder enforced at shard commit; §13 overlap assertion on every run. |
| R6 | Two shard quorums across reconfiguration | HIGH | Configs derived from committed epochs; epoch-stamped ops; transfer-before-vote; closed-set recovery barrier. |
| R7 | Priority inversion inside coherence traffic | MED | RELEASE class above BAST; reserved quanta per class; retransmit sub-quantum; control-queue overflow ⇒ scoped freeze, never drop. |
| R8 | Effect-idempotency gap | MED | Request-id op identity + REPLICATED completed-op cache; dup ACQUIRE/RELEASE return original results across failover. |
| R9 | Reserved-byte exhaustion (Inv 2) | MED | MEPOCH rec 44 B in HB reserved[]; existing 512 B static asserts keep the compiler as the guard. |
| R10 | Slot reuse ABA | MED | Persisted per-slot incarnation + boot nonce; sessions equality-matched; old-inc frames dropped; fence before old-inc resource reclaim. |
| R11 | Mixed-version reinterpretation (Inv 5) | MED | Handshake TLV + feature bits + fail-closed on envelope volumes; inner MXFS_DLM_VERSION untouched for legacy interop. |
| R12 | Freeze becomes silent outage | MED | Reason-coded, budgeted, surfaced freezes; tests assert visible-frozen within budget; timer expiry escalates, never reclaims. |
| R13 | No-fence hardware availability loss | MED (by design) | Mount-time capability warning; NOFENCE posture = visible frozen state. |
| R14 | Volatile shard state + simultaneous restart | MED | Whole-cluster restart = fresh epoch + formation journal replay (no surviving grants); partial loss = closed-set recovery barrier. |
| R15 | Spoofed/stray control traffic | MED | Full-UUID+fs_gen session binding; voter/incarnation-bound FENCE/MEPOCH; SYN rate-limit. |
| R16 | Thread growth | LOW | Mesh: comparable to today; overlay: ~17 threads; either way bounded and measured at gate 7/8. |

---

## 13. Verification (required matrices — full detail in DLM_PLAN_REVIEW.md §5)

RULE 0 everywhere: written budget = infra + native-XFS×2; a timeout IS a
failure — including "safe" freezes: the frozen state must be REPORTED within
budget. RULE 4 for every failure. Instrumentation is part of the deliverable:
per-session/per-class counters (created/first-tx/retx/acked/dup-suppressed/
dup-op-idempotent/out-of-window/stale-inc-epoch-term drops/queue-full/max
residency/resets), freeze counters {reason, scope, age}, fence/replay/
recovery timings, and the standing invariants asserted per run:

```
delivered_effects <= unique_operation_ids
committed RELEASE removals <= completed drain traces
incompatible grants never overlap
every retired retransmit entry has ACK or explicit session-abort disposition
no FENCE/RELEASE/RELEASE_ACK/BAST silently discarded (overflow ⇒ freeze)
```

1. **Midcomms matrix** (user-mode harness + 2-node kernel): loss/dup/
   reorder/delay per message class incl. ACK loss; TCP resets at every
   framing point; backpressure per class; sender/receiver restart with slot
   reuse; epoch change mid-op; window/SACK/wrap boundaries; malformed/
   cross-cluster frames. 1b. **Overlay adjunct**: relay failure, TTL
   exhaustion, dual-path duplication, epoch bridging, no-disjoint-path.
2. **Shard matrix**: leader kill/partition at all 12 commit points;
   partition patterns incl. old-vs-new group and all-replica reboot;
   evidence: single grant-capable leader per committed (E,term), commit_seq
   and gen high-waters never regress, transferring replicas never vote,
   waiter order preserved, total loss ⇒ recovery barrier (never
   empty-table).
3. **Fencing matrix** (VMs): kill-mid-drain at every drain-phase boundary;
   partition-with-LUN-access variants (mcast-only, probe-only, asymmetric,
   one multipath path revoked, delayed PR completion, late old-incarnation
   fence_done); no-fence postures; existing-infra injections (fs_gen
   re-mkfs, evict-ring wrap, MDS slot-0 loss, ever_multi, conflicting
   replay observations). Trace order asserted:
   `fence < exclusion-commit < replay < gen-advance < unfreeze/grant`.
4. **Envelope matrix** (before flipping the default): leader failure at
   every release step, replica loss, fairness parity (yield/streak) vs
   plain CAW, dir_block0/dir_epoch checkpoint asserts, no
   posix_multi/dlm_scaling regression, canary = posix_multi rename+hardlink.
5. **Performance**: `bench/rsync_bench.sh` paired vs native XFS (2× hard
   ceiling); fio_perf variance rules per tests memory; record freeze/fence/
   replay time per run; budgets tightened into
   `tests/criteria/TIMEOUT_BUDGETS.md` after healthy passes. Never widen a
   timeout to pass; never fix a freeze failure by lengthening settle values.

---

## 14. Decisions (v2, resolved 2026-07-17)

- **Full-system single effort** with gated checkpoints (§11) — supersedes
  both v1's "one pass, no gates" and the review's staged-releases framing.
- **NR_SHARDS = 1024; node cap 64; replicas = 3 (2-of-3)** — unchanged.
- **Voters = 3** (5 at ≥16 members, recorded in MEPOCH flags); escalation
  signal: `mepoch_quorum_stall` counter.
- **Topology**: both providers implemented; `net2_topology` modparam
  {auto,mesh,overlay}; auto=mesh until gate 8 is green at the largest
  testable N.
- **Incarnation**: persisted per-slot u32 in own HB record + 64-bit boot
  nonce (§5). Boot-time-derived incarnations rejected.
- **grant_gen**: u64 internal, nonzero always; XFS seam width verified at
  wiring (u32 token via grant_seq32-style accessor is acceptable — reserve
  0, assert monotone per tenure chain).
- **Port registry** `include/mxfs/mxfs_ports.h` — names reflect REALITY
  (the v1 claim that 7602-lease was dead is wrong; it is the live legacy
  fallback in lease.c:323, while both v5 paths pass literal 7603 —
  v5_mount.c:1022/1187 — and 7602 is also CAW BAST):

  ```c
  #define MXFS_PORT_DLM             7600
  #define MXFS_PORT_DISCOVERY       7601
  #define MXFS_PORT_CAW_BAST        7602
  #define MXFS_PORT_LEASE_LEGACY    7602  /* legacy mount path fallback; coexists
                                             with CAW_BAST only because legacy
                                             mounts don't run CAW BAST */
  #define MXFS_PORT_LEASE_V5        7603  /* current v5 literal, made canonical */
  /* 7604 spare */
  #define MXFS_PORT_NET2_MEMBERSHIP 7605
  ```

  Migration: every call site (mount.c:34-35, v5_mount.c:881/882/1022/1171/
  1173/1187, lease.h:61, discovery.h:25, dlm_caw.h:105) reads mxfs_ports.h;
  legacy behavior is NOT silently changed — `MXFS_LEASE_PORT` becomes an
  alias of `MXFS_PORT_LEASE_LEGACY` with a deprecation comment; unifying
  legacy onto 7603 is a separately-versioned change, not part of this plan.
- **Makefile/Kbuild edits still require explicit user go-ahead** at step 12.
- Multicast group stays `239.66.83.1` (existing); NET2 membership uses it on
  port 7605 with its own socket.

---

# ICLUSTER PLAN — inode-cluster DLM granularity (ccloop 72513a13 sess3, GPT-endorsed)

## Why (evidence, sess3)
Kprobe op-ledger on dir_reuse@8: every phase is bounded by per-file DLM device
ops (claim CAW + release CAW + FUA reads ≈ 3-13 cmds per file-touch; ~60k SCSI
cmds/round on ONE LUN).  Budget at 32 nodes (24 rounds ≤120s ⇒ 5s/round) allows
~16k cmds/round ⇒ ≤1.5 cmds/file-touch.  Five shave-fixes (0.11.12-15) landed
and proven individually; round time FLAT.  GPT consult (full verdict in the
sess3 transcript, task k1ud3n6hg): per-inode disk-DLM cannot meet the budget;
ship inode-CLUSTER granularity as the core; allocation steering + grant
retention + batched drains are part of it, not tuning.  Dir-covered lockless
reads (writer-registration bitmap protocol) come only after, restricted to
nlink==1 covered files.

## Design (Phase 1 — minimal-risk cut)
- New resource type `MXFS_LTYPE_ICLUSTER` in include/mxfs/mxfs_dlm.h.  Regular
  files map to resource ino = cluster base = ino & ~(inodes_per_cluster-1)
  (mp->m_inodes_per_cluster, power of 2; pass the shift to the mapping layer).
  DIRECTORIES KEEP per-inode LTYPE_INODE resources (phase 1 unchanged).
- New xfs-side mediating layer (mxfs_iclus in xfs_mxfs_dlm.c or new file):
  per-mount hash cluster_base -> { disk_mode, per-inode ref bitmaps (ex/pr),
  spinlock }.  All S_ISREG inode DLM acquire/release/held route through it when
  `mxfs.icluster_dlm=1` (module param, default 0 = per-inode, full rollback).
  - acquire(ip, mode): local object says disk grant sufficient? -> grant
    locally, set ip's bit, NO disk op.  Else one v5 acquire of the ICLUSTER
    resource (upgrade if PR->EX), then grant.
  - release(ip): clear ip's bit; disk release ONLY at last-ref (invariant #1
    holds: each inode drains before ITS release call, so by last-ref all
    covered inodes are drained; batched drains are Phase 2).
  - unlock_free (ifree): last-ref release passes is_free only if whole-cluster
    refs are zero (tombstone hygiene approximation).
  - held/held_rawmode for REG files answer from the ICLUSTER slot.
- BAST fan-out: v5 bast_cb receives resource; type==ICLUSTER -> xfs handler
  iterates ino in [base, base+ipc): xfs_iget-cached lookup, run the EXISTING
  per-inode bast machinery (bast_pending/dwork/drain) on each cached sibling;
  the mediating layer's last-ref release performs the on-disk demote.  A
  sibling-less BAST (nothing cached) releases directly (existing no-inode path).
- Data-path caution (GPT): the cluster lock covers DINODE/metadata coherence.
  Per-inode DATA coherency machinery (FUA-fresh gating etc.) keys off the same
  grant today; with cluster granularity a sibling's activity must not
  invalidate an unrelated file's data cache — the fan-out marks stale ONLY at
  actual release, which invalidates all covered inodes (conservative, correct).
- Creates stay lazy/unpublished (already ~0 disk claims); verify collapses to
  ~ceil(files/ipc) PR claims per node; rm to ~ceil(files/ipc) EX lifecycles;
  the 800×7 PR-revoke storm becomes 25×7.

## Phase 2 (after Phase 1 proves out on dir_reuse@8 + coherency tests at 8)
- Batched drains: one log-force + AIL wait + device flush per RELEASE BATCH of
  cluster resources (dwork coalescing), then per-resource CAWs.
- xfs_inactive reuses the held cluster grant (nlink==0 demote suppression
  already landed in 0.11.15 for the per-inode path; port to iclus).
- Dir-EX tenure cohorting: deliberate 16-32 ops / 10-20ms tenure bound instead
  of accidental ~14-op tenures.
- Soft per-node allocation steering: seed AG/cluster rotor by node id so
  concurrent creators fill DISTINCT clusters (avoids cluster-EX ping-pong).

## Phase 3+ (only if budget still short)
- Dir-covered lockless reads with per-node writer-registration bitmap in the
  dir slot (dir EX required for 0->registered transition; full drain before
  registered->0; reader holds dir PR across covered reads; nlink==1 only).
- Cluster-generation validated lockless reads as generic fallback.

## Test gates per step (8/cawd, minutes each)
dir_reuse 6-round A/B (expect ≥3x on verify+rm), then cache_coherency,
zero_silent_loss, posix_multi, mmap_coherency, crash_consistency at 8 —
correctness FIRST, budgets second.  Then 32-node rungs.
