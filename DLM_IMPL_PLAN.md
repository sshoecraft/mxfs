# NET2 Implementation Plan — DLM_PLAN.md v2 §11 Steps 1–12

> APPROVED 2026-07-17 (plan-mode session 91f36fa1). This is the living
> implementation checklist for DLM_PLAN.md v2 §11 steps 1-12; DLM_PLAN.md
> remains the design of record. Update gate status + pinned budgets here
> as steps land.
>
> Gate status: [x]1 [x]2 [x]3 [x]4 [x]5 [ ]6 [ ]7 [ ]8 [ ]9 [ ]10 [ ]11 [ ]12
>
> Gate 3 GREEN 2026-07-17 @0.11.3: dlm_shared.{c,h} lift landed
> (identical bodies; dlm.c's duplicate lock_compat + dlm_caw.c's
> fnv1a_hash/const-reader family deduped onto it; popcount helper moved
> from dlm_caw.c's two #ifdef branches; note dlm_caw.h is NOT
> self-contained — dlm_shared.h includes dlm.h first, mirroring
> dlm_caw.c's order). Kbuild += dlm_shared.o (approved line); harness
> compiles it user-mode. gate3_cawsanity.sh: fresh 2/caw prep on
> test1/test2 (MXFS_DEV=/dev/mapper/mpatha — multipath since the
> 0.10.120 ladder) + posix_multi 211/211 + dlm_fairness 5/5, wall 32 s
> vs 300 s provisional → pinned 120 s. CAW provably unchanged
> (srcversion 9D2672E5BFC599CDC8FDA94 on both nodes).
>
> Gate 1 GREEN 2026-07-17 @0.11.0: harness 76 checks PASS (wall 1 s vs
> 30 s budget; vectors checked in), kernel `make modules` clean
> (262 s incremental, srcversion 5221BFFE305AF21A).
>
> Gate 2 FULLY GREEN 2026-07-17 @0.11.2: checkpoint A executed (Kbuild
> += 5 net2 objects; port 7610 registry addition), first `__KERNEL__`
> compile clean after chunking two >1KB stack frames in net2_midcomms
> (NET2_ENQ_BATCH 16), kernel 2-node smoke PASS on test1/test2
> (net2_selftest modparam driver in net2.c; both nodes 32/32 acked,
> retx=0, clean teardown; 13 s vs 60 s pinned; srcversion
> EAE6D695EB942023794C82B on both, only those 2 VMs touched), user
> matrix re-verified green at the final source (29 s / 45 s). Smoke
> run-1 lesson: early-finisher teardown starves peer tail ACKs ⇒ 3 s
> post-pass linger in the selftest (test-driver fix; engine behavior —
> session-survives + COMM_AMBIGUOUS at exactly ambiguity_ms — was
> correct).
>
> Gate 2 USER PART GREEN 2026-07-17 @0.11.1 (historical): step-2 engine
> landed (net2.c, net2_ctx.h,
> net2_link.{c,h}, net2_overlay.{c,h} mesh, net2_midcomms.{c,h});
> gate2_midcomms.sh 19/19 scenarios ×3 seeds + real-time subset + ASan
> sweep, 27 s vs 45 s pinned budget; TSan clean on mutex-guarded state
> (volatile stop-latch reports are the peer.c-precedent idiom, see
> docs/net2.md); kernel `make modules` clean, srcversion UNCHANGED
> (net2 objects not in Kbuild yet — that IS checkpoint A). Deviations
> from this plan's step-2 sketch, all documented in docs/net2.md:
> deliver-on-receipt instead of any reorder-hold (priority classes
> require it; §7.A specifies only cum-ack+SACK+dedup), per-slot link
> ports (base_port+slot — §14 has no NET2 link port; registry addition
> proposed at checkpoint A), coherence window-full returns -ENOBUFS +
> COMM_AMBIGUOUS/freeze-signal (caller keeps the op; never silent),
> session-stats fold into stats.retired at supersede (abort-disposition
> evidence survives restarts).

## Context

CAW criteria are MET on 0.10.120 (1–32 node ladder green). The project has
pivoted to NET2 — the replacement network DLM transport — because the legacy
TCP transport (`dlm/dlm.c` + `dlm/peer.c`) has two proven structural defects:
fire-and-forget messaging (dropped GRANT/RELEASE/BAST = lost lock
transitions; proven root of the tcp_dlm_scaling / dir_reuse leaks) and
single-unreplicated-master + wholesale purge on any membership change.

Plan of record: **DLM_PLAN.md v2** (2026-07-17) — full system, ONE
implementation effort, no deferred stages (user decision, final). §11 defines
12 dependency-ordered build steps with in-effort verification gates.
DLM_PLAN_REVIEW.md §5 holds the required fault-injection matrices (§13
of the plan binds them to gates). This document translates §11 into a
file-by-file, function-level implementation plan plus: the user-mode protocol
test harness (Invariant 4), fault-injection hooks in both builds, and
per-gate test scripts under tests/ with written RULE-0 budgets.

Hard constraints carried through every step:
- RULE 0: every gate test has a written budget (infra + native×2); timeout = FAIL.
- RULE 3: all harnesses/scripts live in the source tree, not /tmp.
- Invariant 1: drain pipeline / release ordering untouched in XFS.
- Invariant 4: everything builds user-mode; no kernel API outside pal/.
- Makefile/Kbuild edits: explicit user go-ahead required at the moment of edit.
- CAW must stay green throughout (criteria-met status is not to be disturbed).
- Version policy: minor bump when NET2 code first lands (0.10.x → 0.11.0),
  patch bumps per subsequent step landing.

## Design understanding (to be confirmed with user before approval)

Three ordered domains, never interchangeable: membership epoch (MEPOCH,
§7.C) ▸ shard term (§7.B) ▸ per-resource dir_epoch/grant_gen. NET2 wraps the
unchanged 32-byte inner `mxfs_dlm_msg_hdr` as opaque payload inside a 64-byte
LE outer header; inner dispatch switch reused verbatim. Reliability boundary
is the end-to-end session (per-incarnation, nonce-matched), not the TCP link.
MEPOCH: single committed authority record {epoch, member_mask, fenced_mask,
slot→incarnation}, persisted as 44-byte LE record in each node's OWN disklock
HB record reserved bytes; observers (lease mcast / probe / disk HB) only
vote; exclusions require attached incarnation-qualified fence_done as commit
precondition; single-decree commit among 3 lowest slots of the PREVIOUS
committed epoch with PREPARED→COMMIT two-phase flags. Shards: 1024, configs
DERIVED from committed E via HRW top-3, totally ordered ⇒ no joint quorums;
2-of-3 log commit; replicated waiters + completed-op cache; closed-set
recovery barrier with gen slack (+1024). Fencing: SUSPECT→FENCING→DEAD only
via fence_done (incarnation-qualified); ladder = SCSI-PR preempt-and-abort
(per-path confirm) > CAW epoch fence (CAW-trusted only) > watchdog PAL >
external agent PAL; no mechanism ⇒ visible budgeted freeze, never reclaim.
Recovery order: fence < exclusion-commit < replay < gen-advance < unfreeze.
grant_gen never 0 on NET2 (XFS gen==0 discriminator sites); transport_caw()
stays false ⇒ monotone > paths. Both topologies (mesh default, overlay
gated); membership always on DIRECT links. 5 priority classes with reserved
quanta, RELEASE > BAST; control-queue overflow ⇒ scoped freeze, never drop.
Envelope ships feature-gated DEFAULT OFF; is_free reset rides the SAME
unlock CAS. Inner MXFS_DLM_VERSION stays 1; NET2 negotiates via its own
handshake TLV. Port registry names reality: LEASE_LEGACY(7602)/LEASE_V5(7603);
7605 = NET2 membership.

Tree facts verified this session that adjust implementation detail (not
design): transport enum lives in TWO places (dlm/mxfs.h:104 AND
v5_mount.h:29-31 — both gain NET2); the user-mode build is greenfield
(pal/linux/user.c implements the whole needed PAL surface but nothing
builds it today — the harness is the first dlm-linking user binary); NO
DLM stats surface exists (freeze/counters visibility = new PAL
`mxfs_pal_stats_register` hook → /proc/fs/mxfs/ + offline MEPOCH decode in
chk_mxfs); discovery announces carry NO slot field (identity rides the
NET2 SYN TLV; discovery gains only a capability flag bit); peer.c's
connect convention is lower-node_id — NET2 deliberately switches to
lower-slot (slot+incarnation IS the NET2 identity); dual-build LE helpers
(`mxfs_cpu_to_le*`, pal.h ~749-833) and the discovery.c/lease.c wire-
conversion pattern already exist and are the precedent net2_wire.h follows;
and the one real collision: the HB record has only 8 reserved bytes left
for MEPOCH (next section).

## Step-by-step implementation breakdown

### ⚠ Pre-step decision — MEPOCH persistence does NOT fit as §7.C assumed

Verified against disklock.h (explorer, 0.10.120): `struct
mxfs_disklock_heartbeat` (disklock.h:118-133) is 40 B header + 464 B evict
ring (`mxfs_evict_ring`, 28 × 16 B entries + 16 B ring header, carved from
the old reserve in sess55) + **reserved[8]**. Only 8 bytes remain — the
44-byte MEPOCH record cannot live in "remaining reserved bytes" as §7.C
states. §7.C explicitly deferred exact offsets to implementation; the
implementation-time answer is: the headroom is gone.

**Recommended resolution (needs user sign-off — on-disk record layout):**
shrink `MXFS_EVICT_RING_ENTRIES` 28 → 25 (disklock.h:81), freeing 3×16 = 48
bytes; place the MEPOCH record (44 B including a leading magic u32 —
§7.C's field list sums to 40 B; +magic = 44) between `evict` and
`reserved[]`, leaving 12 reserved bytes. Record keeps its own magic + crc32c
so stale garbage in old-format records is never misread; HB `flags` gains
`MXFS_HB_F_MEPOCH` marking the new layout. Old readers are safe (ring
`count` ≤ 25 bounds their iteration; unknown flag ignored). Evict ring is a
non-authoritative hint ring — losing 3 of 28 entries slightly raises wrap
frequency, and ring-wrap is already a §13.3 fault-matrix case.
Alternatives considered and rejected: per-lock-slot reserved[448] (not
per-node single-writer), journal slice headers (replay-reset), mkfs
alignment gap (only 7 sectors; not per-node; now formally the transport
self-test scratch). Static asserts updated in place: heartbeat ==512
(disklock.h:140, disklock.c:67) unchanged; evict-ring fit assert
(disklock.h:142, currently ≤472) retargeted to the new layout; new
`_Static_assert(sizeof(struct mxfs_mepoch_rec)==44)` in both builds.
`tools/chk_mxfs` learns to decode/print the MEPOCH record (per §7.E's
status-surface requirement).

### Step 1 — Protocol foundation (files: dlm/net2_wire.h, include/mxfs/mxfs_ports.h, dlm/net2.h, dlm/net2_fault.{c,h}, dlm/net2_stats.h)

- `include/mxfs/mxfs_ports.h` (NEW): the §14 registry verbatim
  (DLM 7600 / DISCOVERY 7601 / CAW_BAST 7602 / LEASE_LEGACY 7602 /
  LEASE_V5 7603 / NET2_MEMBERSHIP 7605). Migration edits (call sites read
  the registry, zero behavior change): mount.c:34-35, v5_mount.c:881/882/
  1022/1171/1173/1187, lease.h:61 (`MXFS_LEASE_PORT` becomes alias of
  `MXFS_PORT_LEASE_LEGACY` + deprecation comment), discovery.h:25,
  dlm_caw.h:105.
- `dlm/net2_wire.h` (NEW, header-only): `MXFS_NET2_MAGIC/WIRE_VERSION`,
  frame_class + flags enums, `struct mxfs_net2_hdr` (64 B exactly, §6
  layout), `MXFS_NET2_MAX_MSG_SIZE 8192` (lifted constant; peer.c:17 keeps
  its private copy for now — merging is step-12 cleanup, zero-risk),
  `MXFS_NET2_MAX_FRAME (64 + 8192)`, explicit LE encode/decode:
  `mxfs_net2_hdr_pack(const struct mxfs_net2_hdr *h, uint8_t buf[64])` /
  `mxfs_net2_hdr_unpack(const uint8_t buf[64], struct mxfs_net2_hdr *h)`
  field-by-field via existing byteorder helpers — no native-struct
  serialization; `_Static_assert(sizeof==64)` compiled in BOTH builds.
  Also the SYN/SYN_ACK TLV block: type/len/value defs for full 16-B cluster
  UUID, volume_id, fs_gen, boot nonce, feature bits
  (MEMBFENCE/BAST_WAKE/ENVELOPE), NET2 wire version.
- `dlm/net2.h` (NEW): `struct mxfs_net2_id` (§5), `enum net2_priority`
  (5 classes, §7.A), reliability flags, lifecycle API decls
  (`mxfs_net2_create/start/stop/destroy`, `mxfs_net2_register_recv_cb`,
  `mxfs_net2_send`, `mxfs_net2_update_view`), `struct mxfs_net2_cfg`.
- `dlm/net2_stats.h` (NEW): per-session + per-class counter struct — the
  §13 evidence list verbatim (created / first_tx / retx / acked /
  dup_suppressed / dup_op_idempotent / out_of_window / stale_inc_epoch_term
  drops / queue_full[class] / max_residency[class] / resets / freezes by
  reason) — plain u64s bumped under the owning lock; exported via the
  existing per-mount stats surface (location per build-explorer findings)
  and printed by the user harness.
- `dlm/net2_fault.{c,h}` (NEW, compiled in BOTH builds always — not
  ifdef'd out in release, per plan §10 "fault-injection hooks compiled into
  BOTH builds"): a small table of injection points keyed by
  {frame_class, inner msg type, direction} with actions
  {drop, dup, delay_ms, reorder, trunc, corrupt} + count/probability +
  deterministic seed (PRNG state per session, seeded explicitly).
  Control: kernel = module params + a runtime knob (same mechanism as
  existing mxfs params; exact surface per build-explorer); user harness =
  direct API `mxfs_net2_fault_set(...)`. Injection call sites live at the
  net2_link frame boundary (send-side + recv-side) so kernel and user
  builds inject identically.
- Golden vectors: `tests/net2/vectors/` — canonical byte images of each
  frame_class incl. TLVs, generated once, checked in; harness asserts
  pack→bytes and bytes→unpack both directions + rejects 20+ malformed
  variants (bad magic/version/len/class/UUID/epoch).

**Gate 1** (script `tests/net2/gate1_wire.sh`): user-mode harness builds +
golden vectors + malformed-frame fuzz (seeded, 10^5 frames) + static-assert
compile check in BOTH builds (kernel build = `make modules` compile only;
no Kbuild change needed yet because net2_wire.h/net2.h are header-only and
net2_fault.c is not yet linked into mxfs.ko — it joins the module at the
step-2 Kbuild ask alongside link/midcomms).

### Step 2 — Core engine (files: dlm/net2_link.{c,h}, dlm/net2_overlay.{c,h} mesh provider only, dlm/net2_midcomms.{c,h}, dlm/net2_ctx.h, dlm/net2.c)

Forked-from-peer.c structure (peer.c anchors verified):
- `net2_link.c`: `net2_link_listen/accept_fn` (fork of mxfs_peer_accept_fn
  peer.c:190-409 — accept loop, SYN/SYN_ACK TLV handshake replaces the
  NODE_JOIN handshake); `net2_link_connect` (fork of peer_connect_impl
  peer.c:643-856; **lower-SLOT-initiates** — deliberate change from peer.c's
  lower-node_id convention at 657-668, because NET2 identity is
  slot+incarnation); per-link `net2_link_recv_fn` (fork of
  mxfs_peer_recv_fn peer.c:67-165: read 64-B outer hdr → validate →
  read payload_len) and per-link `net2_link_egress_fn` (NEW — drains the 5
  priority queues via weighted deficit round-robin, quanta
  FENCE 20/RELEASE 30/REVOKE 25/GRANT 20/DISCOVERY 5%, per-class retransmit
  sub-quantum; replaces mxfs_peer_send's caller-context send +
  send_lock serialization at peer.c:884). Reconnect tears down freely —
  session survives (departure from peer.c:914-940 keep-socket-up policy,
  per §3).
- `net2_overlay.c` (this step: mesh provider only): `net2_route(dst) →
  link` = direct link; `net2_route_alt` = none; provider vtable so step 8
  slots in the overlay without touching callers. `net2_topology` modparam
  {0=auto,1=mesh,2=overlay}, auto resolves to mesh until gate 8.
- `net2_midcomms.c`: session table keyed {uuid_hash, epoch-domain,
  src slot+inc, dst slot+inc} + nonce equality; per-direction tx_next_seq /
  tx_unacked_base / retransmit ring (64) / flow window; rx_cum_ack + 32-bit
  SACK + msg_id dedup ring (1024); ACK policy (piggyback; standalone after
  5 ms delayed-ack or 8 pending — implemented as egress-worker
  cond_timedwait deadline, since PAL has NO timer primitive: periodic work
  is threads, per disklock.h:14 precedent); single RT thread
  `net2_rt_fn` 50 ms tick, RTO 200 ms ×2 capped 2 s; >10 s unacked →
  COMM_AMBIGUOUS → (step 6 wires freeze; until then, counter + callback
  stub); per-session/per-mount memory caps (§7.A numbers); u64 serial
  arithmetic asserted.
- `net2_ctx.h` + `net2.c`: `struct mxfs_net2_ctx` (links[], sessions,
  counters, fault table, freeze hook, view), `mxfs_net2_create/start/stop/
  destroy` (thread lifecycle: `volatile bool running` + cond +
  `mxfs_pal_thread_join(_timeout)` — symmetric create/stop per pal.h
  precedent, deterministic shutdown order: listeners → links → RT → free),
  recv demux (validate outer hdr → session lookup → dedup → deliver
  payload to registered cb).
- Inner-type → priority map `net2_pri_for_type()` (in net2.c):
  LOCK_RELEASE→RELEASE; LOCK_BAST, CACHE_INVAL→REVOKE; LOCK_REQ/GRANT/
  DENY/CONVERT, MD_*→GRANT; JOURNAL_RECOVER/DONE→RELEASE (recovery
  progress); LEASE_*/NODE_*→DISCOVERY; NET2-native MEPOCH_/FENCE_ msgs
  (steps 5-6)→FENCE. (Inner enum verified at include/mxfs/mxfs_dlm.h:66-99.)

**Kbuild checkpoint A (explicit user go-ahead):** before gate 2's kernel
smoke, net2_{link,overlay,midcomms,fault}.o + net2.o must join mxfs.ko —
first Kbuild edit. Will present the exact diff and wait for approval.

**Gate 2** (`tests/net2/gate2_midcomms.sh`): user-mode harness runs the full
§13.1 midcomms matrix (loss/dup/reorder/delay per class incl. ACK loss; TCP
reset at every framing point; per-class backpressure; restart + slot reuse;
epoch change mid-op; window/SACK/wrap boundaries; malformed/cross-cluster)
with the standing invariants asserted; then 2-node kernel smoke
(echo-style send/recv over mxfs.ko with fault injection off).

### Step 3 — Shared-code lifts (CAW-neutral refactor)

New `dlm/dlm_shared.{c,h}` (name final at implementation): move
`resource_hash_raw`/`resource_equal` (dlm.c:221/240) and `lock_compat[][]`/
`is_compatible`/`recompute_granted_mode` (dlm_caw.c:186/250/278) +
EX/PW-popcount corruption check (per slot_appears_corrupt dlm_caw.c:398);
dlm.c/dlm_caw.c switch to including it. Pure move — identical bytes in the
movers, no signature changes.

**Gate 3**: both builds green; srcversion changes but CAW behavior must not:
one 2-node CAW sanity (`run.sh 2 caw posix_multi dlm_fairness`) to prove
refactor-neutrality. (Criteria-met status must never be put at risk by an
unverified refactor.)

### Step 4 — Lock plane (files: dlm/net2_msg.h, dlm/net2_shard.{c,h}, dlm/net2_lock.{c,h})

- `net2_msg.h`: lock-plane payload structs (N2_ACQUIRE/GRANT/DENY/RELEASE/
  RELEASE_ACK/BAST/APPEND/APPEND_ACK/TERM_VOTE/TERM_COMMIT/SNAPSHOT_REQ/
  SNAPSHOT_CHUNK/RECOVERY_REPORT/CAUGHT_UP) — each mutating op carries
  {requester slot+inc, request_id u64, resource_id, membership_epoch,
  shard_term, expected grant_gen where applicable} (§6 op identity); all
  LE-packed like net2_wire.h.
- `net2_shard.c`: shard table (1024 × `struct net2_shard` per §7.B);
  `net2_shard_id(resource)` = FNV1a(uuid‖resource_id)&1023; HRW top-3
  derivation `net2_shard_derive_config(E, member_mask)` (keyed slot+inc,
  `mxfs_pal_sort` pal.h:572); bounded log ring + 2-of-3 commit
  (`net2_shard_append/commit`); election (`net2_shard_elect`: vote solicits,
  max(term,commit_seq) completeness, HRW-rank-biased randomized timeouts,
  N2L_TERM barrier before serving); state transfer (`net2_shard_xfer_*`:
  snapshot pull at commit_seq C, CAUGHT_UP logged, transferring replicas
  never vote/ack); reconfiguration on epoch change
  (`net2_shard_reconfigure`: freeze at C → new rank-0 pulls → TERM(E+1,1)
  barrier → resume; unchanged-R shards keep serving); closed-set recovery
  barrier (`net2_shard_recover`: RECOVERY_REPORT fan-out to ALL E+1
  members, gen-stamped client reports, grant_gen_next=max+1024,
  dir_epoch_next=max+1, rebuilt state logged to quorum).
- `net2_lock.c`: `struct net2_lock_rec` (§7.B verbatim incl. REPLICATED
  waitq {slot,inc,request_id,mode,enq_seq} + ex_streak fairness mirror);
  op handlers (`net2_lock_acquire/release/convert` — effect-idempotent via
  the replicated completed-op cache, 64-entry per client-inc ring); PR
  fan-out + BAST issue (`net2_lock_revoke_pr`); grant_gen/dir_epoch
  allocation (nonzero, u64, freeze-on-would-wrap assert); client-side
  held[] honoring ctx->max_held (32768 default, dlm_caw.h:50). Delegations
  + migration are step 10, NOT here.

**Gate 4** (`tests/net2/gate4_shard.sh`): §13.2 matrix in the user harness —
leader kill/partition at all 12 commit points × partition patterns
(leader-alone, follower-alone, 2v1, old-vs-new group, overlapping,
simultaneous epoch change, all-replica reboot, 2-permanent-loss); evidence
asserts (single grant-capable leader per (E,term), commit_seq/gen
high-waters never regress, transferring replicas never vote, waiter order
preserved, total loss ⇒ recovery barrier never empty-table).

### Step 5 — Membership plane (files: dlm/net2_membership.{c,h}, dlm/net2_epoch.{c,h}; edits: dlm/disklock.h, tools/chk_mxfs)

- Prereq: the MEPOCH-layout decision above (evict 28→25).
- `net2_epoch.c`: `struct mxfs_mepoch_rec` pack/unpack (LE + magic + crc32c,
  44 B) into own HB record via existing disklock write path;
  `mxfs_mepoch_read_all` (scan 64 HB slots, max valid committed);
  single-decree protocol (`mepoch_propose/ack/commit`): proposer = lowest
  live voter slot of E (next-lowest after 2× probe-interval SUSPECT);
  voters = 3 lowest slots of E's member_mask (5 at ≥16 members, count in
  flags); preconditions (monotonic E+1, fenced_mask ⊇, exclusions carry
  incarnation-qualified fence_done); PREPARED persisted to voter's own HB
  record flags before ACK, later proposer must adopt any PREPARED
  candidate (proposer-crash fork prevention); COMMIT → all members persist
  + lease beacon echoes committed epoch number; `mepoch_lease_ms` (10 s)
  self-freeze + disk-visible self-fence check (excluded node reads
  survivors' fenced_mask with zero network).
- `net2_membership.c`: observer aggregation (lease cb via existing
  lease.c expire/recv hooks, NET2 unicast probe on port 7605, disklock HB
  advance scan = alive-on-LUN signal); SUSPECT state machine (≥2 observers
  missing → SUSPECT → freeze-conflicting + probe hard + consult disk
  observer; same inc+nonce reconnect within grace → ACTIVE; grace elapsed →
  FENCING; DEAD only via fence_done — deliberately NOT reusing
  v5_tcp_death_worker_fn's timeout-declare, v5_mount.c:590-622); persisted
  incarnation bump at mount/slot-claim (read own HB → +1 → write before
  joining); boot nonce via mxfs_pal_get_random_bytes (pal.h:685).
- Discovery integration: announce struct has NO slot field
  (discovery.h:36-48, verified) — do NOT extend the announce payload;
  add a NET2-capability flag bit in its existing `flags` field; slot/
  incarnation/features are exchanged in the NET2 SYN TLV (discovery stays
  a {host, node_id} hint, never authority).
- Membership traffic rides DIRECT links always (mesh provider), port 7605,
  FENCE priority.

**Gate 5** (`tests/net2/gate5_mepoch.sh`, user harness + file-backed disk):
bootstrap (fresh cluster, epoch 1 self-quorum), join/leave increments,
proposer crash mid-round → PREPARED adoption, voter-minority stall (no
commit, visible freeze), whole-cluster restart (max valid record adopted),
excluded-node disk self-fence with zero network, exclusion-without-
fence-proof NACK.

### Step 6 — Fencing + freeze (files: dlm/net2_fence.{c,h}, dlm/net2_freeze.{c,h}; edits: pal/pal.h + pal/linux/{kern,user}.c, dlm/scsipr.{c,h})

- `net2_freeze.c`: `struct mxfs_net2_freeze` per §7.E (scope FZ_RESOURCE/
  SHARD/FS, 7 reason codes, frozen_node_mask, require_epoch, since/deadline);
  `net2_freeze_enter/escalate/exit`, `net2_freeze_blocks(resource, mode)`
  consulted by the shard grant path; CAW consults the SAME table via an
  explicit registered hook (used by steps 9/11 — a callback pointer so
  dlm_caw.c never links net2 symbols unconditionally; the legacy TCP
  memb_settle gate at dlm.c:1128 stays legacy-only). Deadlines by reason
  (SUSPECT 8 s, ELECTION 2 s, XFER 5 s, RECOVERY 30 s, NOFENCE/QUORUM_LOSS
  unbounded-but-visible); expiry ESCALATES (widens scope, raises admin
  status), never unfreezes; unfreeze requires epoch ≥ require_epoch AND
  frozen mask ⊆ fenced ∪ reconnected — never a timer.
- `net2_fence.c`: incarnation-qualified fence records {victim slot, victim
  inc, epoch, method, seq, deadline}; `net2_fence_execute` ladder per §7.D:
  (1) SCSI-PR preempt-and-abort — extend PAL:
  `mxfs_pal_scsi_pr_preempt` gains an explicit PREEMPT-AND-ABORT service
  action (verify current kern.c service action at implementation), and NEW
  `mxfs_pal_scsi_pr_read_keys_allpaths` (kern: iterate multipath slaves,
  per prep_node.sh dm-slave precedent; user: single path) — confirmation =
  victim key gone on EVERY active path; (2) CAW epoch fence, CAW-transport
  clusters only; (3) `mxfs_pal_watchdog_arm/pet/cancel`; (4)
  `mxfs_pal_fence_agent(node_id, incarnation, action, done_cb, cb_data)` —
  both new hooks -EOPNOTSUPP by default, kern.c + user.c impls, with
  specified cancellation, incarnation binding, and cb-lifetime-across-
  unmount rules (§10). No method available → FREEZE reason NOFENCE, never
  DEAD. Self-fence: assert reservation mode at mount;
  `mxfs_scsipr_unregister` used only where the mode makes unregister remove
  write access, else preempt-self + I/O quiesce.
- Recovery ordering engine `net2_recover_node()`: the §7.D 8-step sequence,
  each step emitting a trace marker so the §13.3 order assertion
  (`fence < exclusion-commit < replay < gen-advance < unfreeze/grant`) is
  checkable from logs; no grant for affected resources between steps 4-6.
- Live status surface (net-new; none exists for DLM today — verified): new
  PAL hook `mxfs_pal_stats_register(name, show_cb, data)` (kern.c:
  /proc/fs/mxfs/<name> via the existing proc_mkdir("fs/mxfs") precedent in
  pal/linux/xfs_stats.c:149-159; user.c: registry the harness dumps).
  net2 registers one show_cb printing freeze {scope,reason,age}, session
  counters, MEPOCH view. `chk_mxfs` (offline, pread-based — verified no
  live query path exists) gains MEPOCH/incarnation/fenced_mask decode from
  HB records; the §7.E "chk_mxfs query" requirement is satisfied by that
  offline decode + the /proc live surface together.

**Gate 6** (`tests/net2/gate6_fence.sh`, VMs): §13.3 fencing matrix — detail
in the gate-script section below.

### Step 7 — Seam wiring + transport enum + mount negotiation (edits: dlm/v5_mount.{c,h}, dlm/mxfs.h, dlm/discovery.h, mount layer)

- Transport value in BOTH enums (explorer-verified locations):
  `MXFS_V5_TRANSPORT_NET2 3` (v5_mount.h:29-31) AND `enum
  mxfs_dlm_transport` gains NET2 (dlm/mxfs.h:104 — currently CAW=0,TCP=1;
  discovery.h:43 `dlm_transport` field carries it). `force_transport`
  modparam (v5_mount.c:34-37) accepts 3=NET2; validation at 862-867
  extended. AUTO resolution + form/join negotiation live in the
  caller/mount layer (v5_mount does NOT probe — verified): forming
  publishes transport+features (discovery `flags` bit advertises NET2
  capability); joiners conform or fail (Invariant 5).
- `struct mxfs_v5_dlm` gains `struct mxfs_net2_ctx *dlm_net2`
  (v5_mount.c:121). Seam entries gain a leading `if (ctx->dlm_net2)` arm —
  all anchors re-verified this cycle: `inode_lock`@1360,
  `inode_unlock_gen`@1534 (honors expected_gen), `inode_unlock_free`@1498
  (is_free), `ag_lock`@1940, `ag_lock_nb`@1993, `ag_unlock`@2119,
  `inode_grant_gen`@1632 (nonzero u64→u32 token), `grant_handoff`@1723,
  `dir_epoch`@1748, `granted_mode`@1704, orphan-clock accessors 1655/1666
  (NET2 returns 0). `transport_caw()`@1791 body untouched — stays false for
  NET2 ⇒ XFS monotone `>` paths; never-zero gens keep the gen==0
  discriminator sites (xfs_mxfs_dlm.c ~12279/13889) correct.
- Callback wiring modeled on the TCP block (v5_mount.c:884-924):
  `mxfs_net2_create(&cfg{node_id, uuid, uuid_hash, ports, volume_id,
  fs_gen, self_slot, self_incarnation})` → `register_recv_cb(n,
  v5_net2_recv_cb, ctx)` — recv cb reuses the `switch(hdr->type)` dispatch
  body (291-339) verbatim; `mxfs_net2_start`; `v5_refresh_active_nodes`
  (353) additionally calls `mxfs_net2_update_view`. Send cb mirrors
  `v5_dlm_send_cb_tcp` (261) via `mxfs_net2_send(..., net2_pri_for_type
  (h->type), RELIABLE, msg_id, ...)`. BAST cb: replace `mxfs_peer_send`
  (439) with net2_send(REVOKE, RELIABLE); keep local-owner short-circuit
  (414-421); DELETE the ad-hoc 3-retry/50 ms loop (408-451). The legacy
  deferred-death worker (590-622) is NOT wired for NET2; `v5_lease_expire_cb`
  (766) on NET2 feeds the membership plane as an observer vote only —
  MEPOCH owns purge/replay ordering (§7.D adds the gen-advance the legacy
  cb lacks). Both notify families driven: set_bast_notify →
  `mxfs_dlm_bast_notify` AND set_ag_bast_notify → `mxfs_dlm_ag_bast_notify`
  (registrations xfs_mxfs_dlm.c:31654/31657). XFS tree: ZERO edits.

**Gate 7 — the flagship** (`tests/net2/gate7_ladder.sh`): full criteria
suite at 1/2/4/8/16/32 on `net2` transport; tcp-era leak workloads
(`tcp_dlm_scaling`, `dir_reuse_coherency`, `dlm_fairness`, stress)
repeatedly clean WITH injected loss/dup/reorder; zero overlapping grants;
RULE-0 budgets met (2× native ceiling). Requires the run.sh/prep `net2`
plumbing described in the gate-script section.

### Step 8 — Overlay provider (edits: dlm/net2_overlay.c)

Second provider behind the vtable from step 2: deterministic neighbor set
(FNV1a(uuid_hash, memb_epoch, slot, incarnation) keying, `mxfs_pal_sort`
pal.h:572, ring successor+predecessor + fingers ±2^k, dedup, degree clamped
[6,10]); greedy closest-not-past routing ≤ ceil(log2 N) hops;
`net2_route_alt` node-disjoint second next-hop; retransmits alternate
paths; relays decrement TTL (init 6, drop at 0), set RELAYED, re-enqueue at
frame priority through the same egress scheduler, NEVER generate ACKs;
epoch bridging per §7.A (E-1 frames relayed/delivered within the bridge
window — RELEASE/RELEASE_ACK from the old view must complete; handlers
still reject old-epoch MUTATIONS); view updates recompute sets, eager new
links, lazy retirement after retransmit drain. Membership traffic stays on
DIRECT links regardless of provider (§7.C — no circularity).

**Gate 8** (`tests/net2/gate8_overlay.sh`): §13.1b — same correctness
matrix with `net2_topology=overlay`; relay failure; TTL exhaustion;
dual-path duplication; epoch bridging; no-disjoint-path degradation; two
independent link failures lose no transition; relay saturation never delays
RELEASE/FENCE past budget; thread/CPU delta vs mesh recorded. Default
remains mesh until this gate is green at the largest testable N.

### Step 9 — CAW BAST_WAKE (files: dlm/net2_bast.{c,h}; edits: dlm/dlm_caw.c)

Capability on the CAW transport (transport_caw() stays true; CAW `!=` epoch
semantics preserved — xfs sites 16685/16716/18446/22085). Hook points
verified: `caw_send_bast_mcast` (dlm_caw.c:1509; callers 1750/3127/4042)
gains a net2 path — reliable `net2_send(owner, NET2_PRI_REVOKE, ...)`
coalescing per owner while preserving every resource/AG identity in the
payload; waiter blocks on condvar wakeup instead of the 100 ms resend loop
(`MXFS_CAW_BAST_RESEND_MS` dlm_caw.h:96; loop at dlm_caw.c:1748); disk poll
relaxes to `MXFS_CAW_BAST_POLL_RELAX_MS` (dlm_caw.h:95) when net2 is up,
extending the existing adaptive logic (4628-4632); **bounded polling always
continues** — `bast_recv_fn` (4641) and the UDP hint path retained as
fallback; net2-down degrades exactly to today's CAW. grant_meta cache,
grant_seq32 tokens, `mxfs_dlm_caw_granted_mode`, orphan-clock table: none
bypassed. Feature bit BAST_WAKE negotiated.

**Gate 9** (`tests/net2/gate9_bastwake.sh`): CAW suite stays 100% green
1-32; drop-all-net2-wakeups (fault hook) ⇒ correctness unchanged, latency
only; drop UDP hints ⇒ net2 wakeups hold latency; disconnect net2 mid-wait
⇒ bounded poll progresses; command-rate + wall delta vs plain CAW recorded.

### Step 10 — PR delegations + hot-shard migration (edits: dlm/net2_lock.c, dlm/net2_shard.c)

Delegations: leader-logged (replicated) grants {resource, slot+inc,
expiry = mxfs_pal_time_real_ms + 5 s, gen}; repeated LOCAL PR without
network ops until expiry/revoke; revocation = BAST + client proves local
quiescence before EX; 1 s skew guard; an expired-but-unrevoked delegation
is still BAST'd before any EX (expiry bounds renewal only — never
clock-based revocation). Migration: leader-load-triggered (ops/s counter)
logged term transition, same mechanics as reconfiguration steps 1-2;
never a way to resolve an uncertain holder.

**Gate 10** (`tests/net2/gate10_deleg.sh`): delegation revoke/expiry/restart
races in the user harness; fairness preserved across failover; no
dlm_fairness/dlm_scaling regression on the cluster.

### Step 11 — CAW envelope (files: dlm/net2_caw_envelope.{c,h}) — feature-gated, DEFAULT OFF

`struct mxfs_net2_envelope` mirrors the FULL current slot semantics (§7.F
verbatim: holder masks by mode, disk_generation, delegation_gen, dir_epoch,
last_ex_slot, handoff, yield_to, yield_set_ms (real-clock), ex_grant_streak,
waiters_ex_mask, dir_block0_fsb/gen, replicated waitq, pending_revoke_mask).
Release chokepoint `net2_envelope_release`: revoke-all → wait
pending_revoke_mask==0 (each RELEASE gen-qualified + committed) → commit
empty holder set to quorum → `mxfs_dlm_caw_unlock_gen(ctx, res,
expected_gen32, is_free)` LAST (signature verified dlm_caw.c:3224) —
dir_epoch/last_ex_slot and is_free reset ride the SAME tombstone CAS image;
NO separate post-hoc CAS (proven perf regression — TRAP-1). Leader failure:
fence(confirmed, inc-qualified) → new leader CAWs slot to delegation_gen+1
→ replay replicated state → reissue revokes / recovery barrier → only then
incompatible grants; total replica loss → closed-set barrier or fence-all.
Fairness (yield ticket, streak-yield) enforced by leader from replicated
state — must not regress `caw_fair_handoff`. Modparam `net2_envelope=0`;
ENVELOPE feature bit fail-closed for non-speakers on envelope volumes.

**Gate 11 — to flip the default only** (`tests/net2/gate11_envelope.sh`):
§13.4 — leader failure at every release step; replica loss; fairness parity
(yield/streak) vs plain CAW; dir_block0/dir_epoch checkpoint asserts;
canary = posix_multi rename+hardlink; no posix_multi/dlm_scaling
regression.

### Step 12 — Build formalization (EXPLICIT GO-AHEAD) + docs + budget pinning

- Present as reviewable diffs, wait for approval (checkpoint B; checkpoint
  A was the step-2 Kbuild addition): Kbuild net2 objects final list;
  OPTIONAL top-level/tools Makefile integration of the harness (until then
  it builds only via its own `tests/net2/Makefile`); peer.c:17
  `MXFS_PEER_MAX_MSG_SIZE` deduped onto the shared net2_wire.h constant.
- `docs/net2.md` finalized (created at step 1, maintained every step, per
  the docs/.md project rule); docs entries for touched modules
  (disklock evict-ring change, scsipr PAL extension, seam).
- `tests/criteria/TIMEOUT_BUDGETS.md` updated with every pinned net2 gate
  budget + actual walls (RULE 0 tighten-toward-actual).

## User-mode protocol test harness (Invariant 4) — tests/net2/

**This is the first dlm-linking userspace binary in the tree** (verified:
tools are standalone SG_IO probes; `pal/linux/user.c` fully implements the
needed PAL — pthreads user.c:298/328, TCP sockets 588-794, O_DIRECT file
I/O — but is currently built by nothing).

Layout (RULE 3 — everything in-tree):
```
tests/net2/
  Makefile              # NEW standalone file; `make -C tests/net2`.
                        # Does NOT touch top-level Makefile / Kbuild /
                        # tools/Makefile (those edits are approval-gated;
                        # optional integration happens at step 12).
  harness/net2_harness.c        # main + scenario registry + node lifecycle
  harness/scen_midcomms.c       # §13.1 scenario family
  harness/scen_shard.c          # §13.2 scenario family
  harness/scen_mepoch.c         # gate-5 membership scenarios
  harness/scen_deleg.c          # gate-10 delegation races
  harness/harness.h             # node-instance struct, virtual-cluster API
  vectors/                      # golden wire vectors (checked in)
  gate*.sh                      # per-gate scripts (below)
  manifest                      # net2 cluster-test manifest (run.sh category)
```

Build: compiles `dlm/net2_*.c` + `dlm/disklock.c` (user-mode-ready per its
own comments; needed for MEPOCH/incarnation persistence) + `dlm/dlm_shared.c`
(step 3) + `pal/linux/user.c` + harness sources; `gcc -I include -I dlm
-I pal -Wall -Wextra -Werror`. No `__KERNEL__` ⇒ user paths (that IS the
build split today — no MXFS_USER define exists or is added).

Architecture:
- **N nodes = N in-process instances**, each an independent
  `mxfs_net2_ctx` + own threads (through PAL), each bound to
  127.0.0.1:base+slot — REAL TCP through the same `mxfs_pal_tcp_*` code the
  kernel path uses, so link/accept/reconnect races are exercised for real.
- **Shared disk = one file-backed image** accessed via user-PAL pread/
  pwrite: real disklock HB region layout (mkfs'd by harness init writing
  the disklock region format), so incarnation persistence, MEPOCH
  PREPARED/COMMIT flags, and whole-cluster-restart adoption run against
  the true on-disk format. SCSI-PR fencing is MOCKED at the PAL boundary:
  user.c's `mxfs_pal_fence_agent`/scsi_pr hooks record fence calls +
  return scripted outcomes (late/failed/stale-incarnation per scenario).
- **Determinism**: per-scenario u64 seed drives (a) the net2_fault PRNG
  (loss/dup/reorder/delay/corrupt decisions) and (b) scripted scheduling
  points (kill-at-commit-point k). Nonces/incarnations injected via
  `mxfs_net2_cfg`, not by overriding PAL random. Time: all midcomms/
  membership time constants live in a `net2_tunables` struct (defaults =
  spec values: RTO 200 ms, tick 50 ms, ambiguity 10 s, grace 8 s...);
  scenarios run compressed (÷10-50) for breadth PLUS a pinned subset at
  real defaults every gate (compression can mask races; the real-time
  subset is the guard).
- **Node kill/restart** = teardown of an instance (threads joined, state
  dropped, file image retained) + re-create with bumped incarnation —
  exercising the §5 persistence path exactly.
- Runner: `net2_harness list | run <scenario> [--seed N] [--nodes N]
  [--real-time] [--repeat K]`. Every scenario ends by asserting the §13
  standing invariants (delivered_effects ≤ unique_op_ids; committed
  RELEASE removals ≤ completed drain traces; incompatible grants never
  overlap; every retired retransmit entry has ACK or session-abort
  disposition; no FENCE/RELEASE/RELEASE_ACK/BAST silently discarded) +
  scenario-specific asserts, prints the full counter set, and emits a
  `RESULT: PASS|FAIL | test=<scenario> | ...` line (same protocol as
  tests/suite/lib.sh:64 so gate scripts parse uniformly).
- Fault hooks are `dlm/net2_fault.c` — the SAME code in both builds;
  kernel control = modparams (dlm modparam precedent, v5_mount.c:34-37
  style), harness control = direct API. (No in-tree fault framework
  exists — verified; xfs_errortag is kernel-sysfs-only and stays untouched.)

## Per-gate test scripts under tests/ (RULE 0 budgets)

Conventions (from the live harness, verified): gate scripts emit lib.sh
`RESULT:` lines; cluster tests are manifest-driven
(`PHASE TEST COORD MINNODES BUDGET_S [SCALE]`) and run through
`./run.sh <N> <dlm> [test...]` which enforces RULE-0
(elapsed>budget ⇒ FAIL) and records into criteria.json keyed `<N>/<dlm>`;
`RULE0_CALIBRATE=1` = measurement mode. Budgets follow
tests/criteria/TIMEOUT_BUDGETS.md: `budget = infra(measured) +
workload(native×2)`, written BEFORE the run, actual wall recorded after,
budget tightened toward it. Per feedback memories: adapt existing suite
tests (fault_netpartition.sh, fence_during_write.sh, dlm_membership.sh)
before writing new ones; `make clean` before kernel-build gates (stale-.ko
trap) + srcversion verify on every node (cluster_reset_n.sh precedent);
push multi-line remote scripts via `bash -s`, never inline through
mxfs_sshpass (arg-flattening trap); foreground waits, chunked ≤~5 min.

**Harness plumbing edits (shell only — NOT Makefile/Kbuild):** `run.sh`
accepts `net2` as a dlm value (validation at run.sh:2-31 + record keys);
`tests/setup/prep_node.sh` gains `net2` (insmod `force_transport=3`);
`tests/net2/manifest` registered like tests/{caw,tcp}/manifest; suite tests
gain `<N>/net2` runs in criteria.json automatically via the generic
`<N>/<dlm>` keying.

Budget table (provisional → calibrate → pin; user-mode infra = harness
build from clean, measured once; cluster infra numbers from
TIMEOUT_BUDGETS.md reference block: mkfs 0.6 s, first mount 2.7 s, VM
power-cycle 40-50 s, 4-node fresh cluster ~60 s, ssh RT 1-2 s/node):

| Gate | Script | Where | Workload basis (native) | Provisional budget |
|---|---|---|---|---|
| 1 | gate1_wire.sh | clyde | vectors+10^5-frame fuzz, pure CPU (est <10 s) | build(measured) + 30 s |
| 2 | gate2_midcomms.sh | clyde + 2 VMs | ~250 compressed scenarios ×~2 s + real-time subset ~150 s | build + 600 s; smoke: reset(~120 s) + 60 s |
| 3 | gate3_cawsanity.sh | 2 VMs | run.sh 2 caw posix_multi dlm_fairness (existing budgets 15/30 s) | reset + manifest budgets |
| 4 | gate4_shard.sh | clyde | 12 kill-points × 8 partitions × 3 seeds ≈ 300 scenarios | build + 900 s |
| 5 | gate5_mepoch.sh | clyde | ~14 scenarios incl. file-image restarts | build + 120 s |
| 6 | gate6_fence.sh | 4 VMs | ~20 scenarios; per-scenario = reset(~120 s) + drain/fence/recover (grace 8 s + fence + replay; native ≈ 30 s ⇒ ×2) | per-scenario ≤ 240 s, chunked |
| 7 | gate7_ladder.sh | 1-32 VMs | full suite per N; per-test budgets from manifests (net2 coefficients calibrated first ladder, then pinned) | per-test manifest budgets |
| 8 | gate8_overlay.sh | 1-32 VMs | gate-7 matrix + relay/TTL/dual-path faults | per-test manifest budgets |
| 9 | gate9_bastwake.sh | 1-32 VMs | CAW ladder + wakeup-drop/disconnect variants | existing CAW budgets |
| 10 | gate10_deleg.sh | clyde + VMs | delegation races (harness) + dlm_fairness/dlm_scaling reruns | build + 300 s; manifest budgets |
| 11 | gate11_envelope.sh | VMs | §13.4 matrix + posix_multi canary | per-scenario written at authoring |

Every gate script header carries its written derivation (the numbers
above + measured infra), enforces the budget with `timeout`, treats
timeout as FAIL (kill, record, diagnose — RULE 0.3), and appends
{budget, actual} to TIMEOUT_BUDGETS.md's table after a healthy PASS.
Gate-7 fault-injected repeats set net2_fault modparams per run (loss/dup/
reorder percentages + seeds recorded in the RESULT line for reproduction).
No outer kill-timeout around whole ladder invocations (ladder_rung.sh
rationale: killing run.sh mid-flight poisons the next hour); budgets are
enforced per-test by run.sh, per-scenario by the gate scripts.

## Verification

- Gate↔matrix mapping: gate 2 = review §5.1 (midcomms); gate 4 = §5.2
  (shard); gate 6 = §5.3 (fencing incl. existing-infra injections: fs_gen
  re-mkfs, evict-ring wrap — now exercising the 25-entry ring, MDS slot-0
  loss, ever_multi, conflicting replay observations); gate 7/8 = §5.4
  performance evidence (record native baseline, 2× budget, wall, freeze/
  fence/replay time, retx count, queue maxima, CPU, thread/socket count);
  gate 11 = plan §13.4. The §13 standing invariants assert in EVERY
  harness scenario and are grep-verified from kernel runs' counter dumps.
- The recovery-order assertion (`fence < exclusion-commit < replay <
  gen-advance < unfreeze/grant`) is checked from the step-6 trace markers
  by gate6_fence.sh on every scenario.
- End-to-end: after gate 7, `bench/rsync_bench.sh` paired native-XFS vs
  net2 (2× hard ceiling); fio_perf variance rules per tests memory
  (rerun-on-quiet-LUN).
- RULE 4 loop for every failure; RULE 5 escalation to GPT if a gate stalls
  without a proven diagnosis (never grind ≥2 sessions).

## Execution mechanics

- On approval: copy this plan into the repo as `/src/mxfs/DLM_IMPL_PLAN.md`
  (living checklist, per RULE-3 spirit; DLM_PLAN.md v2 stays the design of
  record) and create `docs/net2.md` (maintained every step).
- VERSION: minor bump to 0.11.0 when step-1 code lands; patch bump per
  subsequent gate landing (project version rule).
- Makefile/Kbuild: NO edits without explicit go-ahead. Checkpoint A =
  Kbuild net2 objects (before gate-2 kernel smoke); checkpoint B = step-12
  formalization. `tests/net2/Makefile` is a NEW standalone file (flagged
  here for approval as part of this plan).
- ccteam: claim dlm/ + tests/net2/ paths before edit batches, release
  after; checkpoint per landed step.
- Commits: only when directed (user rule); .ccmemory/ rides along per
  global rule when a commit is directed.
- CAW-green protection: gate 3 after the shared-code lift, gate 9 reruns
  the CAW ladder; any CAW regression at any point = stop-the-line fix
  before proceeding.
- No code before plan approval; no runtime enablement of envelope
  (default OFF) without gate 11.
