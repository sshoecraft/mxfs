# net2 — NET2 DLM network transport

**Status**: §11 step 3 COMPLETE (0.11.3, 2026-07-17) — gates 1-3
green. Gate 2 closed at 0.11.2: checkpoint A executed (Kbuild lists
the 5 net2 objects; port 7610 registered), first `__KERNEL__` compile
clean, kernel 2-node echo smoke PASS on test1/test2. Gate 3 closed at
0.11.3: dlm_shared lift, CAW provably unchanged (2/caw canaries green
on the lifted build; only test1/test2 run new builds — the other 30
VMs stay on 0.10.120). Design of record: `DLM_PLAN.md` (v2,
2026-07-17). Implementation checklist: `DLM_IMPL_PLAN.md`. Review of
record incl. fault matrices: `DLM_PLAN_REVIEW.md` §5.

## What it is

Third DLM transport (`MXFS_V5_TRANSPORT_NET2 3`) behind the `mxfs_v5_dlm_*`
seam, replacing legacy TCP (`dlm.c`/`peer.c`, retained as fallback) for
network-coordinated clusters. CAW remains the primary disk transport and is
untouched. Core properties: reliable per-incarnation sessions (seq/ack/sack/
retransmit/dedup), effect-idempotent lock ops over 1024 epoch-derived
replicated shards, single-authority membership (MEPOCH) with
fence-before-exclusion, scope-budgeted visible freezes, never-zero
grant_gen, both mesh and overlay topologies behind one routing abstraction.

## Architecture (files)

| File | Role | Step |
|---|---|---|
| `include/mxfs/mxfs_ports.h` | Port registry (names reflect reality; 7602 dual-use documented) | 1 |
| `dlm/net2_wire.h` | 64-B LE outer header, pack/unpack, TLVs, feature bits, static asserts | 1 |
| `dlm/net2.h` | Identity (`mxfs_net2_id`), priorities, tunables, lifecycle API | 1 |
| `dlm/net2_stats.h` | Per-session/per-class evidence counters (§13) | 1 |
| `dlm/net2_fault.{c,h}` | Fault injection, BOTH builds, seeded/deterministic | 1 |
| `dlm/net2_link.{c,h}` | Neighbor TCP links, per-link recv + prioritized egress | 2 |
| `dlm/net2_overlay.{c,h}` | Routing providers: mesh (default), overlay (gated) | 2/8 |
| `dlm/net2_midcomms.{c,h}` | Sessions, seq/ack/sack, retransmit, windows, dedup | 2 |
| `dlm/net2.c` / `net2_ctx.h` | ctx, lifecycle, recv demux, priority map | 2 |
| `dlm/dlm_shared.{c,h}` | Lifted resource hash + compat matrix (CAW-neutral) | 3 |
| `dlm/net2_msg.h` + `net2_shard.c` + `net2_lock.c` | Lock plane (§7.B) | 4 |
| `dlm/net2_membership.c` + `net2_epoch.c` | Observers + MEPOCH authority (§7.C) | 5 |
| `dlm/net2_fence.c` + `net2_freeze.c` | Fence ladder + budgeted freeze (§7.D/E) | 6 |
| `dlm/net2_bast.c` | CAW BAST_WAKE capability | 9 |
| `dlm/net2_caw_envelope.{c,h}` | Envelope delegation, default OFF | 11 |
| `tests/net2/` | User-mode protocol harness + gate scripts + vectors | all |

## Wire format (v1)

Outer header: 64 bytes, little-endian, packed/unpacked field-by-field via
`mxfs_cpu_to_le*`/`mxfs_le*_to_cpu` (pal.h) — never native-struct
serialized. Wire offsets are documented in `net2_wire.h`; the in-memory
struct is ordered for natural alignment (also exactly 64 B, asserted) and
does NOT mirror wire order — pack/unpack are the format authority. Payload
is the unchanged 32-B inner `mxfs_dlm_msg_hdr` + body (opaque). Framing:
read 64, validate, read `payload_len` (≤ 8192); no fragmentation.

## Core engine (step 2)

Thread inventory per ctx (mesh, N peers): 1 accept + 1 RT + per active
link {1 recv + 1 egress} + short-lived outbound handshake threads.
Lock order: `ctx->lock > link->lock > sess->lock > stats/fault locks`;
never two session locks at once. Sessions are refcounted (table/GC ref,
link binding, every egress queue reference); a session is freed only at
refs==0, so egress entries can never dangle.

**Links** (`net2_link.c`, forked from peer.c): lower-SLOT-initiates —
links[slot<self] are inbound-only, links[slot>self] outbound-only, which
removes peer.c's accept/connect cross-races (Bug-80 family) entirely.
Teardown keeps peer.c's discipline (shutdown → join threads → close →
install) but DEPARTS from the sess40 keep-socket-up policy: links drop
and reconnect freely because the retransmit ring owns delivery; a link
event is a routing event, never node death. The SYN/SYN_ACK handshake
carries the TLV block (full UUID, volume, fs_gen, boot nonce, features,
wire version) and is fail-closed; a rejected handshake applies a 10 ms
accept backoff (interim per-source rate limiting until step 5).
Egress: weighted deficit round-robin (quanta = tun.quantum_pct of a
32 KB round, strict class order per round, fresh:retx 3:1 alternation
inside a class), standalone ACKs sent first each cycle; delayed-ACK
deadlines implemented as the worker's cond_timedwait (PAL has no timer
primitive — periodic work is threads, disklock.h precedent).

**Midcomms** (`net2_midcomms.c`): sessions keyed {slot, incarnation,
nonce}. Reconnect with the same identity RESUMES the session (resumes
counter); a new incarnation/nonce SUPERSEDES it — remaining ring entries
retire with explicit session-abort dispositions and the dead session's
counters fold into `stats.retired` so the §13 evidence survives the
table moving on. Sends to a not-yet-handshaken peer create an EMBRYONIC
session that buffers in the ring; the handshake adopts it (matching inc)
or aborts it (different inc). Epoch is stamped at ENQUEUE and never
restamped on retransmit; rx accepts E and E-1 (bridge window §7.A) and
drops older with stale_epoch_drops. dst-incarnation mismatch and
superseded-session frames drop with stale_incarnation_drops (slot-reuse
ABA guard, §5).

**Delivery is ON-RECEIPT — deliberately NO reorder-hold.** Holding
frames for seq order would let a congested lower class delay a higher
one end-to-end, defeating §7.A's whole point (RELEASE > REVOKE under
BAST storms). §7.A specifies exactly cum-ack + 32-bit SACK + msg_id
dedup, which is what exists: a 64-bit rcvd_mask dedups the transport
level, the 1024-entry msg_id ring suppresses caller-level retries, and
ordering tolerance lives in the lock handlers (op identity + replicated
completed-op cache, §6/§7.B). Within one class on a healthy link,
arrival order still equals send order (FIFO queue + TCP).

**Flow/backpressure**: tx window = tun.tx_win (64) unacked frames per
session direction. Window-full GRANT/DISCOVERY sends return -EAGAIN
(callers retry — the seam's contract at step 7). Window-full
FENCE/RELEASE/REVOKE sends return **-ENOBUFS with the op left in the
caller's hands** plus COMM_AMBIGUOUS + the freeze-hook callback (step 6
wires the real freeze); the class-queue caps behave the same way. In
both shapes nothing is ever silently dropped, and queue_full counters
record every event. >ambiguity_ms (10 s) unacked — including entries
never transmitted because no route exists — raises COMM_AMBIGUOUS once
per episode; ack progress clears it with a recovery log line.

**Step-2 deviations from the plan sketch** (all argued above): 
deliver-on-receipt (no reorder-hold); per-slot listen ports
(`base_port + slot` — §14 has no NET2 link port; a
`MXFS_PORT_NET2_LINK_BASE` registry addition is proposed at checkpoint
A); -ENOBUFS coherence backpressure semantics; `stats.retired` fold;
small API additions to net2.h (`set_peer_addr`, `get_stats`,
`get_session_stats`, `set_ambiguous_cb`, fault control,
`link_reset`) that the engine, the step-7 seam, and the harness
factually need.

**Known interim items** (tracked for later steps): superseded-session
GC uses a suspect_grace_ms age (step 5 replaces the clock with epoch
observation; unfreeze semantics are NOT involved); per-source SYN rate
limiting is the accept-backoff sleep until membership lands; user-PAL
`tcp_connect` has no timeout, so a kernel-side connect-timeout check
belongs to the step-7 review (the harness's localhost connects fail
fast; conn threads are one-shot and cut loose after 5 s by the RT
sweep).

**Kernel build + smoke (0.11.2)**: the engine's first `__KERNEL__`
compile surfaced exactly two real issues, both stack-frame size
(>1KB) in `net2_midcomms.c` — the 64-entry on-stack snapshot arrays in
`resume_flush`/`rto_scan`. Reworked to 16-entry chunked snapshots
(`NET2_ENQ_BATCH`; the snapshot pattern itself is load-bearing:
link->lock ranks above sess->lock, so enqueue must run with sess->lock
dropped, re-locking between chunks), and COMM_AMBIGUOUS is reported
per-session right after its enqueue phase (peer_slot/peer_inc are
immutable session identity, safe to read unlocked under a ref).
Gate-2 kernel smoke = `net2_selftest` modparam driver at the bottom of
net2.c (kernel-only block, v5_mount.c modparam precedent), hooked from
module init/exit via xfs_super.c's declare-directly convention: builds
a standalone ctx, echoes reliable PINGs with PONGs sent from recv-cb
context (the step-7 seam dispatch shape — `net2_deliver` calls the cb
with no engine locks held), requires full ACK coverage, prints one
dmesg marker, then a **3 s post-pass linger** before teardown. The
linger is the run-1 lesson: an early finisher closing its ctx within
ms of its own pass starves the peer's tail ACKs — the peer then shows
acked<created with retx=0 (link_down clears enqueued; no-route
enqueues never reach the wire, so nothing counts as a retransmit) and
raises COMM_AMBIGUOUS at exactly ambiguity_ms. That is the engine's
*specified* peer-death behavior (membership/fencing owns it from step
5 on); the smoke driver simply must not manufacture it. msgs is capped
at 24: ping+pong ≤ 48 < the 64-entry tx ring, so the recv cb never
sees window backpressure — it runs on the link recv thread, which also
processes incoming ACKs, and must never block there.

**Sanitizers** (0.11.1): full matrix clean under AddressSanitizer
(0 errors, 0 leaks). ThreadSanitizer reports exactly two flagged
objects — the `volatile bool running` / `pending_sock` stop-latches —
which are the established peer.c idiom (one-way latch + socket-shutdown
wakeup as the real synchronization); every mutex-guarded engine
structure (rings, queues, sessions, stats, fault state) is race-free
under the full matrix. TSan on this host needs `setarch -R` (6.8 ASLR
vs libtsan).

## Harness (step 2)

`tests/net2/harness/vcluster.c`: N in-process nodes = N real
`mxfs_net2_ctx` instances on 127.0.0.1:base+slot through the same
`mxfs_pal_tcp_*` code the kernel will use; identities (uuid, nonces,
incarnations) derive deterministically from the scenario seed; restart
= ctx destroy + recreate with inc+1 and a new nonce (§5 semantics —
same-identity-empty-state cannot exist in production, so it cannot be
constructed here either). Time runs compressed ÷10 for breadth; the
pinned real-time subset (`net2_harness run rt`: mc_basic, mc_loss_data,
mc_reset_framing) reruns at spec defaults because compression can mask
races. Reliable tags are unique per op (dedup evidence); unreliable
tags carry VC_TAG_UNREL. Every scenario ends with
`vc_assert_invariants` — the §13 standing invariants read from the
evidence counters. 15 scenarios cover the §13.1 matrix; see
`scen_midcomms.c` and gate2_midcomms.sh for the run shape and budget.

## Lock plane (step 4)

Harness-only for now: `net2_msg.h` + `net2_shard.c` + `net2_lock.c` are
NOT in Kbuild; the kernel module carries only the step-2 engine (plus the
step-4 midcomms/link fixes noted in History).

- **Shape**: 1024 shards (`FNV1a(uuid‖resource)&1023`), HRW top-3 replica
  derivation keyed {slot,inc} per membership epoch, bounded 64-entry log
  ring, 2-of-3 quorum commit with chain-discipline acks (an ack of seq N
  covers every uncommitted seq ≤ N), leader emits results only at commit.
  Client ops (`net2_lock_acquire/release/convert`) retry on a 150 ms
  cadence, rotate targets over the replica set on silence, follow
  NOT_LEADER hints, and are effect-idempotent via the replicated
  completed-op cache (per-client-inc 64-entry rings, carried in
  snapshots).
- **Leader completeness (the load-bearing rule set)**: committed log
  entries are immutable — an append that would rewrite one is NACKed
  (duplicates are detected by full op identity {seq, term, op, slot,
  inc, request_id}, not (seq,term) alone). A NACK whose
  `commit_watermark` exceeds the leader's own commit proves the follower
  is MORE complete: the leader abdicates into a snapshot pull from it
  and re-barriers at a higher term. A leader may answer client ops only
  once `term_proven` — an entry of its own term committed on the quorum
  (the TERM barrier normally; `net2_shard_prove_term()` kicks one if
  needed and the client sees RETRY denials meanwhile). A lazily-created
  rank-0 that has live peers pulls-from-ALL before serving: every peer's
  chunk0 is a completeness vote (an empty answer votes "no state"), the
  best (base, src_last) pair wins and PREEMPTS a claimed stream, and
  finding nothing anywhere runs the closed-set recovery barrier — never
  an empty-table conclusion (§7.B).
- **Snapshots**: SNAPSHOT_CHUNK carries base + src_last in every chunk
  plus rec_count 64 B records (holders/waiters/opcache/recmeta) and, in
  a trailing chunk, the source's un-applied log suffix (commit+1..last)
  as 96 B log records. The pulling leader installs the suffix
  uncommitted and its barrier re-commits it — acked-but-unwatermarked
  entries (committed on a dead leader, watermark never piggybacked)
  survive the transfer. Sources serve from any state incl. SH_FROZEN;
  a serving leader ignores stray chunks; leader-pushed catch-up
  snapshots to lagging replicas use the same format (unsolicited path,
  accepted only when ahead of local commit).
- **Elections**: vote solicits carry (cand_term, commit, last); voters
  refuse less-complete candidates and anything ≤ their voted_term; each
  candidacy round escalates to a FRESH term above anything seen/voted
  (a constant term+1 livelocks two simultaneous self-voted candidates).
  Reconfigure keeps unchanged-R shards serving; a was-replica leader
  re-barriers at term+1; a was-not-replica rank-0 pulls from old-R
  survivors; no survivor ⇒ recovery barrier. The recovering leader
  installs its OWN held records (the implicit self-report bit alone is
  not a report).
- **Epoch bridge**: lockplane dispatch accepts the same membership-epoch
  window midcomms does (drop only mep+1 < E). The epoch-commit wave is
  not atomic across nodes; the new leader's barrier appends arrive
  stamped E+1 at nodes still on E and must not be dropped (they have no
  transport retry — the reliable layer already delivered them).
- **Semantics**: per-node holds (CAW slot model) — an acquire at a
  different mode from the current holder is an upgrade/downgrade
  request, judged with the requester's own holds excluded
  (`rec_slot_view`); same-mode re-acquire re-acks the existing tenure.
  BASTs fan out on the first blocked request (any blocked mode pokes
  every conflicting holder); waiter order is FIFO by replicated
  enq_seq with the EX-streak fairness mirror.
- **Known deferrals**: no leader heartbeat/re-append sweep (a stalled
  uncommitted entry waits for the next append or an election; real
  failure detection and hold-reaping for dead incarnations arrive with
  step 5's membership plane); grant-in-limbo to an unreachable client
  is cleaned by the client's orphan detached-release on delivery, or by
  step-5 exclusion.

## Membership plane (step 5)

`dlm/net2_epoch.{c,h}` + `dlm/net2_membership.{c,h}` — the §7.C
membership-epoch authority and its liveness observers.  Both builds,
PAL only; harness-only for now (NOT in Kbuild — kernel wiring is the
step-7 seam's job, backed by the real disklock I/O path).

**The record.** One committed `struct mxfs_mepoch_rec` (44 B, LE, own
magic "MEPO" + crc32c over bytes 0..39) is the single source of truth
for {epoch, member_mask, fenced_mask, incarnations}.  It lives at
offset 456 of every node's OWN 512-B disklock HB record (single-writer
sector; evict ring shrank 28→25 entries to make room) and every node
republishes the latest committed record there.  Epoch-0 records are
incarnation-bump carriers only (mount bumps `self_incarnation` BEFORE
joining, preserving any other content including a stale PREPARED) —
bootstrap and the disk scan never adopt them as committed authority.

**Single-decree rounds.** Proposer = lowest ALIVE voter of the
committed epoch E (next-lowest takes over once the lowest is SUSPECT
for 2× probe interval); voters = the 3 lowest slots of E's member mask
(5 at ≥16 members).  E+1 needs a majority of E's voters: each voter
validates (monotonic E+1, fenced' ⊇ fenced, every removal covered by
`fence_ok` proof, no conflicting same-epoch promise), persists the
candidate PREPARED in its own HB record, THEN acks — so a proposer
crash can never fork the epoch: the next deterministic proposer adopts
any PREPARED candidate (its own or one found on disk) and completes
the SAME decree.  COMMIT broadcasts to old ∪ new members; adoption
re-derives everything downstream (`committed_cb` → update_view in the
harness).  A dead-reason NACK (NO_FENCE_PROOF / FENCED_SHRANK) kills
the round immediately; other NACKs leave it retrying
(`round_status` exposes both as gate evidence).

**Exclusion, leave, rejoin.** `fence_ok` is the removal-authorization
proof mask (§7.D fence_done OR clean-leave); the fenced BIT marks real
fences only.  Self-fence fires at ADOPTION on the member→excluded+
fenced-bit transition — uniformly for rx-COMMIT and the periodic disk
scan (an excluded node with ZERO network still learns from the LUN
within a probe interval).  A bootstrap adoption has no prior view, so
a restarted node whose old incarnation was fenced REJOINS with its
bumped incarnation instead of killing itself; a clean leaver (bit
clear) adopts its own removal without self-fencing.

**Lease.** `lease_ms` (10 s default) without hearing any voter (or
adopting) ⇒ visible freeze via `freeze_cb` (§7.E: never silent);
any voter rx or adoption refreshes and unfreezes.

**Observers (`net2_membership`).** Liveness is a vote of three
independent observers — lease multicast, NET2 probe, disklock HB
advance — never one timer: ≥2 missing ⇒ SUSPECT; a same-{inc, nonce}
reconnect within grace resumes ACTIVE (a different incarnation NEVER
resumes the old one); grace elapsed ⇒ FENCING; DEAD only via
incarnation-qualified `fence_done`.  Transitions surface via a
callback (outside the lock) that feeds `net2_mepoch_suspect` and,
at step 6, the fence engine.

**Gate 5** (`tests/net2/gate5_mepoch.sh`, 108 s / 120 s pinned): the 8
`mep_*` scenarios over a shared file-backed 64×512 B image at the true
`offsetof(heartbeat, mepoch)` (static-asserted) — bootstrap self-
quorum, join/leave (with the leave-vs-fence distinction), proposer
crash → PREPARED adoption of the same decree, voter-minority stall
(open round + zero commit + visible freeze), whole-cluster restart
adoption, zero-network disk self-fence (delivery-counter-proven),
no-fence-proof NACK, and the SUSPECT/inc-bump machine — × 4 seeds,
N2_DEBUG pass, full-suite ASan sweep.  `tools/chk_mxfs` decodes the
per-slot records (PREPARED labeled, never counted as committed; bad
crc errs) — verified against engine-sealed records on a loop device.

Harness note: vcluster port blocks are 16 apart from 23000 (was 256 —
a full suite's 42 clusters reached listener ports INSIDE the ephemeral
range, where a transient outbound source port fails the bind; proven
root cause of a rare last-scenario env-start FAIL).  Gate 2's matrix
is the `midcomms` group (wire statics + §13.1); gates 4/5 own their
groups and the full-suite ASan sweeps.

## History

- 2026-07-18 (ccloop sess04): step 5 COMPLETED as 0.11.5 — gate 5
  GREEN (`gate5_mepoch.sh`: 8 mepoch scenarios × 4 seeds + N2_DEBUG
  pass + full-suite ASan, 108 s / 120 s pinned).  First build of
  net2_epoch.c caught three review defects pre-run (kernel-guarded
  stdio, suspicion-timestamp refresh livelock, self-fence mis-scoped
  to the raw disk scan — centralized at adoption with the was-member
  transition, making rejoin and clean-leave safe).  User PAL gained
  crc32c (kernel-identical semantics, check-vector verified).
  chk_mxfs MEPOCH decode validated on a loop device against
  engine-sealed records incl. a corrupt-crc negative.  One flake
  root-caused by measurement: harness listener ports crossed into the
  ephemeral range at the old 256 stride (42 clusters × 256 from 23000
  = 33496) — stride now 16, all gates re-run green (g1 9 s, g2 39 s
  re-scoped to `run midcomms`, g4 210 s, g5 108 s).

- 2026-07-17 (ccloop sess03): step 4 COMPLETED as 0.11.4 — gate 4 GREEN
  (`gate4_shard.sh`: 11 shard scenarios × 4 seeds + full-suite ASan,
  199 s wall / 300 s pinned). Five engine defects found and fixed via
  instrumented RULE-4 loops: (1) self-appointed empty rank-0 could
  serve after restart — leader-completeness rule set added
  (immutable-committed NACK, abdicate-on-more-complete-follower,
  term_proven serve-gate, lazy-create pull-from-all); (2) the snapshot
  base never crossed the wire (SNAPSHOT_CHUNK body 16→32 B) so the
  fastest/emptiest source won the claim; (3) acked-but-unwatermarked
  log suffixes were dropped by snapshot pulls — now transferred and
  re-committed by the barrier; (4) election candidacy at constant
  term+1 livelocked simultaneous candidates — terms escalate per round;
  (5) lockplane dispatch dropped E±1 traffic during the epoch-commit
  wave — bridge window now matches midcomms. Plus (in mxfs.ko):
  delayed-ACK arming now kicks the egress worker — previously every
  one-way exchange waited out the peer's RTO (retx ≈ every message,
  +150 ms/op). Kernel `make modules` clean, srcversion
  CA4E3BEF091ED5F4777EF8D (not deployed; test1/test2 stay on 0.11.3).
  Scenario fixes: sh_reconfig resource collision (202), sh_two_loss
  cross-node conflict, sh_partitions isolates a CURRENT follower.
- 2026-07-17 (ccloop sess01): step 3 LANDED as 0.11.3 — gate 3 GREEN.
  dlm_shared.{c,h} lift (identical bodies; deduped dlm.c's lock_compat
  copy + dlm_caw.c's fnv1a_hash + the popcount #ifdef pair);
  gate3_cawsanity.sh fresh 2/caw prep + posix_multi 211/211 +
  dlm_fairness 5/5 on test1/test2, 32 s vs 300 s provisional (pinned
  120). Two infra lessons: `make clean` deletes tools/ binaries that
  run.sh's fs-prep needs over NFS (rebuild with `make tools`), and the
  shared LUN is dm-multipath — MXFS_DEV=/dev/mapper/mpatha, bare
  /dev/sda is held open by multipathd.
- 2026-07-17 (ccloop sess01): gate 2 COMPLETED as 0.11.2 — checkpoint A
  Kbuild edit + port 7610 + frame-size chunking + net2_selftest smoke
  driver; 2-node kernel smoke PASS on test1/test2 (run 1 exposed the
  early-finisher teardown race in the DRIVER, fixed with post-pass
  linger; run 2 clean 13 s / 60 s pinned). User matrix re-verified at
  final source (29 s / 45 s).
- 2026-07-17: step 1 started post plan approval. Layout collision found and
  resolved in plan: MEPOCH record (44 B) does not fit HB `reserved[8]`
  (evict ring consumed the reserve in sess55); resolution = evict ring
  28→25 entries at step 5.
- 2026-07-17 (step-2 session): step 2 LANDED user-mode as 0.11.1 — gate
  2 USER PART GREEN. Files: net2_ctx.h, net2.c, net2_link.{c,h},
  net2_overlay.{c,h} (mesh), net2_midcomms.{c,h}; harness vcluster +
  15-scenario §13.1 matrix + gate2_midcomms.sh (19/19 ×3 seeds + rt
  subset + ASan sweep; 27 s vs 45 s pinned). Kernel `make modules`
  clean, srcversion UNCHANGED 5221BFFE305AF21A (net2 objects not in
  Kbuild — checkpoint A pending). Three engine-behavior findings during
  bring-up, all harness-side in the end: cumulative ACKs self-heal
  ACK-loss in a fast stream (retx only forced by a pause — scenario
  redesigned), sender restart resets sender counters (invariants count
  current-incarnation deliveries only), and a cross-cluster SYN aimed at
  the wrong node's port is dropped on dst_slot before UUID validation
  (scenario now aims at the right listener).
- 2026-07-17 (same session): step 1 LANDED as 0.11.0 — gate 1 GREEN.
  Files: mxfs_ports.h (+9 call-site migrations, zero behavior change),
  net2_wire.h, net2.h, net2_stats.h, net2_fault.{c,h}, tests/net2/
  (harness + Makefile + gate1_wire.sh + 8 golden vectors). Harness: 76
  checks PASS, 1 s wall (30 s budget). Kernel: clean build, srcversion
  5221BFFE305AF21A; module behavior unchanged — cluster stays on
  0.10.120/F2443A0C until step-2 smoke. First-ever compile of pal.h's
  user branch succeeded with -Wall -Wextra -Werror (no bitrot found in
  the byteorder path the harness exercises).
