# DLM Protocol Specification

## Transport choice: why CAW is primary

CAW (SCSI Compare-And-Write) is MXFS's primary DLM coordination transport. That
is a deliberate scaling choice, and the evidence for it is in the prior-art tree
(`~/src/mxfs.1/`, continued in mxfs.2/3):

- `~/src/mxfs.1/README.md` and `docs/architecture.md`: TCP DLM is *correct* at
  32 nodes — zero crashes, zero corruption — but performance-limited above ~16
  nodes by the single-lock-master-per-resource serial bottleneck. The 32-node
  test reached only 27% metadata completion; the 16-node test passed 100%.
- `~/src/mxfs.1/bench.json`: TCP DLM shows a 6.5–7.7× per-node write imbalance
  at 4+ nodes. CAW shows a 1.01× spread on identical hardware.
- `~/src/mxfs.1/libmxfs/lease.md`: at 16+ nodes the DLM opens 120 TCP peer
  connections; heavy DLM traffic fills the send buffers, blocks lease renewals
  and cascades into false node-death. Heartbeats were moved off TCP onto UDP
  multicast for exactly this reason.
- `~/src/mxfs.1/libmxfs/mount.c::check_tcp_scale_warning` already emits a
  one-shot warning recommending CAW above 16 TCP DLM nodes.
- `~/src/mxfs.1/scale_tests_session10.txt`: CAW has its own scaling cost — BAST
  poll I/O at 8 nodes can saturate the iSCSI target — addressed by reducing poll
  frequency and by the BAST yield quantum (`MXFS_BAST_YIELD_QUANTUM`).

The user's shorthand for this is "TCP saturates and begins to lose packets,
around 24 nodes it completely falls off". The spirit is right; the mechanism is
narrower. TCP DLM does not lose data at 32 nodes. It is unusable in production
there because of (a) the serial lock-master bottleneck and (b) TCP send-buffer
congestion causing cascading false-death disconnects.

What follows from that:

- **When a CAW bug is found, fix CAW.** "Switch the lock-coordination critical
  path to the kernel TCP DLM" is not an architectural cure — the prior-art
  evidence against it is unambiguous at production scale.
- TCP DLM (`dlm/v5_mount.c`, `mxfs.force_transport=1`) is a legitimate fallback
  for hardware without CAW support and for clusters below ~16 nodes, and it must
  keep working. It is not a substitute for CAW above that.
- When comparing MXFS to GFS2/OCFS2, keep the two axes apart. Their *transport*
  is kernel TCP DLM and they do not target >24-node shared filesystems, so it is
  not a model here. Their *cache-coherency contract on release/demote* is a good
  reference, and is used as one — see the prior-art section of
  `docs/ag-metadata-coherency.md`. The contract is independent of the transport.
- The kernel `scsi_execute_cmd` non-persistence bug (the sess26 P49-INSTR
  finding) is a real kernel SCSI passthrough bug worth root-causing — not
  evidence that CAW is the wrong primitive.

## Wire Format

All daemon-to-daemon messages are length-prefixed and begin with
`struct mxfs_dlm_msg_hdr`:

```
┌──────────┬──────────┬──────────┬──────────┐
│  magic   │ version  │   type   │  length  │
│  (4B)    │  (2B)    │  (2B)    │  (4B)    │
├──────────┼──────────┼──────────┴──────────┤
│   seq    │  sender  │      target         │
│  (4B)    │  (4B)    │      (4B)           │
├──────────┴──────────┴─────────────────────┤
│                epoch (8B)                 │
├───────────────────────────────────────────┤
│          message-specific payload         │
└───────────────────────────────────────────┘
```

- **magic**: 0x4D584653 ("MXFS")
- **version**: Protocol version (currently 1)
- **type**: One of `mxfs_dlm_msg_type`
- **length**: Total message length including header
- **seq**: Sender's monotonically increasing sequence number
- **sender**: Sender's node ID
- **target**: Target node ID (0 for broadcast-originated messages)
- **epoch**: Sender's current lease epoch

## Message Types

### Lock Operations

**LOCK_REQ** — Request a distributed lock
- Payload: `mxfs_dlm_lock_req` (resource ID, mode, flags)
- Sent to the master node (lowest node ID in cluster)

**LOCK_GRANT** — Lock has been granted
- Payload: `mxfs_dlm_lock_resp` (resource, granted mode, status)
- Sent from master to requester

**LOCK_DENY** — Lock request denied
- Payload: `mxfs_dlm_lock_resp` (resource, status=error code)
- Sent when NOQUEUE flag set and lock incompatible

**LOCK_RELEASE** — Release a held lock
- Payload: `mxfs_dlm_lock_release` (resource ID)
- May trigger grant of queued waiters

**LOCK_RELEASE_ACK** — (sess422, TCP authority ledger step 3) the master
retired the releaser's durable record (or it was already superseded)
- Payload: `mxfs_dlm_release_ack` (resource, rel_id, grant id)
- The holder keeps `rel_pending` state and re-sends the RELEASE every 500 ms
  until the ACK; `release_all` waits (bounded) for every ACK

**PAGE_HANDOFF** — (sess423-424, step 4) ledger page authority handoff
- Payload: `mxfs_dlm_page_handoff` (page, kind, target node+inc, config_id,
  prepared_seq, authority node+inc)
- kinds: FREEZE_REQ (view-named owner asks the current authority), FROZEN
  (authority wrote PREPARED durably; carries the exact prepared_seq the
  target must consume), DEFER (config mismatch / not yet), NOT_OWNER
  (sender is not the authority; requester re-reads and re-routes)

**LOCK_CONVERT** — Convert lock mode (upgrade or downgrade)
- Uses LOCK_REQ with MXFS_LKF_CONVERT flag

**LOCK_BAST** — Blocking AST (downgrade request)
- Payload: `mxfs_dlm_bast` (resource, requested mode)
- Sent from master to current holder when a conflicting request arrives
- Holder should downgrade or release within bast_timeout_ms

**LOCK_QUEUED** — the master has this request and has queued it
- Payload: `mxfs_dlm_lock_resp`; `mode` is the BLOCKING HOLDER's mode, not a
  granted mode, and `req_id` names the attempt being answered
- Sent after the WAITING entry is in the table, so the receipt never runs
  ahead of the thing it attests to

### A queued request, its receipt, and the wait it belongs to

Three separate things are easy to confuse here, and every one of them has
been the subject of a defect.

**Silence is ambiguous.** A master that queues a remote request used to
answer it with nothing, and a request that never arrived also produces
nothing. A requester whose acquire budget has run out must choose between
waiting longer and failing, and that choice depends on exactly the
distinction silence destroys. LOCK_QUEUED is the acceptance receipt that
separates them. It is an acceptance, NOT a promise of progress: a master can
go on queueing a request behind a holder that never releases. What it rules
out is that nothing at the other end has the request at all.

**A receipt is evidence that decays.** The requester keeps receipts in a
small per-resource ring, newest wins, and reads one as evidence only while
it is younger than a staleness window derived from the one-second re-send
cadence. Nothing expires an entry explicitly, because a stale entry and a
missing one must lead to the same answer. The ring is keyed per RESOURCE
rather than per request: the pending entry that names a request id is freed
and reallocated every second, so a per-request key would never survive a
re-send. The precision that costs runs in one direction only — another
task's receipt for the same inode can make this acquire look answered — and
that direction only ever makes a requester wait LONGER.

**A transport attempt is not an acquisition.** `req_id` names one
one-second attempt. `acq_seq` names the WAIT those attempts belong to:
minted once per resource-and-mode while an acquire is live, carried by every
re-send and by every restart of the acquire classifier above it, and
qualified by `{sender, owner_inc}` so it cannot collide across a requester's
restarts. A re-send whose `{acq_seq, owner_inc, mode}` matches an existing
WAITING entry is the SAME wait: the master keeps that entry, so it keeps its
position in the chain and it keeps `queued_at`.

That last property is load-bearing in two places:

- **FIFO position.** Waiters are promoted oldest-`queued_at` first. When a
  re-send replaced the entry, a remote waiter returned to the BACK of the
  FIFO once a second, for as long as it waited — so its recorded age never
  exceeded the re-send interval no matter how long the wait really was, and
  a waiter whose age does not reset (a local one) outranked it indefinitely.
  An arrival barrier stops a NEWLY ARRIVING request from being granted past
  a queued waiter; it does nothing for a waiter whose own age is erased
  every second.
- **Blocking notifications.** Re-queuing fired another BAST at the holder on
  every re-send. Measured on two nodes over a single 244 s acquire behind
  one live holder: 238 notifications at the holder against 234 re-sends by
  the requester, for one wait. A notification can still be lost, so a
  re-send still recovers one — but on its own interval
  (`MXFS_DLM_ACQ_BAST_REFIRE_MS`), which bounds recovery of a lost
  notification without letting the re-send cadence become the notification
  cadence.

A re-send that asks for a different mode, or carries a different requester
incarnation, is a different request: it does not inherit the entry, and it
does not inherit the name. Requests from a sender that mints no acquisition
(`acq_seq == 0`) take the original replace-and-requeue path unchanged.

**The name is per resource-and-mode, per NODE — not per task, and that is a
decision rather than an oversight.** The master's lookup is the resource plus
the SENDING NODE, so its data model is one wait per node per resource and
always has been. A name made unique per task or per acquisition invocation
would fail the `{acq_seq, owner_inc, mode}` test on a second task's re-send,
dropping it onto the replace-and-requeue path — which is one notification per
re-send for that shape, i.e. the defect this mechanism removes. Making the
name "more correct" re-breaks it.

The cost of the shared name is real but narrow, and it falls on the local
path only: two tasks on one node genuinely allocate two waiting entries for
one resource, and both then take their queue time from the same record. They
therefore carry IDENTICAL `queued_at`, and the promotion sort is the kernel's
`sort()` — heapsort, which is not stable — so their order relative to each
other is arbitrary where it previously followed their differing stamps. The
first of the two to finish also retires the record while the other still
waits, restarting the survivor's age and notification clock. Both are
fairness between two waits on one node; neither is a correctness or liveness
property. Measured reachable and free: two readers of one inode in one mode
produced 114 record-sharing events in a single wait and the same 25
notifications as one reader.

**The same pathology exists on the LOCAL-master path and is fixed there too.**
When the waiting node is itself the master there is no wire message: it
allocates a waiting entry, waits one second, times out, FREES the entry, and
the next attempt allocates another. So the entry's queue time was re-stamped
once a second and the notification was fired from the same block that
allocates it. The remote shape cannot be copied across — this path's
existing-entry branch returns a code the acquire classifier reads as
unrecoverable, which would shut the mount down instead of waiting — so
instead the re-created entry takes its queue time from the acquisition record
and the deferred notification is gated on that record's own interval.
Measured: 237 notifications for one 243 s locally-mastered wait before, 25-26
after, on an unchanged re-send cadence.

**`MXFS_DLM_ACQ_BAST_REFIRE_MS` is a suppression interval, not a delivery
guarantee.** It means "no further notification permitted for ten seconds". It
does not mean every blocker is notified within ten seconds, and it is keyed on
the REQUESTER's wait rather than on which blocking grant has been told — so a
holder that releases and is replaced by a different conflicting holder inside
the interval leaves that new holder's first notification suppressed for the
remainder of it. That is bounded only because the blocker list is
re-collected unconditionally on every attempt and ONLY the fire is gated.
That clause is load-bearing: BAST collection copies holder and mode into a
local array and mutates no lock state, takes no references and clears no
flags. If collection ever consumed the notification obligation — a "notified"
bit, a cleared pending flag, a reference released only by the fire — a
suppressed fire would lose it permanently and later collections would find
nothing to send, which is an indefinite wait. Anything added to that
collection loop must preserve this.

### Lease Management

**LEASE_RENEW** — Periodic lease renewal
- Payload: `mxfs_dlm_lease_msg` (duration, lock count)
- Sent to all peers at lease_renew_ms interval

**LEASE_ACK** — Acknowledgment of lease renewal
- Payload: `mxfs_dlm_lease_msg`
- Confirms the peer has recorded the renewal

**LEASE_EXPIRE** — Notification that a node's lease has expired
- Payload: `mxfs_dlm_lease_msg`
- Broadcast to all nodes when a peer is declared dead

### Node Membership

**NODE_JOIN** — Node joining the cluster
- Payload: `mxfs_dlm_node_msg` (name, port)
- Triggers handshake and lock table synchronization

**NODE_LEAVE** — Graceful node departure
- Payload: `mxfs_dlm_node_msg`
- Allows orderly lock release before disconnect
- Receiver gate (0.29.0, sess418, D-0286): a NODE_LEAVE from an identity
  the receiver has already retired (fenced/dead) or whose heartbeat slot is
  recovery-pending is IGNORED (`P-GOODBYE-DEAD-IGNORED`).  Death dominates a
  delayed goodbye: such a node's grants are released only by recovery
  completion, never by its goodbye.

#### Departure state machine (0.29.0, sess418, D-TCP-WEDGE-PIN-NOOP-REPORTS-SUCCESS-0286)

Every mount incarnation carries one atomic word, `depart_state`:

    ACTIVE ──(teardown: all drains done, holds proven gone)──▶ CLEAN_LEAVE
      │                                                              
      └──(first force-shutdown of the FS, SYNCHRONOUS)──▶ POISONED (terminal)

- `mxfs_v5_dlm_poison()` is the non-sleeping half of withdrawal.  It is
  called from `xfs_do_force_shutdown` (via `mxfs_dlm_shutdown_withdraw`)
  BEFORE the withdraw work is queued, so the acquire gates, the master-duty
  drop, and the clean-departure gate all observe the poison in the same
  instant as the shutdown — never a workqueue-latency later.  The sleeping
  half (`mxfs_v5_dlm_shutdown_withdraw`: disklock WITHDRAWN stamp, discovery
  stop) keys its idempotency on `withdraw_done`, not on `withdrawn`.
- The teardown (`mxfs_v5_dlm_shutdown_defer_release`) computes
  `depart_clean` and then takes ACTIVE→CLEAN_LEAVE with one cmpxchg.  That
  CAS is the linearization point against a concurrent poison: if the poison
  landed first the CAS fails (`P-DEPART-POISON-WINS`) and the teardown sends
  no GOODBYE and leaves the heartbeat record ACTIVE, so peers fence and
  replay the node.  A poison that lands after CLEAN_LEAVE logs
  `P-POISON-AFTER-CLEAN-LEAVE` — it is unreachable by construction (no
  drain runs after the point where every drain succeeded) and is a defect
  if seen.
- On TCP this is what "pin" means.  There is no per-resource pin in the
  master's in-memory table (the pin helpers return `-EOPNOTSUPP`, 0.28.7);
  a wedged release poisons the whole session instead: no goodbye, no clean
  slot release, no wire unlock (the sticky WEDGED refusal of D-0285 sits
  above the transport), and the node is recovered like any death.

- Every TCP wire-release arm (`mxfs_v5_dlm_inode_unlock_open`,
  `mxfs_v5_dlm_iclus_unlock_gen`, `mxfs_v5_dlm_inode_release_unconditional`,
  `mxfs_v5_dlm_ag_unlock`) passes `v5_tcp_release_gate()`: after the poison it
  returns `-ESHUTDOWN` (`P-TCP-RELEASE-POISONED`; the AG arm reports
  `STILL_HELD`).  A release that reaches the wire after the FS is shut down is
  unproven by construction — no drain can complete once writes fail.
- Once the teardown has cleared `ctx->mounted`, the TCP message callback drops
  every lock message except NODE_LEAVE (`P-TEARDOWN-MSG-DROP`): a late GRANT
  would mint a local grant after `release_all`'s walk, a BAST would re-enter
  the XFS layer on a mount whose inodes are gone.  Peers blocked on this node
  are released by its goodbye (their `purge_node` → membership change →
  `fail_all_pending(RETRY)`) or by their death detection of it.
- `mxfs.dbg_depart_race=N` (1..5, one-shot) poisons the session from inside
  the teardown at pre-CAS / post-CAS / pre-send / post-send / post-slot-release
  so the linearization semantics are provable on the rig
  (`tests/d0286_depart_race.sh`): point 1 must yield `P-DEPART-POISON-WINS`
  and no goodbye; points 2–4 must leave the committed departure standing and
  fire `P-POISON-AFTER-CLEAN-LEAVE` exactly once.  Reachability on a clean
  unmount (sess419, measured): CAW = points 1, 2 only (3/4 are inside the
  TCP-only GOODBYE block); TCP = 1–4; point 5 is unreachable on every
  transport because Arm C hands the slot release out deferred (`late`) and
  the ctx is freed before `mxfs_v5_dlm_slot_release_commit` — the harness
  reports those as SKIP.  s419 32/caw: p1 13/13, p2 PASS.

The TCP death path (`v5_tcp_declare_dead`, suspect grace expired) no longer
purges a victim that owns a heartbeat slot.  It fences (a TCP-partitioned but
disk-alive node must still be converted into a dead one) and then leaves the
grants and mastership frozen (`P-TCPDEATH-DEFERRED`) until the disklock
recovery path replays the slice and `v5_recovered_cb` /
`mxfs_v5_dlm_recovery_complete` purge — the same deferred-purge protocol the
disklock path has followed since sess9 D2.  Only a slotless identity (owns
no journal slice) keeps the immediate purge.

**NODE_ALIVE** — Piggybacked on lease renewal for efficiency

### Recovery

**JOURNAL_RECOVER** — Claim responsibility for replaying a dead node's journal
- Payload: `mxfs_dlm_journal_msg` (dead node, journal slot)
- Sent by the node taking over recovery duties

**JOURNAL_DONE** — Journal replay completed
- Payload: `mxfs_dlm_journal_msg`
- Signals that the dead node's resources are safe to reuse

### Cache Coherency

**CACHE_INVAL** — Invalidate cached data for a resource
- Payload: `mxfs_dlm_cache_inval` (resource, byte range)
- Sent when a lock holder has modified data and is releasing

## Lock Mastering

Currently using a single-master model: the node with the lowest ID in the
cluster is the master for all resources. The master maintains the
authoritative lock table. Non-master nodes forward lock requests to the
master and block until receiving a LOCK_GRANT or LOCK_DENY response.

When the master node dies, the next-lowest node ID becomes the new master.
Lock table state must be reconstructed from the surviving nodes' local
knowledge of their own held locks.

Future optimization: per-resource mastering via `hash(resource_id) %
active_node_count` to distribute lock traffic across nodes.

## Node Death Sequence

1. Node B's lease renewals stop arriving at Node A
2. Node A's monitor thread detects B missed renewals
3. After node_timeout_ms, A declares B dead
4. A broadcasts LEASE_EXPIRE for B to all peers
5. A calls `mxfsd_dlm_purge_node(B)` — releases all B's locks
6. A sends JOURNAL_RECOVER claiming B's journal slot
7. A triggers XFS journal replay for B's slot
8. A sends JOURNAL_DONE when replay completes
9. B's resources are now available for reuse

## Recovery blocked on unprovable exclusion (0.74.0)

A dead node's journal slice is replayed only behind a PROVED exclusion (a
certified fence).  A fencing attempt that returns before submitting any
PREEMPT-family command — the victim's key is already absent from the target
and no sole-survivor gate applies, the target holds no reservation, the
registration view was truncated — proves nothing and consumes nothing, so it
is safe to repeat and the prover repeats it on a 0.25 → 6 s backoff.  What
0.74.0 adds is that the repetition is BOUNDED and has a terminal, observable,
durable state:

- **The series.**  Only attempts that ran to completion and proved nothing
  advance it.  A "could not answer" re-arm, a busy-prover backoff and a
  SNAPSHOT_PENDING re-drive keep the latch alive without counting.
- **The bound.**  `mxfs.fence_blocked_after_ms` (default 120 000; 0 disables)
  from the first non-proving attempt, with the backoff table exhausted.  The
  default is four times the healthy certify time on the NAS class the first
  release targets (death declared ~40 s after the kill, certified ~30 s after
  that) and two descriptor-sweep periods.
- **The state.**  `RECOVERY_BLOCKED`: `MXFS_RECOV_F_FENCE_BLOCKED` on the
  standing FENCING descriptor (durable, cluster-visible, set under the same
  attempt lease, cleared by the certify CAS or by a fencing-attempt takeover),
  reason `FENCE_BLOCKED` in `/sys/kernel/debug/mxfs/<dev>/recovery_blocked`
  with the last observed fence kind, and one `P238-FENCE-BLOCKED` line.
- **The re-drive.**  The identical attempt is still issued, every 30 s, so a
  change in PR state completes the recovery without operator involvement: the
  victim's key present again (it rebooted and re-registered — a proper PREEMPT
  AND ABORT then certifies), the survivor on a single nexus again, an
  all-registrants reservation back in force (the sole-survivor gate certifies),
  or the operator's `single_node_exclusive=1` assertion (read LIVE by the
  fence gate, so it takes effect at the next re-drive without a remount) on a
  cluster whose live membership is exactly this node.
- **Fail-fast.**  While a slot is blocked, an inode operation whose cluster
  grant is held by that dead node fails `-EIO` instead of waiting out the
  acquire budget: the DLM entry gate refuses the acquire (`P240-RBLK-REFUSE`),
  a request already waiting is failed at its next lap (`P-RBLK-DENY-LOCAL` on
  the master, `MXFS_ERR_RECOVERY_BLOCKED` / `P-RBLK-DENY-REMOTE` on the wire),
  and the central incarnation gate answers `-EIO`.  This is synchronous with
  the prover's state — no per-inode latch — so it clears itself the moment the
  re-drive proves exclusion and the recovery purge releases the grant.  On the
  CAW transport the grant lives in the slot table and the acquire fails at its
  poll budget as before.  Operations whose grant is held by a live node, or by
  a dead node whose recovery is still in progress, are unaffected: they park
  as before.

The operator's decision tree, from the debugfs file: read the fence kind.
`KEY_ABSENT_UNPROVEN` with `P238-FENCE-GATE-NOTSOLE` in the log means the
survivor could not prove it is the only live member or the sole-survivor gate
was refused (multipath nexus set, reservation type); fix that condition, or —
if the victim is certainly powered off and this is the only member — set
`single_node_exclusive=1`.  `NO_RESERVATION` means the target dropped the
reservation; the reservation-health worker re-reserves and the re-drive
certifies.  Nothing here ever replays without proof: the blocked state exists
so that a refusal is distinguishable from a hang, not to weaken the refusal.

## Degraded remote lock waits (0.83.0)

A wait on a REMOTE master is re-sent every second under one logical
acquisition id, and a master that has queued it answers every re-send with a
`LOCK_QUEUED` receipt echoing that attempt's `req_id`.  Those receipts are the
wait's status.  A master that is a live member and never answers is, from the
requester, indistinguishable from one holding the request behind a long drain
— except by them.  The receipt that arrives is judged before it counts:

- it must come from the node this wait's attempts were sent to;
- it must name an attempt this wait actually issued (the requester keeps the
  last four attempt nonces with their issue times, recorded before the send);
- it must arrive inside the response allowance `D` measured from that
  attempt's issue time.

Accepted, it moves the wait's anchor to that attempt's ISSUE time — never to
the arrival time, so a delayed reply cannot buy an arbitrary new interval.
Rejected, it is counted (`P958-ACQ-STATUS-REJECTED`) and refreshes nothing: a
receipt for another wait on the same resource, from a node that is not the
master, or for an attempt no longer outstanding must not manufacture evidence.

**The bound.**  `H = N x P + D`: `N` consecutive one-second status
opportunities (`P`, the re-send period) unanswered, plus the allowance `D`.
Defaults `N = 30`, `D = 15 s`, so `H = 45 s`, overridable by
`mxfs.acq_degrade_ms` (0 disables).  Neither the 180 s acquire budget nor the
receipt-staleness window takes part.  A wait still pending whose master is a
live member and whose anchor is older than `H` is **DEGRADED_UNCONFIRMED**:
said once (`P958-ACQ-DEGRADED`, naming the acquisition, resource, mode,
master, re-sends, unanswered and total age), listed in
`/sys/kernel/debug/mxfs/<dev>/acquire_degraded` until it clears, and said once
on the way out (`P958-ACQ-RECONFIRMED` on an accepted receipt,
`P958-ACQ-DEGRADED-END` when the wait ends by grant, denial, error or
abandonment).  Re-sends, outer-budget restarts, socket state and disk
heartbeats never reset the clock; only an accepted confirmation does, so a
legitimately long queue that keeps confirming never degrades.

**What it is and is not.**  It is bounded, acquisition-specific DETECTION and
REPORTING over a path that does not need the stalled lock: the debugfs read
touches only the requester's own acquisition table under its spinlock — no
I/O, no inode, no DLM call.  It is not containment: a caller that cannot be
failed safely (everything outside the fallible acquire class below) keeps
waiting, and the report says so.  It is not attribution: silence from a live
master does not say whether the request is lost on this side, on the wire, or
in the master's lock service, and it is deliberately NOT an input to
death declaration or fencing.  A later escalation policy needs
cluster-authoritative arbitration and verified revocation before remastering;
reusing the heartbeat-loss entry point would supply neither.

Verification: `tests/tcp_lockreq_blackhole.sh WORKLOAD=held_fd
EXPECT=degraded` (a stat through a held fd, requests discarded at the sender:
DEGRADED inside `H` of the first dropped request, listed while armed, delisted
after) and `tests/live_holder_wait.sh MASTER=remote` (a confirmed 240 s queue:
zero DEGRADED).

## The fallible acquire class: which waits may end in an error, and which may not

An acquire the master never receipts has two honest completions, and which
one applies is decided by what the caller holds when it asks, never by how
long it has waited.

**A fallible boundary** is an acquire taken where nothing is dirty, no
transaction is joined, and every local lock the acquire took can be released
again without undoing anything.  There the acquire may give up at its budget
(3 attempts × 60 retries × 1 s), cancel the acquisition by name at the master
(LOCK_CANCEL, tombstoned so a late re-send cannot recreate the waiter), and
return an error the caller already checks: -EIO to the syscall, -EINTR for a
killed task.  The audited boundaries, each measured refused-with-nothing-changed
under a discarded request and landed behind a legitimate 240 s holder:

- open (its own ride), getattr, the read path (the coherency envelope and the
  IOLOCK ride), splice read;
- readdir at each of its four acquires (refresh, shortform, map, per-leaf
  block);
- the write path's first IOLOCK ride (buffered, DAX, aligned, unaligned and
  atomic direct; the NOSEC relock and the EOF-zeroing re-take), and the two
  direct-write retries (the unaligned exclusive retry and the atomic COW
  retry), which follow an attempt that submitted nothing: under
  IOMAP_OVERWRITE_ONLY the first mapping spans the whole request or answers
  -EAGAIN at the first `->iomap_begin`, before any bio exists;
- the write's timestamp update.  A write whose data grant is a cached PR
  fast-paths its shared ride and then, inside `kiocb_modified`,
  `xfs_vn_update_time` takes ILOCK_EXCL — a cluster EX inside a transaction
  that is reserved and clean with nothing joined — which makes it the first
  request such a write sends.  The write path registers the inode around the
  update; a refusal cancels the clean reservation there and fails the write
  with nothing written.  A write fault's own `file_update_time` is the same
  acquire and is a boundary of its own (the page-fault item below);
- a namespace operation's FIRST acquire, taken after its transaction is
  reserved and before anything is allocated, logged or joined: create and
  mkdir (the parent), unlink and link (the parent and child pair inside
  `xfs_trans_alloc_dir`), rename (its lock set), symlink (as create).  A
  refusal cancels a clean reservation through the operation's ordinary error
  path; a dirty transaction is never cancelled as an escape, because
  `xfs_trans_cancel` is not undo;
- the lookup's two acquires of the parent (the consumer refresh and the
  directory read inside `xfs_dir_lookup`).  `xfs_ilock` returns void and takes
  the local lock whether or not the grant came, so `xfs_dir_lookup` asks,
  right after its lock and before it reads a block, whether the acquire it
  rode was refused (`mxfs_acqfall_refused`); a refused lookup reads nothing
  and caches nothing;
- an attribute change's transaction (chmod, chown, utimensat): the
  ILOCK_EXCL inside `xfs_trans_alloc_ichange` is the change's first request,
  taken on a reserved reservation with nothing joined.  The setattr path
  registers the inode around the allocator; the allocator (and
  `xfs_trans_alloc_inode`, the same shape) asks `mxfs_acqfall_refused` right
  after its lock and cancels the clean reservation.  Only a registered task
  takes that branch;
- fallocate's first take (IOLOCK_EXCL | MMAPLOCK_EXCL, nothing precedes it);
- the extended-attribute read (`xfs_attr_get`, `xfs_attr_list`): the
  attr-fork lock, a cluster PR, taken through
  `xfs_ilock_attr_map_shared_fallible` (the map recheck's relock is a second,
  separately asked acquisition).  Every caller is a boundary and returns the
  error: getxattr and listxattr, and the capability read the VFS issues
  inside truncate, write and setattr
  (`cap_inode_need_killpriv` reads any error as "nothing to strip", so those
  operations go on to their own acquire).  POSIX ACLs are not compiled into
  the module (`xfs_acl.o` is excluded in Kbuild), so no permission check
  reads an attribute.  This read is the first request an ftruncate through a
  held fd sends, ahead of the size transaction;
- the extended-attribute change (setxattr, removexattr, the security init of
  a new inode): `xfs_attr_set` reserves through
  `xfs_trans_alloc_inode`, first for `xfs_attr_add_fork` when the inode has
  no attr fork, then for the change itself; that allocator's ILOCK_EXCL is
  the change's first request on a clean unjoined reservation.  Both calls
  register the inode around the allocator only (`mxfs_attr_trans_alloc_fallible`);
  the transaction body after a granted acquire holds ILOCK_EXCL throughout and
  takes no further acquire of the inode.  The file-attribute ioctls
  (FS_IOC_FSSETXATTR, FS_IOC_SETFLAGS) are not a site: `pal/linux/xfs_ioctl.c`
  is not in Kbuild and `xfs_fileattr_get`/`_set` are stubs answering
  -EOPNOTSUPP.  Every inode is created with an empty extents-format attr
  fork (the default attr offset in `xfs_bmap.c`), so a first setxattr on a
  fresh inode reserves for the change itself; the add-fork reservation is
  reached only on an inode whose last attribute was removed;
- the page fault.  A read fault takes a counted PR hold before
  `filemap_fault`; a write fault updates the timestamps first
  (`xfs_vn_update_time`'s ILOCK_EXCL in a reserved clean transaction) and
  then takes a counted EX hold before `iomap_page_mkwrite`.  Each is taken
  with no folio locked, nothing dirty and no transaction joined, so a refusal
  has nothing to undo beyond the hold itself: the fault path registers the
  inode around each (`mxfs_dlm_ilock_begin_fallible`,
  `mxfs_fault_update_time_fallible`), a refused hold is ended as a begin that
  installed nothing, a refused timestamp update cancels its reservation, and
  the fault answers VM_FAULT_SIGBUS — the error a memory access already has
  for a page the filesystem cannot supply.  The nested `xfs_ilock` inside the
  iomap path rides the counted hold and sends no request.  A stalled
  authority transition (-EAGAIN) is not a lost request; a fault has no retry
  loop, so it waits that out as an unregistered caller does.

**Everything else waits**, with exclusion preserved, and says so
(DEGRADED_UNCONFIRMED above): writeback with pages already under I/O,
unwritten-extent conversion and other ioend work, inactivation past its first
mutation, and every acquire inside a transaction that has logged something.
Those callers hold state that no error return can put back — a cancelled dirty
transaction is a shutdown, a page cleared without being written is data loss —
so the only bounded completion available to them is a repair of the transport
(reconnect, re-send by acquisition id) or the death of the party they wait on.
A socket-level fault is repaired that way and is measured self-healing inside
the 40 s grace; a peer that dies is fenced and recovered.  What remains for
this class is a request discarded at message level while the socket and the
master stay healthy, which no reconnect repairs and which has no producer
outside a defect in the master's own lock service; the DEGRADED report is the
operator's surface for it, and it is deliberately not an input to death
declaration or fencing.

**The master is idempotent by acquisition name.**  Every acquisition carries
`{sender, owner incarnation, acq_seq}`, `acq_seq` strictly increasing per
requester.  A re-send of a queued wait keeps its entry and queue position; a
re-send of a cancelled acquisition is refused by its cancel tombstone; a
re-send of an acquisition whose grant the sender already took and released is
refused by its consumed tombstone (the release says `acq_done` when no live
acquisition record for that resource and mode remains on the releaser).  Both
refusals are silent: a DENY would complete the sender's NEXT pending entry on
that resource with the old one's error.

## Purge publication interlock and its verification (sess419)

`mxfs_disklock_purge_node(victim)` zeroes the victim's ACTIVE lock records
and then its heartbeat sector (the zero of the heartbeat sector IS the
cluster-wide "recovery published / slot consumable" broadcast).  Every zero
is a SCSI COMPARE AND WRITE (FUA) of the exact image whose predicate was
evaluated; the interlock against a second survivor is `purge_recov_gate`
(owner-only at GRANTS_RELEASED), evaluated at phase 0 (refusal
`P234-PURGE-FROZEN`), re-derived every ~2 s of the scan
(`P234-PURGE-REFROZE-MIDSCAN`, scan stopped) and on the exact heartbeat
image the final CAS publishes against (`P235-PURGE-REFROZE`).  A device
without COMPARE AND WRITE can no longer fall back to a plain write
(`P235-PURGE-NOCAW`, 0.29.2): the purge is INCOMPLETE and nothing is
published.  Test injectors (`tests/d_purge_nonatomic_verify.sh`): the
disklock `dbg_purge_hook` (points 1/2/3) served by v5 —
`mxfs.dbg_purge_pause_ms` (owner parks after phase 0),
`mxfs.dbg_purge_refreeze=1|2` (owner publishes a REAL quarantine, reason
`DBG_INJECTED`=7, through the normal refusal path at the scan start / before
the final heartbeat gate), and `mxfs.dbg_purge_victim=<node>` (a non-owner
invokes the normal purge path; expected `P234-PURGE-FROZEN` naming the owner).

## Completion ladder: bounded, classified retry (0.31.0, sess420)

D-RECOV-ADVANCE-UNBOUNDED-RETRY.  After the elected replayer has replayed a
victim's slice, `mxfs_v5_dlm_recovery_complete2()` walks the milestone
ladder on the durable descriptor: `IMAGES_REPLAYED` advance → manifest live
re-verify → CAW authority purge → device flush → `GRANTS_RELEASED` advance →
lease unregister → heartbeat/lock-record purge (the broadcast).  Before
0.31.0 any failure returned an errno and the xfs reap worker re-replayed the
slice and retried the whole ladder every 30 s for ever, silently (sess91: 11
retries in 12 min with the victim's grants frozen).

Every failure AFTER the execution lease is held is now classified by
`v5_complete_classify()` from a RE-READ of the descriptor, never by errno
alone, into a typed outcome (`struct mxfs_recov_complete_res`):

| outcome | observed state | action |
|---|---|---|
| `SUPERSEDED` | slot consumable / superseded (`P234-COMPLETE-SUPERSEDED`), other owner or other recovery identity (`P234-COMPLETE-TAKEOVER`), quarantined (`P234-COMPLETE-QUARANTINED`), terminal FSWIDE manifest mutation | drop our auth, run the idempotent retirement where the slot is consumable; xfs clears the dead-slot bit and does NOT re-arm |
| `RETRY` (now) | descriptor `UNOWNED` (`P234-COMPLETE-UNOWNED`, a departed owner gave it back) or observed stage ≥ intended (`P234-COMPLETE-COMMITTED`: the CAS landed but reported failure — the ladder is monotonic) | re-run the ladder at once |
| `RETRY` (backoff) | ours, unchanged, transient (I/O, CAS race, flush, purge, undecidable re-read) — `P234-COMPLETE-RETRY` | 5/10/20/40 s jittered backoff (`v5_complete_backoff_ms`), capped so no sleep passes the deadline |
| `FATAL_INVARIANT` | ours, unchanged, same identity, and `recov_auth_holds()` still refused (`-EBUSY` at an auth site) — `P234-COMPLETE-INVARIANT` names every field | descriptor and guard left UNTOUCHED for inspection; xfs fail-stops the mount |
| `FATAL_WITHDRAW` | transient failures past the deadline — `P234-COMPLETE-DEADLINE` | per-slot durable relinquish (`mxfs_disklock_recovery_relinquish_slot`, exact fresh image, `P236-RECOV-RELINQUISH-SLOT`); xfs fail-stops the mount |

Deadline: 120 s from the first failure of THIS recovery identity
(`recovery_gen` + `owner_term`, reset at every lease acquisition), with an
absolute 600 s cap from the acquisition.  The fail-stop is the ruling's
answer to positional election ("lowest live slot"): a node that keeps its
heartbeat while holding a lease it cannot advance strands the recovery, so it
withdraws and the next-lowest survivor is elected and takes the preserved
(or UNOWNED) descriptor over.  Both the ladder entry and the election
dispatch refuse a slot whose terminating outcome stands
(`P234-COMPLETE-TERMINAL-REFUSED`, `P234-DISPATCH-TERMINAL-REFUSED`).  Once
our descriptor already proves `IMAGES_REPLAYED`, the reap loop skips the
slice replay (`mxfs_v5_dlm_recovery_stage`) and completes only the remaining
ladder.  Failures BEFORE the lease is held (no fence certificate, quarantine
reclassify, exclusion recheck) stay on the old 30 s wait cadence — they are
owned by the fence-retry / quarantine machines, which carry their own bounds.

Test knob `mxfs.recov_complete_inject` (1 = every advance -EIO, 2 = corrupt
the auth once, 3 = one -EIO); harness
`tests/d_recov_advance_bounded_verify.sh <label> transient|deadline|invariant`.
Still open from the sess420 ruling: a durable per-descriptor decline mask so
a survivor can take over WITHOUT the owner withdrawing (protocol work), and
the owner-incarnation negative arm (A→B→A) of the sess91 ruling.

## Intent/done census: fail-before-purge on undischarged obligations (0.32.0, sess421)

D-FOREIGN-SLICE-INTENTS-ABANDONED, interim step ruled in sess420 (mount
barrier ruling, stop-ship 1): a slot may reach `GRANTS_RELEASED` only if
`IMAGES_REPLAYED && (OBLIGATIONS_DONE || enforced QUARANTINED)`.  Until real
foreign intent completion exists (item 5 of the ledger record — legal only on
the live reap-worker path), the acceptable behaviour is **fail before purge**:
a slice whose intents were not discharged inside the slice is never published.

Mechanism (`xfs/xfs_log_recover.c`, `mxfs_icensus_*`; `xfs/xfs_log.c`):

* Every untrusted replay (foreign shadow xlog or adopted own-slice mount log)
  still applies no intent/done item — but the former silent
  `P226-UNTRUSTED-INTENT-SKIP` drop is now a **census**.  Each intent
  (EFI/RUI/CUI/BUI/ATTRI/XMI and the `_RT` variants) is recorded by its log
  id with the AG set its extents/inodes name; each done (EFD/RUD/CUD/BUD/
  ATTRD/XMD/`_RT`) retires the matching id.  A done with no open intent
  (intent before the tail) is counted `unmatched`, never an error.  A
  malformed format, an unmappable extent (realtime, agno ≥ 64/agcount) or a
  table overflow (65536 open) widens the domain to FSWIDE — refusing too much
  is safe.
* Transaction admission is honoured on both sides by construction: an
  ATOMIC-SKIPped transaction never reaches the item loop, so neither its
  intents nor its dones enter the census — and that replay already fails
  `POLICY_REFUSED` with its own domain.  When it does, the census domain is
  OR-ed into that verdict so the quarantine covers the open obligations too.
* Summary line, once per replay: `P226-ICENSUS victim_slot=N intents= dones=
  unmatched_dones= open= malformed= overflow= fswide= ag_mask=`.
* Terminal predicate (foreign shadow only, after the untagged-skip predicate):
  `open + overflow > 0` (or the census could not be allocated) ⇒
  `P226-FR-INTENTS-UNDISCHARGED`, the replay fails `-EFSCORRUPTED`, and the
  verdict publishes through the D-513 path with reason
  `INTENTS_UNDISCHARGED` (`MXFS_RECOV_REFUSAL_INTENTS_UNDISCHARGED = 8`,
  `MXFS_FREPLAY_REASON_INTENTS_UNDISCHARGED = 6`), domain = the union of
  the open intents' AGs (FSWIDE when any is unmappable).  `chk_mxfs` names
  the reason.  Nothing is purged, no heartbeat is zeroed, the slot stays a
  quarantined RECOVERY_GUARD until repair — exactly the D-513 containment.
* Adopted own-slice mounts print the same summary (`P226-ICENSUS-ADOPTED`)
  and continue; the adopted path's disposition belongs to
  D-OWN-CRASH-RECLAIM-PATH-UNREACHABLE / settle_own_slot.

Expected board effect: `node_death_replay` goes red on a churn kill that
leaves an EFI open in the victim's last checkpoint — that is the honest
reading of the defect until intent completion lands; it must not be widened
away.  Verification: `tests/d_intents_undischarged_verify.sh <label>
burst|clean` (fragmented-file unlink burst killed mid-chain vs an idle
victim).

### Item 5 — real EFI completion (sess461 ruling, increments)

design-consult ruling `docs/rulings/intents-item5-efi-completion-design.md`.
Facts that fix the shape: `mkfs_mxfs` enables FINOBT only (no rmapbt,
reflink, exchange-range or logged xattrs), so **EFI is the only intent class
this filesystem can log**; AGFL frees share the on-disk EFI and the same
`recover_work`, so upstream recovery already completes every EFI as a plain
free (owner UNKNOWN, no AG reservation).  The ladder stage
`OBLIGATIONS_DONE` (5) existed unused between `IMAGES_REPLAYED` and the CAW
purge; that is where completion belongs.

Design (accepted with STOP-SHIP conditions, all recorded in the ruling):
the victim's recovery descriptor carries the obligation AG mask
(`obl_ag_mask`, FSWIDE when unmappable) published atomically with
`IMAGES_REPLAYED`; every AG in it is RECOVERY-FROZEN — purge leaves its
holder bits, live acquires wait — until `OBLIGATIONS_DONE` is durable.  The
recovery owner CAS-transfers the AG holder bit victim→owner (generation-bound:
victim slot/incarnation, lease owner+generation, stage, expected holder),
installs a **recovery-exclusive** local grant that the ordinary allocator
cannot piggyback on, and completes each extent in ONE bounded transaction:
`xfs_alloc_has_records` under the AGF — EMPTY (still allocated) ⇒ direct
non-deferred free (no replacement EFI, no roll); FULL ⇒ already completed,
skip; SPARSE ⇒ terminal quarantine.  Before transferring an AG from a DEAD
PRIOR recovery owner, that owner's slice must be replayed and home-written
(else the successor's bnobt read misses a committed free).  Completion
metadata is log-forced and written home, the device flushed, then
`OBLIGATIONS_DONE` advances, the adopted AGs are released, and the existing
purge → `GRANTS_RELEASED` runs.  The mount barrier publishes
`IMAGES_REPLAYED` + obligations and leaves completion to a live transaction
context.

* **Increment 1 (0.62.0, in tree):** the census keeps each EFI's extents and
  the whole-transaction verdict of the intent's and the done's transaction
  and classifies every open entry (`P226-ICENSUS-CLASS`, summary
  `P226-ICENSUS-SPLIT recover= quarantine=`):

  | intent txn | done | class |
  |---|---|---|
  | admitted (ADMIT / UNTAINTED / SNLOCAL) | admitted done | CLOSED (retired) |
  | admitted | none | RECOVER |
  | admitted | done in a non-admitted txn (`P226-ICENSUS-DONE-AMBIGUOUS`) | QUARANTINE |
  | not admitted (SKIP / SBCLEAN / PREINC) | any | QUARANTINE |
  | any | malformed, duplicate id with a different verdict, overlapping RECOVER extents, realtime, non-EFI class, unmappable | QUARANTINE |

  The disposition is unchanged in this increment: any open entry still
  refuses the slice terminally; the `P226-FR-INTENTS-UNDISCHARGED` line now
  carries the split so the later increments can act on RECOVER only.
* **Increment 2 (0.63.0, in tree; design-consult ruling
  `docs/rulings/item5-inc2-obligation-record-plumbing-only.md`):**
  the durable obligation record + list, PLUMBING ONLY — the ruling forbids
  flipping the disposition before real completion, takeover, prior-owner
  replay, SPARSE quarantine and a durable completion proof land together, so
  a real open-EFI slice still refuses terminally.
  - `dlm/recov_obl.{h,c}` (PAL-only, user-mode buildable): the 40-byte
    `struct mxfs_recov_obl` at recovery-body byte 280 (the former pad:
    magic `RVOB`, flags TERMINAL/FSWIDE/LIST, `obl_ag_mask`, `count`,
    `list_crc32c`, `census_digest`, `pub_seq`, crc bound to the victim
    sector identity like every other sub-record) and the OBLIGATION LIST in
    the victim's rman slot zone `[4 KiB, 64 KiB)`: a 4 KiB header
    (`MXOB`, stable recovery-case identity = victim node/epoch/fs_gen/slot +
    `recovery_gen` + `seq`, publisher identity diagnostic only, geometry,
    entries crc, header crc) at 4 KiB and up to 3072 sixteen-byte entries
    `{fsbno, agno, len}` at 8 KiB.  Canonical form: sorted `(agno, agbno)`,
    len > 0, inside the AG, agno consistent with fsbno, no duplicates or
    overlaps; the mask is recomputed and must match; an AG ≥ 64 forces
    FSWIDE.  Anything else is a validation failure the consumer treats as
    QUARANTINE, never as "no obligations".  The fence prover's manifest owns
    `[0, 4 KiB)` and `[64 KiB, …)`; neither crc covers the other's zone.
  - `dlm/disklock.c`: `mxfs_disklock_recovery_obl_write` (execution lease,
    stage ≥ FENCED; entries → flush → crc'd header LAST → flush; seq > any
    earlier record/header of the case; returns the sealed record —
    `P226-OBL-WRITE`), `..._publish_refusal_obl` (the record rides in the
    SAME CAS as the terminal outcome, `F_TERMINAL` mandatory there),
    `..._read_obl` (leaseless consumer: record → header → entries, every
    mismatch `-EPROTO` = QUARANTINE, `P226-OBL-READ-INVALID`).  Ladder
    gates in `recovery_advance`: `OBLIGATIONS_DONE` is unreachable
    (`P234-RECOV-OBLIGATIONS-NOPROOF` — no completion proof exists in this
    build), `GRANTS_RELEASED` refused over a valid non-terminal record with
    `count > 0` (`P234-RECOV-OBLIGATIONS-OPEN`) or over record bytes that do
    not validate (`P234-RECOV-OBL-CORRUPT`).
  - `xfs/xfs_log.c`: after a clean shadow replay the device is FLUSHED
    before anything else (`P226-FR-HOMEFLUSH`; ruling STOP-SHIP 1 — the
    IMAGES_REPLAYED milestone must attest home-written images, since a
    takeover successor never re-replays past it; the ladder's post-purge
    flush was too late).  The terminal predicate exports the RECOVER
    extents through `mxfs_freplay_verdict` (`obl_count/obl_ag_mask/
    obl_list`, plus the QUARANTINE split; `obl_lost` when the list could
    not be built — never "nothing to recover").
  - `xfs/xfs_mxfs_dlm.c` `mxfs_freplay_publish_refusal`: writes the list
    as TERMINAL EVIDENCE (`P226-OBL-EVIDENCE`) and publishes the refusal
    with the record in the same CAS; a failed/lost list publishes the
    verdict WITHOUT a record (`P226-OBL-EVIDENCE-FAIL/-LOST`) — the
    evidence is optional, the verdict is not.
  - `tools/chk_mxfs --show-quarantine` prints the record
    (`obligations count= TERMINAL-EVIDENCE|OPEN ag_mask= seq=`) and reads,
    validates and prints the list (`obligation list VALID` or an `INVALID`
    error per failed check).
  - Verification: `tests/d_intents_undischarged_verify.sh burst` asserts,
    when `P226-ICENSUS-SPLIT recover>=1`, `P226-OBL-WRITE`,
    `P226-OBL-EVIDENCE`, and chk_mxfs reading the record + list back VALID.
* **Increments 3+4 — completion + takeover (design-consult ruling sess463,
  `docs/rulings/item5-inc3-4-completion-takeover-stopship.md`):**
  the core EMPTY/FULL/SPARSE scheme was accepted; the disposition flip is
  STOP-SHIP until ten conditions are met, and they land as ONE releasable
  change set (the flip is the last edit).  The design below is the ruled
  shape; the sub-steps 3a/3b are inert plumbing that may ship earlier.

  **Verdict flip (3c, last).**  `recover >= 1 && quarantine == 0 &&
  !fswide && list exported && every AG < agcount` ⇒ the shadow replay
  returns SUCCESS with the RECOVER list in the verdict; every other
  open-entry case stays the terminal refusal exactly as today.

  **Publication (phase A).**  After the peer-visibility flush and the
  durable flush the reap worker calls the ladder with the list: lease,
  gates, exclusion recheck, list write (entries → flush → header → flush),
  then ONE CAS to `IMAGES_REPLAYED` carrying the record with `F_LIST` and
  without `F_TERMINAL` = the OPEN case.  A replay whose census is EMPTY
  sets the new descriptor flag `MXFS_RECOV_F_CENSUS_ZERO` in that same CAS
  (SS-H): "no record" is never read as "no obligations" — the states are
  CENSUS_ZERO + zero record area (none), valid OPEN record (pending),
  valid TERMINAL record (terminal), anything else INVALID (quarantine).

  **Publication/purge guard (SS-A).**  A cluster-wide CAW resource
  (`MXFS_LTYPE_SUPER` namespace, fixed id) is held EX by an OPEN
  publication across its validation + list durability + IMAGES_REPLAYED
  CAS, and by EVERY CAW purge (`purge_node`, `purge_dead_nodes[_ex]`,
  `purge_victim_selective`, the terminal-refusal purge, mount/bootstrap
  purges, a new joiner's mount-time purge) across the full 64-sector scan
  + validation + every CAW mutation made from that snapshot.  The scan is
  fail-closed: an unreadable or corrupt sector that could be an OPEN case
  ⇒ no victim-bit mutation at all (held retry); AG resources in the union
  of OPEN masks are skipped (kept, counted, `P226-PURGE-FROZEN-KEEP`).

  **Freeze custodian (SS-B).**  An AG covered by ANY open case always has
  exactly one valid EX custodian.  A case's release at `OBLIGATIONS_DONE`
  unlocks an AG only if no other OPEN case covers it (checked under the
  guard); otherwise the grant stays recovery-exclusive and is transferred
  directly to the next case.  The local exclusion names WHICH case may
  transact.

  **Transfer receipts (SS-C/SS-D).**  Per AG a 64-byte durable receipt in
  the victim's rman zone `[60 KiB, 64 KiB)` (one per AG, 64 AGs):
  `{case identity, agno, old holder slot/incarnation/CAW generation/epoch/
  lineage, new holder ..., lease owner term, descriptor stage_seq, receipt
  seq, crc}`.  The transfer is a GUARDED CAW operation: the compare image
  must be the canonical sole-EX image (`holders_ex == BIT(from)`, every
  other holder map 0, `granted_mode == EX`, our slot in no holder/waiter
  map, expected generation/epoch/lineage from the receipt or the sealed
  fence-time manifest); the new image clears `from` from
  `holders_ex/waiters/waiters_ex`, recomputes `yield_to` if it named
  `from`, resets `ex_grant_streak` as a new tenure, runs
  `caw_grant_epoch_update` (fresh epoch, `dir_epoch`, `last_ex_slot`),
  keeps `revoke` and other waiters, bumps `generation`; the token comes
  from the CAS-written image.  Verdicts: dead non-victim holder whose slice
  is not yet replayed + home-written ⇒ DEFER (dependency, SS-I); holder
  changed with a valid receipt ⇒ follow the chain; no holder / live
  unrelated holder / mixed or malformed image / our unexplained bit ⇒
  terminal `OBLIGATION_FREEZE_LOST` (domain = record mask); CAS mismatch ⇒
  retry only after revalidating lease + descriptor + record + chain.

  **Recovery-exclusive grant (SS-E).**  Under `pag_dlm_acquire_lock` +
  `pag_dlm_lock`: enter RECOVERY_INSTALLING (blocks fresh, cached AND
  nested ordinary acquisition — a nonblock caller gets `-EAGAIN`, a
  blocking caller waits on the pag's demote waitqueue), require
  `holders == 0`, no cached tenure, no acquire/demote/release in flight;
  then the guarded transfer; then publish `grant_epoch/lineage` from the
  written image and enter RECOVERY_EXCLUSIVE; on failure unwind + wake.
  The completion path carries a recovery CREDENTIAL `{case, agno,
  epoch/lineage/generation, op = completion}` through a recovery-only free
  entry into the nested AG-lock check; task identity alone admits nothing
  (the same task entering reclaim or the ordinary allocator is refused).
  BASTs are recorded, never acted on, until the explicit release; the
  release never caches, always runs the full drain (F9) and a failed drain
  keeps the bit and the BAST pending.

  **Completion (SS3, Q4).**  Per adopted AG, per extent in canonical order:
  one transaction (`tr_itruncate` after verifying it covers AGF + bnobt
  splits + AGFL refill + busy insert, else the EFI-recovery reservation),
  `xfs_alloc_read_agf`, bnobt cursor, `xfs_alloc_has_records`: EMPTY ⇒
  `__xfs_free_extent` (owner `XFS_RMAP_OINFO_ANY_OWNER`, legal only
  because the format is gated to `!rmapbt` — an RMAPBT filesystem
  refuses), commit; FULL ⇒ cancel, skip; SPARSE ⇒ cancel, publish the
  TERMINAL outcome (`OBLIGATION_SPARSE`, full domain) durably, full drain,
  unlock only after the terminal state is durable and visible (P240 refuses
  peers).  Error matrix (SS-J): transient (EIO, trans alloc, shutdown of a
  peer path) ⇒ retain the freeze + retry; metadata corruption ⇒ terminal
  per the matrix; nothing falls through as FULL or count 0.

  **Home-write + proof (SS5, SS-G).**  Per AG after its extents:
  `xfs_log_force(SYNC)`, the F9 drain WITHOUT the unlock, and a real
  device flush; the drain must PROVE completion (a bounded AIL push that
  cannot ⇒ no proof, no unlock).  The proof block at rman `[56 KiB,
  60 KiB)` — `{magic MXOD, version, length, fs UUID, rman slot, case
  identity, descriptor stage_seq at authorization, lease owner term,
  receipts digest, list header + entries digest, count, n_empty, n_full,
  n_sparse == 0, committed sequence, outcome bitmap (3072 bits), crc over
  the whole block}` — written two-phase (body + flush, committed header +
  flush, read back).  `recovery_advance_obl_done` re-reads the sector:
  lease still ours at the term, stage_seq exact, record OPEN valid and
  unchanged, no terminal transition won, a valid receipt per AG with its
  dependencies satisfied, outcome bits ↔ canonical entries one-to-one,
  counts agree; ONE CAS sets `OBLIGATIONS_DONE` + record `F_DONE`.

  **DONE cleanup (SS-F).**  At `OBLIGATIONS_DONE` (fresh or re-entered):
  the live owner of the adopted grant releases it idempotently (custodian
  rule permitting); a dead/GUARD adopted holder's slice is replayed +
  home-written first, then its bit is removed/transferred generation-bound;
  a live previous completer releases under the lease protocol or is fenced
  first; `GRANTS_RELEASED` is refused while any obligation AG carries a
  residual case holder.

  **Scheduling (SS-I).**  A victim deferred on a dead holder's replay is
  requeued behind that holder in the worker's dead-slot set; dependencies
  bind the EXACT holder incarnation; cycles are detected and quarantined.

  **Mount barrier.**  Phase A only, and only once the guard exists; a new
  joiner obeys the OPEN scan before any purge; OPEN AGs stay blocked until
  the post-mount worker installs custodian state.

  **Peer waits (P12).**  The 120 s `-ETIMEDOUT` on a dead holder's frozen
  bit is the budget rule, not correctness (the timeout never strips or bypasses).
  A distinct OBLIGATION_PROTECTED wait predicate may extend the wait; the
  liveness oracle must never answer "alive" for a dead slot.

  **Sub-steps.**  3a (inert plumbing): receipt + proof formats and
  validators in `recov_obl.{h,c}`, `MXFS_RECOV_F_CENSUS_ZERO`, the guard
  resource id, chk_mxfs decoders, forge shapes.  3b (behaviour, no flip):
  guard acquisition + fail-closed OPEN scan on every purge path (finds no
  OPEN case while the flip is absent).  3c (one change set): engine,
  custodian, credential + INSTALLING, transfer + receipts, proof + DONE,
  cleanup, scheduler, RMAPBT gate, verdict flip, tests (P14 plus the
  ruling's list: publication racing each purge path, two OPEN cases on one
  AG, kill after transfer before install, kill after DONE, dead completer
  holding adopted bits, dependency A→B + forged cycle, BAST during
  completion, same task in the ordinary allocator refused, corrupt/stale
  proof, CAW generation ABA, drain timeout ⇒ no unlock).

### As built on the TCP transport (0.85.0): retained custody under a freeze

The shipped shape keeps the ruled engine (EMPTY/FULL/SPARSE, one bounded
transaction per extent), the OPEN record published in the `IMAGES_REPLAYED`
CAS, `MXFS_RECOV_F_CENSUS_ZERO`, the two-phase proof + the `OBLIGATIONS_DONE`
CAS and the prior-custodian takeover dependency — and replaces the CAW
transfer/receipt/credential machinery (SS-C/D/E/F) with **retained custody
under a filesystem-layer freeze**.  Why: on TCP a dead node keeps mastership
of its hashed resources and its ledger EX holds until the remaster/purge
trio runs, so no custodian can acquire a victim-mastered AG before that trio;
and the AG grant alone is not local exclusion (the nested fast path admits
any local caller).  Transferring a holder bit therefore buys nothing on TCP;
what is needed is that nothing but the completion may take the AG on ANY
node, which a bit cannot express and a freeze can.  The CAW transport has no
custody model and keeps the terminal refusal.

* **Verdict flip** (`xfs/xfs_log.c`, `P226-FR-INTENTS-RECOVERABLE`): only
  when `recover >= 1`, `quarantine == 0`, `!fswide`, `malformed == 0`, the
  list exported, `!rmapbt`, `!reflink`, TCP transport and
  `mxfs.obl_complete_enable=1` (the A/B control knob).  Everything else is
  the terminal refusal exactly as before.
* **Publication**: the replayer parks the verdict before complete2
  (`mxfs_v5_dlm_recovery_set_obligations` / `_set_census_zero`, `P-OBL-PARK`);
  the ladder's `IMAGES_REPLAYED` advance writes the list (`P226-OBL-WRITE`)
  and carries the OPEN record or `CENSUS_ZERO` in the CAS.  A ladder entered
  below `IMAGES_REPLAYED` with nothing parked is HELD
  (`P234-COMPLETE-NOCENSUS`); `GRANTS_RELEASED` is refused over an OPEN record
  and over "no record and no CENSUS_ZERO" (`P234-RECOV-OBL-UNDECIDED`).
* **The OPEN branch** (`v5_recovery_complete_ladder`, after step 0, reading
  the verdict back from the platter, never from the parked copy): install the
  freeze through the filesystem callback, retire the dead node's grants
  (`v5_dead_grants_retire`: note-dead, lease unregister, remaster refresh,
  ledger purge, table purge, page handoff — factored from step 2b and run
  again, idempotently, at recovery-complete), return
  `MXFS_RECOV_COMPLETE_OBLIGATIONS_OPEN` to the worker (`P-OBL-OPEN`).  The
  retirement runs once per case, keyed on **victim incarnation epoch AND
  pub_seq** — the list's seq counts from 1 per case, so the seq alone aliases
  a later victim in the same slot; the marker is cleared when the case
  publishes.  Retiring before `OBLIGATIONS_DONE` is safe because the victim's
  slice is durably replayed and home at `IMAGES_REPLAYED` (nobody re-replays
  past it), so nothing later needs the victim's authority evidence; the AGs
  stay closed to ordinary callers by the freeze.  FSWIDE or a CAW context ⇒
  HELD (`P-OBL-OPEN-UNSUPPORTED`).
* **The freeze** (`xfs_mount.h` `m_mxfs_oblf_*`; `xfs/xfs_mxfs_dlm.c`
  `mxfs_oblf_note`): one entry per victim slot keyed `(victim_epoch,
  pub_seq)`, the union is what the acquire reads.  Checked at the top of
  `__mxfs_ag_dlm_lock` after the quarantine check and BEFORE every fast path
  (nested, cached, handoff): a non-blocking caller gets `-EAGAIN`
  (`P-OBLF-AG-EAGAIN`; the allocator moves to another AG, a defer chain takes
  its -488 seam), a blocking caller waits on `m_mxfs_oblf_wq` for the lift,
  bounded by the same 120 s budget as a dead holder's frozen grant
  (`P-OBLF-AG-WAIT`, `P-OBLF-AG-TIMEOUT` ⇒ `-ETIMEDOUT`, never a bypass).
  Two exemptions: the custodian task (`m_mxfs_oblf_task == current`) and a
  transaction that already retains this AG's grant (`t_mxfs_ag_unlocks`,
  released at its commit — refusing it would deadlock against the custodian's
  quiesce wait, and it cannot allocate what the custodian has not yet
  freed).  Installed on every node from the platter: by the ladder's own
  callback, by the disklock monitor per readable sector per pass
  (`recov_obl_observe`: NONE / OPEN / INVALID, where INVALID — record bytes
  present but not validating, or no record and no CENSUS_ZERO at
  `IMAGES_REPLAYED` — freezes the whole filesystem for that slot,
  `P-OBLF-INSTALL-INVALID`), and by the synchronous 64-sector scan in
  `mxfs_disklock_set_recov_obl_cb` at mount registration, so a joiner's
  freeze exists before its first allocation.  Lifted per slot
  (`P-OBLF-LIFT`) when the observer sees the slot at or past
  `OBLIGATIONS_DONE`, terminal, or gone; the union keeps every other open
  case's AGs closed (the SS-B custodian question becomes a union).
* **The engine** (`xfs/xfs_mxfs_recov_obl.c`, the post-mount worker's
  `OBLIGATIONS_OPEN` arm): re-read record + list from the platter, re-check
  the list against the MOUNTED geometry, feature-gate (`rmapbt`/`reflink` ⇒
  terminal), wait for the AG to be quiet (`mxfs_ag_dlm_quiesce_wait`: zero
  local holders, not demoting), then per extent ONE `tr_itruncate`
  transaction: blocking AG lock (the custodian is exempt from its own
  freeze; the dead node's grant is already retired), `fix_freelist`,
  `xfs_alloc_has_records`: EMPTY ⇒ `xfs_free_ag_extent(ANY_OWNER)` + busy
  extent; FULL ⇒ skip; SPARSE ⇒ terminal reason 9
  `OBLIGATION_UNRECONCILABLE` over the record's mask.  FULL and SPARSE COMMIT
  the transaction (a dirty cancel after an AGFL refill is a shutdown).  Then
  `xfs_log_force(SYNC)`, the replay path's home flush, the two-phase proof
  (`P-OBL-DONE-WRITE`), `advance_obl_done` (stage 5 + record `F_DONE`,
  `P234-RECOV-OBLIGATIONS-DONE`), freeze lifted, `P-OBL-COMPLETE`, and
  complete2 again for the ordinary publication.  Any other failure keeps the
  case OPEN (freeze retained, grants retired) and the worker retries; a
  corruption return goes terminal.
* **Takeover**: a custodian that dies leaves a case its successor re-runs
  from the same durable list (its committed frees replay home and read
  FULL, the rest EMPTY; no per-extent durable outcome is needed).  The
  worker defers a case while any OTHER dead slot is non-terminal and below
  `IMAGES_REPLAYED` (`mxfs_freplay_open_case_blocked_by`, `P-OBL-DEFER`);
  the mount barrier never completes inside mount — it hands OPEN slots to the
  post-mount worker (`mxfs_barrier_note_open_cases`).
* **Takeover across a total outage** (0.85.1).  On two nodes the custodian
  that dies is the sole survivor, so the cluster is down and whoever mounts
  first recovers both slots through the ordinary mount path (this transport
  has no whole-cluster bootstrap term).  Two things the sole-survivor
  exclusive-write gate (`docs/pr-fencing-departure.md`) makes necessary
  there, because the gate is a per-LUN single-holder Write Exclusive (1)
  reservation that outlives the node holding it:
  - *A joiner under a dead holder's gate.*  Under WE(1) the joiner can
    REGISTER but not WRITE, so its PR-ledger publish is refused and the mount
    aborts.  Before it registers, the TCP mount attributes the holder's key
    through the PR ledger and runs the bootstrap survivor scan over the
    heartbeat table for one full dead window (`v5_tcp_dead_gate_holder`,
    `P-PR-DEADGATE-*`).  Only "nothing moved and a frozen record carries the
    holder's key" proves the holder dead; the joiner then, registered,
    PREEMPTs AND ABORTs that key with the all-registrants type
    (`mxfs_scsipr_preempt_dead_gate_holder`), so WE-AR is in force again,
    marks the holder's ledger entry FENCED and publishes.  Any movement, an
    unattributable key or an unreadable table keeps the refusal.  The later
    monitor-time fence of the holder's slot finds the key absent and, being
    the sole survivor, certifies under a gate of its own exactly as for a
    target-purged key.
  - *A successor re-proving a kind-20 certificate.*  The exclusion a kind-20
    certificate proves is "WE(1) held by OUR key"; once the prover is dead
    nothing holds it, and the successor's recheck lapses for ever.  When the
    recheck answers NO_RESERVATION and this node is the only live member
    (the original prover's predicate: lease membership minus the victim is
    one, no other heartbeat slot live) and the descriptor carries a durable
    kind-20 certificate with the victim's key, the successor re-installs the
    gate under its own key — pinned before the PROUT, then registered as a
    dependant — and proceeds (`v5_gate_reprove`, `P239-GATE-REPROVE-*`).  The
    certificate is not rewritten; every refusal keeps the lapse.
* **Not in this model**: AGI unlinked-list obligations (a separate
  obligation type, see the ledger record), the CAW transport, and intent
  classes other than EFI (the feature gate refuses them).
* `tools/chk_mxfs --show-quarantine` decodes the OPEN/DONE record, the list
  and the proof; `--free-query AGNO:AGBNO:LEN` answers FREE / ALLOCATED /
  PARTIAL for an extent from the platter.  Verification harness:
  `tests/d_intents_2tcp_open_efi.sh` (arms: `CHURN=1`, `MODE=custodian_kill`).

## Node Death on the CAW transport (state 2026-08-23, sess402)

The section above is the TCP DLM.  On the default CAW transport there is no
lock master; the sequence is:

1. Disklock heartbeat slot of B stops advancing; after 31 checks (~62 s) each
   survivor logs `node in slot N is no longer responding ... initiating
   recovery` and retires B's identity (P164-DEAD-NOTE).
2. SCSI-PR fence: a prover writes a durable FENCE-INTENT, issues PREEMPT AND
   ABORT, and certifies exclusion (P236-FENCE-CERTIFIED).  Authorises nothing
   by itself.
3. One survivor is elected (`elected (slot X) to replay dead node ...`), takes
   the recovery lease (P238-RECOV-LEASE) and runs FOREIGN REPLAY of B's log
   slice into the live filesystem (`xfs/xfs_log.c:mxfs_xlog_recover_foreign_slice`).
4. Gate per transaction (`xfs_log_recover.c:xlog_recover_items_pass2`):
   every buffer image carries an authority token {class, resource, owner slot,
   owner incarnation epoch, grant epoch, lineage}.  With
   `foreign_replay_token_enforce=0` (default, shadow-only) any transaction that
   contains a BUF/dquot/icreate image is ATOMIC-SKIPped
   (`P227-FR-ATOMIC-SKIP ... contains unauthorized image(s)` — NOTE the word
   "unauthorized": never filter ssh output with `grep -v authorized`).  With the
   knob armed (setter fails closed unless `release_proof_enforce=1`, either
   `fua_disable=0` or the explicit `target_cache_protected=1`, and — 0.29.1,
   default-on gate item 2 — `icluster_dlm=0`: a cluster-routed tenure is
   released by the ICLUS pipeline without a RELMARK certificate, counted
   `iclus_unmarked`, so its images can never earn an enforceable verdict;
   `tests/f2_iclus_refusal.sh` proves the refusal), a transaction is
   ADMITTED only if every image evaluates ENFORCEABLE_WOULD_APPLY: v3 token,
   resource binding, owner slot == victim, owner epoch == FENCED descriptor,
   and the manifest lookup (`mxfs_dlm_caw_victim_manifest_read`: the resource's
   CAW slot read NOW) shows the victim's bit in holders_ex|pw, epoch and lineage
   equal to the token's.
5. Any skip makes the slice POLICY-REFUSED (-EFSCORRUPTED): a terminal verdict
   is published (P241-RECOV-TERMINAL) and the victim's AG domain is quarantined
   cluster-wide (P240-QUAR-IMPORT; acquires fail EIO) until operator repair.
   Out-of-closure grants of the victim are force-revoked (P299-CLOSURE-PURGE);
   in-closure grants stay frozen.  Otherwise `foreign replay of slot N complete`
   and the CAW authority purge + completion record follow.

sess402 measurement (tests/tmpfile_churn_kill.sh, tests/evidence/sess402_v02315/):
enforcement OFF refuses every dead slice with buffer images (by design);
enforcement ARMED refused the two-owner-AG victims too — their tokens evaluated
`not_held` (victim bit absent from the AG slot at replay) or `staleep` (bit
present, grant epoch advanced by the co-owner ping-pong: records of a cleanly
released earlier tenure).  Design-consult ruling (`docs/rulings/token-gate-held-predicate-fence-snapshot.md`):
"victim bit present at replay" is a mutable current-state predicate used as
historical proof and is unsound; the required design is a fence-time manifest
snapshot into the FENCED descriptor with RECOVERY_PENDING freezing the victim's
resources before any strip/grant, plus a durable clean-release certificate so
old-tenure records classify REDUNDANT_CLEAN instead of refusing.  Ledger:
D-FOREIGN-REPLAY-UNGATED-IMAGES (design), D-TMPFILE-CHURN-KILL-FOREIGN-REPLAY-
EFSCORRUPTED-402 (symptom).

### Clean-release marker and REDUNDANT_CLEAN (0.24.0, sess403)

Evidence (kill5b, 0.23.16, enforce armed, `tests/evidence/sess402_v02316/`):
the victim logged AG1 images at grant epoch 19, cleanly released AG1 to its
co-owner (Invariant-1 drain + CAS), the co-owner took epoch 20 and handed it
back at 04:39:26.0 (holders=0, ex_epoch=20); the victim was destroyed at
04:39:26.4 before re-acquiring.  At replay the {AG1, epoch 19} tokens
evaluated `not_held` → ATOMIC-SKIP → POLICY-REFUSED → AG1 quarantined, although
every epoch-19 image was already on the platter and the co-owner had written
AG1 since (so APPLY would have been wrong too).  The correct disposition is
REDUNDANT_CLEAN: skip silently, never apply, never refuse.

Design (design-consult ruling `ccloop-c7ee71c6-sess403-GPT-ruling-release-marker-log-
item-redundant-clean`; the slot-resident alternative was rejected because a
tombstoned slot is recycled by inode churn within the death→replay window and
takes its certificate with it):

* **Producer** — a node releasing an EX/PW tenure logs ONE
  `XFS_LI_MXFS_RELMARK` (`struct mxfs_relmark_log_format`, 64 B: class,
  resource, lineage, grant epoch, owner slot, owner incarnation) into its OWN
  slice in a tiny `XFS_TRANS_NO_WRITECOUNT` transaction, `xfs_trans_set_sync`,
  so it is durable BEFORE the unlock CAS clears the holder bit.  Sites:
  `mxfs_dlm_ag_bast_work_fn` (after the Phase-2 drains/flushes, before
  `mxfs_v5_dlm_ag_unlock`; identity saved by `mxfs_ag_handoff_commit` into
  `pag_mxfs_rel_epoch/lineage` in the same critical section that invalidates
  authority), `mxfs_dlm_ag_release_work_fn` (deferred completion, idempotent),
  and both `mxfs_v5_dlm_inode_unlock_open` arms of `mxfs_dlm_bast_process`
  (identity captured at the terminal store, published after the drain).  The
  item is `XFS_ITEM_RELEASE_WHEN_COMMITTED` (never AIL-resident); its cache is
  `mxfs_relmark_item`.  A zero epoch, a PR tenure, an unpublished inode or a
  cluster-routed (ICLUS) tenure publishes nothing at the PER-INODE site
  (counted: `relmark` block of the inode-authority debugfs file;
  `iclus_unmarked` — the cluster pipeline marks instead, see below).
* **Cluster (ICLUS) certificate (0.55.0, sess448; design-consult ruling
  `docs/rulings/iclus-relmark-certificate-and-sequencing.md`)**
  — routed inodes' tokens are captured with class INODE, resource = cluster
  base ino, epoch = `ic->auth_epoch`, lineage = `ic->auth_lineage` (NEW: the
  slot's `resource_lineage` from the SAME grant image, `caw_grant_result_fill`,
  installed/cleared with the epoch under `ic->lock`; zero lineage makes the
  snapshot non-proving, so legacy bindings stay fail-closed).  The marker is
  published by `mxfs_iclus_disk_release` under exactly that identity, AFTER
  the closing barrier (DEMOTING closes admission under
  `release_proof_enforce`; `ic->busy` excludes the fast paths), the settle,
  the keyed `icwr` completion proof, the F4 census and the pre-CAS tripwire —
  every failed exit DEFERS/WEDGES before this point — and BEFORE
  `mxfs_v5_dlm_iclus_unlock_gen`.  Irrevocability first: `ic->relmark_
  {lineage,epoch}` is stamped before the publish and never cleared; a grant
  image (fast-path admit or CAS-established) offering that tuple returns a
  non-proving snapshot (`P-RELMARK-ICLUS-REINSTALL-REFUSED`), so its images
  write fail-closed until a new CAS mints a fresh epoch.  Publish failure
  proceeds counted (`P-RELMARK-ICLUS-UNMARKED`, `iclus_failed`) and replay
  refuses that tenure.  Non-alias invariant for reusing class INODE: a
  lineage is a per-slot 64-bit random mint (`caw_mint_lineage`, claim fails
  on zero); the ICLUSTER resource and any per-inode resource whose ino equals
  the cluster base are distinct slots with distinct lineages, and the replay
  lookup matches the FULL tuple {class, resource, lineage, epoch, owner slot,
  owner epoch}, so one marker identifies exactly one tenure.  Epoch advance
  within a held tenure (PR→EX convert) leaves earlier-epoch images uncertified
  (refused, never falsely clean) — the same behaviour as the per-inode site.
  Readiness: `MXFS_ICLUS_RELMARK_READY` (xfs_super.c) is 0 — the durability-
  domain validator keeps refusing `icluster_dlm=1`; a LAB build
  (`KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1`, announced as
  `ICLUS-RELMARK-LAB-BUILD` in `P-DOMAIN-ADMITTED`) is the only way to mount
  the marker path, and the ruling's evidence list (positive routed-death laps
  → REDUNDANT_CLEAN / held-at-death → APPLY, 9-point fault injection, zero
  failure counters) gates flipping it.  Counters: `iclus_marked`,
  `iclus_failed`, `iclus_reinst_ref` in the `relmark` debugfs block.
* **Irrevocability** — once the marker is durable the release may not resume
  under the same epoch: the terminal store has already set mode NL / authority
  RELEASING, and `mxfs_inode_authority_install_durable_ex_locked` refuses to
  install a grant whose {resource, epoch} equals the inode's last published
  marker (`P-RELMARK-REINSTALL-REFUSED`) — a memory-only already-held re-grant
  racing the CAS therefore writes fail-closed (class NONE) instead of
  re-stamping a certified-clean epoch.  A new CAS grant mints E+1 as before.
* **Consumer** — pass 1 of an untrusted replay (foreign shadow xlog / adopted
  slice) collects markers into `log->l_mxfs_relmark_tbl` (64K entries,
  overflow counted, only committed transactions reach pass 1); trusted
  (own-log) replay parses and ignores them.  Pass-2 precedence per token
  (`mxfs_shadow_eval_token`): (1) manifest says the victim HELD {lineage,
  epoch} → held-at-death chain → APPLY; (2) else an exact marker
  {class, resource, lineage, epoch, victim slot, victim incarnation} and a
  FENCED-capable descriptor → REDUNDANT_CLEAN; (3) else the refusal terminals
  (the marker check runs before the -ENOENT/wrong_lineage terminals because a
  recycled/re-bound slot is exactly what it certifies).  The verdict is stored
  on `xlog_recover_item.ri_mxfs_verdict`; a transaction is admissible iff every
  buffer image is APPLY or REDUNDANT_CLEAN and no unauthorizable non-buf item
  rides along; inside an ADMITTED transaction REDUNDANT images are skipped
  (`P227-FR-REDUNDANT-SKIP`, `l_mxfs_redundant_skips`) — not refusals, no
  quarantine domain, no torn-verdict arming.  `P273-SHADOW-EVAL` gained
  `REDUNDANT_CLEAN= txn_with_redundant= redundant_skipped= relmarks=
  relmark_overflow=`; `P227-TOKENSUM` gained `redundant=`.
* **Protocol generation** — `MXFS_PROTO_GEN` 5 → 6: a gen-5 replayer fails
  pass 1 of a gen-6 slice with -EFSCORRUPTED (unknown item type), so mixed
  generations are refused at admission.
* **Still owed** (ledger D-FOREIGN-REPLAY-UNGATED-IMAGES): the fence-time
  manifest SNAPSHOT for the APPLY class (the ruling retains it as the explicit
  freeze boundary; the live read is sound today only because fencing freezes
  the victim's bits and purge is ordered after the verdict), markers on the
  ICLUS cluster-release path, and enforcement default-on.

### Courtesy ticket vs. a dead registered waiter (0.24.2, sess404)

Evidence (kill5c/kill5d, `tests/evidence/sess403_v0240/`, `sess404_v0241/`,
ledger D-DEAD-WAITER-AG-TICKET-CREATE-ETIMEDOUT-404): two nodes share an AG
and hand it back and forth; the victim registers as an EX waiter, the
co-owner's release rebuilds the AG batch ticket `yield_to = waiters`
(dlm_caw.c release path — only INODE resources use the fair round-robin /
direct handoff), and the victim is destroyed before claiming.  The slot then
reads `holders=0 waiters=bit(V) yield_to=bit(V)`.  A ticket naming a
registered waiter is a live reservation (sess299 ruling, never age-cleared),
and the sess31 bounded courtesy (fix A/B) covered INODE fresh acquires only, so
every AG fresh acquire on the surviving co-owner looped the compatible-yield
backoff (3+node%10 ms) 100× and exhausted with -ETIMEDOUT (~1.2 s each) until
the dead slot was purged ~74 s later (62 s HB expiry + fence + replay).  The
NOQUEUE flag was honoured only on the INCOMPATIBLE branch, so the allocator's
"non-blocking" AG probe slept in that loop too and returned -ETIMEDOUT, which
`xfs_dialloc_try_ag` propagates as a hard error (only -EAGAIN skips the AG):
`open(O_TMPFILE)` failed 55× with ETIMEDOUT on an AG that was FREE.  Census
(`P-CAWEXH-AG`, 0.24.1): `yield_bo=100 ea_claim=0 ea_compat=0 ea_regwait=0
last_hex=0 last_waiters=last_yt=bit(dead)`.

Rule (design-consult ruling `ccloop-c7ee71c6-sess404-GPT-ruling-ag-dead-waiter-ticket-
bounded-courtesy`): the holder bitmaps and the CAS generation are the exclusion
authority; `yield_to` is fairness metadata and may never become an
availability barrier.  A dead WAITER needs no fencing to be overridden (it
holds nothing); only a dead HOLDER, or replay state that may still modify the
resource, justifies waiting for fence/purge.

* **Bounded courtesy for AG** — `caw_lock_body` compatible-yield branch: a
  fresh (our_mode=NL) INODE **or AG** acquire registers its waiter bit once
  (`mxfs.caw_fresh_register`) and, after `mxfs.caw_fresh_yield_bound` (16)
  consecutive deferrals as a registered waiter, takes the compatible claim
  (`P221-YIELD-BOUND-AG`, counter `caw_stat_ybound_ag`).  The claim CAS clears
  only OUR waiter bits, recomputes `waiter_mode`, and consumes the sticky
  revoke exactly as any claim does; foreign waiters (including the dead one)
  stay until purge.  Other lock classes (JOURNAL/SUPER/ICLUSTER/EXTENT) are
  deliberately NOT enabled — unaudited.
* **NOQUEUE never sleeps in the courtesy loop** — checked BEFORE any
  registration: a plain NOQUEUE caller meeting a foreign ticket on a holderless
  slot gets -EAGAIN at once and leaves no trace (`caw_stat_ticket_noq_eagain`),
  so the allocator's TRYLOCK pass skips the AG and the blocking pass obtains it
  under the bound.  A `MXFS_LKF_DEMAND` caller (the dirty-trans grow sweep,
  D-488) needs progress and there is no holder to revoke, so it takes the
  compatible claim directly — an explicit, counted fairness override
  (`P-CAW-TICKET-DEMAND-OVERRIDE`), not disguised as ordinary NOQUEUE.
* **No waiter footprint on any exit** — `yreg_live` tracks a fix-A registration
  that was neither claimed nor handed to the wait path; `out:` drops it on any
  error exit (`caw_drop_own_waiter`).  The exhaustion path dropped it already.
* **Not done on purpose** — no age-filtering of registered waiters at release
  (cannot distinguish dead from slow/descheduled/partitioned-unfenced; the purge
  after authoritative fencing is the only correct eraser), and no blocking of a
  free AG until purge.  Longer term the bound should become an elapsed budget
  (~150-200 ms from registration) instead of 16 × (3-12 ms), never tied to the
  heartbeat timeout.

## CAW admission probe (0.41.3, sess435, D-0359 step 1)

The CAW transport is admitted only on a device whose SCSI COMPARE AND WRITE is
**operational**, proved at mount on the one sector this node owns — its
heartbeat slot — through the same PAL path every lock-slot CAS takes:

1. **Positive half** — the slot claim itself must have landed via CAW
   (`claim_via_caw`).  A claim that needed the verified non-CAW fallback
   (`claim_slot_noncaw`, used when the target rejects opcode 0x89 or when no
   SCSI device sits behind the bdev — loop devices) classifies the device
   `UNSUPPORTED`.
2. **Negative half** — `mxfs_disklock_caw_capability()` issues one CAW whose
   compare image differs from the on-disk record (`timestamp_ms` flipped) and
   whose write image *is* the on-disk record.  A correct target answers
   MISCOMPARE (`-EAGAIN`) and writes nothing; the record is then read back and
   must be byte-identical.  `rc==0` (a mismatch reported as success) or a
   changed record is a `VIOLATION`; any other I/O outcome is `TRANSIENT`.

`dlm/v5_mount.c` runs the probe right after the claim and before the CAW DLM
is created.  Anything but `OK` logs `P311-CAW-ADMISSION-REFUSED cap= rc= slot=
single_node_exclusive=`, releases the slot and refuses the mount: `UNSUPPORTED`
and `VIOLATION` are definitive for the device, `TRANSIENT` fails only that
attempt.  Measured motivation (0.41.2 on a loop device): the mount was admitted
(`DLM initialized (CAW`) and then every acquire failed `-95` six retries deep,
because candidate A (D-0354) removed the lone memory-only grants that used to
hide the missing CAS.

The refusal holds even under `single_node_exclusive=1`.  The design-consult ruling
(`docs/rulings/d0359-noncaw-snlocal-exclusive-domain.md`)
makes CAW-less lone operation a *separate, non-joinable* `SNLOCAL_EXCLUSIVE`
authority mode with mode-bound tokens and a torn-write-safe authority record —
step 2 — and explicitly rejects a read/verify/write stand-in for the lock-slot
CAS.  Test: `tests/vergate.sh <node> noncaw_refuse`.

## Authority-token capture across a BLFT re-type (0.53.0, sess445, D-0512)

The token on a buffer image is captured ONCE per transaction window at the
first protected dirty (`xfs_trans_dirty_buf` → `mxfs_bli_auth_capture`,
sess103) and records the buffer log-format type (BLFT) as a second witness
for the owner derivation.  Until 0.52.0 the commit-time serializer voided the
token (class NONE / INCOMPLETE) whenever the BLFT differed from the captured
one.  `xfs_dir2_sf_to_block` ALWAYS does that: `xfs_dir3_data_init` sets
`DIR_DATA_BUF` and logs the new block (the capture), then
`xfs_dir3_block_init` re-types the same buffer `DIR_BLOCK_BUF`.  So every
shortform→block directory conversion produced an unprovable image, and any
foreign replay of the slice holding it was refused (chain 35 point 13: the
whole-cluster bootstrap REFUSED on one 4 KiB dir block).  The same
same-transaction re-type exists in `xfs_dir2_leaf_to_block`,
`xfs_dir2_block_to_leaf` and `xfs_dir2_node.c`.

Design-consult ruling A′ (`docs/rulings/d0512-blft-retype-authority-void-aprime.md`):

- `xfs_trans_buf_set_type` → `mxfs_bli_auth_note_retype`: if the buffer
  already holds a capture in this window and the type differs, mark
  `mba_retype_pending`.  Nothing is classified there — the re-typing path has
  not written the new format's header yet.
- At the NEXT protected dirty of that buffer, `mxfs_bli_auth_capture`
  re-classifies under the current type.  A VALID result with the complete
  proof identity of the original capture (`mxfs_auth_same`: class, status,
  resource, epoch, lineage, owner inode, auth gen) accepts the transition and
  updates only the witness (`P-AUTHCAP-RETYPE-OK`, `retype_ok`).  A VALID
  result naming a DIFFERENT authority is `MIXED` (`P-AUTHCAP-RETYPE-MIXED`).
  An unprovable result replaces the old proof — it is not evidence about the
  new image (`P-AUTHCAP-VOID why=retype_unproven`).
- A re-type never followed by a dirty stays void at commit
  (`P-AUTHCAP-VOID why=retype_nodirty`); the old BLFT comparison remains as
  the backstop.  Counters ride `P240-AUTHCAP`.
- `mxfs.authcap_inject` (TEST ONLY): 1 records a successful re-proof as
  MIXED, 2 skips the re-proof — the ruling's two negative arms, exercised by
  `tests/d0512_sf_to_block_replay.sh` (a victim converts a directory, is
  destroyed, and the survivors' verdict on its slice is checked).

## Durability-domain admission at mount (0.54.0 sess447; transport arm 0.55.0 sess448, TCP admitted 0.73.0)

A clustered (envelope) RW mount is admitted only into a QUALIFIED domain.
`pal/linux/xfs_super.c`:

* `mxfs_durability_domain_admit(mp)` — in `xfs_fs_fill_super` right after
  the C7 proto gate and on the ro→rw reconfigure, before any recovery write.
  Refuses (-EPERM, `MXFS P-DOMAIN-REFUSED clustered RW mount REFUSED: <why>
  (knob snapshot)`): `icluster_dlm=1` (until `MXFS_ICLUS_RELMARK_READY`),
  `foreign_replay_token_enforce=0`, `release_proof_enforce=0`,
  `fua_disable=1 && target_cache_protected=0` (F2), `fua_disable=0`
  (crash-durable domain unqualified, D-0516).  Admits `fua_disable=1 &&
  target_cache_protected=1` silently.
* `mxfs_domain_admitted_announce(mp)` (0.62.0, sess461) — prints
  `P-DOMAIN-ADMITTED ... COHERENCE-ONLY ... transport=CAW|TCP` only after
  BOTH arms passed (after `mxfs_transport_domain_admit` on a fresh mount and
  on ro→rw).  Before 0.62.0 the durability helper printed ADMITTED itself,
  two seconds before the transport arm refused the same attempt (chain 86
  matrix R8: ADMITTED then REFUSED for one mount) — a false verdict line.
* `mxfs_transport_domain_admit(mp)` — right after `mxfs_v5_dlm_init` (the
  SELECTED transport is known only then) and on ro→rw.  Both transports are
  admitted: CAW, and TCP since 0.73.0 — the TCP authority ledger mints
  per-grant authority epochs and the sealed fence-time manifest is foreign
  replay's authority source on TCP, so a dead peer's slice is fenced,
  replayed and published like a CAW slice.  (0.55.0–0.72.x refused TCP as an
  unqualified domain; lab builds lifted that with a compile flag, which is
  gone.)  A mount with no transport selected at all is refused.
* RO mounts are never gated.  Readiness is a property of the BUILD
  (`MXFS_ICLUS_RELMARK_READY`, 0; a lab `-D` build carries a `MODULE_INFO`
  marker because srcversion hashes source).
* Truth table asserted by `tests/domain_admission_matrix.sh` R1–R8 (R8:
  `force_transport=1` ADMITTED).
* Rulings: ccmemory `ccloop-c7ee71c6-sess447-GPT-ruling-default-on-scoped-
  coherence-only-flip`, `...-sess448-GPT-ruling-iclus-relmark-certificate-
  and-sequencing` (+ the TCP follow-up recorded on D-0288).

## Transport conformance at mount (0.75.0)

The DLM transport (CAW slot table or TCP mesh) is a property of the cluster
on the platter, not of the mounting node.  Two lock managers over one
filesystem exclude nothing from each other, so a joiner must run the
transport the existing tenures run, and a mismatch must be refused before
the mount becomes writable.

**Durable record.**  Every heartbeat record's crc-bound feature word carries
`MXFS_HB_FEAT_TCP` (0x0008): set when the tenure that wrote it runs TCP,
clear for CAW.  It is stamped before the claim (`mxfs_disklock_set_transport_tcp`,
refused once a slot is held) and is uniform across the tenure, like the
snlocal and adopted markers.  A tenure's slice can only be recovered by the
transport that wrote it, so the marker is meaningful on WITHDRAWN and on
dead-but-unrecovered ACTIVE records as well as on live ones.

**Census before selection.**  `mxfs_v5_dlm_init` reads the 64 slot records
(`mxfs_disklock_scan_transport`) before either transport is initialised.
Every ACTIVE or WITHDRAWN record of the mount's mkfs generation with a valid
feature block votes by its bit; LEGACY, CORRUPT and other-generation blocks
are counted as unknown and never vote.  Then:

| platter votes           | module default (force_transport=0) | force_transport=1        |
|-------------------------|------------------------------------|--------------------------|
| none                    | form on CAW (unchanged)            | form on TCP (unchanged)  |
| TCP only                | ADOPT TCP (`P-TRANSPORT-ADOPTED`)  | TCP (`P-TRANSPORT-CONFORMED`) |
| CAW only                | CAW (`P-TRANSPORT-CONFORMED`)      | REFUSED (`P-TRANSPORT-MISMATCH-REFUSED`) |
| both                    | REFUSED (`P-TRANSPORT-MIXED-REFUSED`) | REFUSED               |
| table unreadable        | REFUSED (`P-TRANSPORT-SCAN-FAIL`)  | REFUSED                  |

The override selects a transport only when forming; when joining it is
refused rather than silently replaced, because an operator who asked for
TCP and got CAW would not learn it from a successful mount.  A split platter
is refused for both settings until every slot of one side has been released
or recovered — a transport change therefore requires a whole-cluster
unmount with no unrecovered slices, never a rolling switch.

**Live guards.**  The census cannot see a node whose claim lands after it.
The join gate (`mxfs_disklock_join_gate`) classifies a live incumbent on
the other transport exactly like a live foreign proto_gen: the joiner
withdraws (`P-VERGATE-JOIN ... state=4`).  The monitor's per-pass validation
fences a live intruder on the other transport (`P-VERGATE ... state=4`) once
this node has itself been admitted, so of two nodes forming simultaneously
on different settings at most one survives its join gate and neither
operates beside the other.  Finally `v5_discovery_peer_cb` drops an announce
whose `dlm_transport` differs from ours (`P-TRANSPORT-MISMATCH-PEER`): a
mismatched node is never registered into the lease or the peer mesh.

**Protocol generation.**  The bit is new, and on a record written by an
older build it is clear.  A newer joiner reading such a record from a live
TCP node would adopt CAW next to it — the exact shape the bit prevents — so
`MXFS_PROTO_GEN` was bumped to 19 and the version gate excludes the older
build cluster-wide.

## INODE-class release proof: flush-ticket failure now DEFERS (0.55.1, sess449)

`mxfs_relbar_close_or_defer` (xfs/xfs_mxfs_dlm.c) is the INODE-class
release proof consulted by both wire-unlock arms (`noanchor` ~20409,
`anchored` ~20600).  Since sess258 its final F3 check — "is there a durable
flush ticket covering the discharge stamp?" — issued one direct flush on a
miss and, if the ticket was still missing, recorded `proof_failed` /
`MXFS_TICKET_FLUSH_FAILED` on the certificate but returned the NON-defer
value: the unlock CAS proceeded unproved (telemetry release, "step 6 turns
this into a deferral" never landed).  The ICLUS class has deferred on every
failed proof since sess309; the INODE class now matches:

* exit = `MXFS_RELSTATE_DEMOTING`, `mxfs_relbar_deferred++`, one
  `P228-RELBAR-TICKET-DEFER ino= arm= stamp= epoch= forced=` line (capped
  400), return true;
* both callers route the true return through `mxfs_inode_defer_causes`,
  which derives `MXFS_RELCAUSE_TICKET_STALE` from `proof_failed` /
  `ticket_status`, so the bounded defer episode (`release_proof_enforce=1`,
  60 s no-progress / 300 s total → wedge) or the stranded re-arm applies
  exactly as for an open ledger.

Reachability: `mxfs_relbar_ticket_ok` returns true under `fua_disable=1`, so
in the admitted coherence-only domain this exit is taken only by the forced
stage-10 fault (`relgate_fault_stage=10 relgate_fault_force=1`, harness
`tests/relgate_fault_inject.sh inode`, which now FAILS a forced stage-10 hit
that prints no `P228-RELBAR-TICKET-DEFER`).  Under `fua_disable=0` (refused
by `mxfs_durability_domain_admit` until D-CRASH-DURABLE-DOMAIN-UNQUALIFIED-0516
closes) it is the real F3 deferral; `MXFS_RELGATE_F3_COMPLETION_PROOF_READY`
stays 0 until it is verified in that domain.

## CAW same-node reconcile exerciser (0.56.0, sess449)

`mxfs_v5_dlm_caw_samenode_selftest` (dlm/v5_mount.c) + debugfs trigger
`/sys/kernel/debug/mxfs/<s_id>/caw_samenode_selftest` (write `"<mode> [ino]"`)
+ harness `tests/caw_samenode_selftest.sh`.  defect-bar closure vehicle for
D-SAMENODE-WAITER-CANCEL-COLLISION and siblings: the give-up reconcile arm
(`caw_drop_own_waiter`) is never entered under a healthy board, so a green
board cannot verify the lreq registry / owed-worker fix that landed across
0.11.441-0.11.457.  Shared reserved key `(agcount+1+64) << (agblklog+inopblog)
| 1` (unallocatable; beyond every node-slot-derived pw-selftest key, so all
nodes contend on one slot).

* mode 1 HOLD (peer): lock EX, hold 8 s, unlock.
* mode 2 COLLIDE (local): two kernel threads acquire EX behind the peer;
  once the registry shows attempts==2 and the node's waiter bit is on the
  slot, `caw_inject_wait_expire=1` forces ONE attempt down the real timeout
  give-up path (`P272-INJECT-WAIT-EXPIRE`, rc -ETIMEDOUT).  Mid-hold proof:
  obligation pending AND waiter bit still set (the give-up REFUSED the clear;
  `lreq_plan` others==1).  After the peer releases: survivor granted, owed
  worker discharges through the tenure guard (`lreq_guard_hits`/`defer_hits`
  grew), holders_ex bit SURVIVES, granted_mode EX, knob consumed; unlock →
  bit gone.
* mode 3 NEGATIVE (local): one attempt, knob armed → -ETIMEDOUT; waiter and
  holder bits CLEAR, granted_mode NL, no guard/defer hit; a fresh EX acquire
  then succeeds (nothing stranded).  Proves the collide arm's "bit survived"
  is not "the test never ran".

Verdict: `mxfs: P275-SAMENODE <PASS|FAIL> run= mode= ino= rc1= rc2= hex= w=
wex= gm= guard= defer= knob= attempts= tenure_ex= step= rc=`.  Observation
helpers `mxfs_dlm_caw_test_slot_bits` / `_test_lreq_state` /
`_test_arm_wait_expire` (dlm/dlm_caw.c) are read-only apart from the knob.
Scenarios B and C (sess449 design-consult review) are covered by two one-shot barrier
hooks in `dlm/dlm_caw.c`: `caw_inject_dow_pause_ms` (hook B — pause between
the per-iteration `lreq_plan` and the CAS in `caw_drop_own_waiter`,
`P276-INJECT-DOW-PAUSE`) and `caw_inject_owed_pause_ms` (hook C — pause at
the top of `caw_owed_dispatch`, `P276-INJECT-OWED-PAUSE`).  Mode 4
`collide_late`: the give-up plans ALONE, a second attempt joins and registers
inside the widened gap; the CAS must not strip it (miscompare + re-plan, or
the clear-window refusal).  Mode 5 `collide_owed`: K5 (`caw_inject_dow_casfail`)
fails the give-up's own CAS so the obligation reaches the worker; the joiner
arrives after the give-up's finish decrement and before the pass, which must
see it and refuse.  Both assert the same mid-hold proof and post-conditions
as `collide`.  Peer hold is 14 s (`MXFS_SAMENODE_HOLD_MS`).  The knob API
for the exerciser is `mxfs_dlm_caw_test_arm` / `_test_knob_left`
(`enum mxfs_caw_test_knob`).

## Foreign-replay write-failure containment: injection arm (0.57.0, sess449)

D-FOREIGN-SHADOW-UNWIND-HOST-SHUTDOWN-513B (fix 0.12.5/0.12.6, sess338-340):
a buffer queued by a FOREIGN-slice replay carries `b_mxfs_foreign_recovery`;
`xfs_buf_ioend_handle_error` routes its write failure to the replay
(`P227-FR-BUFFAIL`, stale, error to the synchronous delwri waiter), the
pass-2 error arm fails the batch without I/O (`P227-FR-UNWIND`,
`xfs_buf_delwri_fail`), and the survivor's live `b_mount` is never shut down;
a LIVE buffer's write failure keeps upstream policy (SHUTDOWN_META_IO_ERROR).
The rig cannot produce a write error on demand, so `pal/linux/xfs_buf.c`
carries two one-shot test knobs, taken at the top of `xfs_buf_submit_ex`
(after the log-shutdown check, before any credit or bio) and completed
through the same `xfs_buf_ioend_fail` the shutdown arm uses:

* `mxfs.freplay_inject_write_eio=1` — the next foreign-provenance WRITE
  fails with -EIO (`P227-FR-INJECT-WRITE-EIO ... foreign=1`).
* `mxfs.buf_inject_write_eio_live=1` — the next LIVE (non-recovery) WRITE
  fails (`foreign=0`); that mount must shut down.

`tests/d513_write_eio_containment.sh` arms the foreign knob on every
survivor (only the elected replayer's first foreign write consumes it),
kills a victim under an inode-mode dirty load (so the replay genuinely
writes), and asserts zero survivor shutdowns / one refuser / publish /
import / all mounted; then the live control on one node must shut only that
node down.  Both knobs are 0 in production.

### The write-verifier arm (0.74.2) and the end-of-pass drain (0.74.1)

A foreign-replay buffer write fails in one of three places, and all three
route by the buffer's foreign provenance to the replay rather than to the
survivor's mount: the log-shutdown arm and the I/O-completion arm
(`xfs_buf_ioend_handle_error`, since 0.57.0) and, since 0.74.2, the write
verifier's refusal at submission (`P227-FR-VERIFY-FAIL`).  The knob
`freplay_inject_verify_fail` corrupts the next outgoing foreign-replay image
so the arm can be exercised.

Related ordering rule (0.74.1): an untrusted replay never drains its
recovered-buffer queue at commit-record LSN changes.  The upstream per-LSN
drain is safe only under the upstream on-disk-LSN veto; the token override
of that veto for AG/INODE-class images admits partial images of a state
older than the platter's, which are consistent only after every later image
of the slice has overlaid them in core.  The queue is submitted once at the
end of the pass; the completion line reports `drain_deferred`.

## Clean departure: RETIRE_PENDING (0.59.0, sess450)

A clean unmount no longer publishes its heartbeat slot EMPTY.  The release
stamp is `RETIRE_PENDING` (flag 4; identity, epoch, provenance and PR key
kept, identity crc re-bound), and the slot becomes consumable only when the
node's PR key is proven absent from the LUN: a peer's monitor READ KEYS on
first sight (absent → EMPTY, `P304-RETIRE-COMPLETED-BY-PEER`), the departing
node itself when it never held a key (`P304-RETIRE-COMPLETED-SELF`), or —
key still present 30 s after first sight — the peer stamps WITHDRAWN
(`P304-RETIRE-EXPIRED-WITHDRAWN`) and the withdraw pipeline fences the key,
replays the clean slice and purges the slot.  The departing node's own
re-stamp on a failed unregister (`P303`, 0.58.0) is now RETIRE_PENDING →
WITHDRAWN and is an optimisation of that expiry, not the only path.  Claims
never take a RETIRE_PENDING slot.  Full mechanics: `dlm/disklock.md`.

### 0.59.1 (sess451) — the STOP-SHIP fixes to the settlement

The sess450 design-consult review ruled the 0.59.0 implementation STOP-SHIP on
three defects and one regression; 0.59.1 is those fixes:

- **Tri-state key lookup, fail closed.**  `mxfs_scsipr_key_state` answers
  ABSENT / PRESENT / UNKNOWN.  ABSENT is a fencing-grade proof and needs a
  COMPLETE READ KEYS view taken while the answerer's own key is registered
  and the WE-RO/WE-AR reservation is in force; -EOPNOTSUPP, any transport
  error, a truncated view, our key missing or no/wrong-type reservation is
  UNKNOWN.  An UNKNOWN key never settles the record either way: not EMPTY
  (no consumable slot beside a possibly write-capable registration), not
  WITHDRAWN (no recovery action on no evidence) — it stays RETIRE_PENDING
  and the monitor escalates once per grace (`P304-RETIRE-UNKNOWN-STALLED`).
  A record whose identity block is invalid and has no frozen observation
  names NO key: UNKNOWN, not "no key".  A valid identity that disagrees
  with the frozen observation of the same incarnation is
  `P304-RETIRE-KEY-CONFLICT` → UNKNOWN.  One READ KEYS + READ RESERVATION
  snapshot per second serves every pending slot in a monitor lap.
- **No classification of a stale image.**  A settlement CAS lost to a
  concurrent settler or claimant re-reads the sector before returning
  CHANGED; the dead-confirm arm never fires death on a CHANGED image.
- **RETIRE_PENDING holds admission.**  The mount barrier's
  requires-recovery sweep counts RETIRE_PENDING like WITHDRAWN and settles
  it immediately (no grace): proven ABSENT/OWN → EMPTY, PRESENT →
  WITHDRAWN → the fence pipeline; UNKNOWN → the slot holds the gate
  (`P-ADMIT-RETIRE-PENDING-HELD`).  A mount never goes writable beside an
  unretired registration.
- **P305 same-boot settlement.**  A RETIRE_PENDING record of THIS boot is
  no longer refused: the scan records it (`P305-PR-SAME-BOOT-RETIRE-
  PENDING`), and once our PR context and the disklock exist the mount
  settles it (`P305-RETIRE-SETTLED`: our re-registered derived key answers
  OWN; ABSENT also settles).  A present key that is not ours is stamped
  WITHDRAWN and the mount refuses (`P305-RETIRE-KEY-FOREIGN-PRESENT`);
  UNKNOWN refuses (`P305-RETIRE-UNSETTLED`).  The scan runs on every
  mount on both transports (CAW since 0.59.1; TCP since 0.75.3 — until then
  the TCP mount path had none of this sequence, so the last node to leave
  a TCP cluster could not remount in the same boot: its own retire-pending
  record named its own re-registered key, which nothing could prove
  retired), not only when the nexus already held our key, so a remount
  after a SUCCESSFUL unregister settles its own record before a peer can
  see the re-registered key as PRESENT.  The settle runs before the slot
  claim, and the retire machinery (key-state lookups, probe thread, settle
  function, retire worker) is wired before the claim on both transports.
- **Departure ↔ re-registration serialization.**  A host-wide lock
  (`mxfs_v5_dlm_departure_lock`) covers a departing unmount's late phase
  (release → unregister → re-stamp/complete → finish) and a mount's
  REGISTER → P305 settlement on either transport, so a same-boot remount
  can neither lose its registration to the old unmount's late unregister
  nor settle a record the old incarnation's late phase still owns.  The
  admission barrier's immediate settle, which runs after that window has
  closed, takes the same lock itself for the duration of its bracket.

Harness: `tests/pr_unregister_fail_restamp.sh` (restamp, crash) and
`tests/retire_pending_admission.sh` (sameboot, joiner).

### 0.59.2 (sess452) — the second STOP-SHIP: coherent, fresh, off-heartbeat proof

The sess451 review ruled 0.59.1 STOP-SHIP again.  What the protocol now
guarantees (details: `docs/pr-fencing-departure.md`, `dlm/disklock.md`):

- **A proof is a bracket.**  READ KEYS A / READ RESERVATION / READ KEYS B
  with one PR generation, our key in A and B, the WE-AR reservation held;
  absence from B.  Any local PROUT or a reservation conflict invalidates it.
  ABSENT is fresh (≤ 5 s) and single-use per key; PRESENT is served ≤ 2 s.
- **The heartbeat never issues a PR IN for settlement.**  A probe thread
  per PR context does; the monitor reads its table (UNKNOWN when stale) and
  only the mount thread brackets inline.
- **No OWN.**  Our own key is PRESENT to every generic lookup.  Only P305
  clears a record naming it — every same-boot record enumerated, each
  cleared under the departure lock after a fresh bracket proves our
  registration live.
- **Key 0 is UNKNOWN**, a clustered departure never completes its own
  retirement (only a single_node_exclusive / fence_capability_override
  admission may), and P305 settles a key-0 record only by the operator's
  topology assertion.
- **Quiescence is asserted**: the release stamp is preceded by
  `P304-RETIRE-QUIESCED` computed from the mount's own buffer-I/O counter
  after an explicit FROZEN transition; a violation makes the departure
  dirty.

Harness: `tests/retire_pending_admission.sh` (ten arms) and
`tests/pr_unregister_fail_restamp.sh`; chain `tests/sess452_chain71_retire_pending.sh`.


## 0.64.13: D-488 unlock-exit fault arms (sess470)

`caw_unlock_gen_body` (dlm/dlm_caw.c) classifies every exit of an AG release
into the tri-state outcome the D-488 rework introduced (0.11.496-498): a clean
`find_slot` not-found is RELEASED (ruling leg 4), a `find_slot` I/O error and a
clear-CAS hard error are UNKNOWN (the worker re-verifies by slot read-back,
then STILL_HELD re-mints + re-arms, or a still-unprovable outcome quarantines
the AG loudly).  The board's `ag_strand_repair` criterion only ever
manufactured the stranded *postcondition* (skip the wire unlock); the sess470
design-consult disposition review of D-AGLOCK-ORPHAN-EX-TRACKING-LOSS-LIVELOCK-488
required the exits themselves to be executed.  Three TEST-ONLY module
parameters (default 0, AG resources only, consumable) force them on the real
post-COMMIT body:

| knob | forces | expected chain |
|---|---|---|
| `caw_inject_unlk_noslot=N` | `find_slot` → -ENOENT after it answered 0 | `P274-AGUNLK-NOSLOT`, RELEASED with the bit still set = an own-bit strand; recovered by the BAST-driven orphan-nak/readopt (`P5N-AG-ORPHAN-NAK disk_held=1`, `P294-READOPT-MINT`) — doubles as D-0528's out-of-window own-bit measure |
| `caw_inject_unlk_findslot_eio=N` | `find_slot` → -EIO | `P274-UNLK-FINDSLOT-ERR` → UNKNOWN → `P275-AGUNLK-REVERIFY` (held=1) → STILL_HELD → `P275-AGUNLK-REARM` |
| `caw_inject_unlk_cas_eio=1` | clear CAS skipped, -EIO reported | `P274-UNLK-CAS-ERR may_have_written=0` → UNKNOWN → re-verify → STILL_HELD → REARM |
| `caw_inject_unlk_cas_eio=2` | clear CAS committed, -EIO reported | `P274-UNLK-CAS-ERR` → UNKNOWN → re-verify (held=0) → RELEASED |

Every hit logs `P470-UNLK-INJECT ag= site= forced_rc=`.  Harness:
`tests/d488_unlock_exit_arms.sh <X> <Y> <arm>` (X holds a directory's AG, Y
contends, the arm fires on X's release, then X allocates in its own AG and Y
again; PASS = expected lines, no QUARANTINE / REARM-FAIL / splat, every create
inside its bound).  Chain: `tests/sess470_chain111_d488_unlock_exits.sh`.
