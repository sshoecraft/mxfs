# MXFS — New Coordination Architecture (Path A: Portable Reliable-Notification Hybrid)

> Status: PROPOSED (2026-06-06). Supersedes the symmetric-CAW *notification*
> layer only. Does NOT replace CAW as the exclusion authority. Read alongside
> `DESIGN.md` (current system) and `.ccmemory/` (session history).

---

## 1. Why we are changing direction

The `cache_coherency` criterion has been the lone ship-gate holdout for ~40
sessions (sess79–107+). Every fix has either reintroduced the timing wall
(per-op slot reads, FUA storms) or left a stale-read hole. That pattern, held
across dozens of sessions, is not a bug — it is the architecture telling us the
problem is at the substrate level, not the code level.

### The root finding

Fast clustered filesystems escape the coherent-vs-fast tradeoff exactly one way:
aggressive local caching (fast) made safe by **reliable, prompt, targeted
invalidation**. GFS2/OCFS2 get that reliable invalidation from the kernel DLM's
guaranteed BAST delivery.

MXFS has two notification channels and **neither is reliable AND prompt**:

- the **disk-polled `waiters` bit** — reliable, but slow (100 ms–2 s);
- the **lossy eviction ring + best-effort UDP multicast BAST** — prompt, but
  drops entries under load (28-entry ring, head_seq gap) and drops packets.

That gap — no channel that is both reliable and prompt — is the entire residual
coherency bug class. It is not inherent to symmetric shared-disk. It is inherent
to doing symmetric shared-disk *without* a reliable-prompt notification channel,
which we avoided because the obvious one (kernel DLM) is Linux-only and we target
Linux/FreeBSD/macOS/Windows.

### Why the current architecture is still the right base

Given the real constraints — **fast, multinode, cross-platform, POSIX-correct,
and the existing options (GFS2/OCFS2/CephFS) are unusably slow** — the design
space has essentially one answer for the *exclusion* substrate: CAW over a
shared LUN. SCSI Compare-And-Write is the one coordination primitive every target
OS can reach identically. CAW is load-bearing for portability first, scale second
(`.ccmemory/project_caw_is_load_bearing.md`). We keep it.

We are not abandoning the architecture. We are adding the one missing piece.

---

## 2. The decision

**Keep CAW as the sole authority for mutual exclusion and correctness. Replace
the lossy notification layer (eviction ring + best-effort UDP BAST) with a
reliable, prompt, targeted, cross-platform invalidation channel. The disk poll
remains as the always-correct slow backstop.**

The network becomes a *reliable* latency optimization instead of a *lossy* one.
It is still never load-bearing for correctness: if the network is down or a peer
is unreachable, we fall back to the disk-polled `waiters` bit and, ultimately,
fencing — exactly as today. The disk cannot lie.

---

## 3. The mechanism

### 3.1 The CAW slot bitmap IS the cached-holder directory

We do not need a master or a separate distributed directory to know who is
caching a resource. `struct mxfs_caw_lock_slot` already records it on disk:
`holders_ex / holders_pw / holders_pr / holders_cw / holders_cr` are per-node
bitmaps. When a node wants to acquire a conflicting mode, it reads the slot
(it already does this) and the incompatible-holder bitmap tells it *exactly*
which nodes must be notified.

This is why the design is **masterless**: the authoritative registry of who-holds-
what already lives on the disk that every node reads. Adding an in-memory master
registry would only create a second source of truth that can diverge from the
disk — the opposite of what we want.

### 3.2 Reliable targeted invalidation over a TCP mesh (replaces the lossy ring + best-effort BAST)

Transport: a low-latency **TCP** invalidation mesh, PAL-wrapped (`mxfs_pal_*`
sockets) so it builds on Linux/FreeBSD/macOS/Windows. It carries invalidation
messages only — never lock arbitration (that stays on CAW). **Masterless:** the
holder set comes from the CAW slot bitmap (§3.1), so there is no coordinator to
elect, fail over, or keep in sync with the lock state.

On a conflicting acquire (e.g. a writer taking EX on a dir that peers hold PR):

1. Read the slot; compute the set of incompatible holder nodes from the bitmaps.
2. After the durability flush, as part of the CAS that clears the writer's bit,
   bump the slot's `version_epoch`. Send a **guaranteed TCP invalidation**
   carrying `{resource, version_epoch}` directly to each holder node.
3. The holder invalidates the named caches in memory (dir DATA blocks for dirs,
   the inode-cluster buffer / `di_size` for files), records the epoch, runs the
   existing demote (`mxfs_dlm_bast_process`: flush + invalidate + clear on-disk
   bit), then **acks** — only after the drain completes (preserves invariant #1).
4. The acquirer proceeds once all targeted holders have acked, or the fallback
   fires.
5. On an unreachable/slow holder (bounded ack timeout) → fall back to the on-disk
   `waiters` bit + disk poll (today's reliable-slow path) and, if the node is
   truly dead, fencing.

Properties:

- **Reliable** — TCP gives in-order guaranteed delivery; the epoch in the message
  tells the peer exactly what changed; the disk path is the backstop if TCP fails.
- **Prompt** — network RTT, not the 100 ms–2 s disk-poll cadence.
- **Targeted** — only the actual holders are contacted (from the bitmap), never a
  broadcast storm and not a poll over all held slots.
- **Masterless** — the slot bitmap is the holder directory; one source of truth,
  no SPOF, no election/failover window.
- **Not load-bearing** — disk poll + fence remain the correctness backstop; total
  network loss degrades to slow-but-correct.

### 3.3 Using a TCP mesh WITHOUT repeating the prior-art failure

`.ccmemory/tcp_dlm_straggler.md` + `project_caw_is_load_bearing.md`: the previous
TCP DLM stragglered 7.7× at 4 nodes and, at 16+ nodes, its ~120 persistent TCP
connections filled send buffers and blocked lease renewals → cascading false
node-death. That failure was specific to running the **DLM lock-grant path** over
a **full persistent mesh** — serial lock-master arbitration plus N² always-on
sockets coupled to liveness. This design is a different animal and must stay that
way:

- **No lock arbitration over the network.** Arbitration stays on CAW. The TCP
  channel carries only targeted invalidations. The serial-lock-master bottleneck
  that sank the old TCP DLM does not exist here.
- **No pre-established N² mesh.** At 64 nodes a full mesh is ~2000 connections —
  the exact congestion that caused false-death. Open connections **lazily**, only
  to peers this node actually coordinates with, pooled and LRU-reaped. Connection
  count tracks coordination locality, not cluster size.
- **Isolate from liveness.** The invalidation sockets must NOT share send buffers,
  threads, or fate with the lease/heartbeat path (which stays on its own channel).
  A backlog on the invalidation mesh must never delay a lease renewal.

If the TCP mesh saturates under extreme fan-out, the fallback is the disk
`waiters` bit + fencing (slow but correct) — never silent staleness.

### 3.4 Secondary benefit: less disk BAST-poll I/O

Today the `bast_poll_fn` polls held slots every 100 ms (10 ms under contention),
and at ~8 nodes this poll I/O can saturate the iSCSI target
(`.ccmemory/project_caw_is_load_bearing.md`). Once reliable network notification
is the prompt path, the disk poll can relax to a slow safety backstop (e.g. 1–2 s),
*reducing* target I/O and improving scaling — a net win, not just a coherency fix.

---

## 4. The hard prerequisite: kill P106 first

**Reliable notification only works if the on-disk holder bitmap is accurate.**
sess106/sess107 proved it sometimes is not: `P106-STALE-EX` fires when a node
holds `i_dlm_mode==EX` (state CACHED) in memory while its on-disk `holders_ex`
bit is 0. sess106 ruled out reclaim/heartbeat/epoch/steal and concluded a release
path clears the on-disk bit **without** resetting in-core `i_dlm_mode` to NL
(`mxfs_dlm_bast_process` does reset it at xfs_mxfs_dlm.c:1573 — so a *different*
path is the culprit: candidates are the yield path, the AG-side release, or a CAW
internal demote). sess107's deferred-publish backstop removed the corruption
shutdowns but left ~29 residual `P106-STALE-EX`/run on test1.

If a stale holder is not represented in the on-disk bitmap, the acquirer will not
see it, will not notify it, and the stale read survives — **no notification layer
can fix that.** Therefore:

**Phase 1 fixes the exclusion primitive: every path that clears an on-disk holder
bit must, atomically with that clear, reset the in-core `i_dlm_mode`/`i_dlm_state`
(and vice versa). Ideally all releases/demotes/yields route through one chokepoint
so the on-disk bit and in-core mode can never diverge. A permanent, toggleable
assertion/probe must fire the instant they diverge.**

This also subsumes the deferred-publish hazard (§4.6 in DESIGN.md): an unpublished
inode has no on-disk slot, so it is invisible in the directory. Either publish on
create (preferred — small init I/O, see sess107 "Gemini Part A"), or guarantee the
backstop publishes before any namespace exposure.

---

## 5. Implementation phases

**Phase 0 — Decision gate (DO THIS BEFORE BUILDING ANYTHING).**
Force-simulate perfect synchronous coherence: bypass the fast path for reads and
FUA-re-read dir/inode metadata on every lookup (the deliberately-slow, provably-
correct configuration). Then measure on the 4-node cluster under *contended*
metadata:
- (a) Does `cache_coherency` (all 4 sub-tests) PASS?
- (b) What is the multinode benchmark cost vs current MXFS and vs a GFS2 baseline?

Gate:
- **Outcome 1 — passes AND still clearly beats GFS2/OCFS2** → the speed is real,
  the notification pipe is the only thing missing → proceed to Phase 1.
- **Outcome 2 — passes but collapses to ≈GFS2 speeds** → the speed *was* the
  incoherence; Path A cannot preserve the value prop. STOP and report; revisit
  Path B (revert to mxfs.1 synchronous model) or Path C (craft project).
- **Cannot pass even fully synchronous** → exclusion is broken at a deeper level
  than notification; fix P106 (Phase 1) and re-run the gate before any Phase 2.

**Phase 1 — Exclusion-primitive coherence (the P106 kill).**
Couple on-disk holder-bit and in-core mode in all release/demote/yield/purge
paths; single-chokepoint release; permanent divergence assertion. Re-run
`rename_visibility`, `unlink_visibility` — divergence-driven losses should vanish
even before the notification layer, because the slow path now re-acquires cleanly.

**Phase 2 — TCP invalidation mesh + version epoch.**
Carve `uint64_t version_epoch` from `mxfs_caw_lock_slot.reserved[392]`
(format-compatible: no slot-size/table change; verify `sizeof==512` with
`caw_verify`). The writer bumps it as part of the bit-clearing CAS at release.
Implement the TCP invalidation mesh (§3.2/§3.3) behind the PAL: lazy pooled
connections (no N² mesh), holder set from the slot bitmap, epoch carried in the
message, ack after the holder's drain completes, disk-poll demoted to a slow
backstop, fall back to `waiters` bit + fence on an unreachable holder, sockets
isolated from the lease/heartbeat path. The epoch also closes the
`cross_write_read` slow-path residual: a slow-path acquirer whose cached
inode-cluster buffer predates the slot epoch invalidates/FUA-refreshes it before
serving.

**Phase 3 — Retire the lossy mechanisms and validate.**
Demote the eviction ring to a pure prefetch hint (or remove it). Run: full
`cache_coherency` 4-node, the rename/unlink/cross_write_read repros, the complete
ship gate (`tests/criteria/verify_ship.sh`), and the contended multinode
benchmark. Required end state: **12/12 PASS and still clearly faster than
GFS2/OCFS2 under contention.** Slowness is a ship failure
(`.ccmemory/feedback_timing_is_first_class.md`), not just overhead.

---

## 6. Invariants preserved

All DESIGN.md §6 invariants hold. Specifically:

1. CAW slot table stays fixed at 65536 × 512 B; no mkfs/envelope format change is
   required for Phases 0–2 (the optional epoch in §5/Phase 2 fits in `reserved`).
2. CAW remains the sole exclusion/correctness authority. The network never grants
   or arbitrates a lock.
3. No on-disk DLM unlock without a completed drain pipeline (§5.1) — unchanged;
   the ack in §3.2 is sent *after* `bast_process` completes its flush+invalidate.
4. PAL discipline (invariant #4): the notification socket code lives behind
   `mxfs_pal_*` so it builds in userspace and ports to BSD/macOS/Windows.
5. Correctness survives total network loss: disk poll + fencing remain the
   backstop. The network is a reliable optimization, never a dependency.

## 7. What this explicitly is NOT

- NOT a TCP DLM — the TCP mesh carries invalidations only; lock arbitration never
  leaves CAW (the prior-art TCP failure was arbitration over a full mesh, §3.3).
- NOT an elected master / asymmetric metadata server (that was the sess67 pivot,
  reversed at sess68; it gives up symmetry and adds a SPOF — not needed, §3.1).
- NOT a per-op slot read on the fast path (that is P108-REACQUIRE; it hit the
  timing wall — reliable demotion knocks cached holders to the slow path instead).
- NOT the lossy eviction ring as a correctness channel (it stays a hint at most).

## 8. Open questions for implementation

- Exact retransmit budget / timeout before disk-poll fallback (tune empirically;
  must not couple to liveness timers — keep separate from heartbeat/lease).
- Whether to keep best-effort UDP multicast BAST as an additional fast wake on top
  of reliable unicast, or retire it. Lean: retire once unicast is proven, to avoid
  two code paths.
- Phase 2 `cross_write_read`: confirm whether slot-`generation` gating alone fixes
  the stale cluster buffer, or the `version_epoch` field is needed.
- Ack semantics on a holder that is mid-drain (pinned, `i_dlm_pin_count>0`): defer
  ack until unpinned, with a bounded ceiling, then fall back to disk path.
