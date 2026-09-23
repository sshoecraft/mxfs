# dlm (Distributed Lock Manager)

**Owner files**: `dlm/` (21 files, ~20K LOC), `include/` (4 headers), `compat/` (1 file)
**Last updated**: 2026-07-25 (sess6: v0.11.92 orphan-grant NAK); 2026-08-02 (sess43: recovery GUARD slot flag + lease-timeout semantics); 2026-08-29 (sess438: 64-bit per-boot PR key, HB identity block, PR registrant ledger `dlm/prledger.{c,h}`, proto_gen 12); 2026-08-29 (sess440: unregister refuses retained keys, descriptor owner kind, item-5 design §6 — see final section); 2026-08-29 (sess440: unregister refuses retained keys, descriptor owner kind, item-5 design §6); 2026-09-08 (sess559: `mxfs_disklock_host_live_other_boot`, `mxfs_disklock_boot_advancing`, fence kind 21 BOOT_SUCCESSION_ABSENT, `check_dead` fires for never-live frozen slots, P-HB-GHOST-DEAD — see final section); 2026-09-20 (s88: 0.89.21 `struct mxfs_authority` — the lease state moves out of the disklock context into a refcounted object the MOUNT owns, `mxfs_disklock_create` takes it as a 4th arg, `mxfs_mount_write_admitted(mp, site)` replaces the five producers' direct reads of `mp->m_mxfs_dlm`, P291-AUTH-TAIL counters)

## Purpose

Cluster coordination layer. Provides per-resource (AG, inode) DLM locks across nodes via two transports: **CAW** (compare-and-write on the shared LUN's slot table — primary, default) and **TCP** (network-based — fallback for hardware where SCSI CAW is unreliable). Also hosts: SCSI PR fencing, disklock heartbeat + slot claiming, peer discovery (UDP multicast), lease management, dead-node journal recovery.

## Public API (top-level v5 surface)

```c
mxfs_v5_dlm_init(opts) -> *ctx                — Initialize cluster ctx (xfs_super.c calls)
mxfs_v5_dlm_shutdown(ctx)                     — Tear down at unmount
mxfs_v5_dlm_ag_lock(ctx, agno) -> int         — CAW grant for AG (slow path of ag_dlm_lock)
mxfs_v5_dlm_ag_unlock(ctx, agno)
mxfs_v5_dlm_inode_lock(ctx, ino, mode) -> int
mxfs_v5_dlm_inode_unlock(ctx, ino)
mxfs_v5_dlm_get_node_slot(ctx) -> uint32      — disklock-claimed slot 0..63
mxfs_v5_dlm_is_single_node(ctx) -> bool
mxfs_v5_dlm_purge_node(ctx, node_mask)        — drop dead node's grants
mxfs_v5_dlm_advance_epoch(ctx) / get_epoch    — DLM epoch (membership change)
mxfs_v5_dlm_set_peer_joined_notify(ctx, prepare, commit, data)
                                              — 0.83.4: single→multi PREPARE (int, holds a
                                                freeze until COMMIT) / COMMIT pair, run on
                                                the join worker (docs/join-transition.md)
mxfs_mount_write_admitted(mp, site) -> bool   — 0.89.21 THE WRITE GATE, asked of the MOUNT.
                                                This is what the five producers call:
                                                xfs_buf_submit_ex, xlog_write_iclog,
                                                xfs_writeback_submit, xfs_file_dio_write and
                                                xfs_dio_zoned_submit_io.  `site` names the
                                                producer in the diagnostic only.  Defined in
                                                pal/linux/xfs_super.c.
                                                It does NOT read mp->m_mxfs_dlm for its
                                                decision — see below.
mxfs_v5_dlm_write_admitted(ctx) -> bool       — the v5 face of the same question, for
                                                callers inside dlm/ that hold a ctx.

mxfs_authority_alloc() -> *auth               — 0.89.21.  The incarnation's authority over
mxfs_authority_get(auth) / _put(auth)           the shared LUN: a SEPARATE refcounted object
mxfs_authority_ok(auth) -> bool                 holding the ONE copy of {state, deadline,
mxfs_authority_renew(auth, anchor, last_ok)     anchor, incarnation}.  Allocated by the mount
mxfs_authority_close(auth, reason, why)         BEFORE mxfs_v5_dlm_init and released only in
mxfs_authority_take_withdraw(auth, &reason)     xfs_mount_free, so it is still answerable
                                                after the DLM, the disklock and the
                                                heartbeat are gone — the work it governs
                                                outlives all three.  _ok() closes the epoch
                                                when it finds the deadline passed, because
                                                the caller that noticed may be the only
                                                thread running.  _renew()'s anchor is the
                                                instant the landed beat was ISSUED, never its
                                                completion.  _take_withdraw() is claimed by
                                                the PR worker's 250 ms tick.  Two atomic
                                                loads and a compare on the fast path; no lock
                                                the withdrawal path needs, no allocation, no
                                                device, never sleeps.

mxfs_disklock_authority_{ok,renew,close,take_withdraw}(ctx, …)
mxfs_disklock_authority(ctx) -> *auth         — the disklock face of the same object; the
                                                context borrows a reference for its lifetime.

struct mxfs_dlm_ctx.authority_lost_cb(cb_data) -> int
                                              — 0.89.21.  "Has this incarnation's
                                                authority closed?", tested at acquire
                                                ADMISSION, at the top of every retry
                                                iteration, and in the membership-settle
                                                wait; returns -ESHUTDOWN, which is
                                                already what the function answers for
                                                `shutting_down`, so callers' unwinds
                                                treat it as terminal.  Registered by
                                                v5_mount as v5_authority_lost_cb.  It is
                                                a CALLBACK and not a direct call into
                                                disklock because dlm.c also builds
                                                user-mode and the tauth binaries link
                                                dlm.o without disklock.o.

**`shutting_down` IS NOT A GENERAL SHUTDOWN FLAG.**  `ctx->dlm->shutting_down`
is assigned in exactly one place — `mxfs_v5_dlm_shutdown_defer_release()`, at
UNMOUNT.  `mxfs_v5_dlm_shutdown_withdraw()` does not set it, and its own comment
says "conflicting acquires ride their 60 s budgets through the few-second
window".  Measured (`tests/evidence/20260920T175325Z_lockreqbh_s88f`): with a
task blocked on a request the master would never answer, the lease closed AND
the filesystem shut down inside one three-second sample and the task stayed
blocked **72 s** longer, ending at its own retry budget.  That is what
`authority_lost_cb` fixes; do not widen `shutting_down` instead, because
productive acquisitions closing and the DLM engine going away are different
events and the withdrawal path needs the first without the second.

**WHY THE OBJECT IS SEPARATE, and the rule it encodes.**  Until 0.89.21 the
gate read `mp->m_mxfs_dlm` and treated NULL as "not a clustered mount".
`put_super` clears that pointer and joins the heartbeat thread BEFORE
`xfs_unmountfs` writes the log cover and the unmount record, so the whole
teardown tail was admitted with no lease consulted, by a node no longer
proving liveness (measured: exactly one iclog crosses that line on an ordinary
unmount).  So: **clustered-ness is `mp->m_mxfs_clustered`, set once before
anything clustered can submit and never cleared**, and the state lives in an
object that outlives every context that could hold it.  A clustered mount that
reaches the gate with no authority object is REFUSED and counted.  Never write
this predicate against the liveness of a pointer again.

mxfs_dlm_caw_create(dev, base, node, slot, uuid, max_held) -> *ctx   — CAW engine
mxfs_dlm_caw_destroy(ctx)
mxfs_dlm_caw_set_bast_cb(ctx, cb, data)
mxfs_dlm_caw_lock/unlock/convert
mxfs_dlm_caw_purge_dead_nodes(ctx, dead_mask) -> npurged

(legacy mxfs.1-style API in dlm/dlm.h still present for user-space tools)
```

## Key Data Structures

```c
struct mxfs_v5_dlm_opts {
    int      transport;         // CAW=0, TCP=1, AUTO=2
    uint64_t disklock_offset;
    uint64_t journal_offset;
    uint32_t max_nodes;
    void    *bdev;
    uint8_t  volume_uuid[16];
    int      max_dlm_lock_caw;  // v5 sess33: cap on held CAW locks (0=default)
};
struct mxfs_dlm_caw_ctx {
    mxfs_bdev_t      *dev;
    uint64_t          base_offset, lock_region_offset;
    mxfs_node_id_t    local_node;
    uint8_t           node_slot; uint64_t node_bit;
    struct { uint32_t *slots; int count; ... } held;  // dynamic, sized by max_held
    int               max_held;                       // v5 sess33: was static MXFS_CAW_MAX_HELD
    struct mxfs_caw_mem_lock *mem_locks;              // dynamic, single-node fast path
    int               mem_lock_count;
    bool              single_node;
    /* threads, sockets, callbacks, stats */
};
```

## Internal Architecture

**Slot table.** `MXFS_CAW_MAX_SLOTS=65536` slots on disk in the lock region (after disklock heartbeat area). Each slot is 64 bytes containing magic, generation, holders_ex/pr bitmasks, granted_mode, requested_mode, resource_id (32 bytes). Hash from `mxfs_resource_id` → starting slot index, linear probe.

**CAW lock acquire** (`mxfs_dlm_caw_lock`): `find_slot` (read+probe) → `caw_slot` CAS submitting our want → `caw_wait_for_grant` poll loop until granted or 120s timeout (`MXFS_CAW_WAIT_TIMEOUT_MS`). Poll with backoff 1ms→25ms.
**Deadline-bounded acquire** (`mxfs_dlm_caw_lock_deadline`, sess386/0.19.23): same path with an absolute `deadline_ms` (mxfs_pal_time_ms domain, 0=unbounded) threaded through `caw_lock_body`→`caw_wait_for_grant`. Checked AFTER each read/grant lap (grant-wins), exits via the robust `caw_drop_own_waiter` cancel, logs `P-RESV-DEADLINE`, returns -ETIMEDOUT. `mxfs_v5_dlm_inode_lock_retries` now honors `retries` on CAW as a retries×1s deadline (it used to ignore it — the 474 leg-A hole: dialloc reserve blocked minutes under a held AGI buffer). Callers that hold any XFS resource (AGI, ILOCK) across a cluster acquire MUST use the deadline variant.

**BAST poll thread** (`bast_poll_fn`): kthread reads our slot table entries every `MXFS_CAW_BAST_POLL_MS=200` (idle) or `MXFS_CAW_BAST_POLL_FAST_MS=100` (under contention; was 5ms — sess33 storm fix). When peer's request bit set on a slot we hold, fires `bast_cb` → upper layer (xfs) handles drain+release.

**TCP transport** (sess27, v5_mount.c): full TCP DLM via `mxfs_dlm_ctx`. Used when `mxfs.force_transport=1` or auto-detected from peers' transport. Coexists with CAW; v5 ctx picks one at init.

**Single-node bypass:** When `dlm_caw_ctx->single_node=true` (no peers seen), lock/unlock operate purely in `mem_locks[]` without disk I/O. On single→multi transition, `mxfs_dlm_caw_flush_held_to_disk` writes them all out.

**Disklock heartbeat:** 64 slots × 512 bytes at `disklock_offset`. Each node claims one slot and writes a heartbeat every few seconds; dead slots (heartbeat stale > timeout) are reclaimable. Slot index → node_bit (1<<slot) used everywhere as the cluster identity.

## Cross-Subsystem Dependencies

| Depends On | How | Notes |
|---|---|---|
| pal | `mxfs_pal_*` for I/O, threading, mutex, time, sockets | All platform calls go through PAL |
| include | Public headers: `mxfs_resource.h`, `mxfs_node.h`, etc. | Type definitions |

| Depended On By | How |
|---|---|
| xfs | `mp->m_mxfs_dlm` opaque; calls `mxfs_v5_dlm_*` and indirectly `mxfs_dlm_caw_*` | Primary consumer |
| pal/linux/xfs_super.c | Calls `mxfs_v5_dlm_init` from fill_super | Sets `m_mxfs_dlm` on mount |

## Invariants

1. **CAW slot table size is fixed at `MXFS_CAW_MAX_SLOTS=65536`** — on-disk layout. `max_held` (per-mount cap on locally-tracked held locks) MUST be ≤ this.
2. **Transport selection (CAW vs TCP) at mount time:**
   - **Joining existing cluster:** adopt whatever transport peers are using. No override.
   - **Forming new cluster (no peers):** probe CAW first; fall back to TCP if CAW probe fails.
   - **Command-line `mxfs.force_transport=1`** applies ONLY when forming a new cluster.
     Joining an existing cluster IGNORES the override (you must conform to peers).
   Once a cluster exists, transport is fixed; switching requires full unmount on every node.
3. **Disklock slot 0..63 is unique per live node.** Two nodes claiming the same slot = corruption. `mxfs_disklock_claim_slot` enforces via CAS on heartbeat.
4. **`mxfs_v5_dlm_ag_lock` may sleep up to 120s.** Callers MUST NOT hold short-term mutexes (xfs `pag_dlm_acquire_lock` excepted, since iodone path doesn't use it).
5. **Stale BAST messages must be tolerable.** UDP multicast can duplicate/lose; receiver must treat BAST as advisory + verify slot state on disk.
6. **`held.slots[]` and `mem_locks[]` are heap-allocated, sized by `max_held`** (v5 sess33). Pre-sess33 they were `[MXFS_CAW_MAX_HELD]` arrays — too small (4096) for real workloads.
7. **A mount may mutate the shared LUN only while it holds an unexpired AUTHORITY LEASE** (0.89.20). Authority is held to a deadline, not lost when something says so: `MXFS_AUTH_NOT_ADMITTED -> ADMITTED(deadline) -> CLOSED`, and `CLOSED` is sticky — only a fresh coordinated admission under a new incarnation leaves it. `MXFS_DISKLOCK_AUTH_LEASE_MS` is 30 s against a 62 s peer death window; the derivation, and why it is not a ratio of it, is on the constant in `dlm/disklock.h`.
   - The deadline is anchored at the instant a heartbeat is **issued** (`hb_t0`), never at its completion, so local authority can never look younger than the authority peers observe.
   - A renewal is accepted only while the previous authority is still valid. A heartbeat CAS succeeds fine against a target that has released its reservation, so a beat issued after the lease lapsed renews nothing.
   - Every mutating submission asks `mxfs_v5_dlm_write_admitted()` (→ `mxfs_disklock_authority_ok()`), which closes the epoch itself if it finds the deadline passed. Correctness must not depend on the periodic evaluator having run — it and the heartbeat thread can be stalled along with the rest of the VM.
   - Coordination I/O is **not** exempt: the heartbeat checks the lease before sending another beat, and the reservation-health tick is skipped once authority is gone (its repair arm RESERVEs and its fenced-self arm can re-REGISTER, either of which would be an expired incarnation undoing its own fence). Neither is the journal — an "essential log write" exemption reopens the hazard the lease closes, and a dirty log is the correct outcome.
   - It applies to **every** transport and every cluster size, because it lives in disklock and keys off this node's own heartbeat. A CAW mount stamps `hb_last_ok_ms` the same way. A mount with no disklock heartbeat at all never leaves `NOT_ADMITTED`, so the gate passes and nothing changes. A lone node is NOT exempt and must not be made so: it cannot know it will stay alone, and a peer that mounts and finds its slot stale will fence it.
   - What it does NOT establish: that a command already submitted below the gate can never execute later. That residue is open in the defect queue.

## Known Pitfalls

- **`MXFS_CAW_MAX_HELD` capacity:** legacy default 4096 was below typical workload demand (element-web rsync alone uses ~5400 inodes per node). v5 sess33 default bumped to 32768 + dynamic alloc + per-mount override via `dlm_lock_max` module param + `mxfs_cache_caps.dlm_lock`. Hitting the cap → `disk lock table full` flood + perf collapse.
- **5ms BAST poll storm:** at 256 slots/cycle × 5ms = 51K reads/sec, saturates the LUN's SCSI queue at 16+ nodes. Bumped to 100ms in v5 sess33 (mxfs.1 sess74 finding). UDP multicast BAST is the primary fast path; disk poll is just a backup.
- **Single→multi transition (0.83.4, D-0959) — design in `docs/join-transition.md`:**
  the XFS layer registers a PREPARE/COMMIT pair through
  `mxfs_v5_dlm_set_peer_joined_notify(ctx, prepare, commit, data)`
  (`mxfs_dlm_join_prepare` / `mxfs_dlm_join_commit`). The discovery and
  TCP-accept callbacks only QUEUE a sighting (`v5_join_queue`); the per-ctx
  join worker runs prepare (a kernel `freeze_super` on a mounted filesystem:
  data + log written back, cached views dropped), registers the peer in the
  lease, connects it, refreshes the view and commits (thaw). The peer is
  registered only after prepare succeeded, so nothing can install or beacon
  a view that includes it earlier. A prepare that does not succeed is
  retried; it never shuts the node down (the old destage rounds did, and
  that shutdown lost every unsynced byte). The settle gate in
  `mxfs_dlm_lock` now holds EVERY acquiring mode (PR too) and stays closed
  past the wall clock while a live member's beacons carry a different view
  (`dlm_view_pending_live`); an acquire whose bound expires there is refused
  `EAGAIN`. Never call the prepare from a protocol thread; never register a
  peer in the lease before its prepare has succeeded.
- **CAW single→multi flush:** `mxfs_dlm_caw_flush_held_to_disk` runs synchronously on transition. If lots held in memory, this is slow. Triggered when first peer joins the cluster.
- **CAW retry exhaustion:** `MXFS_CAW_MAX_RETRIES=100`. Beyond that returns -EAGAIN. Caller (xfs alloc paths) must handle, typically by trying a different AG. Don't increase blindly — sess29 v0.3.79 tried 500, made things WORSE (longer retry windows widened race exposure).
- **TCP mount refusal arms (0.73.2, sess505):** the deferred death-checker
  thread (`v5_tcp_death_worker_fn`, created just before `mxfs_peer_start`)
  ticks on `ctx` every 500 ms. EVERY refusal arm after its creation must call
  `v5_tcp_transport_unwind(ctx)` (join the thread, peer shutdown, DLM destroy)
  and then `goto err_scsipr` (or `err_disklock` once the retire settle worker
  has started, i.e. after `v5_retire_worker_start`). A bare `goto err_free`
  frees `ctx` under the running thread — proven panic on test32, RIP in the
  worker one tick after the refusal. Never add a new arm with inline
  peer/dlm teardown.
- **Fence-capability gate is one helper for both transports (0.73.1):**
  `v5_fence_capability_admit(ctx, "CAW"|"TCP")` wraps
  `mxfs_scsipr_validate_admission` plus the override rule (override alone is
  refused; override + `single_node_exclusive` admits loudly). It runs after
  register+reserve+probe and before the disklock claim on BOTH branches. A
  PR-less target used to pass the TCP branch with no P303 line at all.
- **A lock flag's semantics live in BOTH engines (0.75.42, sess523):**
  `MXFS_LKF_DEMAND` (NOQUEUE that leaves demand behind) was honoured only by
  `dlm_caw.c` (sticky revoke bit); `dlm.c` denied a NOQUEUE|DEMAND request
  with `MXFS_ERR_DEADLOCK` and told the holder nothing, so every "bounded
  demanding nb sweep" (`mxfs_ag_dlm_lock_bounded`, the 0.75.41 pre-acquire
  poll) was inert on TCP — measured 84/84 polls expired.  Now
  `demand_collect_holders` + `demand_fire` at both NOQUEUE deny sites
  (local master ~4745, remote master ~7689) BAST the conflicting GRANTED
  holders like a queued request would, without queueing; on release nothing
  is promoted and the next probe is granted.  Probe `P-DEMAND-BAST`.  Before
  building on any `MXFS_LKF_*` flag, grep both `dlm/dlm.c` and
  `dlm/dlm_caw.c` for it — AND every `mxfs_v5_dlm_*` wrapper in
  `dlm/v5_mount.c` that branches on `ctx->dlm` vs `ctx->dlm_caw`, because
  the wrapper can drop the flag on one branch while the engines both honour
  it.  0.87.13 (D-0939): `mxfs_v5_dlm_inode_reserve_try` passed NOQUEUE
  alone on the TCP branch, so the inode allocator's DEMAND escalation was
  inert on TCP and a peer's cached grant on a number it had already freed was
  released only by that peer's lazy path (2.3 s per dir_reuse round).  The
  wrapper now carries DEMAND on both branches, and `xfs_ialloc.c` cools a
  DEMANDED refusal for the peer's release fence (`MXFS_DEMAND_COOL_MS`
  40-80 ms) rather than the silent ring's 500-1000 ms.  Evidence that the
  wire carried DEMAND is `P-DEMAND-BAST` on the master, never a caller-side
  demand counter.

## TCP DLM grant-generation protocol (sess-tcp, build 404BC55C)

The 2-node `tcp_dlm_scaling` ~50% double-grant (two nodes both holding dir-EX →
durable lost-update) was fixed by a per-grant **generation token**. Wire:
`mxfs_dlm_lock_resp.grant_gen` + `mxfs_dlm_lock_release.grant_gen`
(include/mxfs/mxfs_dlm.h); `struct mxfs_lock.grant_gen` + `mxfs_dlm_ctx.grant_gen_next`
(dlm.h). `dlm_next_gen(ctx)` (monotonic, never 0, under table_rwlock) stamps every
GRANTED transition; `send_grant` carries it; the client mirror stores it and echoes
it in its RELEASE. Rules (dlm.c):
- `process_remote_request`, sender already GRANTED at mode>=req -> **always RE-AFFIRM**
  (keep entry, bump gen, re-send grant). NEVER remove+promote a waiter (that was the
  proven double-grant: the holder never released). Replaced the old Bug-51 still_safe
  block + stale-removal+promote branch.
- `process_remote_release` IGNORES a stale release (release.grant_gen != entry.grant_gen,
  both nonzero) -- the holder re-acquired since. gen==0 -> unconditional remove (liveness
  fallback for any pre-gen message).
- `process_remote_grant` (client): `pending_signal_resource` now returns matched; UPDATE
  an existing mirror in place (no dup); if !mirror && !matched -> UNSOLICITED grant (a
  re-affirm that arrived after we released) -> REJECT it (send gen-stamped RELEASE) to
  avoid a phantom-EX hang.
Both dispatchers (v5_mount.c, mount.c) extract grant_gen. CAW transport is NOT affected
(it never routes through process_remote_*).

**sess420 (0.30.0) — TCP token plumbing (docs/tcp-authority-ledger.md step 1).**
`v5_tcp_grant_result_fill(ctx, res, granted, gres)` in v5_mount.c fills
`mxfs_grant_result` after every successful `mxfs_dlm_lock*` on the seven TCP
arms (`mxfs_v5_dlm_inode_lock`, `_inode_lock_retries`, `_iclus_lock`,
`_inode_lock_try`, `_inode_reserve_try`, `_ag_lock`, `_ag_lock_try`) from
`mxfs_dlm_grant_gen()` + `mxfs_dlm_resource_master()`: `grant_epoch = gen`,
`resource_lineage = (master<<32)|gen`, status per `mxfs_mode_can_write` +
gen!=0 (same contract as `caw_grant_result_fill`).  Before this every TCP image
was noepoch/durnoep.  Pitfall: gen is per-master and restarts at 1 on a master
(re)start — step 3 replaces it with `{authority_epoch, grant_seq64}`.
Verify: `tests/tcp_token_plumbing_verify.sh` (P228/P239 deltas on 32/tcp).

**sess420 (0.31.0) — bounded/classified completion ladder** (docs/dlm-protocol.md
"Completion ladder").  `mxfs_v5_dlm_recovery_complete2()` returns a typed
`struct mxfs_recov_complete_res` (PUBLISHED/RETRY/SUPERSEDED/FATAL_INVARIANT/
FATAL_WITHDRAW); `v5_complete_classify()` re-reads the descriptor;
`mxfs_disklock_recovery_relinquish_slot()` is the per-slot give-back;
`mxfs_v5_dlm_recovery_stage()` lets xfs skip a redundant replay.  xfs
(`mxfs_dlm_foreign_replay_work_fn`) fail-stops the mount on FATAL.  Pitfalls:
`v5_complete_classify` must NOT run under member_lock (the SUPERSEDED arm calls
`v5_recovered_cb` → `v5_note_dead_node`, which takes it); the incarnation lives
on `ctx->disklock->{local_node,epoch}`, and `inc_eq`/`recov_tok_eq` are static
to disklock.c (equal-and-nonzero / plain equality).

## sess39 — membership split-brain fix (8/tcp dir_reuse catastrophic)

Two DLM coherency fixes (default-on; `tcp_death_grace_ms=15000`, `memb_settle_ms=6000`):
- **Deferred-TCP-death** (`v5_mount.c`): `v5_peer_disconnect_cb_tcp` marks a disconnected
  peer SUSPECT (`tcp_suspect_since[]`) instead of immediately purging+unregistering+
  refreshing. Grace-checker thread `v5_tcp_death_worker_fn` calls `v5_tcp_declare_dead`
  (the old purge/unregister/refresh) only if the peer fails to reconnect within the grace;
  `v5_peer_connect_cb_tcp` cancels on reconnect. Stops a ~7s transient TCP stall from
  flapping membership (8→7→8) → re-master → split-brain concurrent EX → dir corruption.
  Genuine death still caught by `v5_lease_expire_cb`.
- **EX-grant membership-settle gate** (`dlm.c`): `dlm_lock_impl` blocks an EX acquire
  (bounded 60s) while `dlm_membership_settling()` — the active set changed within
  `mxfs_memb_settle_ms` (new `ctx->last_memb_change_ms`, stamped in
  `mxfs_dlm_update_active_nodes`). Defers exclusive work until mastership converges
  (formation 1→N ramp + real death). Single-node + steady-state never gate.

RESIDUAL (unfixed): rare steady-state xfsaild zombie reflush (`readdir=799`) — see sess40.

## sess40 — `readdir=799` is a TCP DLM transport flap (not buffer-layer); flap-prevention fix

**REFRAME (PROVEN, RULE 4):** the dir_reuse single-dirent durable loss correlates 1:1 with a
transient ~500ms TCP flap (`TCP peer N disconnected — deferring death / reconnected — flap
absorbed`). The loss happens even at ROUND 1 on a fresh dir; all 8 nodes agree; `P-DATACLOBBER`,
`P25-RELVERIFY`, `P40-WRBARRIER` all SILENT (so not a stale dir-block write / release gap / late
bio — 39 prior sessions chased the wrong layer). sess39 deferred-death stops the flap churning
MEMBERSHIP, but the socket TEARDOWN still DROPS in-flight DLM grant/release/BAST messages
(fire-and-forget, never retransmitted) → lost-update → 1 dirent gone → cascades to
`DABUF_MAP_HOLE` shutdown. Both 8/tcp failure modes share this root (flap >15s → declared-dead →
split-brain mass-fail; flap <15s → 1-dirent loss).

**FIX (KEPT, `dlm/peer.c::mxfs_peer_send`):** a TRANSIENT send failure (`-ETIMEDOUT`/`-EAGAIN` =
peer's receiver slow / sndbuf full under the 8-node storm, NOT dead) no longer
`mxfs_pal_tcp_shutdown()`s the socket + fires `disconnect_cb` (which caused the flap). It returns
`-EAGAIN` keeping the connection up (caller retries on the same live socket; TCP still holds the
buffered bytes). Only a HARD error (ECONNRESET/EPIPE/ENOTCONN) tears down + reconnects. True
death still caught by TCP keepalive (~19s, `kern.c` set_opts keepidle=10/intvl=3/cnt=3) + UDP
lease (~75s). Result: 8/tcp dir_reuse 3/6 → **6/8**; 2/tcp 3/3 (no regression). Build `A985424B`.

**STILL NOT 100%** — residual = the deeper DLM message-reliability gap (hard-error flaps still
lose messages). **NEXT (GPT-5.5, 2 consults on file):** reliable midcomms (per-peer seq +
cumulative ack + resend-unacked-on-reconnect + receive-side dedup) + grant-generation cookies on
GRANT/RELEASE/BAST; audit "master never grants EX without a generation-matched RELEASE" and "every
release path drains like the BAST path" (under a correct DLM a lost msg should STALL, not corrupt
— there's a secondary corruption bug). `docs/history/reframe-799-is-tcp-flap-not-buffer-barrier-noop.md`,
`docs/history/fix-tcp-flap-prevention-send-no-teardown.md`.

## Historical Bugs

- **sess26 SCSI CAW non-persistence under stress:** kernel `scsi_execute_cmd` reported CAS-success without persisting writes when many CAS ops piled up. Sidestepped by sess27 TCP transport (still default-CAW, TCP via `force_transport=1`). v0.3.128 manual-bio path partially mitigates within CAW.
- **sess21 LIO FUA drop:** LIO target silently strips SCSI FUA bit (per `target_core_iblock.c:772`). Read-side coherency broken. Fix: `mxfs_pal_scsi_read_fua_bdev` issues SCSI READ(16) with FUA bit through PAL, plus `_XBF_FUA_FRESH` flag in xfs.

## Files

- `dlm_caw.{c,h}` — CAW engine, slot table, BAST poll thread (4500 LOC)
- `dlm.{c,h}` — TCP DLM (legacy + sess27 TCP transport hook)
- `peer.{c,h}` — TCP peer manager
- `discovery.{c,h}` — UDP multicast discovery
- `lease.{c,h}` — node lease + dead-node detection
- `disklock.{c,h}` — heartbeat + slot claiming
- `scsipr.{c,h}` — SCSI PR fencing
- `journal.{c,h}` — per-node journal slicing + dead-node replay
- `mount.{c,h}` — legacy mxfs.1-style `mxfs_mount` (user-space tools only)
- `v5_mount.{c,h}` — v5 kernel-side `mxfs_v5_dlm_init`

## sess4 (ccloop a16ec5f2) — unlock-fallback live-request protection (dlm.c/dlm.h)

- **ROOT FIX (proven runs 19/20 via P4L %px lifecycle trace):** `mxfs_dlm_unlock`'s
  WAITING/BLOCKED fallback used to reap ANY same-owner entry; bucket chains are
  LIFO so it ate a CONCURRENT local thread's live in-flight request → the
  requester's `newlk` dangled → kmalloc recycled the memory for a peer's entry →
  the requester's 1000ms timeout freed the recycled LIVE entry (run19: a peer's
  GRANTED EX gen 8210) → holder vanished from master table → immediate re-grant
  → CONCURRENT EX → stale-base dir RMW → durable dirent loss.
- `struct mxfs_lock.pend_waiter` (dlm.h): identity-only link to the local
  waiter's pending. Set when dlm_lock_impl queues WAITING (pending now allocated
  BEFORE the entry becomes table-visible), cleared at promote_waiters promotion
  and at the requester's own timeout-unlink. NEVER dereferenced.
- `mxfs_dlm_unlock` fallback skips entries with `pend_waiter != NULL`
  (P4U-SKIP-INFLIGHT — fires ~20-130×/run under dir_reuse churn, each one a
  prevented request-eat). Truly abandoned leftovers (NULL) still reaped.
- Timeout path frees newlk only if owner==local && WAITING/BLOCKED &&
  `pend_waiter == pend` (P4G-TIMEOUT-FREE-ALIAS otherwise; 0 post-fix).
- Probes: P4L-ALLOC/FREE/PROMOTE (%px, ino<=256, cap 400k) in
  lock_alloc/lock_free/promote_waiters.
- Verified: runs 21-26 = 0 P-DOUBLEGRANT / 0 MX-DOUBLEGRANT / 0 readdir dirent
  loss (previously every 8/tcp dir_reuse run lost dirents).

## sess5 (ccloop-4dd7) — TCP join hardening (v0.11.72/73)
- `v5_peer_connect_cb_tcp` (v5_mount.c): an INBOUND/fallback TCP connect can be a node's
  first sight of any peer; it now fires `peer_joined_notify_fn` (XFS flush + DLM-cache
  invalidation) BEFORE lease-register/refresh when still single-node. Without it the later
  discovery announcement early-returns on `mxfs_lease_has_node` and the single→multi
  transition never runs on that node → phantom holds → split-brain (pve9 pair root #7).
- MEMBERSHIP-SETTLE GATE (both TCP and CAW mount branches, v5_mount.c): if the disklock
  slot table shows ACTIVE foreign slots at mount, the mount blocks (≤15s, 250ms poll)
  until the lease view covers them (`P-MEMB-SETTLE-TIMEOUT` on dead slots). Prevents the
  joiner's first write from self-granting on a stale base (root #8: durable dirent loss).
  The "DLM initialized" log line MUST print BEFORE this gate — run.sh's convergence awk
  resets its beacon window at that line.

## v0.11.74-76 — SCSI PR teardown ordering + slot release (physical QNAP campaign, 2026-07-24)

- **TEARDOWN-ORDER INVARIANT: PR unregister must FOLLOW the final XFS log write.**
  `xfs_fs_put_super` calls `mxfs_v5_dlm_detach_pr_key(v5dlm)` (v5_mount.h) BEFORE
  `mxfs_v5_dlm_shutdown`, then `mxfs_pal_scsi_pr_unregister_bdev(bt_bdev, key)`
  AFTER `xfs_unmountfs`. Unregistering inside v5 shutdown fenced the node's own
  unmount record on WE-RO-enforcing targets (EBADE log-error shutdown on every
  clean non-holder umount; unmount record lost → recovery next mount). Never
  reorder this back. New: `mxfs_scsipr_key/abandon` (scsipr.h).
- **`mxfs_disklock_release_slot(ctx)`** (disklock.h): clean teardown clears the
  heartbeat record's ACTIVE flag (FUA). Called from v5 shutdown when
  `!ctx->withdrawn` — withdraw/crash keeps the record ACTIVE so peers detect
  death + recover the slice. Without it every tenure ghost-taxes later mounts.
- **Settle gate ghost discrimination**: both gates (TCP+CAW) run a one-time
  liveness rescan (`get_stale_slot_mask` threshold=5000) if not settled after
  2s; frozen slots are discounted (`P-MEMB-GATE-GHOSTS`), worst case ~7s vs 15s.
  All-live joins settle <2s and never pay it.
- **TCP branch aborts mount on PR register failure** (parity with CAW): device
  with PR that refuses REGISTER = unfenced node under possible WE-RO → abort.
  One-shot injection `mxfs.dbg_pr_register_fail` (kern.c) verifies the path.
- **QNAP TS-453 Pro PR is NON-CONFORMANT**: purges ALL registrations on session
  logout/login without PRgen bump; UNREGISTER doesn't bump gen; enforcement of
  WE-RO vs unregistered writers is strict. PR on this target is advisory-only —
  D4 (preempt hygiene) + D8 (periodic PR self-check w/ self-fence) still open.
- **OPEN D7**: joiner root-ino EX acquire stalls 4.7-20s (variable) when holder
  has unflushed root-EX at join; joiner-side, self-mastered, pre-grant wait,
  attempts=1. Needs request-ID timestamps (see memory physrig-fixes-v74-76).
- **OPEN D6**: clean umount sends no goodbye → surviving peer's umount grinds
  the full 40s tcp_death_grace with "lock request retrying" spam.

## v0.11.77-80 — fail-closed mount, view-proof settle, goodbye, PR fence program (ccloop c7ee71c6 sess1, 2026-07-25)

- **v0.11.77 (D9) FAIL-CLOSED MOUNT INVARIANT**: an envelope volume whose
  `mxfs_v5_dlm_init` returns NULL must FAIL the mount (`xfs_super.c` →
  -ENOTCONN, `goto out_filestream_unmount`). The old "continuing single-node"
  fallback mounted BOTH test nodes uncoordinated on one LUN when PR-register
  aborted DLM init. Never restore the fallback; single-node use = DLM init
  succeeding as a 1-node cluster.
- **v0.11.78 (D7 CLOSED)**: the 4.7-20s joiner EX stall was the sess39/45
  wall-clock membership-settle gate (`memb_settle_ms=20000`) riding every
  membership change — it froze EVERY node's EX for up to 20s. Fix: lease UDP
  beacon (500ms) carries a FNV-1a-64 **view signature** (sorted member ids +
  count; `mxfs_lease_udp_msg.view_count/view_hash`, old-length packets remain
  valid beacons sans report). `dlm_view_confirmed()` (dlm.c) settles the gate
  as soon as every active peer reports MY exact signature received after MY
  last change. Wall-clock window is the fallback — behavior identical when
  proof is absent. Join wall 20.1s → 0.66s. APIs:
  `mxfs_dlm_get_view_sig/report_peer_view` (dlm.h),
  `mxfs_lease_set_view_provider/report_cb` (lease.h), glue in v5_mount.c TCP
  branch. Probe `P-D7-SETTLEGATE` stays in-tree.
- **v0.11.79 (D6 CLOSED) GOODBYE PROTOCOL**: `mxfs_v5_dlm_shutdown` broadcasts
  `MXFS_MSG_NODE_LEAVE` (after release_all + journal-slot release, before
  peer_shutdown, only when `!ctx->withdrawn`). RX clears the tcp_suspect
  entry, purges, lease-unregisters, and **refreshes active nodes** (P-GOODBYE-RX);
  the disconnect cb skips suspect/EX-freeze for nodes no longer in the lease
  (`mxfs_lease_has_node`) — "closed after clean departure — no death grace".
  Survivor EX work after peer clean-umount: 38s → 10ms. Fenced/withdrawn nodes
  never send goodbye (peers must recover their slice).
- **v0.11.80 (D4/D8) PR FENCE PROGRAM**: v5 never PR-preempted dead nodes at
  all (legacy mount.c blind preempts are user-mode only). Now both death paths
  (`v5_lease_expire_cb`, `v5_tcp_declare_dead`) call
  `v5_pr_fence_dead_node` FIRST (fence before purge/remaster/slice-replay):
  `mxfs_scsipr_fence_node(ctx, victim, live_members)` does READ KEYS
  classification — preempt only PRESENT victim keys; **topology guard**
  (count<live ⇒ P-PR-ADVISORY, no preempt/self-fence — shared-I_T-nexus rigs
  like the tcm_loop VM rig hold ONE registration for ALL VMs, each register
  overwrites the last); own-key-gone self-fence (-ESTALE → fence_notify)
  only when unambiguous (count>=live && live>=2). `registered` flag makes
  destroy's safety-net unregister idempotent (double-PROUT gone).
  D8: `mxfs_scsipr_probe` after register+reserve (both branches) logs
  per-node-PR usability at mount (P-PR-PROBE); periodic self-check in the TCP
  death worker (30s) → P-PR-ADVISORY latch / P-PR-SELFFENCE. Pending on
  sane-nexus rigs (cawd/QNAP): positive preempt + real ESTALE execution.

## v0.11.92 — orphan-grant NAK: membership-purge zombie heal (ccloop c7ee71c6 sess6, 2026-07-25)

**Defect (live-captured, TCP)**: `mxfs_dlm_update_active_nodes` (dlm.c)
purges the ENTIRE local lock table on EVERY membership change, and nodes
process membership events at different times during the mount ramp.  A
node's own GRANTED record can be purged locally while the (settled)
master's record survives.  The holder's later release then hits local
`-ENOENT` in `mxfs_dlm_unlock_gen` and — before this fix — sent NOTHING:
the master's zombie GRANTED entry starved the whole cluster (test6 AG-9:
`P5U-AGUNLOCK-ENOENT` at 17:28:15; master test2 re-BASTed 1/s for 500+s,
`P12-AGBAST-RX holders=0 cached=0 schedule=0`; test1's rm-rf blocked in
`mxfs_trans_preacquire_inode_ags` HOLDING the dir ILOCK → P132 →
3/3 runs DNF as SYSCALL_HANG/ABORTED_BY_PEER).

**New public API**:
- `mxfs_dlm_release_orphan_if_unheld(ctx, resource)` (dlm.c, decl dlm.h):
  guarded NAK — scans the bucket for ANY-state local-owner entry
  (GRANTED/CONVERTING/WAITING incl. in-flight `pend_waiter`); if one
  exists returns `-EBUSY` (never releases under a live local tenure or
  in-flight acquire), else sends the FIX-20b unconditional (gen=0)
  `LOCK_RELEASE` to the resource's current master.
- `mxfs_v5_dlm_ag_orphan_nak(ctx, agno)` (v5_mount.c, decl v5_mount.h):
  AG wrapper; TCP engine only (`ctx->dlm`) — CAW's on-disk slot is the
  single truth, no remote master table to diverge.

**Wire points**:
- `mxfs_dlm_unlock_gen` ENOENT branch (AG type): sets `ag_orphan_nak`,
  sends after `table_rwlock` drops, prints `P5N-AG-ORPHAN-NAK
  src=unlock-enoent rc=%d`, still returns -ENOENT.
- `mxfs_dlm_ag_bast_notify` (xfs_mxfs_dlm.c): unheld shape
  (`holders==0 && !cached && !bast_scheduled` && bast pending >3s) →
  NAK outside `pag_dlm_lock`, `P5N ... src=bast-rx`.  Self-limiting:
  fires once per incoming bast (~1/s) and stops when the master drops
  the zombie.

**Decode notes**: P12-AGBAST-RX's `page_ms` = ms since bast first went
pending (NOT paging); its `holder=` pid/comm is the stale LAST holder.
`schedule=` requires `cached=1` — `cached=0 holders=0` + old pending is
the zombie signature.

**Open (deferred, unobserved)**: the REVERSE purge arm — master's record
purged while the holder keeps its fs-layer grant → possible concurrent
EX after the 20s settle freeze.  Must be reasoned/instrumented before
any production verdict.  P5N/P5U counters are the standing harvest.

## sess10 (ccloop c7ee71c6, 2026-07-26, v0.11.104-108) delta
- v5_mount.c mxfs_v5_dlm_recovery_complete: both silent early-returns now print
  (P163-COMPLETE-BAIL / P163-COMPLETE-NOPEND) — permanent sentinels after the frankenstein
  NFS-module incident (see sess10-B memory).

## sess11 (ccloop c7ee71c6, 2026-07-26, v0.11.109-111) delta
- **Post-death membership (withdraw@2 fix)**: lease membership drives TCP mastership
  (`mxfs_dlm_resource_master` = active_nodes[hash%count]; active_nodes ⇐
  `mxfs_lease_get_active_nodes` = ACTIVE|JOINING entries). The P163 recovery path now
  calls `mxfs_lease_unregister_node(dead)` in BOTH `mxfs_v5_dlm_recovery_complete`
  (elected replayer) and `v5_recovered_cb` (deferred survivors), immediately before
  their `v5_refresh_active_nodes`. Do NOT unregister earlier (fence time): mastership
  must stay ON the dead node until its journal slice is replayed (sess9-D2 freeze).
- **P164 dead-identity set** (`mxfs_v5_dlm.dead_nodes[32]` ring): noted at fence
  (v5_lease_expire_cb), v5_tcp_declare_dead, GOODBYE. `v5_discovery_peer_cb` and
  `v5_peer_connect_cb_tcp` reject retired ids (P164-DEAD-REJECT) — a force-shutdown
  zombie keeps announcing/renewing until unmounted and must never re-enter membership.
  `v5_refresh_active_nodes` deliberately does NOT filter on the dead set (comment in
  code): filtering there would remaster at fence time and re-open the torn window.
- Victim side: `mxfs_v5_dlm_shutdown_withdraw` now also runs `mxfs_discovery_stop`
  (announce silence). Lease renewals intentionally KEEP running until unmount — they
  hold the entry ACTIVE so mastership stays frozen until the complete-unregister;
  post-unregister they're ignored (lease.c unknown-node print, now ratelimited).
- Print-level trap: "lease: unregistered node" is DEBUG (invisible in dmesg);
  P163-RECOVERY-COMPLETE prints AFTER a multi-second disklock_purge_node zeroing pass;
  the "peer joined — flushing" lines during recovery are the foreign-replay worker
  reusing mxfs_dlm_peer_joined_flush (NOT a membership join).

## TCP peer-connection lifecycle & the false-death class (sess12, v0.11.114)
- **Connection heal paths are asymmetric by construction**: `v5_discovery_peer_cb`
  (dlm/v5_mount.c) re-connects a lease-known-but-disconnected peer on EVERY ~500ms
  announce (lower-id → `mxfs_peer_connect`, higher-id → `_connect_force`). The peer
  layer (dlm/peer.c) resolves duplicate/simultaneous connections by REPLACING in the
  accept path — a join-storm flap where the two sides keep different sockets is normal.
- **connect_cb MUST fire on BOTH connect directions.** Historic defect: only the
  accept (inbound) path fired `ctx->connect_cb`; an outbound reconnect success left
  the v5 suspect timer armed → `v5_tcp_death_worker_fn` declared a peer with a live
  ESTAB socket dead after 40s → `v5_tcp_declare_dead` → whole-table purge (phantom
  grants at surviving masters) + P164 permanent exile of a LIVE node + membership
  fork (15 vs 16) → divergent hash-mastership → FIX-20b reconcile releases routed to
  the wrong master (silent rc=0) → root-ino EX starved → cluster-wide rc=-110.
  Fixed in `peer_connect_impl` (fires connect_cb after start_recv_thread) + a
  death-worker belt: cancel any suspect whose `mxfs_peer_is_connected()` is ACTIVE.
- **Debug affordances**: `ss -tn | grep :7600` on a node is ground truth for the peer
  mesh vs the DLM's beliefs; deterministic flap repro = `ss -K dst <peer> dport/sport
  = 7600` (both sides must print "deferring death" then "connected + cancelling
  pending death" within ~1s; the lower-id side heals OUTBOUND).
- ctx->peer / suspect table / death worker exist ONLY under
  `MXFS_V5_TRANSPORT_TCP` (v5_mount.c:1339) — CAW transports have no TCP mesh, so
  peer.c changes cannot regress CAW conditions.

## sess32 (session 14) — slot-claim provenance
- Both disklock claim variants (CAW + non-CAW) record `ctx->slice_adopted`:
  pass-1 own-stamp reclaim = false (full mount recovery required/safe),
  pass-2 fresh claim = true (inherited slice may be an already-recovered
  incarnation's; mount recovery suppresses its images). Exposed via
  `mxfs_disklock_slice_adopted()` → `mxfs_v5_dlm_slice_adopted()` →
  `mp->m_mxfs_slice_adopted`. Claim log prints which pass won.

## sess37 (ccloop c7ee71c6, 2026-08-01, 0.11.314-315) delta — DIRECT GRANT HANDOFF

### dlm_caw.c — release-CAS ownership transfer (knob mxfs.caw_direct_handoff=1)
- `mxfs_dlm_caw_unlock_gen` yield block: when releaser is LAST holder and fair-handoff
  picks EX waiter W → same CAS sets holders_ex|=W, clears W's waiter bits, yield_to=0,
  dir_epoch++ if last_ex_slot!=W, last_ex_slot=W, streak_note(EX). P6H-HANDOFF.
  Streak-yield arm batch-grants the whole PR class (holders_pr|=pr_w, streak reset
  in-CAS). P6H-PRBATCH. Nudge (`caw_send_grant_mcast`) targets ONLY the handed-off
  bits (p6h_handoff_bit) — an EX grant makes nobody else grantable.
- `caw_wait_for_grant` gained `reg_gen` param (generation the caller's registration
  CAS wrote — threaded from both call sites) + ADOPT branch before the self-stale
  check: adopt iff gen>reg_gen && own waiter bit CLEARED && holder bit set in the
  REQUESTED mode. ad_handoff := (cached grant_meta dir_epoch != slot dir_epoch)
  via new `caw_grant_meta_get_epoch`; no cache ⇒ true (safe). Also heals
  ambiguous own CAW (landed but reported -EAGAIN) — the sess34 untracked-wire-grant
  class. P6H-ADOPT.
- `caw_drop_own_waiter(ctx, slot_idx, giveup_mode)`: abort reconcile — the cleanup
  CAS also clears own holder bit of the ABANDONED mode (covers handoff-landed-mid-
  abort; P6H-ABORT-RECONCILE). Callers pass mode/new_mode. Upgraders keeping their
  old mode are untouched (only the abandoned mode's bit).
- Ownership-incarnation rules (GPT consult): stale pre-registration self-bits can't
  satisfy adopt (waiter bit still set → routes to P-SELF-STALE-EDEADLK as before);
  free boundary = EX exclusion; dead node = lease purge.
- A/B (same build, 32/caw, caw_grant_wait_anatomy 8 32): ON 11.1s total wait/max
  255ms vs OFF 95.8s/max 2657ms. Creates mean 109 vs 235ms.

## sess38 (0.11.321-322) — tail census + PR batch-claim
- P139-TAILCENSUS (in `caw_wait_for_grant`, unconditional >800ms, INODE only):
  per-wait counters bit_lost/chosen/foreign_yt/free_defer/doze250 + caw stats.
  P139-LOCKTOTAL (in `mxfs_dlm_caw_lock` at out:, >800ms): whole-acquire clock +
  per-CAS-site ea_* census — catches multi-retry and ADOPT-exit waits the
  per-wait census misses (adoption bypasses the promote-site emission).
- BATCH-COMPLETION-ON-CLAIM (promote CAS in caw_wait_for_grant): a PR claimer
  named by yield_to admits ALL still-registered shared-class ticket siblings in
  the same CAS (holders_pr|=sibs, waiters&=~sibs, yield_to=0). P6H-PRCLAIMBATCH.
  Kills the measured 9-node ~900ms one-CAS-at-a-time admission storms.
- Release-side P6H-PRBATCH guard relaxed: !slot_has_holders → no EXCLUSIVE-class
  holders (holders_ex|pw|cw); batch fires while sibling PR/CR holders remain.
- Turn economy at 32/caw dir_reuse (measured): inter-handoff p50=58ms p90=140ms;
  discovery (HANDOFF→ADOPT realms join) p50=2ms p99=40ms; grace idle tail 40ms
  (knob dir_ex_batch_grace_ms); remainder = holder work + Invariant-1 release
  drain (log_force SYNC + targeted AG drain, xfs_mxfs_dlm.c ~13600) — dominant.
  xfs_log_force_seq targeting was tried v0.3.38 and REVERTED (no effect + grant
  timeouts) — do not retry that shape.
- grace=10 A/B: cc 41→25s crash 79→21s BUT exposes
  D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (see ledger; default stays 40).

## sess38 late (0.11.324) — heartbeat outage anatomy
- disklock_hb_fn (dlm/disklock.c): per-cycle clocks — P-HB-SLOW (write_ms,
  lockwait_ms, age_since_last_ok_ms, prev monitor_ms; fires when write >2s or
  last-ok age >2 intervals) + P-HB-MONSLOW (monitor pass >2 intervals).  The
  hb write and the 32-peer monitor reads share ctx->lock through the one LUN;
  a saturated queue can stall the write past the 62s default lease
  (lease_timeout_ms=0 deployed) = the test21 self-fence
  (D-RELABORT-ORPHAN-LOOP-HEARTBEAT-SELFFENCE).  Probes unconditional,
  healthy-path silent.  hb failure log now carries age_since_last_ok_ms.
- sess38 FIX (0.11.325): the three disklock read loops (read_all;
  get_stale_slot_mask snapshot + poll) now take ctx->lock PER SLOT READ, not
  across the scan — the whole-scan hold starved the hb writer 26.7s live
  (P-HB-SLOW lockwait_ms=26726) and was the self-fence root.  INVARIANT: never
  hold ctx->lock across a multi-slot I/O loop; slot reads are 512B
  device-atomic.  D-RELABORT-...-SELFFENCE FIXED AND VERIFIED (ledger).


## sess43 (2026-08-02, v0.11.353) — recovery GUARD + lease-timeout semantics

### New HB record flag: `MXFS_DISKLOCK_FLAG_RECOVERY_GUARD` (=3)
An UNCLAIMED slot's AGI unlinked bucket can hold durable zombies with no owner
to reap them (an offline `chk_mxfs -y` repair lands on bucket `agino%64`; a
survivor can die after its sweep retired the dead slot; a shrinking cluster
never re-claims old slots).  The node sweeping such a bucket must hold a
CLUSTER-VISIBLE exclusion against a joiner claiming that slot mid-sweep —
inode-EX alone is not an ownership proof (GPT ruling: bucket removal also
mutates the AGI head / predecessor inode, and competing recovery authorities
could duplicate deferred-reap work).

- `mxfs_disklock_guard_slot/guard_refresh/unguard/slot_unclaimed` (disklock.c),
  exposed to the FS layer as `mxfs_v5_dlm_guard_*` / `_slot_unclaimed` /
  `_local_slot`.  All transitions are CAS from the exact stored image, with a
  write+settle+FUA-readback fallback on non-CAW targets.
- Both `claim_slot` pass-2 scans (CAW and non-CAW) SKIP a fresh same-generation
  guard; a STALE guard (holder died; older than
  `MXFS_DISKLOCK_GUARD_STALE_MS` = dead_threshold × hb_interval) is claimable
  again, and the new claimant's own-bucket rescan re-drives the bucket, so
  takeover needs no monitor or fencing involvement.
- The monitor, join gate, vergate and membership all key on
  `flags == ACTIVE`, so GUARD records are invisible to them: no member-count
  change and no fence risk for the live holder.
- The CAS is also the ELECTION between concurrent scanners — no separate
  singleton protocol.

### Lease timeout is TEN MINUTES, and that is load-bearing
`MXFS_LEASE_TIMEOUT_DEFAULT_MS = 600000` with `MXFS_LEASE_SUSPECT_MISSES = 150`
(lease.h).  A node that dies and rejoins takes a NEW node_id, so peers keep the
dead identity ACTIVE in their lease table — and therefore in the
`MXFS-MEMBERSHIP active_count` beacon — for up to ten minutes after every
fault-injecting event.  This is correct, self-healing behaviour, NOT a ghost
member: measured at 32/caw after crash_consistency, the beacon read 33 while
the on-disk heartbeat table held exactly 32 correct live writers (their
node_ids diffed 1:1 against all 32 nodes), and the beacon returned to 32 on
schedule.

**Consequence for any consumer of `active_count`:** never gate on
`active_count == N` over a window shorter than the lease timeout.  The
authoritative membership is the on-disk HB table (see
`tests/hb_live_count.sh`); `run.sh`'s reconvergence gate was fixed in sess43 to
consult it whenever a beacon over-counts.  Note `mxfs_lease_get_active_nodes`
counts ACTIVE **and** JOINING, and the expiry scan skips any entry whose
`last_renewal == 0` (lease.c:225) — an entry inserted without a renewal stamp
would never age out; every current insertion path does stamp it.


## sess44 (2026-08-02) — guard fencing facts (cite, don't re-derive)

- guard refresh (mxfs_disklock_guard_refresh) and unguard are FULL-512B
  owner-image CAS: any concurrent change fails them.  Refresh failure logs
  P99-GUARD-LOST, sets guard_slot=-1, returns -ESTALE — the UBSWEEP loop then
  sweeps nothing (per-AG refresh gate).  Unguard CAS failure logs
  P99-UNGUARD-RACED and leaves the successor's guard untouched.
- Refresh timestamps are FORCED monotonic (+1 floor) so identical successive
  stamps are impossible; ABA excluded by full-image compare + epoch/fs_gen +
  in-memory-only guard_slot (a rebooted holder cannot resume a guard).
- Refresh runs IN the sweeping thread between AGs — no independent timer — so
  a wedged sweeper's guard FREEZES and peers take it over (hb_guard_abandoned
  change-detection probe, 3x1000ms).  Verified live by guard_race_arms
  stale_resume/abandoned.
- mxfs_survivor_sweep_bucket_ag is READ-AND-ENQUEUE only; every destructive
  step revalidates on fresh iget under EX + AG-DLM (P19 B1-B5 gates), so
  concurrent double-drive of a bucket is safe by construction.
- C7 join gate: P-VERGATE-JOIN (disklock.c ~1440) — a joiner that finds a
  LIVE protocol-incompatible incumbent (feature-state + timestamp/epoch
  movement) refuses and withdraws.  Old-binary-refuses-new-fs still needs a
  superblock INCOMPAT bit (GPT sess44).

## sess93 (2026-08-04, 0.11.422-424) — THE FENCE-EVIDENCE CHANNEL IS WIRED

Until 0.11.422 the entire fence-certificate subsystem built in sess74/75/76 had
**zero callers** (proven by exhaustive grep, sess91). It had an on-disk wire
format, a `MXFS_PROTO_GEN` bump, and seven entry points, and none of them ever
ran. This is the change that connected it.

### The shape of the protocol (read this before touching recovery)

```
peer death (every survivor, heartbeat-monitor thread)
  v5_pr_fence_prove(node, slot, epoch)            dlm/v5_mount.c
      fence_intent()        durable BEFORE the P&A     -> stage FENCING
      mxfs_scsipr_fence_node()  PREEMPT AND ABORT
      fence_certify()       -> stage FENCED, UNOWNED, certificate written
  v5_start_slice_recovery -> elect -> XFS replay hook

elected replayer (foreign-replay workqueue / mount thread — NEVER the HB thread)
  mxfs_v5_dlm_recovery_acquire(slot)              dlm/v5_mount.c
      recovery_claim()      certified + unowned -> execution lease, auth parked
                            in ctx->recov_auth[slot] and HELD across the replay
      -EBUSY + owner proved dead  -> recovery_takeover()      (resume from stage)
      -EPERM + prover proved dead -> recovery_fence_takeover() + re-prove
      v5_exclusion_recheck()  the exclusion must STILL hold
  replay
  mxfs_v5_dlm_recovery_complete()  gate again -> advance -> purge -> zero
```

### Rules that are not negotiable

1. **ONE durable intent, ONE issuing prover, ONE command result, ONE possible
   certificate.** A node that does not win the intent CAS issues NO PREEMPT AND
   ABORT. Letting all 31 survivors fence (which is what shipped before) is
   unsound, not merely wasteful: a loser can remove the key before the intent
   owner issues its command, the owner then observes `KEY_ABSENT_UNPROVEN`, and
   the loser that actually got `PREEMPT_ABORT_DONE` is forbidden to certify.
   That converts a provable fence into an unrecoverable one.
2. **`mxfs_disklock_recovery_begin()` is RETIRED** — it refuses at entry with
   `P238-RECOV-BEGIN-RETIRED` / `-EPROTO`. It minted `FENCED` with
   `fence_kind = NONE`, i.e. the uncertified descriptor every gate must refuse.
   Do not resurrect it as a fallback.
3. **The gate sits below the dispatcher.** Both replay dispatch sites
   (`mxfs_dlm_foreign_replay_work_fn` and the mount barrier's inline round) and
   the completion path all ask. A dispatcher-only check lets a future caller
   recreate the defect.
4. **Claim ONCE and hold the auth** across replay and completion. Re-claiming
   per step makes ownership ambiguous and hides a takeover that happened while
   you worked.
5. **`-EPERM` from `recovery_acquire` is a WAIT state, not a failure.** There is
   deliberately NO timeout after which an unproven slice becomes replayable.
6. **A detector with `victim_epoch == 0` is not a fencing authority.** The
   lease-only path fences nothing and marks nothing pending — an epoch-0 pending
   marker would make `v5_start_slice_recovery`'s is-pending guard swallow the
   heartbeat monitor's later REAL detection, and only that one can certify.
7. **`recovery_takeover` and `recovery_fence_takeover` sleep
   `MXFS_RECOV_ABANDON_MS`.** Never call `mxfs_v5_dlm_recovery_acquire` from the
   heartbeat-monitor thread.

### What a certificate does and does NOT prove — MEASURED

`tests/pr_reregister_probe.sh` measured, at the SCSI layer: a
PREEMPT-AND-ABORTed node's write is REFUSED (exclusion is real at that instant),
and then the same node `REGISTER_AND_IGNORE`s a fresh key and writes
SUCCESSFULLY. So the certificate is **evidence of a completed eviction event,
not evidence that the host remains fenced**. For the ~8 s of in-place replay it
authorises, the only thing keeping a fenced-but-running victim off the LUN is
that victim's own cooperative self-fence.

`mxfs_scsipr_exclusion_holds()` (0.11.424) re-checks reservation health and key
absence at four points and stops the recovery when it has lapsed
(`P239-EXCL-RETURNED` / `P239-EXCL-LAPSED`). It is a **detector**: it cannot
prevent a write that races it. The enforcement gap is tracked as
`D-FENCED-VICTIM-MAY-REREGISTER`; the ruled options are a temporary
single-holder WRITE EXCLUSIVE gate (needs a cluster-wide freeze/drain protocol
MXFS does not have) or target/fabric revocation (outside a kernel module).

### New symbols

| symbol | file | what |
|---|---|---|
| `v5_pr_fence_prove` | v5_mount.c | the PROVER: intent -> P&A -> certify. 0 = a certificate exists, >0 = none (routes to settle residue), <0 = hard stop |
| `mxfs_v5_dlm_recovery_acquire` / `_release` | v5_mount.c | the gate + execution lease |
| `v5_exclusion_recheck` | v5_mount.c | is the exclusion still true? |
| `mxfs_scsipr_exclusion_holds` | scsipr.c | READ RESERVATION + READ KEYS re-check |
| `mxfs_disklock_recovery_slot_status` | disklock.c | read-only classifier: CONSUMABLE / SUPERSEDED / UNFENCED / FOREIGN / DESCRIPTOR / UNREADABLE. `recovery_claim` collapses these into `-ENOENT` and the correct response differs completely between them |

### Probes (all in `tests/`, all re-usable)

`fence_evidence_probe.sh` (one prover / one certificate / consumed by a
different node), `recov_takeover_doublefault_probe.sh` (kill the victim, catch
the owner claiming, kill the owner), `pr_reregister_probe.sh` (does a fenced
victim get back in?), `excl_lapse_probe.sh` (does a returned victim stop the
recovery?).

**Rig technique worth reusing:** the SCST backing store `/home/steve/disk.img`
can be read from clyde with `O_DIRECT` and is COHERENT with the live cluster
(verified: a live node's heartbeat sector changes across a 1.5 s host-side
reread). Superblock at 0, disklock table offset at `sb+64`, slot record =
`dloff + slot*512`; in the record `magic(0) flags(4) node_id(8)`, descriptor at
40, so `desc.stage` at 46 and `desc.owner_node` at 84. `RECOVERY_GUARD` = 3,
`FENCED` = 2. This gives a sub-millisecond vantage point for anything
timing-critical — the takeover probe needs `virsh destroy` in the SAME PROCESS
as the detection, because the window is ~8 s and an ssh round trip loses it.

**Do NOT identify a node from the `claimed heartbeat slot` dmesg line alone.**
It is a boot-time line and dmesg retention varies ~60x across nodes; the
longest-lived node (usually slot 0) has rotated it out. Close the map from the
platter instead — every ACTIVE heartbeat record carries its owner's node id.

### 0.11.425 — `RECOVERY_BLOCKED_FENCE`, the observable state

`/sys/kernel/debug/mxfs/<dev>/recovery_blocked`. Empty means nothing is
blocked. Populated, it names the victim (node / incarnation / key / slot), the
last fence kind + reservation type + PR generation, who holds the fencing
attempt and who holds the execution lease, how long the slice has been
unrecoverable, how many attempts, and an ACTION line per reason.

Ten reasons: `NO_PR`, `FENCE_UNPROVEN`, `CERT_UNRECORDED`, `NO_INTENT`,
`NO_CERTIFICATE`, `OWNED_ELSEWHERE`, `EXCL_LAPSED`, `SELF_FENCED`,
`NO_INCARNATION`.

**Layering:** the record and its accessor (`mxfs_v5_dlm_blocked_iter`, filling a
caller-provided `struct mxfs_recov_blocked`) live in `dlm/`; the debugfs file
lives in `xfs/xfs_mxfs_dlm.c`. That split is architectural invariant 4 — `dlm/`
must still build user-mode, so no `linux/debugfs.h` may appear there.

`first_ms` is stamped ONCE and kept. How long a slice has been unrecoverable is
the number an operator acts on; restamping it on every retry would hide exactly
that. `attempts` counts retries and is what separates a transient from a wedge.

### 0.11.426 — `dead_timeout_ms`, and zero-incarnation descriptors forbidden

**The module parameter `lease_timeout_ms` never configured the lease.** It fed
`mxfs_disklock_set_dead_timeout_ms()` and nothing else; the lease's own timeout
is `MXFS_LEASE_TIMEOUT_DEFAULT_MS` (600000, lease.h) and nothing ever writes it.
Canonical name is now `dead_timeout_ms`; `lease_timeout_ms` still works as a
deprecated alias (`dead_timeout_ms` wins if both are set) and logs the
correction at load. **The lease deliberately does not track it** — see the
sess43 section above on why ten minutes is load-bearing.

**`fence_intent()` refuses `!inc_valid(cur->epoch)`** (`P238-FENCE-ZEROINC`).
With `recovery_begin` retired, those are the only two writers of
`desc.victim_epoch` in the tree, so a zero-incarnation descriptor is now
unconstructible rather than merely unlikely — the sess91 ruling's "forbid them
at CREATION" option.

Note for anyone injecting an epoch into a heartbeat record: `hb_feature_crc()`
covers `fs_gen`, `node_id` AND `epoch`, so a naive epoch rewrite makes
`hb_feature_state()` read !OK and a *different* refusal arm fires. Reseal the
feature block or you measure the wrong thing.

## sess376 (2026-08-19, 0.14.8-0.14.9) — closure-purge observability, and what the logs actually mean

The out-of-closure selective purge (D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356)
has two chokepoints into the SAME function, `caw_closure_strip_one()`
(`dlm/dlm_caw.c`):

- **publisher scan** — `caw_purge_victim_selective_body()` walks all 65536 CAW
  slots in 32-slot batches; each batch entry is a candidacy HINT only.
- **survivor demand scrub** — `caw_closure_scrub_slot()`, called from the
  acquire wait loop and from the NOQUEUE conflict path, so a node blocked on a
  refusal victim's grant repairs the slot itself instead of running to the 120s
  DLM wait timeout.

### Two log-reading traps that cost a session each

1. **"the publisher purges before it publishes" is FALSE.** The durable publish
   is `mxfs_v5_dlm_recovery_publish_refusal()` at `xfs/xfs_mxfs_dlm.c:46711`;
   the purge scan runs after it at `:46759`; the `terminal outcome PUBLISHED`
   xfs_alert at `:46791` is only the trailing summary. Remote monitors import
   the verdict ~2.1s after their own fence-done, and the whole un-injected scan
   is **418 ms** (measured: `P299-CLOSURE-SCAN ENTRY` 14028.136 →
   `P299-CLOSURE-PURGE` 14028.554). Proof that publication is not gated on the
   scan: a publisher destroyed mid-scan, which never emits the summary line at
   all, still had its verdict imported by all 30 remote survivors.
2. **`caw_inject_closure_pause_n` is a single global consumed by whichever
   caller arrives first**, and both callers pass through the same site. An
   unfiltered injection therefore parks a blocked waiter's demand scrub, which
   reads exactly like "the scrub never fired". Use
   `caw_inject_closure_pause_who` (0=any, 1=publisher scan, 2=demand scrub).

### Probes added (all default-off or log-only)

| marker | where | what it answers |
|---|---|---|
| `P299-SCRUB-TRY` | end of `caw_closure_scrub_slot` | census on EVERY demand-scrub attempt: `site=WAIT\|NOQ`, wait age at hook ENTRY (`el_ms`), and which zero-return reason applied (`kept/vanished/bit_gone/res_moved/flipped/cas_mis/hard_rc`). Before this, a scrub that stripped nothing was completely silent. |
| `P299-INJECT-PAUSE` | both injection sites | logs a pause actually taken, with `who=` and `inv=`. |
| `P299-HINT-MOVED` / `-FLIPPED` | `caw_closure_strip_one` | per-attempt, naming slot, hint resource, found resource, `gen`, `lineage`, `vbit_present`. The aggregate `P299-CLOSURE-SHAPES` counters accumulate over a WHOLE scan and therefore name no slot — never assert on them alone. |
| `P299-STRIP-CASMISS` | CAS miscompare path | the expected image (`expect_ino/gen/lineage/vfoot`) that lost. |
| `cand=`/`scrubs=`/`laps=` | `P-ACQ-STUCK` | the live `closure_cand_mask`, how many times THIS wait entered the scrub chokepoint, and the lap count — distinguishes "hook never entered" from "hook entered, oracle refused". |

`el_ms` on `P299-SCRUB-TRY` is the wait's age at hook ENTRY, snapshotted before
the call. It is **not** the mutation time — the strip happens inside.

### Slot identity semantics the ABA argument rests on

- `generation` is **per-binding** and restarts at 1 on a fresh claim, so it is
  not a global monotonic discriminator for a slot.
- `caw_tombstone_slot()` **preserves** generation, resource identity,
  `dir_epoch`, `last_ex_slot`, `ex_grant_epoch`, `open_holders` and
  `resource_lineage` — a tombstone is the binding surviving an idle gap.
- `resource_lineage` is a random nonzero 64-bit id minted per FRESH binding
  (`caw_mint_lineage`, fail-closed: no lineage, no claim) and **inherited** by a
  same-resource tombstone recycle (`caw_claim_inherit_epoch`).
- What actually excludes an ABA success on a closure strip is neither: the
  expected image necessarily carries the victim's footprint (`strip_one` returns
  at the victim-bit check otherwise), and reaching a tombstone requires every
  holder/waiter/open bit to be clear first. Measured: A → tombstone → A with
  identical resource AND identical lineage still produced `P299-STRIP-CASMISS`,
  and the retry re-read, found the bit gone, and mutated nothing.

## sess380 — new instrumentation knobs and probes (dlm/dlm_caw.c)

| symbol | default | what it is |
|---|---|---|
| `mxfs.caw_watch_slot` | -1 (off) | Arm a single CAW slot index; every single-slot read and every CAW this node issues to exactly that LBA is counted and timed. |
| `mxfs.caw_watch_{reads,read_totms,read_maxms,spans,caws,caw_totms,caw_maxms,miscmp,err}` | 0 | The counters. Writable, so a test zeroes them between arms. Plain ints, unserialised — every value is a LOWER bound. |
| `mxfs.caw_locktotal_ms` | 800 | Floor for the **P139-LOCKTOTAL** whole-acquire census. The old hardcoded 800ms sat ABOVE the whole 32-node create-tail distribution, so the probe that exists to explain that tail produced zero lines. Lower it (50) for a census run. |

New probes:
- **`P381-UNLK-CONTEND ino= retries= miscmp= sleep_ms= wall_ms= backoff=`** —
  fires only when an INODE unlock CAS lost at least one race. This is the
  release-side half of the shared-slot CAS collision; see
  `D-32NODE-SHARED-DIR-CREATE-PACE`.
- **`P380-RA-CASRETRY node= slot= attempts= cleared= last_rc=`** — per-slot
  attempt count in `caw_release_all_body`, whose retry loop has no backoff.

Reading the existing probes correctly (this cost sess380 several runs):
`P138-WAIT` times ONE `wait_for_grant` call at a >5ms floor, so a contended
acquire made of many sub-5ms waits with outer retries is INVISIBLE to it.
`P139-LOCKTOTAL` brackets the whole acquire including retries and its
`retries=`/`ea_*` fields are the CLAIM-BOUND vs HOLDER-BOUND discriminator.
`P138-BAST`'s `sx` field is the wire unlock proper; `sa+sb+sc+sd` is the drain
pipeline. On a contended directory `sx` is 95-98% of the release.

---

## 0.16.0-0.17.0 — SCSI-PR reservation LIFETIME and the fencing retry state machine (sess381)

Two critical defects closed here changed the shape of PR fencing. Read this
before touching `dlm/scsipr.{c,h}`, the `MXFS_PAL_PR_TYPE_*` constants, or
`dlm/disklock.c`'s fence intent / certify / takeover trio.

### The reservation is now WRITE EXCLUSIVE - ALL REGISTRANTS (0x07), not WE-RO

`MXFS_SCSIPR_RESV_TYPE` in `dlm/scsipr.h`. WE-RO (0x05) is a **single-holder**
type: SPC releases it when its holder's registration is removed, and MXFS
retires its own registration unconditionally at `put_super`. Measured at 32
nodes: **one node's routine 0.49-second clean unmount took the LU from a held
reservation to none, with 31 nodes still mounted**, nothing re-reserved, and the
next peer death fenced with `NO_RESERVATION(8)` and left the filesystem
permanently unmountable. Under an all-registrants type every registrant is a
holder, so the reservation survives until the last registration goes.

Consequences to keep in mind:

- **`READ RESERVATION` reports the holder key as ZERO** under any all-registrants
  type (measured on SCST). `held` is therefore decided by the **type**, never by
  the key — `pal/linux/kern.c`'s old `held = (rsv.key != 0)` would have called a
  live WE-AR reservation "none held" and failed every fence closed.
- **RESERVATION CONFLICT is no longer success.** Under WE-AR a matching
  scope+type RESERVE from any registrant completes GOOD, so a conflict means the
  reservation in force has the wrong type/scope or our registration is gone.
  `mxfs_scsipr_reserve()`'s return value is checked at all four call sites and an
  incompatible reservation refuses the mount.
- **The fence path and the certificate re-check accept EITHER Write Exclusive
  form** (`mxfs_pr_type_excludes_nonregistrants()`), because that is the property
  an exclusion proof rests on. Only the ADMISSION gate insists on
  `MXFS_SCSIPR_RESV_TYPE`. **There are FIVE such type tests in the tree** —
  `scsipr.c` fence/admission/cert-recheck plus `disklock.c` ~5007 and ~5261 (the
  certificate minter and its verifier). Missing the disklock pair produced the
  worst possible outcome on the rig: the fence PROVED exclusion and the minter
  then refused to certify it, with the victim key already consumed.
- **`mxfs_scsipr_observe_reservation()` must be called before register+reserve.**
  The sess378 admission gate ran immediately AFTER `mxfs_scsipr_reserve()` and so
  validated a reservation it had just created — it logged `P303-FENCECAP-OK
  ... WE-RO held` on a LUN two independent observers read as unreserved.
  `P304-PREOBSERVE` is the honest line.
- `MXFS_PROTO_GEN` is **5**. Gen-4 binaries hard-require type 0x05 in three
  places and cannot see a WE-AR reservation at all; mixed generations are
  excluded cluster-wide by the existing three gate layers.
- **Never PREEMPT with SARK == our own key** (`P304-PREEMPT-SELFKEY`): SPC
  protects the issuer's own registration from its own PREEMPT, so it fences
  nobody and removes our sibling nexus instead.

### The command-submission boundary

`enum mxfs_fence_phase` (`scsipr.h`) — `PRECOMMAND` / `MAY_HAVE_SUBMITTED` /
`VERIFIED` — is set at the two lines that bracket the PROUT, and is **never
derived from `fence_kind`**: a future refactor could detect reservation loss
after submission and the reason would then lie.

Durably, the same boundary is `MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN` (0x8) on the
recovery descriptor, written by `mxfs_disklock_recovery_fence_arm_submit()`,
which `mxfs_scsipr_fence_node()` calls through its `arm_submit` hook on the last
line before the PROUT. **If it cannot be made durable, the command is not
issued.** The bit is monotonic and its name is the contract: it may never be read
as proof that submission *did* happen.

Three durable states result: `FENCING`+clear (nothing was submitted — safe to
repeat), `FENCING`+set (reconcile before assuming anything), `stage >= FENCED`.

### The fence-retry worker

`v5_fence_retry_*` in `dlm/v5_mount.c`. Its **queue is the on-disk descriptor**
(`mxfs_disklock_recovery_fence_retryable()` = stage FENCING, bit clear, prover
is us); `ctx->fence_retry[]` is only a wake-up accelerator and every firing
re-reads the descriptor. Backoff 250ms..6s with jitter, a 60s descriptor sweep
behind it, and it **never gives up on an attempt count**. The thread is created
lazily on the first retryable outcome.

**Do NOT drive fence retries from the heartbeat monitor or from mount
admission.** `expire_cb` means "a live identity became dead, do the one-time
retirement" — re-firing it repeats dead-node retirement, notifications,
slice-recovery creation, purge and successor rebasing. A mounting node is not yet
a member and must not become a fencing authority. Certification instead fires an
explicit wake-up (`P304-FENCE-RETRY-OK` -> `v5_dispatch_slice_recovery`).

**sess406 (D-FENCE-RETRY-PROVE-BUSY-SPIN-406, 0.26.2):** when a firing finds
the slot's single-prover guard held (`v5_pr_fence_prove` returns 1,
`P304-FENCE-PROVE-BUSY`), `v5_fence_retry_one` re-arms with the backoff table —
only if the latch is not armed or its deadline has expired (the guard holder may
have re-armed with an earlier live deadline, keep that). Before this the busy
path left the latch armed with an expired `next_ms` and the worker re-fired it
every 250 ms tick for as long as the prover was busy (test9 0.26.0: 5 min of
RETRY/BUSY pairs while the HB-thread prover sat in the D-405 blocked bio). The
60 s sweep arms any own SNAPSHOTTING attempt as re-drivable, so a merely slow
prover was enough. Test knob `rman_inject=4` holds the prover 12 s on the HB
thread and sets `ctx->fence_retry_scan_now` so the worker sweeps at once
(matrix arm `busy`: 1 <= PROVE-BUSY, <= 8 per node, exactly the victims sealed).

`ctx->fence_prove_busy[]` guards ONE prover per slot per node: the attempt lease
is per node, so two local threads would both "resume our own attempt" and the
second P&A would take RESERVATION CONFLICT and classify as `RACE_LOST` at
`MAY_HAVE_SUBMITTED` — converting our own success into a blocked slice. The
disklock CAS cannot catch that; both threads hold the same valid lease.

### Still open

The `MAY_HAVE_SUBMITTED` half has **no reconciliation** and
`mxfs_disklock_recovery_fence_takeover()` does not consult the new bit before
letting a successor issue a fresh P&A — `D-FENCE-POSTSUBMIT-AMBIGUITY-NO-RECONCILIATION-381`.
Post-PREEMPT verification must not be made mandatory until that is green.

### Harnesses

- `tests/pr_reservation_ownership_probe.sh <observer> [dev]` — read-only; holder,
  type, key counts, or `NONE HELD`.
- `tests/pr_all_registrants_semantics.sh <spare> <observer>` (`PART2=1`) — proves
  the WE-AR properties on the real target; restores pre-state.
- `tests/fence_lifetime_ab.sh <resv-node> <victim> [observer]` — the minimal
  sequence that used to brick the filesystem.
- `tests/fence_precondition_retry.sh <spare> <victim> [observer]` — removes the
  reservation out of band, kills a node, restores it, asserts self-certification.
  **It verifies its own kill**: `virsh destroy` can leave a domain wedged in
  "in shutdown" with the guest still running and serving I/O, and a test that
  proceeds from there scores the absence of a fence as a code defect.

## sess383 (2026-08-20, 0.19.6) — the terminal-outcome import CHOKEPOINT

Three consumers read a victim's terminal recovery-outcome record. They applied
three different levels of scrutiny, and two of them applied none. Measured on
the real LUN with `tools/recov_forge` + `tests/d513_forged_record_checks.sh`
(ledger `D-TERMINAL-OUTCOME-IMPORT-UNVALIDATED-383`):

- the registration-time scan imported a crc-valid record carrying
  `outcome=99` as a real AG-scoped verdict, and fed the selective grant purge
  from it;
- a **pre-mkfs ghost** (a sector whose `fs_gen` is not ours) quarantined the
  live filesystem, because `recovery_read_outcome()` never looked at `fs_gen`
  while the requires-recovery sweep always did;
- an FSWIDE quarantine discovered by that scan **did not refuse the mount** —
  the barrier's two FSWIDE gates run ~0.5 s earlier, inside `xfs_mountfs`.

### What changed

`recov_outcome_structural(ctx, hb, slot, &oc)` (disklock.c) is now the ONE
place that decides what a sector's recovery object structurally is. Both the
monitor and `mxfs_disklock_recovery_read_outcome()` go through it, so they
cannot disagree. It adds two gates every consumer now inherits:

- **generation first**: a foreign `fs_gen` returns **`-ESTALE`**, distinct
  from `-ENOENT`. A ghost is outside this filesystem's recovery namespace, so
  malformed bytes inside one must not quarantine the new filesystem either.
  `-ESTALE` may never cause backfill, closure-note insertion, grant purge,
  slot retirement/zeroing or quarantine import — it is observational only,
  and the scan aggregates it into one `P241-RECOV-GHOST-GEN` line.
- **descriptor identity**: `d->victim_slot != slot` is `-EPROTO`. The
  descriptor crc binds the SECTOR header, which travels with a byte-copied
  record, so `victim_slot` is the only binding to the slot it was read from.
  Only `backfill_legacy` used to check this.

`mxfs_disklock_recov_outcome_cb` now **returns** `enum mxfs_quar_disposition`
(`NOT_TERMINAL` / `VALID_AG` / `VALID_FSWIDE` / `INVALID_FSWIDE` / `FOREIGN`,
disklock.h). The semantic predicate is XFS policy and stays in ONE place
(`mxfs_freplay_import_verdict`); the disposition is what lets a caller act on
a record beyond importing it. **"It imported FSWIDE" is NOT evidence of
validity** — a rejected record imports FSWIDE by design, so closure candidacy
follows `VALID_AG` only, and `v5_closure_note_terminal()` now runs AFTER the
callback, never before.

The monitor no longer pre-filters on `oc->outcome == TERMINAL_REFUSED`. That
filter was itself a bypass: an unknown outcome kind was skipped silently every
pass, so a QUARANTINED slot never quarantined any live peer — the D-513
park/timeout shape. `-EPROTO` now joins `-EBADMSG` on the fail-closed arm.

### Admission is a transaction now

`mxfs_dlm_cache_init()` sets `mp->m_mxfs_quar_admitting` under
`m_mxfs_quar_lock` **before** registering the consumer;
`mxfs_dlm_admission_commit()` (called from `xfs_fs_fill_super` after the
recovery settle) reads `m_mxfs_quar_fswide` and clears the flag under that
same lock, returning `-EIO` to refuse the mount. The shared lock is the whole
point: an import landing before the transition is seen by the check, and one
landing after meets an admitted mount, where a runtime EIO quarantine is the
only response mount can still give. A bare post-registration flag test can
read false and be overtaken one instruction later.

**Still open** (ruling's longer-term item): the barrier derives its cut from
`get_recovery_pending_slots()`, which omits `stage >= GRANTS_RELEASED`. That
is a valid reason to omit a slot from the REPLAY cut, not from ADMISSION — the
barrier should examine current-generation terminal guards independently. The
admission commit makes the outcome correct today; the mount just pays a full
`xfs_mountfs` before unwinding.

### Reusable levers

- `tools/recov_forge <dev> mkguard <slot> [--fsgen|--victim-slot|--stage|
  --live|--break-desc-crc|--oc SHAPE|--oc-agmask]` — writes a real GUARD
  record with a real CRC binding, via SCSI READ(16)/WRITE(16)+FUA. Also
  `dump` / `save` / `restore` / `copy`. **`save` before forging, `restore`
  after** — the harness does.
- `tests/d513_forged_record_checks.sh <shape> [slot] [node]` — ~15 s per
  shape, non-destructive: one node cycles its mount, the other 31 stay up.
  Asserts mount disposition, byte-preservation of the refused sector,
  quarantine expectation and no-shutdown.

## sess404 (0.24.1-0.24.2) — AG courtesy ticket naming a DEAD registered waiter
- Ledger D-DEAD-WAITER-AG-TICKET-CREATE-ETIMEDOUT-404; ruling `docs/rulings/ag-dead-waiter-ticket-bounded-courtesy.md`;
  design text in docs/dlm-protocol.md "Courtesy ticket vs. a dead registered waiter".
- `caw_lock_body` compatible-yield branch (dlm_caw.c ~8990-9110): sess31 fix A/B
  (register once + `caw_fresh_yield_bound`=16 then take the compatible claim) now
  covers INODE **and AG** fresh acquires; NOQUEUE is checked BEFORE registration —
  plain NOQUEUE -> -EAGAIN immediately (trace-free), DEMAND|NOQUEUE -> takes the
  compatible claim (P-CAW-TICKET-DEMAND-OVERRIDE).  `yreg_live`/`yreg_t0` locals:
  a fix-A registration not claimed and not handed to wait_for_grant is dropped at
  `out:` on any error exit.  Counters (file-static mxfs_atomic32_t):
  caw_stat_ybound_ag/ybound_ino/ticket_noq_eagain/ticket_demand_override, printed
  on P221-YIELD-BOUND-AG and P-CAWEXH-AG.
- P-CAWEXH-AG (0.24.1): the AG twin of P-CAWEXH — per-site census + last slot
  ticket image (last_waiters/last_yt/last_yt_age_ms) + flags + comm.  Before it,
  an AG exhaustion logged only "lock exhausted 100 retries for ino=0 type=3".
- PITFALL: the AG release path builds the BATCH ticket `yield_to = waiters`
  (~10399) — it never uses the INODE fair/direct handoff, so an AG ticket can name
  a waiter that will never claim (dead) and the ONLY eraser is the post-fence
  purge (`caw_strip_node_state`), ~74 s after death at 32 nodes.

## sess404-405 (2026-08-23, 0.25.0-0.26.0) — the FENCE-TIME RECOVERY MANIFEST (docs/recovery-manifest.md)

The foreign-replay verdict's "held at death" predicate no longer reads the
live CAW slot as evidence.  The prover takes a durable, sealed SNAPSHOT of
the victim's EX/PW authority at fence time into a new envelope region and the
replayer consumes only that; the live slot is read once per resource as a
CURRENT-SAFETY check, and a writer guard makes the "frozen between fence and
purge" audit an enforced invariant.

### On disk / envelope (include/mxfs/mxfs_super.h, PROTO_GEN 7)
- `MXFS_FORMAT_F_RMAN` + `rman_offset`/`rman_size`: region of 64 slots ×
  `MXFS_RMAN_SLOT_BYTES` (2 MiB + 64 KiB) between disklock and XFS data; mkfs
  lays it out and zeroes it, chk validates it, `--upgrade-protogate` refuses a
  volume without it (only mkfs can create it).
- Per victim slot: `struct mxfs_rman_hdr` (4 KiB at +0, magic `MXRM`, seal
  `SLEDSEAL` at 88, crc over 0..83) and `struct mxfs_rman_entry[]` (32 B:
  type, mode EX|PW, slot_idx, id=agno|ino, lineage, grant_epoch) at +64 KiB.

### Descriptor (dlm/disklock.h, DESC_VERSION 3)
- Stage ladder: FENCING=1 → **SNAPSHOTTING=2** → FENCED=3 → IMAGES_REPLAYED=4 →
  OBLIGATIONS_DONE=5 → GRANTS_RELEASED=6.  SNAPSHOTTING = exclusion PROVED and
  certificate bytes durable, manifest not yet sealed; every `>= FENCED` gate
  still refuses; the prover KEEPS the attempt lease (owner_* = prover).
- `struct mxfs_recov_manifest_ptr` (56 B at body offset 216, magic `RMVP`,
  crc bound to victim identity): seq, entry_count, byte_len, entries crc,
  header crc, prover, fence_term.  `recov_mptr_of()` strict reader; claim and
  replay_authorized REFUSE a FENCED descriptor without a valid pointer.
- API: `fence_certify` → SNAPSHOTTING (refuses -ENODEV without the region;
  -EEXIST once FENCED); `manifest_write` (zero hdr+flush, entries+flush,
  sealed hdr+flush, lease re-check); `fence_seal` (SNAPSHOTTING→FENCED +
  UNOWNED + pointer, one CAS); `manifest_read` (strict header-vs-pointer
  validation, entries crc; any failure = NO verdict);
  `fence_intent` returns `MXFS_FENCE_INTENT_SNAPSHOT_PENDING` for our own
  SNAPSHOTTING attempt; `fence_takeover` accepts SNAPSHOTTING (lease +
  fence_term move, certificate bytes incl. fence_prover_* immutable);
  `fence_retryable` re-drives our own SNAPSHOTTING lease;
  `recov_fence_auth_holds` skips the prover test at SNAPSHOTTING.
  `mxfs_disklock_set_rman()` installs the region on the ctx.
- Monitor pass computes `protected_mask` (slots with ANY validated descriptor,
  stage >= FENCING — protection starts at the intent, before the P&A;
  unreadable record keeps last bit; only a COMPLETE pass publishes) and fires
  `protect_cb` on change (`P-RMAN-PROTECT`); `mxfs_disklock_set_protect_cb`
  first does a synchronous 64-sector refresh (`mxfs_disklock_protected_mask_refresh`).
- Pointer/header carry `writer_node/writer_epoch` (the manifest writer) apart
  from the certificate's `fence_prover_*`; a SNAPSHOTTING takeover moves only
  the lease (owner_*), never `fence_term`.  Terminal outcome reasons added:
  `MXFS_RECOV_REFUSAL_AUTHORITY_MUTATED` (4, manifest vs live mismatch at
  replay or pre-purge `mxfs_v5_dlm_rman_verify_live`) and
  `MXFS_RECOV_REFUSAL_MANIFEST_INVALID` (5, structural -EPROTO under
  enforcement).  Both FSWIDE, nothing purged.

### Prover (dlm/v5_mount.c, dlm/dlm_caw.c)
`v5_pr_fence_prove_locked`: certify → `snapshot:` → `v5_rman_snapshot` =
`mxfs_dlm_caw_manifest_collect` (128-slot prio bulk reads, any unread slot →
-EIO fail closed; `P-RMAN-COLLECT`) → `manifest_write` (`P-RMAN-SEALED`) →
`fence_seal` (`P236-FENCE-SEALED`, `P-RMAN-SNAPSHOT`).  Failure →
`MXFS_RBLK_SNAPSHOT_PENDING` + fence-retry worker (`P-RMAN-SNAPSHOT-PENDING`);
lease-holder death → the acquire -EPERM branch takes the SNAPSHOTTING lease
over (`P-RMAN-SNAPSHOT-TAKEOVER`) and redoes the scan (P&A never repeated).
TCP transport → `MXFS_RECOV_MPTR_F_NO_CAW_TABLE` manifest.  Test knob
`mxfs.rman_inject`: 1 fail pre-write, 2 fail pre-seal-CAS, 3 torn entries crc.

### Writer guard (dlm/dlm_caw.c `caw_slot_ex`)
`protected_mask` pushed by `v5_protect_cb` → `mxfs_dlm_caw_set_protected_mask`.
A CAS whose `compare` image has a protected node's EX/PW bit is REFUSED
(-EPERM, `P-RMAN-GUARD-REFUSED`, ctx->guard_refused++) if it changes
holders_ex/holders_pw AT ALL, tombstones/rebinds the slot, or changes
ex_grant_epoch / resource_lineage — unless called with `MXFS_CAW_CAS_F_PURGE`
plus the exact victim mask (only `caw_purge_dead_nodes_body` with dead_mask
and `caw_closure_strip_one` with victim_bit), which may ONLY clear that mask's
bits.  `caw_slot()` is a wrapper for `caw_slot_ex(..., 0, 0)`.
TEST ONLY: `mxfs.rman_test_mutate` (1 guarded clear → must be refused; 2
bypass → replayer/pre-purge must detect) via `mxfs_dlm_caw_test_mutate_protected`,
consumed once by the elected replayer right after claim.
**sess407 local proof (0.26.3, D-RMAN-WRITER-GUARD-MONITOR-LAG-407):**
`mxfs_disklock_protected_mask_add(ctx, slot)` publishes the bit immediately on
the node that holds direct proof (prover: fence-intent rc 0 / SNAPSHOT_PENDING;
replayer: claim success, before P238-RECOV-LEASE + the test hook) and bumps
`ctx->protected_gen`; the monitor pass snapshots the gen at its start and skips
publishing if it moved (its sectors may predate the proof).  Without it the
guard on the replayer lagged its own monitor by 1.7 s and the mode-1 test
mutation went through with rc=0 (matrix mutate1, 0.26.2).  PITFALL: never
assume `protected_mask` covers a victim just because the platter says so —
only a pass or a local-proof add publishes it.  Publication (gen check + mask
install + cb) is serialized under `disklock_ctx->prot_lock` (GPT Q1).
**Structural guard rules (sess407, 0.26.4):** `caw_slot_ex` refuses ANY
non-PURGE CAS that clears another node's EX/PW bit (shape rule, no mask
needed); `caw_guard_refuses` refuses ADDING a protected node's EX/PW bit;
`caw_repair_slot` (raw CAW, not via caw_slot_ex) refuses under a protected bit
and preserves epoch/lineage.  A P-RMAN-GUARD-REFUSED from any live path is a
defect signal (the kill harness counts it).
TRAP: every PAL bio must be a whole multiple of 4 KiB — a 96-byte
`mxfs_pal_bdev_write` hung in `submit_bio_wait` on the dm LUN (D-405).

### Pitfalls
- The evaluator's "held" answer under a loaded manifest is `-ENOENT` for an
  absent entry (not_held terminal), `-ENODEV` for a NO_CAW manifest; the
  live `mxfs_v5_dlm_victim_*_manifest_read` is now the current-safety check
  only (`P-RMAN-POSTSEAL-MUTATION` / `P-RMAN-LIVECHECK-ERR` → attempt abort).
- Never rebuild mxfs.ko while a rig run is in flight (NFS-served module).


## sess406 — fenced-self withdrawal: SELF_GONE acts, every write class counts (D-498, 0.26.2)

The natural occurrence (test9, 0.26.0, 2026-08-23): HB thread blocked in the
D-405 bio -> peers fenced it -> `P305-RESV-HEALTH state=SELF_GONE` at +1 s was
only LOGGED -> no `P277-FENCED-SELF-WITHDRAW` for six minutes: the D-498 counter
(`mxfs_v5_dlm_note_resv_conflict`, threshold 3) was fed only by the HB CAS
`conflict_cb` and the CAW unlock wrappers; the HB thread was blocked, and the XFS
metadata writes that DID bounce were never counted, so xfsaild retried them at
~12/s (4494 SCST conflict lines, the kmsg-guard FLOOD halt) until a log I/O
error shut the mount down.

Changes (`dlm/v5_mount.c`, `pal/linux/xfs_buf.c`, `xfs/xfs_log.c`,
`pal/linux/xfs_aops.c`):
- `v5_resv_health_tick` on SELF_GONE (PR IN READ KEYS: our key absent while
  mounted+registered; UNKNOWN on any PR IN error — never manufactured) adds a
  full threshold to `resv_conflict_count` (so an inspection parked in
  anomaly-watch re-inspects past its watermark) and launches the inspection:
  `P305-RESV-SELF-GONE-INSPECT`.  A target-confirmed missing KEY means someone
  preempted us — withdraw, never re-register (sess276 ruling stands; repairing an
  ABSENT reservation is a different thing and stays with the maintainer).
- `__xfs_buf_ioend` (write branch), `xlog_ioend_work`, `xfs_end_ioend`: an
  `-EBADE` completion (`blk_status_to_errno(BLK_STS_RESV_CONFLICT)`, the only
  source of that errno in the block layer) calls `mxfs_v5_dlm_note_resv_conflict`
  through `READ_ONCE(mp->m_mxfs_dlm)` (NULLed by put_super before xfs_unmountfs,
  the same raw-pointer pattern as every xfs-layer hook).
- `note_resv_conflict` is now NONBLOCKING: at threshold it sets
  `ctx->resv_inspect_request`; the PR worker tick (`v5_fence_retry_worker_fn`,
  250 ms) does the one-shot launch via `v5_resv_inspect_launch` — a completion
  path must not create a kthread (GFP_KERNEL under XFS locks), and the worker is
  joined before the PR key is unregistered and before the ctx is freed, so a
  launch can neither race our own deliberate unregister nor outlive the ctx.
  Only a mount whose worker never started (`P304-FENCE-RETRY-NOTHREAD`, already
  degraded) launches from the reporter's context.
- Verification: `tests/fence_live_node.sh <label> idle|churn [victim] [peer]` —
  sg_persist PREEMPT of the victim's key from a peer; asserts PR IN before/after,
  withdrawal latency (bound 75 s; idle = HB CAS conflicts x3 or SELF_GONE audit,
  churn = buffer-path conflicts), <= 200 conflicting commands at the target,
  mount gone, survivors recover the slot.

PITFALL: the reservation-health tick's SELF_GONE is the one signal a fenced node
gets while its HB thread is stuck; any future "observe only" arm there recreates
the six-minute exposure.

## sess409 — withdraw semantics, log-error shutdown gap (0.26.10), HB-pause injection (0.26.11)

- "Withdraw" (`dlm/v5_mount.c v5_resv_conflict_withdraw` / `v5_self_fence_cb`) = `fence_notify_fn`
  → `xfs_force_shutdown`: the filesystem is force-shut-down; NOTHING unmounts (the mount persists like any
  XFS shutdown).  Cluster withdrawal (fence acquires + stop the disklock heartbeat) is the sess9
  `mxfs_dlm_shutdown_withdraw` queued from `xfs_do_force_shutdown`.
- D-LOG-ERROR-SHUTDOWN-SKIPS-DLM-WITHDRAW-409: when the first shutdown comes from the LOG path
  (`xfs_log.c xlog_force_shutdown` on a bounced/failed log write) the mount shutdown bit is set there and
  `xfs_do_force_shutdown` never runs → no DLM withdrawal, HB keeps running.  Fixed 0.26.10: `xlog_force_shutdown`
  now calls `mxfs_dlm_shutdown_withdraw` in its first-shutdown branch (idempotent queued work).
- Out-of-band key removal (sg_persist preempt by an operator/test) leaves the slice designed-unreplayable:
  prover sees `KEY_ABSENT_UNPROVEN` (`scsipr.c P-PR-FENCE-ABSENT`), retries with backoff (`P304-FENCE-RETRY`),
  replayer refuses every 30 s (`P236-CLAIM-UNCERTIFIED`, "NOT replayed — no proven exclusion").  sess381 ruling.
- New TEST-ONLY knob `mxfs.dl_inject_hb_pause_ms` (disklock.c, one-shot): pauses the local heartbeat thread
  N ms — the false-death injection used by `tests/fence_live_node.sh` (FLN_INJECT=hbpause, default).

## sess410 — fence_live_node enforcement knobs, logioerr arm, D-409 verified on the xlog path

- `tests/fence_live_node.sh` now arms `target_cache_protected=1 foreign_replay_token_enforce=1` fleet-wide after
  prep (FLN_PARAMS; `tests/fleet_set_params.sh`).  At the knob default (enforce=0) EVERY foreign transaction with
  buffer images is ATOMIC-SKIPped (P227-FR-ATOMIC-SKIP sbreason=2 -> P227-FR-TORN-UNPUBLISHED -> -117 ->
  P241-RECOV-TERMINAL + AG-mask quarantine) — the designed fail-closed blanket of D-FOREIGN-REPLAY-UNGATED-IMAGES.
  sess409 fln2_hb_churn's "foreign replay of slot 12 failed: -117" and sess410 fln3_log_idle/hb_churn were exactly
  that, not a new defect; only a clean slice (fln3_hb_idle) recovers at enforce=0.
- FLN_INJECT=logioerr (0.26.12 `mxfs.log_inject_ioerr`): D-409's xlog_force_shutdown hook verified — 'shut down
  due to log error' -> P-WITHDRAW-QUEUE +4 ms -> P-WITHDRAW -> HB stopped -> peers fenced the WITHDRAWN slot in
  ~330 ms (victim P305 SELF_GONE), 0 target conflicts.
- hbpause victim timeline (fln3_hb_churn): pause at +0, peers fence at ~+62 s, victim P277-FENCED-SELF-WITHDRAW at
  +73-76 s with conflicts=44 (churn) / +65 s conflicts=3 (idle); its own disklock withdraw stamp is then
  P236-WITHDRAW-REFUSED because a survivor's RECOVERY GUARD already owns the slot (expected).

## sess418 (2026-08-27, 0.29.0) — departure state machine (D-0286) + TCP death deferral

**Why:** on TCP there is no per-resource pin in the master's table; the only
wire-visible teardown release is the NODE_LEAVE goodbye (`mxfs_dlm_release_all`
frees the LOCAL table only), and `ctx->withdrawn` used to be published a
workqueue-latency after `xfs_force_shutdown`.  A wedge landing after the
`xfs_super.c` withdraw check could still send the goodbye → survivors purged
the wedged tenure's grants with no fence/replay.

**API (v5_mount.c / v5_mount.h):**
- `enum MXFS_V5_DEPART_{ACTIVE,CLEAN_LEAVE,POISONED}` in `ctx->depart_state`
  (`mxfs_atomic32_t`).  `mxfs_v5_dlm_poison(ctx, why)` — non-sleeping, cmpxchg
  ACTIVE→POISONED + `WRITE_ONCE(withdrawn)`; never overwrites CLEAN_LEAVE
  (logs `P-POISON-AFTER-CLEAN-LEAVE`, a contradiction detector).  Called
  synchronously from the XFS hook `mxfs_dlm_shutdown_withdraw` before
  `schedule_work`.  `mxfs_v5_dlm_is_poisoned(ctx)`.
- `mxfs_v5_dlm_shutdown_withdraw` = poison + once-guarded sleeping half
  (`ctx->withdraw_once` atomic TAS, not the old bool).
- Teardown linearization point: right after `depart_clean` is computed,
  `cmpxchg(ACTIVE→CLEAN_LEAVE)`; failure ⇒ `P-DEPART-POISON-WINS`, no goodbye,
  HB record stays ACTIVE.
- `ctx->member_lock` (`mxfs_mutex_t`): serialises NODE_LEAVE RX
  (check+purge+note_dead) against `v5_note_dead_node` and
  `v5_mark_recovery_pending_serialized` (used by start/defer slice recovery).
  Leaf lock; order member_lock → mphase_lock / disklock lock.  Never take it
  and then call `v5_note_dead_node` (use `_locked`).
- NODE_LEAVE RX ignores a dead / recovery-pending sender
  (`P-GOODBYE-DEAD-IGNORED`).  Msg cb drops lock traffic once
  `!ctx->mounted` (`P-TEARDOWN-MSG-DROP`) EXCEPT NODE_LEAVE, RELEASE_ACK
  (0.75.17) and LOCK_RELEASE (0.75.66, D-0925 mech 2: a peer unmounting
  alongside us still gets its releases retired — the ledger is open until
  engine destroy; a page already PREPARED by handoff_depart answers
  REMASTER).  `v5_bast_cb_tcp` drops a LOCAL BAST once `!mounted`
  (`teardown_local_basts_dropped`); both counters print on
  `P-GOODBYE-SENT`.
- `v5_tcp_declare_dead`: fence + note_dead, then if the victim owns a HB slot
  → NO purge/unregister/refresh (`P-TCPDEATH-DEFERRED`); recovery completion
  purges.  Slotless identities keep the immediate purge.
- `v5_tcp_release_gate()` → `-ESHUTDOWN` (`P-TCP-RELEASE-POISONED`) on every
  TCP wire-release arm (inode_unlock_open, iclus_unlock_gen,
  release_unconditional, ag_unlock → STILL_HELD).
- Debug knob `mxfs.dbg_depart_race=1..5` (one-shot): poisons from inside the
  teardown at pre-CAS / post-CAS / pre-send / post-send / post-slot-release.
  Harness `tests/d0286_depart_race.sh`; TCP wedge lap
  `tests/d0286_tcp_wedge.sh`.
- PAL: `mxfs_atomic32_cmpxchg` / `mxfs_atomic32_xchg`.

**Open (D-0287, critical):** TCP membership change purges EVERY node's whole
lock table (`dlm.c mxfs_dlm_update_active_nodes`) and `v5_membership_cb_tcp`
is a no-op — held grants are never re-asserted to new masters.  Measurement
harness `tests/d0287_remaster_measure.sh`.

## sess419 (2026-08-28, 0.29.1-0.29.3) — departure-race reachability, purge interlock verification

- **Departure-race injector reachability** (`v5_depart_race_inject`, `mxfs_v5_dlm_destroy`):
  on a CLEAN unmount only points 1 and 2 are reachable on CAW; 3/4 sit inside the TCP-only
  GOODBYE block; point 5 is on the `!late` slot-release arm but a clean unmount ALWAYS hands
  the slot out deferred (Arm C `late`, `P278-LATE-RELEASE`) and frees the ctx before
  `mxfs_v5_dlm_slot_release_commit` — unreachable on every transport.  The harness reports SKIP.
- **Purge interlock** (`dlm/disklock.c mxfs_disklock_purge_node`): `purge_cas_zero` no longer
  falls back to a plain write on `-EOPNOTSUPP` (`P235-PURGE-NOCAW`, purge stays INCOMPLETE).
  CAW is issued with FUA (`pal/linux/kern.c`), so record zeros are durable before the HB CAS.
- **Test hook** `mxfs_disklock_dbg_purge_hook` (`ctx->dbg_purge_hook`, set with
  `mxfs_disklock_set_dbg_purge_hook`): point 1 after the phase-0 gate, point 2 at scan start
  (nonzero return forces the mid-scan re-read), point 3 before the final HB gate.  v5 serves it
  (`v5_dbg_purge_hook`) from `mxfs.dbg_purge_pause_ms` and `mxfs.dbg_purge_refreeze=1|2`, the
  latter publishing a REAL quarantine with the new reason `MXFS_RECOV_REFUSAL_DBG_INJECTED`=7
  through `mxfs_v5_dlm_recovery_publish_refusal`.  `mxfs_v5_dlm_dbg_purge_node(ctx, id)` runs the
  normal purge path from a non-elected survivor (`P-DBG-PURGE-TRIGGER node= rc= purged=`).
- **Dead window fact**: `dead_timeout_ms=0` (fleet default) = `MXFS_DISKLOCK_DEAD_THRESHOLD`
  31 × 2 s = 62 s; any observer-side wait in a harness must be derived from it.
- Unclaimed-bucket sweep (`xfs_mxfs_dlm.c mxfs_unclaimed_bucket_scan`) is armed at every
  mount settle and after recovery batches — NOT periodically; a cleanly departed slot's
  deferred open-unlink zombies are freed by the NEXT mount of any node.

## sess421 (2026-08-28, 0.32.0) — intent census fail-before-purge, settle pass-1 no-purge, barrier hold knob
- **Intent/done census** (`xfs/xfs_mxfs_icensus.{c,h}`, hooked at the former
  P226-UNTRUSTED-INTENT-SKIP site `xfs_log_recover.c` pass-2 item loop, terminal
  predicate in `xfs_log.c mxfs_xlog_recover_foreign_slice` after the untagged-skip
  predicate).  Records every skipped intent by log id (id sits at byte 8 in every
  intent/done format) with its AG set; dones retire ids; open set at the end of a
  FOREIGN replay ⇒ `P226-FR-INTENTS-UNDISCHARGED`, `-EFSCORRUPTED`, verdict reason
  `MXFS_FREPLAY_REASON_INTENTS_UNDISCHARGED`(6) → wire
  `MXFS_RECOV_REFUSAL_INTENTS_UNDISCHARGED`(8), domain = open intents' AGs
  (FSWIDE on anything unmappable/overflow/alloc-lost).  Adopted mounts only print
  `P226-ICENSUS-ADOPTED-OPEN`.  New xlog fields `l_mxfs_icensus`,
  `l_mxfs_icensus_lost`; freed in `xlog_dealloc_log`.  chk_mxfs names reasons 6 and 8
  (6 was previously "UNKNOWN" in chk output).
- **`mxfs_v5_dlm_settle_own_slot`**: when `!mxfs_disklock_slice_adopted()` (pass-1
  own-stamp reclaim) it performs NO purge (`P226-SETTLE-PASS1-NOPURGE`), still closes
  the adopt window.  Fresh-claim purge kept; nonzero count is now the
  `P226-SETTLE-FRESH-LEFTOVER` anomaly (ERR), not P225-SETTLE.
- **`mxfs.dbg_barrier_hold_ms`** (xfs_mxfs_dlm.c, one-shot, self-clears): sleeps at
  the top of `mxfs_dlm_mount_recovery_barrier`'s loop, before the first late-death
  drain; `P-DBG-BARRIER-HOLD start ms=`/`released after ... (mphase_pending=0x..)`.
- **The barrier's admission wait is bounded by ELAPSED time** (0.89.2, D-0980): a
  jiffies deadline from the wait loop's start (30 s; 30+62+30 s once, as a cap,
  while undeclared ghosts exist), judged before a round, before every slice and
  after every poll — round work (6 s takeover observations, ≤45 s stability
  proofs, replays) counts.  The poll is `schedule_timeout_killable`; a fatal
  signal at any of those boundaries refuses the mount **-EINTR**
  (`P-BARRIER-CANCELLED`); the bound refuses **-EBUSY** as before.  Every exit
  prints `P-BARRIER-CLOCK result= wait_ms= bound_ms= overrun_ms= rounds=
  last_round_ms= total_ms=` (overrun > last_round_ms is a defect).  The acquire
  is `mxfs_v5_dlm_recovery_acquire_bounded(ctx, slot, budget_ms)`: a takeover
  whose 6 s observation + 3 s continuation would not fit is refused up front
  (`P238-TAKEOVER-NOBUDGET`).  disklock's two abandonment waits
  (`recov_abandon_wait`) are interruptible, never shortened, and return -EINTR
  on a fatal signal.  Design: docs/rulings/mount-admission-barrier.md.
  Harness: tests/d0980_barrier_killable.sh.
- **Dead is not reclaimable** (0.89.3, D-0981; platter-backed at 0.89.4): `recovery_judging_cb` on the DLM ctx
  (v5: `v5_recovery_judging_cb` — this node's recovery-pending marker is a hint:
  a marker's slot descriptor at IMAGES_REPLAYED or beyond releases; otherwise
  the 64 records are read with `mxfs_disklock_read_record` and an ACTIVE record
  or a RECOVERY_GUARD descriptor naming {node, inc} below IMAGES_REPLAYED
  protects, as does any unreadable slot — `P-TAUTH-RETENTION-ACTIVE/-PLATTER/
  -UNKNOWN`; measured s67f: a lone cold return onto a departed prover's
  standing FENCING intent swept its own previous incarnation's records before
  declaring anything, and the manifest sealed later was empty) is judged at
  `dlm_takeover_page` before prepare/activate/purge
  (`P-TAUTH-TAKEOVER-UNDER-JUDGEMENT`, `-EAGAIN`) and pre-filtered by the orphan
  sweep (`P-TAUTH-ORPHAN-AUTH ... judging=`, sweep line `judging_pages=`).  The
  replay's manifest check needs the victim's records intact until then; the
  completion ladder's purge/takeover runs after that stage.  Design:
  docs/tcp-authority-ledger.md "Dead is not reclaimable".  Harness:
  tests/d0981_pending_victim_sweep.sh, which builds its own precondition with
  **`mxfs.dbg_barrier_refuse_after_claim`** (xfs_mxfs_dlm.c, one-shot, self-clears):
  the barrier refuses the mount right after it claims a slice's recovery lease and
  gives the lease back durably (`mxfs_v5_dlm_recovery_relinquish`), leaving the
  descriptor FENCED with owner 0/0 (`P-DBG-BARRIER-REFUSE-AFTER-CLAIM`).
  `mxfs_v5_dlm_mount_peek_late_deaths()` = non-consuming read of `mphase_dead_mask`.
- 0.31.0 rig facts: `tcp_token_plumbing_verify` PASS on 32/tcp (noepoch 0→0,
  durnoep 0→0 on test1-4, ~78k tokens each) — tcp-authority-ledger step 1 is
  rig-proven; step 2 may proceed.
- **TCP authority ledger step 2 (0.33.0, PROTO_GEN 8)**: `include/mxfs/mxfs_tauth.h`
  (layout + pure helpers, kernel/user neutral), `dlm/tauth_store.{c,h}` (PAL-only
  shadow-page store: open / page_read / page_write / verify; `-EUCLEAN` = page
  UNKNOWN, fail closed; write = highest-seq+1 on the OTHER copy, FUA+flush+readback),
  new envelope region `MXFS_FORMAT_F_TAUTH` (`tauth_offset/size`, 16.5 MiB, after
  rman), plumbed `xfs_super.c` → `mxfs_v5_dlm_opts.tauth_*` → `ctx->tauth_*` (no
  consumer yet — step 3 opens the store from the TCP master path).  Pitfalls: page
  I/O is whole 4 KiB (PAL sector trap); never copy a 4 KiB struct on the kernel
  stack (region crc helper crcs around the field instead); a tear that happens to
  contain every changed byte IS a complete write (crc-identical) — tests must
  change bytes beyond the tear point.  Unit test `tests/tauth/` (21 cases).

## sess422-424 (2026-08-28, 0.34.0-0.35.0) — TCP authority ledger steps 3-4 (docs/tcp-authority-ledger.md)
- **Step 3 (0.34.0)**: `dlm/tauth_ledger.{c,h}` on the shadow-page store — per-page
  cached image + mutex, `ensure/lookup/scan_active/commit/purge_owner`, poison +
  reconcile, fail-closed refusals (-EEXIST collision, -EBUSY double grant, -ENOSPC,
  -EUCLEAN UNKNOWN, -ESTALE generation).  `dlm.c`: page-aligned mastership
  (`active_nodes[page % N]`, page = (hash % 65536)/31), states PENDING_DURABLE /
  PENDING_RELEASE, `dlm_txn` commit/finalize/promote/grant (durable-before-deliver),
  `LOCK_RELEASE_ACK`, blocker import (`P-TAUTH-IMPORT-ACTIVE`), membership purge keeps
  own GRANTED/PENDING entries, `ledger_gen` MONOTONIC (view_seq).  `v5_mount.c`: ledger
  open + attach right after the TCP slot claim (`P-TAUTH-MOUNT-REFUSE` on failure),
  `ledger_required` on TCP+region, purge_owner after refresh at all 6 purge sites.
- **Step 4 (0.35.0)**: durable page authority (UNOWNED/ACTIVE/PREPARED in the page
  header, `write_nonce`, same-seq divergent copies = CONFLICTED).  Engine in `dlm.c`
  ~1219-1915: `dlm_page_ensure_mine` gates every decision (-EAGAIN ⇒ REMASTER to the
  requester, 10 retries then -EIO); `MXFS_MSG_PAGE_HANDOFF` FREEZE_REQ/FROZEN/DEFER/
  NOT_OWNER; `mxfs_dlm_handoff_tick` (500 ms, TCP death worker); `mxfs_dlm_handoff_takeover
  (node, inc)` — ONLY the bootstrap node (lowest live hb slot) — after every recovery
  purge; `mxfs_dlm_handoff_depart` before GOODBYE.  v5 callbacks `v5_bootstrap_cb`,
  `v5_node_inc_cb`, helper `v5_handoff_takeover(node, inc, why)`.
- **Pitfalls**: (1) a dead authority's pages park EVERY requester forever until the
  successor takeover runs — every purge site must pair purge_owner with takeover, and the
  takeover needs the victim's INCARNATION (`P-TAUTH-TAKEOVER-NOINC` = parked).  The
  parking branch of `dlm_page_acquire` logs `P-TAUTH-PAGE-PARKED page= auth= in_view=
  purged= bootstrap=` (0.75.6, capped 400/boot); before that it was silent and the only
  symptom was `why[prepare=60]` / REMASTER×60.  **Whole-cluster clean stop (0.75.7,
  D-...-0905)**: the LAST leaver keeps every page the era touched ACTIVE under its dead
  incarnation (`mxfs_dlm_handoff_depart` has nobody to hand to), a lone remount is blind
  (single node bypasses the DLM), and the first join parks; the survivor's fail-fast arm
  in `mxfs_dlm_ilock_begin` then SHUTS THE HEALTHY SURVIVOR DOWN and it is fenced.  The
  identity is known only where the record is settled, so `v5_settled_incarnation()`
  (P305 own predecessor, retire-worker EMPTY, admission-barrier EMPTY) queues the
  departure trio for it, deferred (`settled_q` → `v5_settled_flush` after "TCP DLM
  initialized"); `takeover_only` when the departed incarnation carries OUR node id
  (pinned id — the purges key on node id); `P-TAUTH-TAKEOVER-NOTBOOT` when the settling
  mount is not the bootstrap node; `depart_done[]` ring → `P-DEPART-DONE-ALREADY`.
  Platter census: `tools/tauth_page_auth.py <dev> <base>` (base from
  `P-TAUTH-LEDGER-OPEN base=`; needs root on clyde to open the LUN).  **Taken-over
  pages still carry the departed records (0.75.8, D-...-0906)**: `purged_owners` is
  PER NODE, so a page the takeover hands to a peer that never observed the departure
  imported the last leaver's EX as a live blocker (`P-TAUTH-IMPORT-ACTIVE owner=<dead>`)
  and the joiner's mount queued behind it forever (`P-LKTIMEOUT-HOLDER holder=<dead>`).
  A PREPARED page whose writer ≠ authority is a takeover (only the certified successor
  writes one): `dlm_page_departed_authority()` marks that authority purged (node id
  only, `dlm_owner_mark_purged`) before activation, on the FROZEN message (sender ≠
  auth) and on the platter read in `dlm_page_acquire` (`a.writer_node` ≠ auth) —
  `P-TAUTH-DEPARTED-AUTH`.  And `mxfs_dlm_ledger_purge_owner` drops the SLOT half of
  a purge when `slot_node_cb` names a different live occupant (`P-TAUTH-PURGE-SLOT-LIVE`):
  the slot half clears that slot's shared bits on every page this node masters, which
  are the successor's live grants.  Known hole (unmeasured): a page the successor takes
  over for itself is activated WITHOUT import; a later view-change hand-on (writer ==
  authority) carries the departed records with no marker.  **The bulk takeover is too
  slow for a parked request (0.75.9, D-...-0907)**: the departure worker's purge scan
  + takeover scan is ~8 s at 26426 pages, the put_super SB summary lock has 60 × 100 ms,
  so a same-boot remount followed by an unmount within ~2 s parked ×60 on its own
  predecessor's page and the CLEAN unmount was recorded DIRTY (slot + PR key retained,
  next same-boot mount refused −17).  `dlm_takeover_page(ctx, p, node, inc, how)` is the
  per-page transition shared by the bulk pass (`how="takeover"`) and two on-demand paths:
  the bootstrap node's parked branch takes the page over itself when the authority is in
  `purged_owners` (`"takeover-ondemand"`), and a non-bootstrap requester sends FREEZE_REQ
  to `bootstrap_node_cb` naming the authority, whose handler takes the page over for the
  sender once purged there (`"takeover-request"`) and answers NOT_OWNER naming it until
  then (a NOT_OWNER naming an out-of-view authority keeps the 500 ms cadence instead of
  resetting `page_req_ms`).  `P-TAUTH-TAKEOVER-ONDEMAND page= departed= owner= via=`;
  counter `handoff_ondemand`.  Two measured residuals of the joiner side (0.75.10 /
  0.75.11): for one heartbeat interval (2 s) after its claim the joiner's
  lowest-live-slot election names ITSELF (`bn=we` on the PARKED line, 17/18 parks) — an
  unsettled election now asks EVERY node in the view; and the bootstrap node's
  `node_inc_cb(sender)` is 0 for the same interval (`P-TAUTH-TAKEOVER-REQUEST-DECLINED
  purged=1 rc=-11 sender_inc_known=0`) — `dlm_takeover_page` takes a {hint_node,
  hint_inc} from the FREEZE_REQ's `target_inc`.  **The hand-on hole is real
  (0.75.14, measured with `SAMEBOOT_ARM1_DELAY_S=12`, chain step 12)**: the bulk purge
  before a takeover walks only pages this node ALREADY masters (`P-TAUTH-PURGE
  notmine=26426`), so a page that becomes ours by the takeover keeps the departed
  incarnation's records until a lazy import; a view-change hand-on (`dlm_page_hand_to`,
  writer == authority == us) then carries them unmarked and the receiver imported the
  dead AG 0 EX as a blocker (census: `tools/tauth_page_auth.py --entries` showed
  `ex=<predecessor> mode=5` still on the page).  Fix: `dlm_takeover_page` owner==local
  → `mxfs_tauth_ledger_purge_owner_page(node, -1, page)` (the per-page body of the
  recovery purge, factored into `tauth_purge_page`) + `dlm_ledger_import_page` at
  activation; `P-TAUTH-TAKEOVER-RETIRE page= departed= cleared= import_rc=`.  A
  departed node id is a RETIRED identity to its peers (`P164-DEAD-NOTE` /
  `P164-DEAD-REJECT`): a harness must never rejoin under a reused `node_id_override`;
  (2) an
  ACTIVE page for an old incarnation of the SAME node id is "someone else" to the engine —
  fine here because node ids are per-incarnation, so it is recovered as any dead peer;
  (3) a raw `mxfs_tauth_page_write(store, pg, authority_epoch, ...)` REWRITES the page's
  authority — tests planting records must pass `pg->hdr.authority_epoch`; (4) usermode
  gate `make -C tests/tauth test` (tauth_test 8, ledger_test 15 groups, dlm_ledger_test
  11 groups) must pass before rig time; (5) compile single objects with
  `make -C $KDIR M=/src/mxfs dlm/dlm.o ...` while a rig run is live — never relink mxfs.ko.
- **Open (RULE 4 owed)**: 0.34.0 on 32/tcp: 4/32 mounts refused ("can't read superblock"),
  tcp_token_plumbing_verify workload hung (30 s), 13 unmounts hung, rig
  `P-TAUTH-DOUBLE-GRANT` ×1 on test24 and test30 — no node dmesg captured;
  `tests/sess424_chain.sh` sweeps raw P-TAUTH/mount/REMASTER lines after every tcp stage.
- **sess424 GHOST fix (0.35.0)**: `dlm_txn_finalize` delivers every successful commit
  (remaster only on the ledger's -ESTALE; `P-TAUTH-LATE-DELIVERY` otherwise);
  `dlm_import_holder` re-resolves UNKNOWN-owner shared bits (`P-TAUTH-IMPORT-RESOLVED`).
  Root cause of the 0.34.0 32/tcp mount failures (root-inode PR bit stuck, D-...-0340).
  Pitfall: a durable grant that is not delivered is a permanent blocker on a live cluster —
  never suppress delivery after a commit; never "release on send failure" (ruling).
- **sess425 concurrent-release wedge fix (0.35.1, D-...-0341)**: 0.35.0 on 32/tcp failed
  26/32 mounts — `P-TAUTH-DOUBLE-GRANT` then `P-TAUTH-FREEZE-DRAIN-TIMEOUT` ×94 on the root
  inode's page.  Root: `promote_waiters` ignored EVERY PENDING_RELEASE holder (releases run
  concurrently on the master: local unlock threads vs the rx thread), so an EX was decided
  over a sibling's still-durable bit; the bundled `[release, grant]` commit was refused
  -EBUSY, and the refusal stranded the release entry (kept PENDING_RELEASE, the releaser's
  retry ACKed OK as a "duplicate").  Fix: `promote_waiters(…, txn)` bypasses only the
  release item(s) of THIS txn (`dlm_txn_retires`); `dlm_promote_txn` re-scans after every
  durable retirement even when nothing was granted; a bundle refused for a grant reason
  re-commits its releases alone (`dlm_txn_recommit_releases`, ACK deferred); a retirement
  that still fails is `P-TAUTH-RELEASE-STUCK` and re-driven by the MASTER
  (`dlm_release_redrive_tick` in `mxfs_dlm_release_retry_tick`, entry fields
  `rel_id/rel_remote/rel_failed_ms`) or by the next releaser retry — never ACKed OK while
  pending; refused-for-conflict grants are denied `MXFS_ERR_LEDGER_BUSY` → `MXFS_DLM_RETRY`.
  `P-TAUTH-DLM-STATS` (release_all) prints the ctx counters.  Reproducer + regression:
  `tests/tauth/concurrent_release_test` (race laps + refused-bundle + stuck/re-drive +
  crashed-releaser scenarios; ledger knobs `commit_delay_once_ms`, `refuse_grant_once`,
  `fail_commit_once_rc`/`fail_commit_skip`; probe `mxfs_dlm_page_pending_count`).
  Invariant (ruling `docs/rulings/concurrent-release-fix-shape.md`):
  every PENDING_* entry has exactly one live MASTER-owned driver — the freeze-drain waits
  on exactly those entries, so a driverless one wedges the page for the whole cluster.
- **sess425 local orphan grant (0.35.1, D-...-0343)**: a LOCAL requester that exhausts its
  budget while its grant is PENDING_DURABLE has no waiter when the commit lands;
  `dlm_txn_finalize` used to ignore `pending_signal_resource`'s false and leave the entry
  GRANTED for the master with nobody holding it (durable EX blocker).  Fix:
  `mxfs_lock.unclaimed` (set at GRANTED for local signal_local grants, cleared under the
  table write lock by any adopting local request) + `dlm_release_local_orphan`
  (`P-TAUTH-LOCAL-ORPHAN-RELEASE`) — the local analogue of the unsolicited-GRANT
  LOCK_RELEASE.  Reproducer: `concurrent_release_test` scenario 5.  Pitfall: the timeout
  unlink (P4G guard) deliberately never frees a PENDING_* entry — the committing thread
  owns it — so every "waiter gone" outcome must be handled at delivery, not at timeout.
  Requester side (same session): `dlm_lock_impl` finding its OWN entry PENDING_DURABLE
  now ATTACHES (pending registered under the table lock, one acquire-window wait)
  instead of RETRY-after-10 ms — the spin burnt the 10-retry budget under a slow page
  write (formation_test 1-in-3 laps `fails=1`; rig "lock request failed after 10
  retries").
- **sess425 D-0342 partial purge (0.35.2)**: `mxfs_dlm_ledger_purge_owner` rc<0 → owner on
  `ctx->purge_pending[]` (P-TAUTH-PURGE-PENDING), imported blockers KEPT (`mxfs_dlm_purge_node`
  skips them while pending), `dlm_purge_redrive_tick` (release tick, 1 s) re-runs the purge
  over the pages mastered NOW and promotes when it completes; `recovery_complete2` treats
  rc<0 as a HELD failure (P-TAUTH-COMPLETE-LEDGER-PURGEFAIL) before purge_node/takeover/
  slot zero.  Test: `dlm_ledger_test` 7b (knob `fail_commit_once_rc` also fires in the
  purge walk).  Ruling: `docs/rulings/partial-ledger-purge-held-failure.md`.
- **sess425 D-0344 purged-slot poisoning (0.35.2)**: `dlm_owner_purged` matched on SLOT
  alone — any later occupant of a purged heartbeat slot had its live records retired from
  the platter on the master's next page import (`P-TAUTH-PURGE node=<live>`; proven by
  7b before the fix).  Now node-id only.  Pitfall: usermode tests must give a returning
  node a FRESH id — a purged id never returns (by design; rig ids are per-incarnation).
- **sess425 RULE-4 instrumentation**: `dlm_retry(ctx, why)` tags every RETRY site in
  `dlm_lock_impl` (1 pend-retry, 2 remaster, 3 ledger-busy, 4 prepare, 5 own-pending,
  6 own-release, 7 refused, 8 grant-again, 9 wait-retry); the "lock request failed after
  N retries" line now prints type/ino/mode/last_rc and the per-request `why[...]` tally
  (D-0345).  `P-TAUTH-DLM-STATS` at release_all prints the ctx counters.
- **sess426 D-0345 UNOWNED page at a non-bootstrap master (0.35.4)**: `dlm_page_acquire`'s
  UNOWNED branch returned `-EAGAIN` without asking anyone (no auth_node to route to), so a
  never-decided page whose view-master is not the bootstrap node parked every request
  until the budget was gone (rig: `P-TAUTH-REMASTER-PARKED page_state=0 cached_auth=-2`,
  `why[remaster=60]`).  Fix: `bootstrap_node_cb` (id+inc of the lowest live slot;
  `v5_bootstrap_node_cb` / mesh `vbootstrap_node`) and a FREEZE_REQ to that node at the
  existing 500 ms cadence; its handler's `bootstrap-for-request` path claims + PREPAREs.
  Handler now also requires `target_node == sender`.  Proof: `tests/tauth/unowned_page_test`
  (fails `why[remaster=10]` / `why[prepare=10]` before, ~104 ms grants after).  Ruling:
  `docs/rulings/unowned-page-route.md` — carries two pre-existing hazards:
  bootstrap tenure across a lowest-slot flip is not fenced (write+readback ≠ CAS), and handoff
  progress burns the caller's REMASTER budget on a slow LUN.
- **sess426 D-0347 conditional commit (0.36.0)**: `tests/tauth/bootstrap_race_test` proved two
  "bootstrap" nodes could both claim one UNOWNED page and the stale-based late writer erased the
  other's activation + grant.  `mxfs_tauth_page_write` is now a conditional commit: base token
  (`hdr.seq`+`hdr.write_nonce` of the image the caller patched) must match the platter's highest
  valid image (`P-TAUTH-STALE-BASE` → `-ESTALE`), then a 512 B ticket (`struct mxfs_tauth_ticket`)
  is CAW'd into the spare copy's sector 0 (one winner; live foreign ticket → `-EBUSY` unless
  `store.fenced_cb` = `dlm_owner_purged` says fenced), body FUA, publish = CAW(ticket→final
  header) (`P-TAUTH-TICKET-STOLEN` = fencing fault).  Ledger: `-ESTALE`/`-EBUSY` reload the cache,
  never poison.  PAL user.c emulates CAW on regular files.  Pitfall: every commit is now 2 CAW +
  1 body write + 3 flushes — watch `P-TAUTH-STATS avg_ms`.  Ruling:
  `docs/rulings/tauth-conditional-commit-ticket-caw.md`.

- **sess426 disklock/v5 (0.36.1)**: `hb_rebase_epoch()` (disklock.c, next to `inc_valid`) is the ONLY
  way the monitor rebases `node_track[slot].last_epoch` from a sector — a zero sector never overwrites a
  known nonzero incarnation (`P-HB-INC-ZERO`, `ctx->hb_inc_zero_retained`; D-MONITOR-INCARNATION-
  DOWNGRADE-TO-ZERO items 1+2).  `ctx->hb_last_ok_ms` = when our own heartbeat last landed.
  `v5_bootstrap_ready()` gates `v5_bootstrap_cb`: own beat within the death timeout AND every lower
  monitored-dead slot recovery-resolved (`mphase_resolved_mask`) — D-0347 election refinement.
  Chain for all of it: `tests/sess426_chain.sh` (dre → incprobe → token → d0287 → board).

## TAUTH format v2 — mkfs-sized ledger geometry (sess427, D-0348 step 2)
- `include/mxfs/mxfs_tauth.h`: `MXFS_TAUTH_VERSION 2`; region header carries `npages` (validated in `[MXFS_TAUTH_NPAGES_MIN=2115, MXFS_TAUTH_NPAGES_MAX=2^20]`), `hash_version=1`, `hash_seed`; `MXFS_TAUTH_REGION_BYTES_FOR(npages)`; routing `mxfs_tauth_res_hash(res, len, seed)` → `mxfs_tauth_home_page(hash, npages)` / `mxfs_tauth_home_index(hash, npages)`. The old `MXFS_TAUTH_SLOTS/slot_page/slot_index` helpers are gone; `MXFS_TAUTH_REGION_BYTES` = the minimum (usermode-test) geometry. PROTO_GEN 8→9.
- Store reads the geometry from the header (`s->npages`, `s->hash_seed`) and refuses a header whose region exceeds the envelope size. Ledger: `mxfs_tauth_ledger_hash/page/home(l, res)` take the OPEN ledger. DLM ctx: `page_count` + `hash_seed` (`mxfs_dlm_attach_ledger` or `mxfs_dlm_set_ledger_geometry`), `dlm_res_page(ctx, res)` everywhere; a ledger-less member routes by the explicitly set geometry (usermode mesh does this) — defaults = min geometry, seed 0.
- mkfs: `-t ENTRIES` or `tauth_npages_for_device` = one record per 64 KiB, clamped (128 GiB LUN → 67,650 pages, 2.1M records, 528 MiB dual); seed from /dev/urandom. chk prints `pages= records= seed=` and checks both header copies agree. Tests: `TL_SEED`, `tl_page/tl_home`; `tests/tauth/pageof <type> <ino> <ag> [npages] [seed]`.

## sess429 (0.39.0) — tauth view record step 1
- `dlm/tauth_view.{c,h}` (Kbuild `tauth_view.o`): PAL-backed I/O only — `mxfs_tauth_root_read`, `mxfs_tauth_root_caw` (full-block COMPARE AND WRITE: -EAGAIN miscompare, -EIO ambiguous per §12), `mxfs_tauth_view_read`, `mxfs_tauth_view_write` (FUA + flush + readback). No policy yet: proposals/ballots/barrier are later steps (`docs/tauth-view-table.md` §10 build order).
- Format helpers are header-only in `include/mxfs/mxfs_tauth.h` (`mxfs_tauth_view_validate`, `mxfs_tauth_root_validate`, `mxfs_tauth_ctrl_validate`, `mxfs_tauth_view_owner_index` HRW by heartbeat slot, `mxfs_tauth_root_next_ballot`), SHA-256 in `include/mxfs/mxfs_sha256.h`.

## sess432 (0.39.11, D-0353) — single-node grant provenance
- `dlm/dlm_caw.c caw_lock()` single-node fast path now fills the `mxfs_grant_result`:
  `resource`, `kind`, `mode`, `status = MXFS_GAUTH_SINGLE_NODE` (new enum value in
  `include/mxfs/mxfs_dlm.h`, appended before `STATUS_MAX`).  Still NON-PROVING
  (`mxfs_grant_result_proving()` false; no epoch — single-node holds never touch a slot
  image, sess25 OR-bug decision unchanged).  Before this it returned the UNSET init value and
  the XFS side could not tell "no epoch because single-node" from "publication gap", which
  forced a false-fresh acquire on every re-acquire (D-0353).
- Contract: a SINGLE_NODE grant is valid only within the single-node era; the single→multi
  transition (`v5_mount.c` peer-join: `peer_joined_notify_fn` = XFS join flush FIRST, then
  `mxfs_dlm_caw_set_single_node(false)`) ends it.  The residual window between the flush's
  last AIL push and the flip is now LOUD (P131-INVAL-REFUSED on the next fresh acquire)
  rather than a silent discard — see D-0353 ledger residual.
- Open: D-0354 — epoch-0 images from the single-node era are unreplayable under token
  enforcement if the lone node crashes before a peer joins (needs a durable single-node
  authority incarnation; directed crash test first).

## sess433 (0.40.0, D-379(B)/D-0355) — PR key retention + predecessor guard

- `mxfs_v5_dlm_slot_release_commit(late, unmount_clean)` now RETURNS `bool`:
  true iff the heartbeat slot was durably released (unmount_clean AND the
  CAS/FUA release write returned 0).  put_super retires the PR key only then.
- `mxfs_scsipr_register(ctx, replace_predecessor)` (signature change, 4
  callers: v5_mount.c CAW+TCP pass `ctx->single_node_exclusive`, dlm/mount.c
  x2 pass false).  PAL register is a PLAIN REGISTER; `-EEXIST` = our nexus
  already holds a different key -> `P305-PR-PREDECESSOR-KEY-PRESENT` and the
  mount is refused unless replace_predecessor (then
  `P305-PR-PREDECESSOR-KEY-REPLACED` via REGISTER-AND-IGNORE).
- INVARIANT: keys are per-incarnation (random node_uuid), so READ KEYS can
  never attribute a key to a nexus — the SCSI conflict on plain REGISTER is
  the only in-band "nexus already registered" test.
- Full state machine + boundaries: `docs/pr-fencing-departure.md`.
- (sess433, 0.40.1, D-0357) `v5_caw_release_gate()` in dlm/v5_mount.c: when
  `depart_state == POISONED`, the CAW arms of `mxfs_v5_dlm_ag_unlock`
  (→ STILL_HELD), `_inode_unlock_open`, `_inode_unlock_free`,
  `_iclus_unlock_gen` (→ -ESHUTDOWN) refuse the on-disk CAS
  (`P306-CAW-RELEASE-POISONED`).  INVARIANT: a poisoned incarnation never
  removes a grant from the lock table — the grants are the survivor's
  manifest evidence.  Mirrors the sess418 TCP gate.

### sess435 (0.41.3) — D-0359 step 1: operational CAW admission probe
- `dlm/disklock.h`: `ctx->claim_via_caw` (true only when the claim's COMPARE AND WRITE landed; the verified non-CAW fallback leaves it false); `enum mxfs_caw_cap {OK, UNSUPPORTED, TRANSIENT, VIOLATION}`; `mxfs_disklock_caw_capability(ctx, &rc)`; `mxfs_caw_cap_name()`.
- `dlm/disklock.c mxfs_disklock_caw_capability()`: negative probe on OUR OWN heartbeat slot — compare image = hb_img with `timestamp_ms` flipped, write image = hb_img; expects `-EAGAIN` (MISCOMPARE) and a byte-identical read-back. Logs `P311-CAW-CAP slot=N <cap>`.
- `dlm/v5_mount.c` CAW branch, right after `claim_slot`: non-OK → `P311-CAW-ADMISSION-REFUSED cap= rc= slot= single_node_exclusive=` → `release_slot` → `err_disklock` (mount refused BEFORE the CAW DLM exists; no `DLM initialized (CAW`, no `caw_slot ... -95` storm). Refused even under `single_node_exclusive=1` until the ruling's SNLOCAL_EXCLUSIVE mode (step 2) lands.
- Consequence: loop devices (no SCSI device behind the bdev → `-EOPNOTSUPP`) cannot mount with the CAW transport; `tests/vergate.sh noncaw_refuse` asserts that; the loop arms `legacy_refuse/upgrade/mixed_build` FAIL by design until step 2.

## sess437 additions (0.41.11)
- `dlm/v5_mount.c v5_incarnation_state(ctx, node, epoch, &why)` → LIVE/REVOKED/UNKNOWN: the ONLY liveness test for a recovery owner / fencing prover (never `v5_node_is_dead(node)` alone — node_id is per mount, epoch per slot claim). Used by `mxfs_v5_dlm_recovery_acquire` (-EBUSY takeover gate, FENCING/SNAPSHOTTING takeover gate). REVOKED → `mxfs_disklock_recovery_takeover` (6 s abandon window, owner_term+1).
- `mxfs_v5_dlm_recovery_acquire`: claim -ENOENT + `mxfs_disklock_recovery_slot_status == UNFENCED` → `P238-FENCE-REDRIVE` → `v5_pr_fence_prove` → claim again (a death-time fence refused by ZEROINC is retried once the platter reads a valid incarnation).
- `dlm/disklock.c hb_still_dead_stamp`: same node + !inc_valid(epoch) is NOT a successor tenancy (barrier stays; no P163-RECOVERED without a replay).
- Measurement: `tests/handoff_anatomy.sh <label> [P] [F] [mht|keep] [locktotal]` + `tests/handoff_anatomy.py` — full P-probe capture + per-LBA counters + P383 caller census for one contended-dir burst (sharding increment 0).

## sess439 additions (0.44.0, proto_gen 13) — whole-cluster BOOTSTRAP RECORD (docs/whole-cluster-restart.md §5)

- **Ruling** (`docs/rulings/bootstrap-record-self-succession-intent.md`): self-succession by REGISTER-IGNORE without a durable intent is UNSAFE (peer's P&A sees KEY_ABSENT_UNPROVEN); "rebooter claims a free slot ACTIVE and runs the barrier" is UNSAFE for a total outage (no recovery-set closure, no slotless identity, no no-ACTIVE-before-global-complete). Required: a dedicated CAW bootstrap record + `SELF_SUCCESSION` fence intents on the predecessor slot + 5-phase order.
- **`dlm/bootstrap.{c,h}`**: envelope region `MXFS_FORMAT_F_BOOTSTRAP` (super `bootstrap_offset/size`, 4 KiB after prkey, one 512 B record "MXBS"). States IDLE/CLAIMED/MANIFEST_SEALED/RECOVERING/RECOVERY_COMPLETE; owner = provisional `{host_uuid, boot_uuid, node_id, epoch, pr_key, key_gen, nonce}`; sealed `victim_bitmap`, `complete_bitmap`, `ledger_gen`, `manifest_hash`, `registrants[_done]`, prev-owner + `prev_fence_kind` on takeover; crc32c(record, crc=0). API: `open/close/read`, `claim` (IDLE|COMPLETE → CLAIMED term+1), `takeover` (ONLY with PREEMPT_ABORT_DONE / SELF_SUCCESSION_DONE for the exact `owner_pr_key`, record unchanged across the caller's two reads, ≥ ABANDON_MS 6 s), `heartbeat` (CAW, -ESTALE when the platter no longer names our term/owner/nonce → stop acting), `seal`, `set_recovering`, `slot_complete` (refuses a slot outside the sealed bitmap), `registrant_done`, `complete` (refuses while any sealed slot/registrant is unresolved), `owner_is` (liveness view). mkfs writes IDLE (`write_bootstrap_record`); an all-zero sector is UNFORMATTED and the kernel fails closed (`P-BOOT-UNFORMATTED`). Validation binds fs_uuid only (fs_gen is recorded at claim).
- **Mount** (`v5_bootstrap_setup`, CAW path after the disklock exists, before the slot claim): reads the record, logs `P-BOOT-STATE`, and REFUSES admission (`P-BOOT-ADMISSION-REFUSED`, -EBUSY) while the state is CLAIMED/SEALED/RECOVERING — ruling invariant 3 landed before any claimer exists. No region → `P-BOOT-NO-REGION` refusal (gen 13). TCP path: opened for the liveness view only, failure reported not fatal (`P-BOOT-TCP-NOT-GATED`).
- **Owner liveness**: `v5_incarnation_state` treats a tuple absent from the HB table but named as the current bootstrap owner with a stamp < 6 s as LIVE (`mxfs_bootstrap_owner_is`); a stale stamp stays UNKNOWN (silence never authorises).
- **New fence kind** `MXFS_FENCE_KIND_SELF_SUCCESSION_DONE` (19, proves exclusion) — defined + named; its consumption (`mxfs_recov_cert_proves_exclusion` and the intent method) is build item 4.
- **chk_mxfs** `check_bootstrap`: validates + prints `bootstrap: <state> term owner key victims complete registrants prev kind`; flags a claimed recovery.
- Not yet built: item 5 (bootstrap phases 1-5 in the mount path). Nothing claims the record in 0.44.0/0.45.0.

### sess439 (0.44.0) — PR key: REGISTER before ledger (Item 2 correction)
- MEASURED on 0.43.0: under WE-AR an unregistered initiator cannot write the LU → `P-PRKEY-PREPARE-FAILED rc=-52`, 1/32 mounted. Ruling: ccmemory `...-GPT-ruling-prkey-register-before-ledger-derived-key`.
- `mxfs_prledger_derive_key(host, boot, fs)` (≥2³², ≠~0); `select` no longer writes (own entry must carry the derived key else `P-PRKEY-LEDGER-MISMATCH`; other owner with it = `P-PRKEY-COLLISION`, never redrawn; remembers READ KEYS's view + a reusable index); `mxfs_prledger_publish(l, node, nexus_reused, succ)` CASes the entry straight to REGISTERED after the verified REGISTER (`P-PRKEY-PUBLISHED`), refusing when the key was on the target but not on our nexus. PREPARED is never produced any more.
- PAL `mxfs_pal_scsi_pr_register_swap(dev, old, new)` = REGISTER rk=old sark=new, -ENOKEY on conflict; `scsipr` probes `swap(K,K)` after a plain-REGISTER conflict → `P305-PR-SAME-BOOT-KEY-REUSED`, `mxfs_scsipr_nexus_reused()`.
- Verified chain 20: 32/32 mount, 32 REGISTERED, takeover arm fails=0.

### sess439 (0.45.0, UNBUILT at write time) — item 4 self-succession
- `v5_self_succeed` (CAW, -EEXIST, !single_node_exclusive): `mxfs_prledger_find_predecessor` (exactly one previous-boot entry of this host with its key still registered) → `v5_self_succession_clone_scan` (two HB-table reads 2.5 s apart; an advancing record with our host_uuid = `P305-PR-HOST-DUPLICATE-LIVE` refusal) → `mxfs_scsipr_register_succeed` (swap old→new, `P305-PR-PREDECESSOR-BOOT-REPLACED`, READ KEYS verify) → publish with `succeeds{old_key, old_key_gen, old_boot}`.
- Prover: `v5_self_succession_consume` on `KEY_ABSENT_UNPROVEN`: victim host/boot from the death snapshot (`mxfs_disklock_victim_identity`; `ident_obs`/`pending_host/boot` now frozen with the key) + `mxfs_prledger_find_successor` (exactly one) + READ FULL STATUS old absent / new present ⇒ `MXFS_FENCE_KIND_SELF_SUCCESSION_DONE` (now in `mxfs_fence_kind_proves_exclusion`); ledger entry marked FENCED after certification.
- Harness pitfall: `fence_live_node.sh` / `excl_lapse_probe.sh` / `pr_reregister_probe.sh` derived PR keys from node_id — fixed to read `P-PRKEY-PUBLISHED key=`.

## sess438 additions (0.43.0, proto_gen 12) — 64-bit per-boot PR key (docs/whole-cluster-restart.md item 2)
- **HB record layout changed**: evict ring 23→19 entries (union 384→320), `struct mxfs_hb_identity` (64 B) at offset 360 {magic "MXID", ver, key_gen, host_uuid[16], boot_uuid[16], pr_key, host_src, crc32c}; tail 424/456/500 unchanged. `hb_ident_crc` binds {slot, flags, fs_gen, node_id, epoch}. Stamped by `hb_ident_fill` at all 5 write sites (hb, 2 claims, withdraw, guard). Installed by `mxfs_disklock_set_identity()` BEFORE the claim (-EBUSY after).
- **Victim key is FROZEN, never derived**: monitor `hb_ident_observe` (ACTIVE/WITHDRAWN only, never GUARD) → `ident_obs[slot]` per exact (node, epoch); `hb_ident_freeze_victim` at fire_dead → `pending_key*[slot]`; `mxfs_disklock_victim_key(slot,node,epoch,&gen)` serves ONLY the death snapshot. 0 ⇒ `MXFS_FENCE_KIND_NO_VICTIM_KEY` / `P-PRKEY-FENCE-REFUSED` (retryable; another survivor lays the intent). `P-PRKEY-CONFLICT` = two keys for one incarnation (tuple poisoned).
- **Registrant ledger** `dlm/prledger.{c,h}`: envelope region `MXFS_FORMAT_F_PRKEY64` (super `prkey_offset/size`, 256×512 B, after tauth). Entry {magic "MXPK", state FREE/PREPARED/REGISTERED/RETIRED/FENCED, key_gen, node_id, pr_key, host/boot/fs uuid, stamp, seq, crc(entry+idx)}; all transitions are CAS from the last image. `mxfs_prledger_select()` = reuse own boot's entry else draw ≥2^32 + READ KEYS once per candidate + CAS PREPARED; `set_registered` after READ KEYS verify; `set_retired` on clean unregister; `mark_fenced` after a certified P&A; `key_of_node` for slotless victims. REGISTERED entries whose key is absent from READ KEYS are reusable (`P-PRKEY-STALE-ENTRY`); PREPARED never swept.
- **scsipr**: `mxfs_scsipr_create(dev, name, uint64_t key)` (was node_id), `mxfs_scsipr_set_key`, `mxfs_scsipr_key_present`, `mxfs_scsipr_fence_node(ctx, victim_node, victim_key, ...)`; REGISTER now verified by READ KEYS (`P-PRKEY-REGISTERED` / `P-PRKEY-REGISTER-UNVERIFIED` → mount refused).
- **v5_mount**: `v5_prkey_setup()` (identity → ledger PREPARED → key installed) runs before REGISTER on both transports; `P-PRKEY-NO-LEDGER` / `P-PRKEY-NO-IDENTITY` refuse the mount; fence intent/P&A/certify use the frozen key; vergate fences LEGACY/MISMATCH records by node_id (that protocol's key), CORRUPT by ledger lookup. `mxfs_v5_dlm_detach_pr_key` leaves the entry REGISTERED (retired by the next selector's stale sweep).
- **Pitfall found while building**: `struct mxfs_prledger_entry` was 504 B on first cut — a sub-sector PAL I/O hangs dm (ccmemory trap); the `_Static_assert` is now unconditional.
- **Not built**: items 3–6 (predecessor-boot self-replacement, own-boot reclaim, bootstrap coordinator, matrix). `P305-PR-PREDECESSOR-KEY-PRESENT` still refuses.

## sess440 — refused-mount key retention fix (0.45.2) + item-5 groundwork (0.45.3, unbuilt)

- `mxfs_scsipr_unregister()` now REFUSES (`-ENOENT`, `P302-PR-UNREGISTER-SKIPPED`)
  when `!ctx->registered`: a retained fence target (`mxfs_scsipr_retain_key`,
  same-boot dirty refusal) or a never-registered key is never unregistered by
  any teardown, and the caller's "unregistered → ledger retired" step is skipped
  with it.  Measured on 0.45.1 (chain 23 s440b): the refusal printed
  P302-PR-KEY-RETAINED-ON-REFUSAL and the LU then held NO keys — `err_scsipr`
  in `v5_mount.c` calls unregister unconditionally.  Verified 0.45.2 chain 24
  s440c (keyheld=2).  Ledger: D-REFUSED-MOUNT-UNREGISTERS-RETAINED-FENCE-TARGET-0451
  (FIXED AND VERIFIED).
- Descriptor owner kind (`dlm/disklock.h`): `MXFS_RECOV_F_OWNER_BOOTSTRAP`
  (flag 0x20) + `MXFS_RECOV_NO_SLOT` (0xFFFF).  Every owner-field write goes
  through `recov_desc_set_owner_slot(ctx, d)` (from `ctx->owner_bootstrap`);
  relinquish/seal clear the bit; `recov_desc_of()` fails closed when kind and
  `owner_slot` disagree.  `struct mxfs_disklock_ctx` gained `owner_bootstrap`
  and `epoch_predrawn`; `mxfs_disklock_claim_slot()` consumes a valid
  `epoch_predrawn` instead of redrawing (bootstrap owner keeps ONE epoch from
  provisional to ACTIVE — RULE-5 ruling Q2).  API:
  `mxfs_disklock_set_owner_bootstrap(ctx, bool)`,
  `mxfs_disklock_predraw_epoch(ctx)`.
- Item 5 design as ruled: `docs/whole-cluster-restart.md` §6; ruling `docs/rulings/item5-slotless-bootstrap-build-review.md`.

## sess441-442 — item 5b/5d/5e: bootstrap owner, adopted slice K, same-boot RESUME (0.46.0-0.48.0)

- `dlm/bootstrap.{h,c}` v3 (PROTO_GEN 15): `struct mxfs_bootstrap_escrow` at
  record offset 224 (state NONE/PREPARED/K_CLAIMED/K_REPLAY_OK/K_REPLAY_REFUSED,
  K, victim tuple, the consumed descriptor byte for byte, claim identity,
  replay_rc).  API: `mxfs_bootstrap_escrow_prepare` (CAS + READ BACK; a
  PREPARED escrow for the same K/victim may be RE-PREPARED — sess442, the
  resume's claim from a moved lease image), `mxfs_bootstrap_escrow_advance`,
  `mxfs_bootstrap_release_claim` (CLAIMED→IDLE, before the seal only),
  `mxfs_bootstrap_manifest_write/read` (sectors 1..15, 7 entries/sector,
  crc'd, hash in the record), `mxfs_bootstrap_survivor_scan`,
  `mxfs_bootstrap_resume` (exact host/boot/key/gen ⇒ adopts node/epoch),
  `mxfs_bootstrap_refuse`.  `mxfs_bootstrap_complete` derives K's bit from
  `escrow.state == K_REPLAY_OK`.
- `dlm/v5_mount.c` owner path: `v5_bootstrap_peek` (pre-REGISTER; refuses a
  claimed term UNLESS it names this host's boot ⇒ `boot_resume_pending`),
  `v5_bootstrap_run` (scan → CLAIM → hb thread → rescan → classify keys →
  manifest → seal → RECOVERING → phase 3 → adopt), `v5_bootstrap_adopt`
  (escrow → `mxfs_disklock_claim_victim_slot`), `v5_bootstrap_resume_prepare`
  + `v5_bootstrap_adopt_resume` (sess442, §6.7), `v5_bootstrap_unwind` (retains
  the key, records NOTHING about K), `mxfs_v5_dlm_bootstrap_k_refused` (the
  ONLY path that ends a term on K — called from `xfs_log_mount`),
  `mxfs_v5_dlm_bootstrap_terminal/finish/adopted`.  `v5_victim_desc_read`
  serves K's descriptor from the escrow (the sector is our ACTIVE record).
- INVARIANTS (sess442): (1) an unfinished bootstrap term is NEVER a clean
  departure — `v5_dlm_destroy` forces `depart_clean = false` and the two
  explicit `release_slot` sites in init are guarded, else K's record is
  CASed to EMPTY and the victim's slice is "released" unreplayed; (2) the
  resume adopts the record's `owner_node` into `ctx->node_id` BEFORE
  REGISTER/publish/`mxfs_disklock_create` (node_id is random per mount),
  and `mxfs_disklock_adopt_epoch` before any record write; (3) the bootstrap
  owner fences with NO CAW engine, so `v5_rman_snapshot` collects the
  fence-time manifest with `mxfs_dlm_caw_manifest_collect_dev` (bare device,
  `disklock_offset + MXFS_DISKLOCK_HB_SIZE`) — the NO_CAW arm is for the TCP
  transport only (chain 27: 7/31 slices refused on empty manifests).
- `dlm/disklock.c`: `mxfs_disklock_claim_victim_slot` (CAW from the exact
  guarded image to ACTIVE|`MXFS_HB_FEAT_BOOTSTRAP_PENDING`, `slice_adopted =
  false`, pre-drawn epoch consumed), `mxfs_disklock_reclaim_own_slot` (re-take
  our own ACTIVE|PENDING record, nothing written), `mxfs_disklock_adopt_epoch`,
  `mxfs_disklock_read_record`, `mxfs_disklock_clear_bootstrap_pending`,
  `mxfs_hb_feature_bootstrap_pending`, `mxfs_disklock_mark_recovery_pending_ident`
  (victim tuple frozen from the manifest — no monitor snapshot after a total
  outage).  The completion ladder CASes `mxfs_bootstrap_slot_complete` after
  GRANTS_RELEASED and BEFORE the sector zero (HELD failure on a lost CAS).
- `dlm/dlm_caw.c`: `mxfs_dlm_caw_manifest_collect` is now a wrapper over
  `mxfs_dlm_caw_manifest_collect_dev(dev, lock_region_offset, ...)`.
- TEST ONLY knob `mxfs.bootstrap_inject` (1 after phase 3 / 2 after escrow
  PREPARED / 3 after K claimed; one-shot).  Harnesses:
  `tests/bootstrap_seal_fence.sh`, `tests/bootstrap_full_restart.sh`,
  `tests/bootstrap_resume.sh <label> <point>`.
- Docs: `docs/whole-cluster-restart.md` §6 (5b/5d/5e as built).  Rulings:
  `docs/rulings/item5d-adopt-one-slice.md`,
  `docs/history/gpt-review-item5d-code-landing.md`.

## sess443-444 (0.50.0-0.51.1) — item 5f takeover (Stage A/B/C) + completion pace
- Item 5f as built: `dlm/bootstrap.{h,c}` PROTO_GEN 17, record v5, 32 KiB
  region (manifest banks by term parity, DIRECT/INHERITED completion
  tombstones CAW'd before every completion bit, lineage, takeover journal);
  `dlm/v5_mount.c` takeover arm (`v5_bootstrap_takeover_run`: abandon
  window → election → stale-contender fence → old-owner fence on K or
  slotless → validated inheritance → lineage → `mxfs_bootstrap_reseal`).
  Chain 31 (0.50.0) verified points 11/12 end to end up to the ICREATE
  slice; docs §6.8.  Stage C (composite-K evaluator) lives in
  `xfs/xfs_log_recover.c` (see xfs.md) fed by `mxfs_v5_dlm_victim_lineage_
  count/_load`.
- First end-to-end whole-cluster restart with no operator action: chain 32
  on 0.51.0 (`20260829T085854Z_bootfull`) — RECOVERY_COMPLETE, 31 DIRECT
  tombstones, payload 32/32.
- **Completion pace (D-PURGE-NODE-FULL-TABLE-SECTOR-SCAN-0511, 0.51.1):**
  `mxfs_disklock_purge_node` read the 65536-record lock table one 512 B
  sector at a time (~8.3 s per dead node; 265 s of chain 32's 545 s mount;
  the same on every ordinary death).  Now `PURGE_BATCH=128` records per
  `mxfs_pal_bdev_read` with per-sector fallback for a failed batch
  (rd_fail accounting, per-record CAS-zero and the 2 s authority
  revalidation unchanged); `P-PURGE-DONE node purged scan_ms total_ms
  batched rec_unread`.  The completion path in `v5_mount.c` prints
  `P-COMPLETE-TIMING slot node refresh_ms ledger_ms dlmpurge_ms handoff_ms
  disklock_purge_ms rc` per publication.  Verified by chain 36.
- Per-slice foreign replay costs 4.4 s in `mxfs_xlog_slice_snapshot`
  (2 stability passes × `mxfs_fr_stab_interval_ms`=2000, D-527 quiesce
  proof) — a known serial cost, within the derived budget; changing it needs
  a ruling.
- D-0450 leftovers: `P-BOOT-STATE` / `P-BOOT-CLAIM-BUSY` no longer print
  `mxfs_pal_time_ms() - stamp_ms` (cross-node clock arithmetic); they print
  `seq=` and `owner_stamp_ms=` raw.

## sess449: same-node reconcile exerciser (0.56.0)
- `mxfs_v5_dlm_caw_samenode_selftest(ctx, ino, mode)` (dlm/v5_mount.c, after
  the pw selftest): mode 1 HOLD (EX 8 s), 2 COLLIDE (two kernel threads
  acquire EX behind a peer; `caw_inject_wait_expire=1` forces one give-up;
  mid-hold proof = obligation pending + waiter bit still set; survivor's
  holders_ex bit must survive the owed pass with a guard/defer hit), 3
  NEGATIVE (one attempt; bits must clear; fresh acquire must succeed).
  Verdict `P275-SAMENODE`.  Shared key `(agcount+1+64)<<(agblklog+inopblog)|1`.
- Read-only helpers in dlm_caw.c: `mxfs_dlm_caw_test_slot_bits`
  (find_slot image → `struct mxfs_caw_test_bits`), `_test_lreq_state`
  (attempts / tenure[EX] / owed pending under lreq_lock; -ENOENT no entry),
  `_test_arm_wait_expire` / `_test_wait_expire_left` (the K6 knob).
- Trigger: debugfs `caw_samenode_selftest` (xfs_mxfs_dlm.c), dentry
  `m_mxfs_samenode_dentry` removed early in put_super like the pw one.
  Harness `tests/caw_samenode_selftest.sh`, chain 66.
- Closure vehicle for D-SAMENODE-WAITER-CANCEL-COLLISION and siblings;
  scenarios B/C (plan staleness across a CAW retry, join between finish
  decrement and deferred pass) still need barrier hooks.

## Departure while this node owns a standing fencing attempt (verified 0.87.15)
- No retry budget anywhere on this path.  `P304-FENCE-RETRY` / `P304-FENCE-
  PROVE-BUSY` are the PR worker's latch firings refused by the node's OWN
  parked prover (single-prover guard); `P304-RETIRE-WORKER exiting` is the
  settle worker, a different thread.
- Certifiable attempt (victim key purged, sole survivor): the resumed prover
  takes the exclusive-write gate, recovers the victim, restores WE-AR, then
  releases RETIRE_PENDING (s53b).  Uncertifiable attempt: the unmount's SB
  summary sync and root acquire wait on the dead victim's grants until the
  recovery-blocked cutoff answers EIO (`P240-RBLK-EIO-ABORT`,
  `P-SB-SUMMARY-FINAL-FAIL lock_rc=-112`), the departure is DIRTY
  (`P277-SLOT-RETAINED-UNMOUNT-DIRTY`, `P302`), slot ACTIVE + key retained,
  attempt standing under our tuple.  The returning victim fences us (kind 16),
  takes the attempt over (term+1, BOOT_SUCCESSION_ABSENT), replays both
  slices, mounts (s53d: 93 s).  Harness `tests/d0356_stranded_prover_return.sh`
  (knob `fence_gate_inject_refuse`).  Design: docs/pr-fencing-departure.md.

## sess449: departure re-stamp (0.58.0, D-0356 / D-377)
- `mxfs_v5_dlm_slot_release_commit` NO LONGER destroys the disklock — call
  `mxfs_v5_dlm_slot_release_finish(&late)` last (both put_super and the
  failed-mount path do).  New `mxfs_v5_dlm_slot_restamp_unretired(&late)` →
  `mxfs_disklock_restamp_withdrawn_after_release(ctx)`: CAS from our own
  RELEASED (flags EMPTY, identity/epoch kept) or ACTIVE record to a WITHDRAWN
  record with the PR key; `P303-RETIRE-PENDING-RESTAMPED`; -ESTALE when the
  slot was re-claimed (`P303-RESTAMP-REFUSED`).  Peers fence via the sess9
  withdraw path.  Knob `dbg_pr_unregister_fail` (pal/linux/kern.c).

## sess450: RETIRE_PENDING two-phase departure (0.59.0, D-0356 / D-377)

- `disklock.h`: `MXFS_DISKLOCK_FLAG_RETIRE_PENDING` (4), `MXFS_DISKLOCK_RETIRE_GRACE_MS`
  (30 s), `mxfs_disklock_key_present_fn` + `mxfs_disklock_set_key_present_fn`,
  ctx `key_present_fn/data`, `retire_seen_ms/node/epoch[64]`,
  `mxfs_disklock_retire_complete_self`.
- `disklock.c`: `release_slot` writes RETIRE_PENDING (ident crc re-bound);
  `hb_ident_rebind`, `hb_retire_pending`, `hb_retire_settle` (enum
  `HB_RETIRE_EMPTY/WAITING/WITHDRAWN/CHANGED`; READ KEYS absent → CAS EMPTY,
  present past grace → CAS WITHDRAWN); wired into the monitor's pending-victim
  block, first-sight arm (before the WITHDRAWN arm) and dead-confirm arm;
  `hb_ident_observe` accepts flag 4; both claim paths skip it
  (`P274-CLAIM-RETIRE-PENDING-SKIP`); `restamp_withdrawn_after_release` accepts
  RETIRE_PENDING|ACTIVE (not EMPTY); `hb_foreign_kind` names the two.
- `v5_mount.c`: `v5_disklock_key_present` (no scsipr → PRESENT, fail closed)
  wired at both disklock callback sites; `mxfs_v5_dlm_slot_retire_complete`;
  P305 same-boot predecessor scan accepts RETIRE_PENDING.
- Log strings: `P304-RETIRE-PENDING-RELEASED / -SEEN / -COMPLETED-BY-PEER /
  -COMPLETED-SELF / -EXPIRED-WITHDRAWN / -SELF-REFUSED / -*-WRITEFAIL`.
- Invariant: a slot released by a clean unmount is consumable ONLY after its
  PR key is proven absent (by READ KEYS) or fenced.  Doc: `dlm/disklock.md`.

## sess451 (0.59.1) + sess452 (0.59.2): RETIRE_PENDING settlement, two STOP-SHIP rounds

**0.59.1 (sess451):** tri-state `mxfs_scsipr_key_state` (ABSENT/PRESENT/UNKNOWN),
`hb_retire_reread` after a lost CAS, RETIRE_PENDING counted by
`mxfs_disklock_get_recovery_pending_slots(..., out_retire_mask)` and settled
immediately by `mxfs_v5_dlm_mount_pending_recovery` (`P-ADMIT-RETIRE-PENDING-HELD`),
P305 same-boot settlement (`v5_same_boot_scan` on every CAW mount,
`v5_p305_settle_retire_pending`), host-wide `mxfs_v5_dlm_departure_lock/unlock`
(`mxfs_v5_dlm_global_init` from `init_xfs_fs`).

**0.59.2 (sess452)** — the sess451 STOP-SHIP #2 fixes (`docs/pr-fencing-departure.md`,
`dlm/disklock.md` sess452 section):
- `dlm/scsipr.{c,h}`: bracketed proof (`scsipr_bracket_run/_and_commit`,
  `scsipr_answer`, single-use ABSENT via `absent_used[]`), probe thread
  (`mxfs_scsipr_probe_start/stop`, `probe_lock` vs `snap_lock`),
  `mxfs_scsipr_key_state` (async) / `_key_state_sync` (mount thread) /
  `mxfs_scsipr_own_registration_proven` / `mxfs_scsipr_snap_invalidate`
  (called after every PROUT).  Constants `MXFS_SCSIPR_PRESENT_TTL_MS` 2000,
  `MXFS_SCSIPR_ABSENT_FRESH_MS` 5000, `MXFS_SCSIPR_PROBE_MIN_GAP_MS` 250,
  `MXFS_SCSIPR_ABSENT_USES` 64.  `scsipr_free` (abandon no longer leaks).
- `dlm/disklock.{c,h}`: enum `mxfs_disklock_key_state` has NO OWN; `key_state_sync_fn`
  + `mxfs_disklock_set_key_state_sync_fn`; `hb_retire_settle` picks sync when
  `immediate`; key 0 → UNKNOWN (`key0-invalid`); new
  `mxfs_disklock_retire_settle_own(ctx, slot, node, epoch, key, proof)`.
- `dlm/v5_mount.{c,h}`: `p305_retire_mask` + per-slot node/epoch/key arrays
  (replaces `p305_retire_slot`), `keystate_lock` (async callback vs
  `mxfs_v5_dlm_detach_pr_key`), `v5_disklock_key_state` (async, own key = PRESENT)
  + `v5_disklock_key_state_sync`, `v5_resv_conflict_cb` invalidates the snapshot,
  `struct mxfs_v5_dlm_slot_release.self_retire_ok` (filled in
  `mxfs_v5_dlm_shutdown_defer_release`), `mxfs_v5_dlm_slot_retire_complete`
  refuses clustered self-clear (`P304-RETIRE-SELF-REFUSED-CLUSTERED`).
- Markers: `P-PR-KEY-STATE-SYNC`, `P-PR-OWN-PROOF`, `P-PR-BRACKET-INCOHERENT`,
  `P-PR-BRACKET-DISCARDED`, `P-PR-PROBE-THREAD`, `P-PR-PROBE-NOTHREAD`,
  `P305-RETIRE-SETTLED-OWN`, `P305-RETIRE-OWN-CHANGED/-CAS-LOST/-WRITEFAIL/-UNPROVEN`,
  `P305-RETIRE-KEY0-TOPOLOGY/-UNSETTLEABLE`, `P305-RETIRE-MULTI`.
- INVARIANT: no PR IN on the heartbeat thread for settlement; ABSENT never from a
  time-cached view; a record naming our key is cleared only by P305 under the
  departure lock with a fresh bracket.
- Tests: `tests/retire_pending_admission.sh` (arms sameboot, joiner, unknown,
  unknownresv, trunc, slowpr, joinerunk, race, genmove, multipending),
  `tests/sess452_chain71_retire_pending.sh`.

## sess454 — 0.60.0 fail-closed CAS + 0.61.0 settle worker / proof token / quarantine

- `dlm/disklock.c` 0.60.0: EVERY `-EOPNOTSUPP` from `mxfs_pal_bdev_compare_and_write`
  on a record write fails closed via `hb_cas_nocaw_locked()` (ctx->lock held —
  `hb_cas_own_slot` runs under it) / `hb_cas_nocaw()` (takes it): marker
  `P304-CAS-NOCAW slot= op=` (op ∈ empty|withdrawn|settle-own|complete-self|
  restamp|release|heartbeat|withdraw|recovery-milestone|guard|guard-refresh|
  guard-zero), once per slot (`retire_nocaw_logged[]`).  Only
  `claim_slot_noncaw` (EMPTY sector, pre-admission) still blind-writes.
- `dlm/scsipr.{c,h}` 0.60.0: `mxfs_scsipr_validate_admission` refuses
  `!ctx->registered` (`P303-FENCECAP-UNREGISTERED ... key=`).
- `dlm/v5_mount.c` 0.60.0: `fence_capability_override` alone refuses clustered
  RW (`P303-FENCECAP-OVERRIDE-REFUSED-CLUSTERED`); `self_retire_ok =
  single_node_exclusive` only.
- `dlm/scsipr.{c,h}` 0.61.0: THE DEPARTURE MUTEX lives here —
  `mxfs_scsipr_departure_init/exit/lock/trylock/unlock/held` (re-entrant by
  pid; `mxfs_v5_dlm_departure_*` are wrappers).  Every PROUT is a wrapper
  (`mxfs_scsipr_register/_register_succeed/_reserve/_preempt/_unregister` →
  `scsipr_*_locked`) that nests or takes it (`P-PR-DEPARTURE-UNHELD`, INFO).
  `mxfs_scsipr_settle_absent(ctx, key, cas_fn, data, &enum mxfs_scsipr_settle)`:
  fresh bracket + CAS under `probe_lock`, single-use token (`token_*` fields,
  `mxfs_scsipr_proof_consume(ctx, token)` adjacent to the CAS; `P-PR-SETTLE-ABSENT`,
  `P-PR-SETTLE-UNPROVEN`, `P-PR-SETTLE-UNHELD`, `P-PR-PROOF-REFUSED why=`).
  `mxfs_scsipr_probe_stop` returns int: bounded join `MXFS_SCSIPR_JOIN_MS` 5000,
  `-ETIMEDOUT` = quarantined (`P-PR-PROBE-STUCK`; list + module pin;
  `mxfs_scsipr_quarantine_active/reap`, `P-PR-PROBE-REAPED`).  Flags
  `probe_stop/probe_kick/probe_exited` via `mxfs_pal_flag_*`.
- `dlm/disklock.{c,h}` 0.61.0: `mxfs_disklock_settle_absent_fn` callback +
  `mxfs_disklock_set_settle_absent_fn`; `MXFS_DISKLOCK_RETIRE_PRESENT`;
  `mxfs_disklock_retire_cas_empty(ctx, slot, expect, validate_fn, data)`;
  `hb_retire_settle`: monitor → table PRESENT keeps grace/WITHDRAWN, else the
  callback (enqueue, WAITING); immediate → callback inline (no sync lookup).
- `dlm/v5_mount.{c,h}` 0.61.0: retire settle worker (`retire_thread/stop/kick/
  lock/mask/key[]/img[]`, `v5_retire_worker_fn`, `v5_retire_settle_run`,
  `v5_retire_cas`, `v5_retire_validate`, `v5_disklock_settle_absent`;
  `P304-RETIRE-WORKER`); bounded stop → `retire_quarantined` + global list
  (`v5_quarantine_add/reap/free`, `P304-RETIRE-WORKER-STUCK/-REAPED`,
  `P304-RETIRE-QUARANTINE`); `mxfs_v5_dlm_detach_pr_key(ctx, bool *quarantined)`;
  mount refuses under quarantine (`P-PR-QUARANTINE-REFUSED`).
- Tests: `tests/settle_token_arms.sh <N> <victim> <probe> plain|inval|double|probehang`
  (injectors `dbg_settle_pause_ms`, `dbg_settle_inval_after_mint`,
  `dbg_settle_double_consume`, `dbg_probe_hang_ms`).
- INVARIANT: an EMPTY publication of a RETIRE_PENDING record happens only
  inside `mxfs_scsipr_settle_absent` (departure mutex + probe_lock + token).

## sess456 — fence intent names the incarnation it was asked to fence (0.61.2, D-0520)
- `mxfs_disklock_recovery_fence_intent` (`dlm/disklock.c`): after the P238-FENCE-ZEROINC refusal, `!inc_eq(cur->epoch, victim_epoch)` → ACTIVE + feature block OK ⇒ `MXFS_RECOVERY_SUPERSEDED` (P237-FENCE-SUPERSEDED), else -ESTALE (P237-FENCE-INC-MISMATCH); the descriptor-present tuple mismatch logs P237-FENCE-DESC-FOREIGN. Before this the intent copied `cur->epoch` into the descriptor whatever the caller asked (chain 61 nonzero: GUARD naming E2 0.5 s after the survivors declared E1 dead).
- `v5_pr_fence_prove_locked` (`dlm/v5_mount.c`): new `case MXFS_RECOVERY_SUPERSEDED` → `mxfs_disklock_clear_recovery_pending` + retry disarm + blocked clear + P237-FENCE-SUPERSEDED-RETIRED, return 0.
- node_id is a random UUID hash per mount (`dlm/mount.c:144`), so same-node_id succession is reachable only by a forged/torn sector (the probe) — see D-0520's record for the reachability argument.

## sess460 — hb_caw() chokepoint + retire-worker hang injector (0.61.6)

- disklock.c: the 12 exact-image record CAS sites (withdrawn-expiry, heartbeat,
  release, withdraw, restamp, complete-self, empty, settle-own, recovery-milestone,
  guard, guard-refresh, guard-zero) call `hb_caw(ctx, HB_CAW_OP_*, "what", off,
  expect, want)` instead of `mxfs_pal_bdev_compare_and_write` directly; the wrapper
  consults `mxfs_pal_dbg_cas_nocaw` (module param dbg_cas_nocaw_ops) and otherwise
  is the PAL call.  The remaining direct CAW sites (purge zero, claim, test paths)
  are not record writers of the P304-CAS-NOCAW family and are unchanged.
- v5_mount.c v5_retire_worker_fn: `mxfs_pal_dbg_retire_hang_take()` at the loop top
  (dbg_retire_hang_ms) — the worker parks ignoring retire_stop; v5_retire_worker_stop's
  5 s join then quarantines (P304-RETIRE-WORKER-STUCK).  Arms workerhang /
  workerhangheld in tests/settle_token_arms.sh.  NOTE (measured by workerhangheld):
  put_super's late phase takes the departure mutex AFTER the bounded worker stop, so a
  worker parked INSIDE a settle (mutex held) makes the late phase wait for it — an
  unbounded wait if the worker is truly wedged; disposition pending the measurement.
- dlm_caw.c (0.61.7, D-32NODE-SHARED-DIR-CREATE-PACE step 1): `find_slot_skip` gained
  a trailing `const void *who` and prints `P383-RESOLVE base= idx= via=hint|walk|
  walk-reread|absent rc= who=%pS` when `caw_watch_slot` is armed on the resource's
  home slot (`caw_resolve_note`); `find_slot`/`find_slot_deadline` pass
  `__builtin_return_address(0)`, the acquire loop passes its own.  P383-SLOTREAD
  names the READER (always find_slot_skip); P383-RESOLVE names who ASKED.
  tests/shared_dir_slot_cost.sh histograms it per caller and per path.  Census of
  find_slot callers (sess460 scout): acquire retry loop (caw_lock_body_inner:8417),
  unlock retry loop (caw_unlock_gen_body:10506), convert loop (12315), held-verify
  (mxfs_dlm_caw_held:11371, the BAST poller's read), granted_mode, test_slot_bits,
  open_holders/open_set/open_clear/open_probe (ICLUS open tracking), read_generation,
  victim_manifest_read_ex, set_dir_block0, dump_slot, owed collector (deadline).

## sess462 (2026-09-02, 0.63.0) — quarantine list double-add panic (D-0522)

`dlm/v5_mount.c`: `v5_retire_worker_stop()` is called twice per unmount
(`mxfs_v5_dlm_detach_pr_key` from `xfs_super.c:1967`, then
`mxfs_v5_dlm_shutdown` from `xfs_super.c:4126`).  With the retire settle
worker stuck, 0.61.0-0.61.7 timed out twice, pinned the module twice and
called `v5_quarantine_add(ctx)` twice — the singly-linked quarantine list
became a one-element cycle (`ctx->quarantine_next == ctx`), and the next
clustered mount's `v5_quarantine_reap()` freed the context and then walked
back into it (panic in `mount`: `v5_quarantine_reap+0x41`, or `kfree` via
`mxfs_scsipr_abandon -> scsipr_free_now -> mxfs_pal_mutex_destroy`).
Invariants now enforced: a context is quarantined at most once
(`P304-RETIRE-QUARANTINE-AGAIN` on the second stop, `-ETIMEDOUT` returned
without re-pin/re-link) and `v5_quarantine_add` refuses a context already on
the list (`P304-RETIRE-QUARANTINE-DUP`).  `mxfs_scsipr_probe_stop`
(`scsipr.c:937`) already had the equivalent guard.  Signature in a harness:
`stuck=2` (two `P304-RETIRE-WORKER-STUCK` lines in one unmount).
Verification owed on the rig: `tests/settle_token_arms.sh workerhang` /
`workerhangheld` on 0.62.1+ (chain 91), expecting one STUCK + one AGAIN, the
post-hang remount admitted after one `P304-RETIRE-WORKER-REAPED`, no oops.

## sess463 (2026-09-02) — item 5 increments 3+4 ruled; completion evidence formats (UNWIRED)

RULE-5 ruling `ccloop-c7ee71c6-sess463-GPT-ruling-item5-inc3-4-completion-
takeover-stopship`: the EMPTY/FULL/SPARSE completion scheme is accepted, the
disposition flip is STOP-SHIP on ten conditions (design text:
`docs/dlm-protocol.md` "Increments 3+4"; tree anchors: `docs/history/item5-inc3-implementation-map.md`).  Facts that shape
the DLM side:

* `caw_slot_ex` (dlm_caw.c:1597) structurally refuses any non-PURGE CAS that
  clears another node's EX/PW bit, and `caw_guard_refuses` (1490) lets a
  PURGE-class CAS only CLEAR bits of its victim mask, never ADD one.  The
  AG holder-bit TRANSFER victim→recovery owner therefore needs its own CAS
  class (`MXFS_CAW_CAS_F_TRANSFER`, to be added) with an allowed delta of
  exactly {clear BIT(from) from holders_ex/waiters/waiters_ex, add our bit,
  mint via `caw_grant_epoch_update`, generation+1, lineage preserved}.
* Every CAW purge path must hold a cluster-wide publication/purge guard (a
  `MXFS_LTYPE_SUPER` resource — the type exists, no `.c` uses it yet) across
  a fail-closed 64-sector OPEN-obligation scan; call sites: `v5_mount.c`
  8239 (settle sweep SKIP_TRACKED), 9500 (ladder purge_node), 11037 (mount
  KEEP_EX), 13962 (selective); `dlm/mount.c` is NOT in Kbuild.
* `recov_obl_of`/`recov_obl_present` (disklock.c 1344/1357) are the STRICT
  record readers to reuse for the scan; `mxfs_disklock_recovery_read`
  (disklock.h:2130) reads one descriptor.
* New descriptor flag reserved: `MXFS_RECOV_F_CENSUS_ZERO 0x40` (set in the
  IMAGES_REPLAYED CAS when the census is empty — "no record" is never zero).

New module (written, NOT in Kbuild yet — nothing compiles it):
`dlm/recov_obl_done.{h,c}` — 128-byte per-AG TRANSFER RECEIPTS at rman
`[40 KiB, 48 KiB)` (`MXRC`; from/to slot+node+incarnation, compare/written
CAW generation, from/to EX epoch, lineage, lease term, stage_seq, pub_seq,
seq; `mxfs_rman_obl_rcpt_check`, `mxfs_rman_obl_rcpt_digest`) and the 4 KiB
two-phase COMPLETION PROOF at `[48 KiB, 52 KiB)` (`MXOD`, `F_COMMITTED`,
2048-bit outcome bitmap, n_empty/n_full/n_sparse, receipts digest, list +
header crc, fs UUID, lease term, stage_seq, seq; `mxfs_rman_obl_done_check`
returns 0 / -ENOENT / -EINPROGRESS / -EPROTO).  Wiring requires lowering
`MXFS_RECOV_OBL_MAX_EXTENTS` 3072→2048 (entries then end at 40 KiB; the
`.c` layout guards enforce it) and mirroring in chk_mxfs.

## sess464 (2026-09-02) — D-0523: rejoin claim fails -28 during a transient sweep guard at capacity

- `mxfs_disklock_claim_slot` (dlm/disklock.c ~9775-9920): pass 1 = own
  node_id ACTIVE (a rebooted node has a fresh random node_id, so never);
  pass 2 = first free slot, SKIPPING RECOVERY_GUARD (any kind), WITHDRAWN,
  RETIRE_PENDING; no slot → `hb_report_claim_exhausted` (diagnostic only)
  → `-ENOSPC` immediately.  `MXFS_DISKLOCK_CLAIM_RETRIES=16` covers only CAW
  races on a FOUND slot.  On a 32-slice/32-node volume the dead node's own
  former slot is the ONLY one it can get, and a survivor's transient
  unclaimed-bucket sweep guard on it (P99-UBSWEEP-HOLD) makes the mount fail
  (chain 88 test2 07:22:57Z; remounted fine 6 s after the guard cleared).
  Ledger D-REJOIN-CLAIM-ENOSPC-DURING-TRANSIENT-SWEEP-GUARD-AT-CAPACITY-0523
  (high).  The permanent variant is D-QUARANTINED-SLOT-...-376.
- Ruling (ccmemory ccloop-c7ee71c6-sess464-GPT-ruling-d0523-claim-wait-
  transient-guard-at-capacity): in-kernel bounded WAIT in the claim layer
  (drop ctx->lock, sleep, full reclassify from disk, exact-image CAW); change
  = progress ONLY for refreshed records (sweep guards re-stamp every
  `MXFS_DISKLOCK_GUARD_REFRESH_MS`=1000; frozen → `hb_guard_abandoned`'s
  existing reclaim path); WITHDRAWN/RETIRE_PENDING wait on resolver
  eligibility + the MEASURED fence+replay / retirement walls
  (`MXFS_DISKLOCK_RETIRE_GRACE_MS`=30000 is the retirement bound); ONE
  monotonic absolute deadline from measured 32-node walls, expiry =
  `-ETIMEDOUT` + P300-CLAIM-WAIT-GAVE-UP (never -ENOSPC); peer loss mid-wait
  → internal restart-bootstrap result; permanent fast-fails unchanged.
- Recovery-ordering audit (ruling STOP-SHIP #1) is satisfied by existing
  gates: the mount recovery barrier folds crashed-stale (P225) and WITHDRAWN
  (P276, v5_mount.c ~11125-11194) slices into the joiner's inline replay
  cohort before `xfs_mxfs_dlm.c` ~54470 "barrier complete"; RETIRE_PENDING
  blocks writable admission at the join gate (disklock.h ~95-112).
- Harness: `tests/guard_race_arms.sh joiner` reworked — SAFETY (never claim
  the guarded slot while the holder's sweep is unfinished) and AVAILABILITY
  (mount within 240 s = measured 35 s boot→claim + 180 s hold) are separate
  verdicts; P300-CLAIM-* refusal lines are quoted in the FAIL.

## sess465 (2026-09-02, 0.63.1) — claim WAIT for transient occupants (D-0523)

- `dlm/disklock.c hb_claim_wait()` (before `mxfs_disklock_claim_slot`): when pass 2 finds no
  claimable slot it re-reads/classifies the table under `ctx->lock` each lap. Permanent →
  `-ENOSPC` via `hb_report_claim_exhausted` (unchanged diagnostics). Waitable (sweep guards,
  recovery leases, WITHDRAWN, RETIRE_PENDING) with ≥1 live OTHER member → one absolute deadline
  `MXFS_DISKLOCK_CLAIM_WAIT_MS` (disklock.h; 181 s measured max kill→replay + retire grace +
  HB interval + guard refresh), scan every `MXFS_DISKLOCK_CLAIM_SCAN_MS` (= HB interval) with the
  lock dropped. Liveness = ACTIVE stamp moved within `dead_threshold × HB_INTERVAL`. Results:
  0 = rescan (pass 1/2 again, exact-image CAW), `-ETIMEDOUT` (P300-CLAIM-WAIT-GAVE-UP, transient),
  `-ERESTART` (P300-CLAIM-WAIT-PEERS-LOST; v5_mount fails the mount, next attempt bootstraps).
  `attempt` (16 CAW retries) increments only on P130-CLAIM-RACE.
- Markers: P300-CLAIM-WAIT-START / -SCAN / -DONE / -GAVE-UP / -PEERS-LOST / -PERMANENT /
  -FROZEN-GUARD. Harness: `tests/guard_race_arms.sh joiner` prints them.
- Design doc: `dlm/disklock.md` "0.63.1".
- sess465 (0.63.2): `struct mxfs_v5_dlm.samenode_bast_ino/samenode_bast_guard` — `v5_bast_cb` skips the
  XFS-layer inode-BAST dispatch for the same-node exerciser's pseudo-inode while a run is active
  (`P275-SAMENODE-BAST-HELD`); before this, the peer's cache handler released the raw
  `mxfs_dlm_caw_lock` EX on the first BAST (no registered XFS holder: `P381-UNLK-CONTEND noreg=1`) and
  every exerciser arm was vacuous. Chain 95 `tests/sess465_chain95_samenode_bastguard.sh` re-runs it.

## sess467 — claim wait -ERESTART re-runs the bootstrap in-mount (0.64.2)
- `dlm/v5_mount.c` (mount init, after the disklock identity install): the
  `v5_bootstrap_run` + `mxfs_disklock_claim_slot` pair is now a bounded loop —
  `claim_slot == -ERESTART` (P300-CLAIM-WAIT-PEERS-LOST: every ACTIVE peer fell
  silent during the claim wait) logs `P300-CLAIM-WAIT-RESTART-BOOTSTRAP
  attempt=n/N` and jumps back to the bootstrap (`MXFS_V5_CLAIM_BOOTSTRAP_RESTARTS`
  = 1 in `v5_mount.h`).  The claim-wait state (`struct hb_claim_wait`) is
  allocated per `claim_slot` call, so a restart starts a fresh absolute
  deadline.  A second -ERESTART fails the mount truthfully.  Docs:
  `dlm/disklock.md` "0.64.2".  Test: `tests/guard_race_arms.sh peerloss`.

## sess470 — D-488 unlock-exit fault arms (0.64.13) and the D-0528 adoption gap
- `dlm/dlm_caw.c` `caw_unlock_gen_body`: three TEST-ONLY consumable module
  params force the formerly-silent AG-unlock exits on the real post-COMMIT
  body — `caw_inject_unlk_noslot` (find_slot → -ENOENT: `P274-AGUNLK-NOSLOT`,
  RELEASED with the bit still set = own-bit strand), `caw_inject_unlk_findslot_eio`
  (find_slot → -EIO: UNKNOWN), `caw_inject_unlk_cas_eio` (1 = skip the clear
  CAS and report -EIO; 2 = commit it, then report -EIO).  Every hit prints
  `P470-UNLK-INJECT ag= site= forced_rc=`.  AG resources only; an inode
  unlock never consumes an arm.  Expected outcomes and the harness
  (`tests/d488_unlock_exit_arms.sh`, chain `tests/sess470_chain111_*`) are in
  `docs/dlm-protocol.md` "0.64.13".
- The worker's tri-state handling lives in `xfs/xfs_mxfs_dlm.c`
  ~49160-49350: UNKNOWN → 10×1 s `mxfs_v5_dlm_ag_held` read-back
  (`P275-AGUNLK-REVERIFY tries= state=`) → RELEASED (handoff accounting) /
  STILL_HELD (`P275-AGUNLK-REARM`, re-mint through `mxfs_ag_dlm_lock` +
  unlock; `-REARM-FAIL` requeues) / still UNKNOWN (`P275-AGUNLK-QUARANTINE`,
  demoting held, release_pending set, no wake).
- Adoption of a retained own bit is MOUNT-WINDOW ONLY (`caw_adopt_retained`
  ~4527-4542 returns 0 when `!ctx->mount_adopt_window`); there is no
  acquire-side "my own bit, no tenure" reconciliation (a per-acquire slot read
  was tried and reverted, `__mxfs_ag_dlm_lock` ~40872-40892) — the BAST-driven
  orphan-nak/readopt in `mxfs_dlm_ag_bast_notify` (~48246-48286,
  `READOPT_PENDING` → worker `P294-READOPT-MINT`) is the only recovery.  Filed
  as D-0528; multicast BASTs loop back (`IP_MULTICAST_LOOP`, pal/linux/kern.c
  ~2807), so a node waiting on its own stranded bit BASTs itself.

## sess494 (0.70.12, D-0493) — a terminal guard is not an outage signal
- `dlm/disklock.c` `mxfs_hb_terminal_guard_classify(hb, slot, fs_gen, &oc)`
  (prototype next to `mxfs_disklock_terminal_gate_check` in disklock.h):
  CONTEXT-FREE classification of one heartbeat image as a terminal recovery
  guard, the same identity binding as `closure_gate_predicate` — RECOVERY_GUARD
  of `fs_gen`, `recov_desc_of` (version + crc over the sector's
  {fs_gen,node,epoch}), victim tuple == the record's own tuple and `slot`,
  `MXFS_RECOV_F_QUARANTINED`; returns 0 with the outcome for a canonical
  TERMINAL_REFUSED verdict (FSWIDE mask 0 / AG_MASK non-zero), -ENODATA for the
  exact legacy all-zero outcome region, -EBADMSG for a torn or non-canonical
  verdict, -EAGAIN for a sub-terminal descriptor, -EPROTO/-ESTALE/-ENOENT
  otherwise.  Usable before a disklock ctx exists and from tools.
- `dlm/bootstrap.c` `mxfs_bootstrap_survivor_scan`: a RECOVERY_GUARD with a
  descriptor is classified first.  0/-ENODATA → NOT member-shaped: skipped with
  `P-BOOT-SCAN-TERMINAL-GUARD slot= victim= verdict|legacy-quarantine domain=
  ag_mask= seq=`; nothing fences, replays, adopts or zeroes it (claim_slot's
  wait counts a QUARANTINED guard as permanent non-consumable, and the
  admission barrier's `mxfs_freplay_classify_terminal` imports the mask before
  availability — the same path a joiner to a live cluster takes).  -EBADMSG →
  `unread++` with `P-BOOT-SCAN-GUARD-TORN` (the caller refuses with
  P-BOOT-SCAN-UNREAD).  -EAGAIN/-EPROTO → a victim as before (identity
  required).  With no victim left after the skip the scan logs
  `P-BOOT-SCAN-TERMINAL-ONLY` and the caller takes the ordinary path (n == 0);
  `P-BOOT-SCAN-FROZEN` now carries `terminal_guards= torn=`.
- Why not a manifest class (GPT concurred): the guard is durable state a live
  cluster runs beside; alone it would leave `v5_bootstrap_adopt` with no slice
  to adopt (-ENOSPC).  Conditions it verified against: slot never
  claimed/adopted/zeroed, import before admission on every joining node
  (journal order `P240-QUAR-IMPORT` before `mount ADMITTED with AG mask`),
  torn/tuple-mismatch refuse.
- `P-PR-DEPARTURE-UNHELD` (scsipr.c `scsipr_dep_enter`) is INFO: the PROUT
  wrapper takes the host-wide departure mutex itself when the caller did not;
  the line on a refused mount's unregister names a caller-discipline gap, not
  an unlocked PROUT.

## 0.71.0 — the TCP fence-time manifest comes from the authority ledger (docs/tcp-authority-ledger.md step 5)

- `tauth_store.{h,c}`: `mxfs_tauth_store_scan(s, first, count, cb, data)` —
  bulk reader over both copy arrays (64 KiB runs via `mxfs_pal_alloc_io`,
  per-page fallback on a failed run), same per-page selection rule as
  `mxfs_tauth_page_read` (highest valid seq; same-seq divergent = UNKNOWN);
  `cb(data, page_id, pg|NULL, rc)` with rc 0 / -EUCLEAN / -EIO per page.
- `tauth_ledger.{h,c}`: `mxfs_tauth_ledger_collect_ex_holder(l, node, inc,
  slot, cb, data, &scanned, &inc_mismatch)` — every ACTIVE record whose
  exclusive holder is `{node, slot}` under `inc` (other incarnations counted,
  not reported), read fresh from the platter; -EUCLEAN/-EIO when ANY page has
  no committed image (`P-TAUTH-COLLECT-INCOMPLETE`, fail closed).
  `mxfs_tauth_ledger_read_fresh(l, res, &entry, &slot_idx)` — one record,
  fresh, no cache side effect; `slot_idx = page * 31 + index`.
- `dlm.{h,c}`: `sealed_owners[]` + `mxfs_dlm_seal_owner(ctx, node, inc)`
  (records the owner, waits ≤3 s for its PENDING_RELEASE entries to settle,
  `P-TAUTH-SEAL` / `P-TAUTH-SEAL-BUSY`); `mxfs_dlm_process_remote_release`
  refuses a sealed sender's release with no ACK
  (`P-TAUTH-SEALED-RELEASE-REFUSED`, counter `sealed_releases_refused`);
  `mxfs_dlm_purge_node` unseals.
- `disklock.h`: manifest flag `MXFS_RECOV_MPTR_F_TAUTH_LEDGER` (1<<2);
  reader accepts it, requires `scan_slots != 0`, and forbids it together with
  NO_CAW_TABLE.  The consumer `mxfs_v5_dlm_victim_manifest_load` refuses a
  ledger manifest whose `scan_slots` is not its own region's page count.
- `v5_mount.c`: `v5_rman_snapshot` TCP branch (`ctx->tauth_open && ctx->dlm
  ->ledger`): seal → collect → `P-RMAN-COLLECT-TAUTH victim_slot= victim=
  epoch= pages= entries= ex= pw= inc_mismatch= ms=` → manifest write with
  the flag (the sealed `P-RMAN-SNAPSHOT` line then shows `flags=0x4`).
  `mxfs_v5_dlm_victim_live_read` answers from `read_fresh` on TCP (holds iff
  ACTIVE with `ex_slot == victim_slot`; `-ENOENT` otherwise) so the gate's
  POSTSEAL-MUTATION / LIVECHECK-ERR terminals keep their meaning;
  `mxfs_v5_dlm_rman_verify_live` no longer skips TCP.
- PITFALL: the seal is LOCAL to the prover.  With one survivor that is the
  whole barrier; with several survivors a victim's release can still commit
  at another master after the scan — the gate then aborts fail-closed
  (availability, not integrity).  The ruling's SEAL message is still owed.
- Oracles: `tests/tauth/ledger_test.c` group 16 (usermode);
  `tests/tcp_death_replay.sh` + `tests/tcp_2node_death_chain.sh` (rig).

## 0.72.0 (2026-09-04) — sole-survivor exclusive-write gate, fence kind 20 (D-0904)

- **Why**: a target that purges a dead node's PR registration with its iSCSI
  session (QNAP TS-453 Pro, ~34 s after a power cut, PR generation unchanged)
  leaves no key for PREEMPT AND ABORT to name; `mxfs_scsipr_fence_node` can
  only answer `KEY_ABSENT_UNPROVEN`, the PRECOMMAND retry re-drove it forever,
  the slice was never replayed and the survivor froze behind the victim's EX.
- **New fence kind** `MXFS_FENCE_KIND_EXCLUSIVE_WRITE_GATE` (20, on-disk
  certificate value, proves exclusion). Supporting fact: `fence_resv_type ==
  MXFS_PAL_PR_TYPE_WR_EX` (0x01), enforced by the new
  `mxfs_fence_kind_resv_type_ok(kind, type)` in both disklock certificate
  checks (`mxfs_recov_cert_proves_exclusion`, `recovery_fence_certify`).
- **scsipr API** (`dlm/scsipr.c`): `mxfs_scsipr_gate_sole_survivor(ctx,
  victim_node, victim_key, arm_submit, arm_data, out)` — observe (complete
  READ KEYS; own key on exactly ONE nexus else `P-PR-GATE-MULTINEXUS`
  ERROR/-ENOTUNIQ; victim key absent else kind NONE = "use the key preempt";
  WE-AR held else NO_RESERVATION; idempotent `P-PR-GATE-ALREADY` when WE(1)
  is already ours alone), arm_submit, PROUT P&A `rk=own sark=0 type=1`,
  verify keys = own only + READ RESERVATION type 1 held by own key →
  `P-PR-GATE ... EXCLUSION PROVED`, `ctx->gate_held`. `mxfs_scsipr_gate_holds`
  = the replay-time recheck for kind 20 (type 1 still held by our key, our
  key registered). `mxfs_scsipr_gate_restore` = plain PREEMPT `rk=own
  sark=own type=7` (atomic on the QNAP), verified → `P-PR-GATE-RESTORED`.
  While `gate_held`, the key-state bracket's `resv_ok` and
  `check_reservation_health` treat WE(1)-held-by-us as the fencing
  reservation (not WRONG_TYPE).
- **v5 wiring** (`dlm/v5_mount.c`): after `v5_self_succession_consume`, a
  still-`KEY_ABSENT_UNPROVEN` verdict tries the gate only when `nlive == 1`
  AND `mxfs_disklock_lowest_live_slot(disklock, local_slot) < 0` AND the
  victim key is frozen and not ours (`P238-FENCE-GATE-TRY`, else
  `P238-FENCE-GATE-NOTSOLE`). sark=0 evicts every other registrant, so the
  membership condition is the safety of the whole thing. `mark_fenced`
  includes kind 20; `v5_exclusion_recheck` branches on cert kind 20 to
  `gate_holds`; the recovery-complete ladder calls `v5_gate_restore` right
  after `P163-RECOVERY-COMPLETE`, and a failed restore sets
  `ctx->gate_restore_due` for the PR worker to re-drive each tick.
- **Pitfalls**: joiners are refused at admission (`P303-FENCECAP-WRONGTYPE`)
  while the gate is held — fail closed until the restore lands. A survivor
  unmounting before the restore releases the single-holder reservation
  (LUN unreserved; the next mount RESERVEs WE-AR). The mount-time recovery
  path has no gate arm. Multipath nexus sets are refused. The infinite
  PRECOMMAND retry itself (ledger item 4) is untouched.
- Oracle: `tests/tcp_death_replay.sh` asserts the gate leg when
  `P-PR-GATE-ISSUE`/`ALREADY` appears (kind 20 certified, zero gate failure
  probes, P163 published, `P-PR-GATE-RESTORE site=`, then `sg_persist` from
  the survivor: one key, WE-AR).

## 0.83.0 — DEGRADED_UNCONFIRMED remote lock waits (dlm.c / dlm.h / xfs_mxfs_dlm.c)

- **Why** (D-0958): a wait on a live remote master that never receipts it is
  unbounded for every caller that cannot be failed, and until now invisible
  outside dmesg. Design consult ruled: bounded acquisition-specific DETECTION
  and REPORTING, no escalation (silence does not identify a fence victim).
- **Requester acquisition record** (`dlm.h` `acq[]`): `master`, `receipt_ms`
  (arrival, diagnostic), `confirm_ms` (ISSUE time of the confirmed attempt =
  the anchor), `degraded_ms`, `retx`, `rejected`, `attempt[4]{req_id,sent_ms}`
  ring written by `dlm_acq_note_sent` BEFORE the send.
- **Contract constants**: `MXFS_DLM_ACQ_STATUS_LATENCY_MS` 15000 (D),
  `MXFS_DLM_ACQ_STATUS_MISSES` 30 (N), P = `MXFS_LOCK_ACQUIRE_WAIT_MS`;
  `mxfs.acq_degrade_ms` default N×P+D = 45000, 0 disables.
- **Flow**: `dlm_acq_note_unanswered` at the remote -ETIMEDOUT site
  (anchor = max(first_ms, confirm_ms); past H → `P958-ACQ-DEGRADED` once);
  `dlm_acq_note_receipt` from `mxfs_dlm_process_queued_ack` (accept only if
  sender == master, req_id names a kept attempt, arrival within D of its issue;
  else `P958-ACQ-STATUS-REJECTED`; accepted clears → `P958-ACQ-RECONFIRMED`);
  `dlm_acq_end` logs `P958-ACQ-DEGRADED-END` for a degraded wait.
- **Export**: `struct mxfs_dlm_acq_state` in `include/mxfs/mxfs_dlm.h`;
  `mxfs_dlm_acq_degraded_iter` → `mxfs_v5_dlm_acq_degraded_iter` →
  debugfs `acquire_degraded` (`mxfs_acquire_degraded_show`, no I/O, no DLM
  call). CAW: always empty.
- **Harnesses**: `tests/tcp_lockreq_blackhole.sh EXPECT=degraded`
  (WORKLOAD=held_fd) asserts detection inside `DEGRADE_BOUND_S`+6 s of the
  first armed drop, listing while armed, delisting after;
  `tests/live_holder_wait.sh MASTER=remote` is the control (zero DEGRADED,
  zero rejected receipts over a confirmed 240 s queue).
- **Pitfall**: the receipt names the resource and the attempt, not the mode;
  matching is by attempt nonce so a second wait on the same resource cannot
  supply evidence for this one. Design: `docs/dlm-protocol.md` "Degraded
  remote lock waits".

## 0.82.6 — the gate is lifted only when nothing owes it (v5_mount.c / disklock.c)

- **Why**: one gate per LUN, more than one recovery under it. 0.82.4's
  in-memory dependant set covered recoveries that had VALIDATED; an obligation
  this node had certified but not yet claimed registered nothing, so the set
  emptied while work remained and the restore landed one second before the
  next claim (measured, `tests/evidence/20260911T180314Z_d0932own_s580k`).
- **New disklock API**: `mxfs_disklock_gate_owed_sweep(ctx, &owed,
  &unreadable, &malformed)` — every sector; owed = validated descriptor with
  `fence_kind == EXCLUSIVE_WRITE_GATE`, stage `< GRANTS_RELEASED`, not
  `QUARANTINED`; unreadable = read failure or unvalidatable guard record;
  malformed = gate kind below `SNAPSHOTTING` (also owed). Not the admission
  sweep with a filter: no skip slot, no WITHDRAWN/RETIRE_PENDING folding.
- **v5 context**: `gate_lock` (mutex), `gate_pin_slots`, `gate_owed_logged`,
  `gate_restore_last_ms`. `v5_gate_dep_add/clear` now take the lock.
  `v5_gate_pin_add` before `mxfs_scsipr_gate_sole_survivor`;
  `v5_gate_pin_reconcile` in the `v5_pr_fence_prove` wrapper after the body
  returns (unpin on durable gate certificate or no gate held, else
  `P-PR-GATE-PIN-KEPT`). `v5_gate_restore` takes departure mutex then
  `gate_lock`, refuses on pins|deps (`P-PR-GATE-RESTORE-HELD deps= pins=`), then
  on the platter (`P-PR-GATE-RESTORE-OWED owed= unreadable= malformed=`), then
  converts. PR worker re-drives a due restore every
  `V5_GATE_RESTORE_REDRIVE_MS` (2000), not per 250 ms tick. Terminal refusal
  wrappers clear the dependant (`why=refused-terminal`).
- **0.87.12 (D-SOLE-SURVIVOR-GATE-NEVER-RESTORED-AFTER-A-TERMINAL-REFUSAL)**:
  the sweep's signature is now `(ctx, &owed, &unreadable, &malformed,
  &terminal, terminal_key[64])` — quarantined gate-kind descriptors are
  reported with their certificate's victim key, and `v5_gate_restore`
  re-checks each key with `mxfs_scsipr_key_state_sync` and converts only on
  a proven ABSENT (`P-PR-GATE-RESTORE-VICTIM-PRESENT` otherwise). The two
  terminal-refusal wrappers (`mxfs_v5_dlm_recovery_publish_refusal[_obl]`)
  call `v5_gate_terminal_release`: dep clear, mark the restore due under
  `gate_lock`, `P-PR-GATE-TERMINAL-RELEASE`, then `v5_gate_restore(ctx,
  "refused-terminal")` inline. Before this nothing drove the restore after a
  terminal verdict and the gate outlived the recovery. Harness arm:
  `MODE=terminal_rejoin tests/d_intents_2tcp_open_efi.sh`.
- **Pitfalls**: never take `gate_lock` and then wait for the departure mutex.
  A gate-kind certificate that is never completed or refused holds the gate
  for ever, logged — that is the design, not a leak to time out. Design:
  `docs/pr-fencing-departure.md` "What may lift the gate".

## 0.72.2 — `mxfs_v5_dlm_sole_survivor(ctx)` (v5_mount.c / v5_mount.h)

New query next to `mxfs_v5_dlm_is_single_node`: true when the membership is
single-node NOW and `ctx->ever_multi` latched earlier in this mount, i.e.
this node is the sole survivor of a peer's death or departure. The xfs
overlay's single-node fast paths consult it so a dead peer's pending
invalidations (demote to NL, `i_dlm_stale`, `MXFS_IF_DIR_RELOAD`, dir gen)
are still serviced; a never-multi mount keeps its behaviour unchanged.
`is_single_node`'s per-call `P-SINGLENODE-REGRESSION` warning is replaced by
one `P-SOLE-SURVIVOR` note per episode (`ctx->sole_survivor_noted`, re-armed
when a peer joins). Invariant behind it: `v5_membership_cb_tcp` is a
deliberate no-op ("the XFS cache layer self-recovers via per-resource BAST
events") — that premise holds only while a peer exists to send BASTs, so
membership collapse to one node must not be treated as a plain single-node
mount by any cache consumer. Ledger:
D-SURVIVOR-SINGLE-NODE-BYPASS-SERVES-STALE-VIEW-AFTER-PEER-DEATH-0904.

## 0.87.16 — `mxfs_v5_dlm_never_multi()` removed: no membership exemption from inode ownership (v5_mount.c / v5_mount.h, xfs_mxfs_dlm.c, xfs_icache.c)

The 0.83.3 predicate below is gone, with all nine sites keyed on it
(`mxfs_dlm_ilock_begin` bypass, `ilock_end` gate and the two
`P71-SURVIVOR-UNPAIRED` detectors, `ilock_try`, `ilock_demote`,
`rearm_unpublished`, `publish_dirs_work`, `publish_inode`, `dir_hold_ex`, and
the four `xfs_iget_cache_hit/miss` sites — the create-time local
unpublished-EX grant and the three coordinated stale-shell reloads). A mount
that has never had a peer now takes real inode grants from the master (itself)
exactly as a sole survivor does and as its AG grants have been real since
0.41.0. Why: the replayer of a dead node's slice authorizes an inode-owned
image (dir block, bmbt, remote symlink/attr block) only against the grant the
owner held at capture; a never-multi mount's inodes had none, so every such
image shipped `AUTH_NOT_HELD` and the replay refused the transaction and
quarantined its AGs (s53f: 40 fsynced files lost from view, root EIO). Proven
by instrument (`tests/lone_dir_block_authority.sh` s54a/s54b): 45 non-durable
captures at NONE/NL alone, zero with a peer. Design consult 2026-09-18 ruled
this shape (A) over a narrow divert and over a replay-side "never had a peer"
certificate. `ever_multi` stays: `mxfs_v5_dlm_sole_survivor()` still reads it
for the departed peer's pending invalidations. `is_single_node()` remains for
peer-signalling shortcuts only; never gate an ownership decision on it.
Ledger: D-LONE-MOUNT-DIRECTORY-BLOCK-IMAGE-SHIPS-AUTH-NOT-HELD-SO-ITS-CRASH-SLICE-IS-REFUSED-AND-AG0-QUARANTINED.
Regression harnesses: `tests/lone_mount_crash_replay.sh` (dir + bmbt witness,
same-node or peer recovery, cold read, offline check),
`tests/lone_dir_block_authority.sh` (capture-time authority, no crash).

## 0.83.3 — `mxfs_v5_dlm_never_multi(ctx)` and the survivor's real grants (v5_mount.c / v5_mount.h) — predicate REMOVED in 0.87.16, see above

Third membership predicate next to `is_single_node` and `sole_survivor`:
`never_multi` = single-node NOW and `ever_multi` never latched — the only
state in which the xfs overlay may modify and publish an inode without a
grant. `ever_multi` is now also latched by the membership protocol itself
(`v5_membership_cb_tcp`, `v5_membership_beacon_caw`, when the installed view
holds more than one member), not only when a hot path happens to observe two
members through `is_single_node`. The ownership/freshness/publication sites in
the overlay (`mxfs_dlm_ilock_begin` bypass and the paired `ilock_end` gate,
`grant_local_new` and `rearm_unpublished`, the iget stale-shell reloads,
`publish_dirs_work`, `publish_inode`) key on `never_multi`, so a sole survivor
takes real grants from the master (itself) and runs the multi-node protocol
unchanged; the 0.72.2 inline `P-SURVIVOR-RELOAD` in the bypass is gone with
it (the slow path services pending invalidations). Why: the D-0955 fix that
merely enabled `mxfs_submit_partial_inode_write` for a survivor stranded its
own new directory at NL (design record `docs/sole-survivor-sweep.md`, "The
third predicate"). Ledger: D-0955.

## 0.73.3 — the TCP death checker idles interruptibly

`v5_tcp_death_worker_fn` ticked with the plain `mxfs_pal_sleep_ms(500)`
(msleep, TASK_UNINTERRUPTIBLE): a permanent D-state `mxfs-worker`, +1 load
average on every TCP node at idle, and the `precond_readiness` D-state probe
failing on every 2/tcp board. Rule, already in `pal/pal.h` since sess381:
every always-on worker's idle wait is `mxfs_pal_sleep_ms_interruptible`; the
plain sleep is for short in-operation backoffs only. The fence-retry worker
and the disklock claim scanner followed it; this thread exists only on TCP,
so no CAW board ever caught it.

## 0.74.0 — bounded fence retry: RECOVERY_BLOCKED (D-FENCE-PRECOMMAND-RETRY-UNBOUNDED-NO-BLOCKED-STATE-0904)

Design: `docs/dlm-protocol.md` "Recovery blocked on unprovable exclusion".
Public surface added:

- `v5_mount.c`: `fence_retry[slot]` gains `blocked`, `series_ms`, `last_kind`;
  `ctx->recovery_blocked_n` (atomic count, the O(1) gate).
  `v5_fence_retry_arm(ctx, slot, victim, epoch, nonproving, kind)` returns 1
  on the transition; only the PRECOMMAND unproven arm passes `nonproving`.
  Blocked slots re-drive every `V5_FENCE_BLOCKED_REDRIVE_MS` (30 s).
  `v5_fence_retry_disarm` ends the state (`P238-FENCE-UNBLOCKED`).
  Module params (defined here): `fence_blocked_after_ms` (120000, 0 =
  never), `fence_gate_inject_refuse` (TEST ONLY: refuse the sole-survivor
  gate so the absent-key attempt stays non-proving).
  `v5_single_node_fence_gate` used to read `opts->single_node_exclusive_live`
  (a pointer to the pal parameter) so the operator assertion worked without a
  remount. **Removed in 0.89.18** together with
  `v5_fence_kind_contradicts_single_node`: the assertion gated minting fence
  kind 17, which is revoked, so both predicates lost their only caller. The
  `single_node_exclusive_live` pointer is still carried, but nothing
  authorises anything from it.
- `v5_mount.h`: `MXFS_RBLK_FENCE_BLOCKED` (16);
  `mxfs_v5_dlm_any_recovery_blocked(ctx)` (0.75.33: true while
  `recovery_blocked_n > 0` OR `recovery_refused_n > 0` — it must agree with
  `node_recovery_blocked`, which has counted refused victims since 0.75.25;
  the mismatch was D-0915),
  `mxfs_v5_dlm_node_recovery_blocked(ctx, node)`,
  `mxfs_v5_dlm_inode_held_by_blocked(ctx, ino)` (TCP only; CAW answers 0);
  `mxfs_v5_dlm_opts.single_node_exclusive_live`.
- `disklock.h/.c`: `MXFS_RECOV_F_FENCE_BLOCKED` (0x40) on the FENCING
  descriptor; `mxfs_disklock_recovery_fence_mark_blocked(ctx, slot, auth)`
  (idempotent CAS under the attempt lease, `P304-FENCE-BLOCKED-DURABLE`);
  cleared by `fence_certify` and by the FENCING branch of `fence_takeover`.
- `dlm.h/.c`: `ctx->recovery_blocked_cb(cb_data, node)` (set by v5 next to
  `slot_node_cb`); the local timeout arm returns `-EHOSTDOWN` when a GRANTED
  holder is blocked (`P-RBLK-DENY-LOCAL`); `process_remote_request` denies
  `MXFS_ERR_RECOVERY_BLOCKED` (`P-RBLK-DENY-MASTER`), mapped to `-EHOSTDOWN`
  by the requester (`P-RBLK-DENY-REMOTE`);
  `mxfs_dlm_resource_held_by_blocked(ctx, res)` for the xfs gates (local
  master only).
- `mxfs_common.h`: `MXFS_ERR_RECOVERY_BLOCKED` appended to `enum mxfs_error`.
- xfs side (`xfs.md`): `mxfs_recovery_blocked_covers_ino(mp, ino)`,
  `P240-RBLK-REFUSE` at `mxfs_dlm_ilock_begin`, `P240-RBLK-EIO-ABORT` in the
  timeout classifier (before the quarantine arm), `-EIO` from
  `mxfs_inode_incarn_estale`, debugfs ACTION text for `FENCE_BLOCKED`.

### 0.75.28 — the live-holder oracle (D-ACQUIRE-TIMEOUT-BEHIND-LIVE-HOLDER-FAILSTOPS-REQUESTER-0912)

- `dlm.h/.c`: `ctx->node_live_cb(cb_data, node)` (set by v5 right after
  `cb_data`); `mxfs_dlm_resource_wait_is_live(ctx, res)` — 1 when the remote
  master is live, or the local master has ≥1 GRANTED holder and every remote
  holder is live; 0 for "no holder" (a real coordination failure) or a dead /
  blocked / refused party or no oracle.
- `dlm_caw.c/.h`: `caw_count_resource_slots` gained `holders_all_or` (every
  holder class OR'd over the probe chain);
  `mxfs_dlm_caw_resource_holders_live(ctx, res)` = holders (our bit excluded)
  all pass `holders_alive_fn` (the same disklock heartbeat oracle the
  120 s→480 s wait extension uses).
- `v5_mount.c/.h`: `v5_node_live_cb` = self, or lease valid ∧ not dead-noted ∧
  recovery not blocked/refused; `mxfs_v5_dlm_inode_wait_is_live(ctx, ino)`
  dispatches by transport (withdrawn mount → 0).
- xfs side: `mxfs_dlm_ilock_begin` arm (2b) between the pending-recovery park
  and the fail-fast shutdown: `rc == -ETIMEDOUT && !shutdown && wait_is_live`
  → `P-LKWAIT-LIVE ino mode laps beyond_budget_s` + backoff park + restart.
  A requester no longer fail-stops because a live peer's release outlasts
  the 180 s TCP budget (measured s517g: 184 s wait → SHUTDOWN_CORRUPT_INCORE
  → withdraw → fenced, holder released 140 s later).  Closure harness
  `tests/live_holder_wait.sh`.

Known open leg: a non-prover master on 3+ nodes does not import the durable
flag, so its remote waiters park as before.

## 0.75.0 — transport conformance (sess507)

The DLM transport is a property of the cluster on the platter. Public
surface:

- `disklock.h`: `MXFS_HB_FEAT_TCP` (0x0008) in `struct mxfs_hb_feature
  .feat_flags`; `struct mxfs_disklock_ctx.transport_tcp` +
  `mxfs_disklock_set_transport_tcp(ctx, bool)` (refused once `local_slot >=
  0`, like snlocal — write-time provenance, stamped by `hb_feature_fill` on
  every record); `struct mxfs_disklock_transport_census {n_tcp, n_caw,
  n_unknown, first_tcp, first_caw}` + `mxfs_disklock_scan_transport(dev,
  base_offset, fs_gen, &census)` — standalone (no ctx), reads the 64
  records with plain `mxfs_pal_bdev_read`, ACTIVE/WITHDRAWN records of the
  given `fs_gen` with a VALID feature block vote; fails closed on a read
  error.
- `disklock.c`: `hb_transport_mismatch(ctx, hb)`; `MXFS_HBFEAT_TRANSPORT`
  (4) as a join-gate / monitor state beside legacy/mismatch/corrupt — a
  live record on the other transport makes `mxfs_disklock_join_gate` return
  `-EPROTO` (`P-VERGATE-JOIN ... state=4`) and the monitor's per-pass
  version check fence it (`P-VERGATE ... state=4`).
- `v5_mount.c` `mxfs_v5_dlm_init`: the census runs right after the device
  wrap and BEFORE the transport branches. Rules: no votes → selection as
  before; TCP votes + default modargs → `ctx->transport = TCP`
  (`P-TRANSPORT-ADOPTED`); CAW votes + `force_transport=1` →
  `P-TRANSPORT-MISMATCH-REFUSED`; both → `P-TRANSPORT-MIXED-REFUSED`;
  unreadable → `P-TRANSPORT-SCAN-FAIL`; otherwise `P-TRANSPORT-CONFORMED`.
  Refusals unwind through the new `err_dev:` label (only the device is
  wrapped at that point). Both claim sites call
  `mxfs_disklock_set_transport_tcp` next to `set_snlocal`.
  `v5_discovery_peer_cb` drops an announce whose `dlm_transport` differs
  from ours (`P-TRANSPORT-MISMATCH-PEER`, ratelimited) before any lease /
  peer registration.
- `mxfs_super.h`: `MXFS_PROTO_GEN` 18 → 19 (a clear bit on an older
  build's record would vote CAW beside a live TCP node).

Design: `docs/dlm-protocol.md` "Transport conformance at mount". Harness:
`tests/transport_conformance.sh`. Pitfall that produced the defect: the
listen-then-adopt logic in `dlm/mount.c` is USERSPACE and never ran in the
module; `xfs_super.c` always passed `transport = CAW`.

## 0.75.1-0.75.3 (sess509, 2026-09-04) — departures off the heartbeat thread; TCP same-boot remount

- **Whole-ledger passes never run on the heartbeat thread.**  A departed
  peer costs three ledger passes (owner purge, table purge, page takeover);
  on the QNAP LUN (26426 pages) each is ~4 s.  0.75.1/0.75.2 made both
  ledger passes bulk candidate scans (`mxfs_tauth_ledger_scan_auth`,
  `tauth_purge_scan_page` in `dlm/tauth_ledger.c`, both copies via
  `mxfs_tauth_store_scan`) and moved the trio to a departure worker in
  `dlm/v5_mount.c` (`v5_depart_queue` / `v5_depart_worker_fn` /
  `v5_depart_run`, probe `P-DEPART-WORK ... purge_ms= takeover_ms=`,
  `P-DEPART-COALESCED` for a queued or in-flight duplicate).  Callers:
  GOODBYE (peer receive thread), `v5_clean_depart_cb` and
  `v5_recovered_cb` (heartbeat thread).  The recovery-complete ladder
  (`mxfs_v5_dlm_recovery_complete`) keeps its synchronous trio: its
  held-failure gate needs the purge result.  Stop is bounded 30 s
  (`V5_DEPART_JOIN_MS`), quarantines like the retire worker, and runs in
  `v5_tcp_transport_unwind` and `mxfs_v5_dlm_shutdown` before
  `mxfs_dlm_destroy`.  Measured before: `P-HB-MONSLOW monitor_ms=48821`
  (0.75.0), 18636 (0.75.1); after 0.75.2: zero stalls, and the departing
  peer's own unmount stays CLEAN (its put_super SB-summary lock had been
  exhausting the 60 x 100 ms retry budget, `why[prepare=60]`, parked on a
  page PREPARED for its earlier incarnation).
- **The lock retry budget is 6 s** (`dlm.c` ~4427: 60 retries, 100 ms).
  Any membership callback longer than that turns a peer's clean unmount
  into a DIRTY departure (`P-SB-SEAL-DIRTY-DEPARTURE`,
  `P277-SLOT-RETAINED-UNMOUNT-DIRTY`, key retained) — which then votes as
  an unrecovered TCP tenure in the next transport census.
- **TCP mounts run the same-boot sequence (0.75.3).**  `mxfs_v5_dlm_init`'s
  TCP branch (`return ctx` before the CAW section) had none of the CAW
  branch's sess451/452 sequence: no `mxfs_v5_dlm_departure_lock`, no
  quarantine reap, no `v5_self_succeed` on -EEXIST, no
  `v5_same_boot_scan` (so `p305_retire_mask` stayed 0 and
  `v5_p305_settle_retire_pending` never ran), and the retire machinery was
  wired only AFTER `mxfs_disklock_claim_slot`.  Consequence: any same-boot
  remount that beat the peer's settle (or the last leaver, always) reused
  its PR key, skipped its own RETIRE_PENDING slot
  (`P274-CLAIM-RETIRE-PENDING-SKIP`), saw its own key PRESENT forever
  (`P-ADMIT-RETIRE-PENDING-HELD`, `NOT replayed (-61)` rounds,
  `P-PR-SETTLE-UNHELD` from the mount pid each round) and the mount failed
  after 36-100 s; every later mount by either node hung on that slot.
  Ported in 0.75.3, in the CAW order, with the retire machinery before
  the claim.  The immediate settle (`v5_disklock_settle_absent`
  `immediate=1`) now takes the host-wide departure mutex itself when the
  caller does not hold it.  Harness: `tests/sameboot_remount.sh` (last
  leaver remounts first; lone-node cycles); chain
  `tests/sess509_chain_sameboot.sh`.
- **A RETIRE_PENDING record with a key the CAW bootstrap scan cannot
  classify** reads as `P-BOOT-SCAN-FROZEN ... noident=1` /
  `P-BOOT-KEY-UNCLASSIFIED` after 64 s and refuses the mount — seen once
  (s509b arm B) behind a failed rejoin that left its key registered; not
  yet its own record.
- **Ledger size is a device-size function**, not a node-count one:
  `tools/mkfs_mxfs.c tauth_npages_for_device` = one entry per 64 KiB of
  device (26426 pages on a 50 GiB LUN); `-t ENTRIES` overrides.  Every
  membership-change pass scales with it.
- **`DLM init:` prints twice** since 0.75.2: `requested_transport=` before
  the census, `transport=` (effective) after it — a harness must read the
  second.

## sess514 (2026-09-05, 0.75.15-0.75.16) — a clean departure releases its remaining grants (D-0908)

**Why:** `mxfs_dlm_release_all` (dlm.c ~5663, called from `mxfs_v5_dlm_shutdown`
before the GOODBYE and before `xfs_unmountfs`) freed every table entry this node
owned WITHOUT a wire release, leaving them to the peers' departure purge.
Measured on 0.75.15 (rejoin_residue s514a, every clean leave): exactly two PR
grants left — ino=128 (root) and ino=131 — one mastered by the peer, one by the
departing node itself (its page is then handed off with the bit still set).
The peer's purge cleared NOTHING (`P-TAUTH-PURGE ... cleared=0 cand=0`) because
a successor had already claimed the departed slot when it ran, which drops the
slot half (`P-TAUTH-PURGE-SLOT-LIVE`, 0.75.8); the bit stayed on the platter
until the successor imported it on its own slot (`P-TAUTH-IMPORT-RESIDUE`,
0.75.5 release) or a master attributed it to the successor (the 0908 shape A:
blocked-upgrade refusal on the successor's first EX, healed by the 0.75.12
P109 arm). AG grants were already published earlier in the unmount
(`xfs_super.c` `mxfs_dlm_ag_force_release_all`); inode grants were not.

**Change:** `dlm_wire_release_all()` (static, dlm.c: the collect-under-rdlock /
`mxfs_dlm_unlock`-outside-the-lock walk that was `mxfs_dlm_withdraw_release_all`,
which now wraps it) runs in `mxfs_dlm_release_all` after the existing 3 s ack
wait when anything is held; a second `mxfs_dlm_wait_release_acks(3000)` follows.
Probes: `P-RELALL-LEFT node= held= pr= ex= other=` + up to 12
`P-RELALL-LEFT-ENTRY type= ino= ag= mode= state= master=` (the census, always),
then `P-RELALL-WIRED node= released= ack_rc= held_after=` (the fix) or
`P-RELALL-UNWIRED` (knob off). DEBUG knob `depart_wire_release` (v5_mount.c,
default 1; user-mode `#define 1` in dlm.c) restores the pre-0.75.16 shape so
the planted phantom lap (rejoin_residue arm 4) can still be run. Death
departures are unchanged: the elected replayer's recovery-complete purge is
synchronous and the slot is republished only after it (v5_mount.c ~10487).

**Invariant this restores:** after a CLEAN departure no ledger page carries a
record of the departed incarnation, so the purge is a backstop (death, unacked
release), never the mechanism a successor's admission races.

**0.75.17 follow-up:** the RELEASE_ACK for the departure's own releases was
dropped by `v5_peer_msg_cb_tcp`'s teardown quiesce (v5_mount.c ~1124: once
`ctx->mounted` clears only NODE_LEAVE passed), so every clean leave sat the
whole 3 s ack bound (`P-TAUTH-RELEASE-WAIT unacked=1 after 3000ms`,
`P-RELALL-WIRED ... ack_rc=1`). `MXFS_MSG_LOCK_RELEASE_ACK` now passes the
quiesce (it only retires a pending-release record); measured s514c: ack_rc=0
on every leave. `P-TAUTH-RELEASE-WAIT-ENTRY type= ino= ag= rel_id= sends=
master=` names what is still unacked when the wait does time out.

## sess514 (0.75.18) — hand-off target re-read after the freeze drain (D-0909)

`mxfs_dlm_handoff_tick` computes a page's owner (`dlm_page_owner`: id-sorted
DLM active list, page % N) and calls `dlm_page_hand_to`, whose
`dlm_page_freeze_drain` can wait up to 3 s. A GOODBYE processed in that
window (`mxfs_dlm_update_active_nodes` swaps the list, then sets the new
ledger config id) left the tick preparing the page to the departed
incarnation under the NEW config (s514d: `P-TAUTH-PREPARED page=16642 ...
target=<departed> cfg=<new view>` right after `MXFS-MEMBERSHIP
active_count=1`); the successor's AG 0 request parked on it (`why[prepare=60]`)
until the purge-driven `P-TAUTH-RETARGET` 13 s later. Now `dlm_page_hand_to`
re-reads the owner and `dlm_node_in_view` just before the ledger prepare and
refuses a stale target (`P-TAUTH-HANDOFF-STALE-TARGET`, counter
`handoff_stale_targets`, page stays FROZEN, `handoff_scan` re-armed), and the
tick's retarget branch also fires for a PREPARED target that is not in view
(not only a recovery-purged one). Harness: rejoin_residue armed arms assert
zero `P-TAUTH-HANDOFF ... to=<goodbye id> why=view-change` on A.

**0.75.19 correction:** the 0.75.18 re-check used `dlm_page_owner` for every
caller; `mxfs_dlm_handoff_depart` maps its pages over the view WITHOUT the
departing node, so the check refused every depart hand-off (s514g/h/i:
`P-TAUTH-HANDOFF-STALE-TARGET ... why=depart` on every leave, `pages_left=1`,
successor rejoins 14 s parked on the stranded page). `dlm_page_hand_to` now
takes `bool departing`: a departing node requires only `dlm_node_in_view(target)`;
the owner-equality re-check applies to the view-change pass alone.

## sess515 (0.75.20) — the departing flag: the real D-0909 mechanism

The 0.75.18/19 re-checks narrowed a window that was never a ledger race. A
clean departure hands its pages out BEFORE its goodbye over the view without
itself; the survivor's view still names the departer as those pages' owner
until the goodbye lands, so `mxfs_dlm_process_page_handoff` FROZEN treated
each hand-off as a non-serving RELAY (owner != local: activate, FROZEN,
`handoff_scan`) and `mxfs_dlm_handoff_tick` (500 ms) handed the page straight
back to the departer (s514k: `ACTIVATE seq=19`, `GOODBYE-RX`, `PREPARED seq=20
target=<departer>` — the tick landed in the tens-of-ms hand-off..goodbye
window, ~1 in 12). Fix: `MXFS_HANDOFF_F_DEPARTING` in the hand-off message's
former pad byte (size and proto gen unchanged), set on every FROZEN while
`ctx->departing` (set by `mxfs_dlm_handoff_depart`). The receiver records the
sender in `ctx->departing_nodes[]` (`P-TAUTH-DEPARTING-RX`, under
`active_nodes.lock`, pruned in `mxfs_dlm_update_active_nodes`) and hand-off
routing uses `dlm_page_handoff_owner` = the view WITHOUT departing members
(the departer's own mapping) in the FROZEN serve-vs-relay decision, the tick,
and `dlm_page_hand_to`'s re-check (a departing target = stale). Request
routing (`dlm_page_owner` / `mxfs_dlm_resource_master`) is unchanged until
the goodbye. With 3+ nodes a survivor learns of the departure only from a
hand-off addressed to it; the not-in-view retarget stays as the backstop.
Verified s515a/b/c: 24 armed departures, zero hand-offs to the departer.

## sess515 (0.75.21-0.75.22) — RECOVERY_BLOCKED: a dead MASTER, not only a dead holder

A dead member stays in the view until its recovery completes, so under
RECOVERY_BLOCKED it still masters page % N resources. Three places had to
learn that: (1) 0.75.19 `dlm_lock_impl` remote path asks
`recovery_blocked_cb(master)` before the send (`P-RBLK-DENY-DEAD-MASTER`,
-EHOSTDOWN → `P240-RBLK-EIO-ABORT`, which is a VOID return from
`mxfs_dlm_ilock_begin` — the op proceeds without a grant unless an entry gate
stops it); (2) 0.75.21 `mxfs_dlm_resource_held_by_blocked` (behind
`mxfs_recovery_blocked_covers_ino` → `mxfs_inode_incarn_estale` /
`mxfs_quar_gate_op`) answers 1 for a resource mastered by the blocked node
(`P-RBLK-COVERS-DEAD-MASTER`) — before that a stat served cached attributes
rc=0 after its acquire was refused; (3) 0.75.22 `mxfs_dlm_unlock_gen` remote
path skips the LOCK_RELEASE send and the pending-ACK entry for such a master
(`P-RBLK-RELEASE-SKIP-DEAD-MASTER`) — the survivor's umount spent 8 s in
`dlm_wire_release_all` (3 sends × 100 ms per grant + `mxfs_dlm_wait_release_acks`
3 s). `P240-QUAR-NSOP-REFUSE` now prints `incarn_stale= rblk= quar_flag=
quar_map=` so the refusing predicate is named. Arm:
`tests/sess507_chain_0750.sh <label> 1,11` (umount rc=0 in 3 s on 0.75.22).

## sess516 (0.75.23-0.75.25) — a SEALED / terminally REFUSED dead master

After a refused foreign replay the victim keeps its lease membership (the
refusal path never unregisters it: `v5_refresh_active_nodes` keeps dead
members until `v5_recovery_complete`, and a refusal is terminal until
remount), so it masters its page share for the life of every survivor's
mount. (1) 0.75.23 `mxfs_dlm_unlock_gen` also skips the release send for a
SEALED master (`dlm_master_sealed`, table-locked read of `sealed_owners`;
the skip line prints `blocked=/sealed=`). (2) 0.75.25 the ACQUIRE side: the
xfs quarantine import chokepoint (`mxfs_quarantine_import_oc`) calls
`mxfs_v5_dlm_recovery_refused(ctx, slot, victim)` (victim 0 = resolve from
`blocked[slot]` / `fence_retry[slot]`), which records `refused_victim[slot]`
+ `recovery_refused_n` (`P-RBLK-TERMINAL`) and makes
`mxfs_v5_dlm_node_recovery_blocked` answer 1 for that node — so every
`recovery_blocked_cb(master)` gate (acquire pre-send, release skip, the xfs
covers-ino gates) fails fast for it. "Sealed" alone is NOT the predicate: a
node is sealed at the fence, before its verdict, and requests to it must
keep parking (`P240-QUAR-PARK`) until replay completes. Measured s516a on
0.75.24: the survivor's umount under a fswide quarantine sent the final SB
summary lock request to the sealed master 60 times over 42 s
(`mxfs_sb_summary_lock` → `mxfs_dlm_lock_retries`), rc=-107, then the
DIRTY departure it takes anyway (`P-SB-SUMMARY-FINAL-FAIL`, slot retained).
Open consequence for AG-MASK refusals: D-0910 (out-of-mask resources the
dead node masters are EIO, 1/N of the namespace on TCP).

### 0.75.30 — a refused victim LEAVES the view (D-0910)

Measured s518i (2/tcp, AG-mask verdict sparing AG 0): the survivor could not
create at the root at all — 8/8 mkdir TIMEOUT, 68 `P-RBLK-DENY-DEAD-MASTER`
for the new inodes 173-180 whose pages the refused dead node still
mastered. Fix: `mxfs_v5_dlm_recovery_refused(ctx, slot, victim, victim_inc,
fswide, ag_mask)` (caller `mxfs_quarantine_import_oc`) now, on the FIRST
refusal for a slot, stores `refused_fswide[slot]`/`refused_ag_mask[slot]`,
dead-notes the victim, `mxfs_lease_unregister_node`, `v5_refresh_active_nodes`
(remaster) and queues a `refused` departure (`v5_depart_req.refused`).
`v5_depart_run` then runs the SELECTIVE trio: unless fswide,
`mxfs_dlm_ledger_purge_owner_selective` + `mxfs_dlm_purge_node_selective`
(`dlm_purge_node_impl(selective=true)`: no unseal, keeps in-domain entries),
then `v5_handoff_takeover`. The DLM asks the mount layer through
`ctx->refused_owner_cb` (`v5_refused_owner_cb`): res==NULL → "is owner
refused" (+slot); res!=NULL → "keep this record frozen" = fswide, other
volume, or `closure_classify_fn(res, ag_mask) <= 0` (not provably outside
the mask). Ledger side: `mxfs_tauth_ledger_purge_owner_keep` /
`_purge_owner_page_keep` take an `mxfs_tauth_purge_keep_fn`; `P-TAUTH-PURGE`
prints `selective= kept_total=`. `dlm_takeover_page` activation purges a
refused owner selectively BY NODE ID AND HB SLOT (its shared bits on
out-of-mask resources would otherwise import as blockers and deny), then
imports the kept records as frozen blockers; `dlm_page_departed_authority`
never marks a refused authority purged (`P-TAUTH-REFUSED-AUTH`).
`v5_bootstrap_ready` treats a refused lower slot as resolved so the
higher-slot survivor can be the takeover's bootstrap node. Invariants: the
selective purge is NEVER registered in `purge_pending` (the re-drive path is
the unconditional purge and would retire in-domain grants); the refused
victim stays sealed and `recovery_blocked_cb` still answers 1 for it, so
its frozen blockers deny fast (`P-RBLK-DENY-MASTER`). Lines:
`P-RBLK-TERMINAL ... inc= fswide= ag_mask=`, `P-DEPART-REFUSED`,
`P-TAUTH-PURGE-SELECTIVE`, `P-TAUTH-TAKEOVER-RETIRE ... kept= refused=`.

## 0.75.65 (sess545, 2026-09-08) — departure purge from the page cache; 512 KiB scan runs (D-0925)

Measured on 0.75.64 (`P-DEPART-WORK`): a departed peer's purge read both
copies of the whole ledger region (26426 pages, 206 MiB, 64 KiB runs, ~50
MiB/s) for cand=0..5 — `purge_ms` 3969..4568 on every departure — and the
takeover scan read it again (`scan_ms` 3975..4371).  The last node's unmount
sat in `v5_depart_worker_stop`'s join behind both (4525..4776 ms).
`mxfs_tauth_ledger_purge_owner_keep` (tauth_ledger.c) now builds its candidate
bitmap by walking `l->pages[p]` under `pg->lock` and classifying the CACHED
image with the same `tauth_purge_scan_page`; no platter read.  INVARIANT it
rests on: the only writers of a page's authority state are
`mxfs_tauth_ledger_activate`, `_prepare` and `_prepare_unowned`, all through
`lpage_write_fresh_locked`, which installs the written image in `pg->img`;
commits memcpy into `pg->img`.  So a page ACTIVE(self) on the platter is
always in this node's cache.  Fail-closed arms: `pg->poisoned` and the new
`pg->dropped` (`mxfs_tauth_lpage`, set by `lpage_load_locked` when a HELD
image fails to reload, cleared on a successful load) keep the page a
candidate so `tauth_purge_page` ensures/reconciles it as the platter pass did
for an unreadable page.  `mxfs_tauth_store_scan` (tauth_store.c):
`TAUTH_SCAN_RUN_PAGES` 16 -> 128 (512 KiB = the LUN's `max_sectors_kb`; a
larger READ(16) is refused and would drop the run to single pages), ladder
128/32/16 via `mxfs_pal_alloc_io`, then the one-page fallback; `rca/rcb` are
heap-allocated.  Measured on 0.75.65: purge 1 ms, last-out unmount 817 ms,
concurrent 569/849 ms, death-lap survivor purge cleared=165 over cand=164 in
2 ms (records still found from the cache), takeover scan 2399 ms.  NOTE the
concurrent (both-leaving) shape never runs the takeover
(`mxfs_dlm_handoff_takeover` -EPERM: not the bootstrap node); only the serial
last-out and the death shapes scan.

**0.75.66 (D-0925 mechanism 2):** the concurrent unmount's LOCK_RELEASE drop
at the tearing-down master.  `v5_peer_msg_cb_tcp`'s quiesce now passes
`MXFS_MSG_LOCK_RELEASE` as well as NODE_LEAVE + RELEASE_ACK:
`mxfs_dlm_process_remote_release` commits on the ledger (open until
`mxfs_dlm_destroy`, which is after `mxfs_peer_shutdown` joins the recv
thread), a page `handoff_depart` already PREPARED gets `-EAGAIN` from
`dlm_ledger_prepare` -> REMASTER ack -> the releaser's tick re-routes
(`sent_ms=0`, immediate resend), and the only XFS re-entry a promotion could
cause — a post-promotion BAST to a LOCAL holder via `v5_bast_cb_tcp` — is
dropped once `!ctx->mounted` (`mp->m_mxfs_dlm` is already NULL at that
point; the inode notify path would iget on a superblock being put).
Reproducer/workload: `tests/cross_grant_workload.sh` (300 creates per node +
peer stats = ~300 live grants each, half peer-mastered) under
`tests/unload_laps.sh ... parallel`.  Unfixed baseline
(`unload_laps_s552base.log`): released=237-303, teardown_drops=680-916,
unacked=102-160 after 3000 ms, umount 5.1-7.7 s.  Same laps found D-0926
(kernel PAL TCP send without MSG_NOSIGNAL -> umount killed by SIGPIPE, rc 141,
when the peer's socket closed first).

**0.75.70 (D-0928, crash leftovers never declared dead):** the heartbeat
monitor's `check_dead` fired only for a slot it had once seen live
(`nt->live`), so an ACTIVE record already frozen at first sight
(auto-monitored via `P-EVICT-AUTOMON`, `changed_samples` never reaching
`MXFS_DISKLOCK_LIVE_THRESHOLD`) was monitored forever and never fenced or
recovered; the TCP mount gate's "crash leftovers; monitor will evict"
(`P-MEMB-GATE-GHOSTS`) was therefore a promise nothing kept (the CAW branch's
step 6.5 `P225-STALE-DEFERRED` / `mxfs_v5_dlm_mount_settle` routing has no TCP
counterpart).  Consequence: no lower slot resolved, `v5_bootstrap_ready` false
on every node, every page takeover and the 0.75.69 orphan sweep `-EPERM`, all
page requests parked.  Now `check_dead` fires when
`equal_samples >= dead_threshold && (live || last_timestamp != 0)` (same FUA
confirm; a recovery-pending slot never re-fires); `P-HB-GHOST-DEAD` names it.
`tools/disklock_hb_dump.py <dev> [offset]` reads the 64 records with plain
pread (the QNAP refuses `recov_forge dump`'s READ(16) FUA, sense 05/24/00).
Harness `tests/ghost_slot_restart_probe.sh`.

**0.75.71 (D-0929, fence kind 21 `MXFS_FENCE_KIND_BOOT_SUCCESSION_ABSENT`):**
on a target that purges registrations with the session, a dead previous-boot
incarnation has no key to PREEMPT, no self-succession record (the plain
REGISTER succeeded) and, with two live members, no sole-survivor gate: every
attempt was `KEY_ABSENT_UNPROVEN` → `P238-FENCE-BLOCKED`.  Prover arm
`v5_boot_succession_consume` (after `v5_self_succession_consume`):
`mxfs_disklock_victim_identity` (frozen host/boot) →
`mxfs_disklock_host_live_other_boot(ctx, host, boot, &node, &slot)` (own
identity, or a monitored slot with `node_track.live` whose `ident_obs` carries
the host under another boot) → `mxfs_disklock_boot_advancing(ctx, boot,
&advancing, &records)` (64-slot double read 2.5 s apart; any record with that
boot_uuid advancing refuses, `P238-BOOT-ADVANCING`) →
`mxfs_scsipr_exclusion_holds` (WE form excluding non-registrants held, own key
present, view complete, victim absent) → kind 21 with the observed resv_type
(`mxfs_fence_kind_resv_type_ok` requires a non-registrant-excluding type on
read).  Probes `P238-FENCE-BOOT-SUCCESSION`, refusals
`P238-BOOTSUCC-{NOIDENT,HOST-NOT-LIVE,BOOT-ADVANCING,TABLE}`.  The ledger
entry is marked FENCED after certification like kinds 16/19/20.  Exclusion
argument: boot boundary (the OS instance is gone from its host) + the
reservation refusing the unregistered new session + the code never
auto-re-registering a lost key (`P-PR-OWNKEY-GONE`).  With N=2 every dead
incarnation is either the peer-while-alone (kind 20) or a previous boot of one
of the two hosts (kind 21).

**0.75.74 (D-0932, a certified incarnation was never REVOKED on the ordinary
path):** `v5_incarnation_state`'s exact-incarnation dead set (`dead_incs`,
`v5_note_dead_inc`, `P-DEAD-INC`) was populated only by the bootstrap paths
(`v5_bootstrap_takeover_run`, the ladder's bootstrap block), so a prover that
died holding FENCING attempts kept them forever on every node
(`P236-CLAIM-UNCERTIFIED stage=1 kind=0` per slot per round; s561/s562).  Now
noted at: fence certify success (`v5_pr_fence_prove_locked` after
`mxfs_disklock_recovery_fence_certify`), a claim that read a certificate
(`mxfs_v5_dlm_recovery_acquire`: `mxfs_disklock_recovery_claim` checks the
certificate BEFORE ownership, so a stage return or `-EBUSY` proves it),
`v5_recovery_complete_ladder` next to `v5_note_dead_node`, and
`v5_recovered_cb` (peer watched the slot zero; epoch =
`node_track[slot].last_epoch`, as `v5_depart_queue` uses).  Instrumentation:
`P238-FENCE-HOLDER-STATE` (ratelimited) prints the holder tuple, holder_slot
and the state/why whenever a FENCING/SNAPSHOTTING attempt is NOT taken over.

**0.75.75 (D-0932 second gap, `v5_holder_slot_state`):** once a prover's own
recovery is published its record is ALL-ZERO (`mxfs_disklock_purge_node`
CAS-writes a 512 B zero buffer), so a later boot has no in-memory route to
REVOKED (`'node not in the heartbeat table'` x51-54 per slot per node, s563).
The takeover arms of `mxfs_v5_dlm_recovery_acquire` (-EPERM: attempt/snapshot
holder; -EBUSY: execution owner) now fall back, when `v5_incarnation_state`
is UNKNOWN, to a platter read of `desc.owner_slot`
(`mxfs_disklock_read_record`): all-zero, another `{node, epoch}`, or EMPTY
under the holder's own tuple ⇒ REVOKED (`P238-FENCE-HOLDER-SLOT
verdict=REVOKED`); the holder's record still standing under any flag,
unreadable, unrecognised magic, bootstrap holder (`MXFS_RECOV_F_OWNER_BOOTSTRAP`,
no slot) or `owner_node != holder` ⇒ UNKNOWN.  INVARIANT this rests on: a
slot's record changes tenant only through a terminal event for the tenancy it
carried (release → EMPTY/RETIRE_PENDING; published recovery → zero; a claim
needs EMPTY/zero first).  Anything that ever rewrites a live incarnation's
record with another tuple, or zeroes a record outside the published-recovery
purge, breaks this proof — do not add such a writer.  0.84.23: "all-zero"
is the whole 512-byte sector (`v5_hb_record_is_zero`), and a non-zero
sector without the disklock magic, or with a feature block that is neither
the pre-gate zero tail nor `MXFS_HB_FEAT_MAGIC` (`v5_hb_record_well_formed`),
leaves the verdict UNKNOWN naming the slot — before that the scan skipped it
and a torn holder record read as "no record carries the tuple" = REVOKED.
Reachability on two nodes: never inside the episode that publishes the
holder (certificate → takeover in the same replay round → purge 20 s later,
s581a); node ids are random per mount (`node_uuid`, v5_mount.c ~12859) so a
later mount has ONLY the platter.  Staged with the test knob
`dbg_fence_takeover_decline` (declines the takeover after REVOKED,
`P238-FENCE-TAKEOVER-DECLINED`; the holder's own recovery still publishes;
the mount aborts) and judged by a fresh mount: `tests/d0932_platter_fallback.sh`.
Design: `docs/whole-cluster-restart.md` §7.  Pitfall: the ledger
validator takes the LOCAL date (CDT); a record stamped with the UTC date
after 19:00 CDT is 'in the future' and the write is refused.

**0.75.76 (D-0933, no frozen victim key for a victim found dead at
admission):** `mxfs_v5_dlm_mount_pending_recovery` marked GUARD/WITHDRAWN
records pending with the plain `mxfs_disklock_mark_recovery_pending` — no key
— because the only key freezers were `hb_ident_freeze_victim` (fire_dead, a
death THIS node watched) and the bootstrap manifest
(`mark_recovery_pending_ident`).  After a fence-attempt takeover the new
prover then refused to lay an intent (`P-PRKEY-FENCE-REFUSED`, s564 x36).  New
`v5_mark_pending_from_record` reads the record and freezes
`ident.pr_key/key_gen/host/boot` via `mark_recovery_pending_ident`
(`P-ADMIT-VICTIM-FROZEN`), else the plain mark + `P-ADMIT-VICTIM-UNFROZEN`.
Also: `mxfs_disklock_recovery_fence_takeover`'s third argument is the VICTIM
KEY written into `fence_victim_key`; the v5 caller passed `(uint64_t)dead_node`
(s564 platter: fence_key == victim node id).  Now passes
`mxfs_disklock_victim_key()` and refuses (`P238-FENCE-TAKEOVER-NOKEY`) when 0.

**0.75.77 (D-0933 continued, s565):** (a) `mxfs_hb_identity_valid` failed on
every guard ('identity block invalid'): the identity crc covers `flags`
(`hb_ident_crc(slot, flags, fs_gen, node, epoch, ident)`), the three guard
writers (disklock.c `flags = MXFS_DISKLOCK_FLAG_RECOVERY_GUARD` at ~5865,
~7706, ~11019) move flags WITHOUT `hb_ident_rebind`; only the retirement
paths re-bind.  `mxfs_hb_guard_identity_valid` (disklock.c/.h) validates a
guard's block under ACTIVE / WITHDRAWN / RETIRE_PENDING; everything else
unchanged.  PITFALL: any new reader of a guard's identity block must use it,
not `mxfs_hb_identity_valid`.  (b) `v5_holder_slot_state` required
`desc->owner_node == holder`; after a takeover whose prover unmounted the
descriptor reads owner=0 owner_slot=0 with the holder in `fence_prover_*`
(x280 'descriptor owner is not the holder being judged').  It now uses
owner_slot only when owner == holder, else a fresh 64-record platter scan for
the tuple; EMPTY or RETIRE_PENDING under the tuple (the writer's own final
image) or no record anywhere ⇒ REVOKED; still standing / any unreadable slot
⇒ UNKNOWN.  Log `P238-FENCE-HOLDER-SLOT` now prints desc_owner,
desc_owner_slot, found_slot.

## 0.75.114-0.75.115 (sess571, 2026-09-10) — the poison gate, asked at the choke point (D-0945)

### The invariant

An incarnation may release an on-disk grant only while no replay-eligible image
of that incarnation can still require it.  `MXFS_V5_DEPART_POISONED` — the log
shut down, the heartbeat slot WITHDRAWN, the PR key retained, a survivor still
to fence and replay this slice — means that can no longer be proven for *any*
grant, so every release must be refused and the grants stay held by the
withdrawn incarnation as the evidence a survivor's fence-time manifest is
sealed from.

### What was wrong (D-0945)

The gate is implemented at each of `v5_mount.c`'s release wrappers —
`v5_tcp_release_gate()` and `v5_caw_release_gate()`, called with a `what` string
("ino", "iclus", "ag", …).  Eight release primitives, and
`mxfs_v5_dlm_inode_unlock_free()` had it on its **CAW arm and nothing on its TCP
arm**.  A dirty-death inode free therefore surrendered a durable grant; the
survivor sealed a manifest not holding it and answered `notheld` to a **VALID**
token, which atomically skips the whole transaction and quarantines its AGs.

**Diagnostic signature to recognise:** `P-TCP-RELEASE-POISONED ag=0` and
`P52-GRANT-FREE ino=N` in the *same* victim log — one release refused, another
not — plus `P220-EPOCH-LEDGER-OPEN ino=N pend=…` naming that tenure as ending
with unlanded work.  A `notheld` verdict on a VALID token is never a producer
defect: the producer proved its authority and something destroyed the proof
before the seal, so the search is for a **release**, not for a capture.

### API added — `local_poisoned_cb` (dlm.h, dlm.c, v5_mount.c)

```c
int (*local_poisoned_cb)(void *data);   /* struct mxfs_dlm_ctx */
```

Registered in `v5_mount.c` beside `cb_data` and `node_live_cb` (**not** with the
ledger callbacks — a mount that never opens the authority ledger still releases
grants), backed by `v5_local_poisoned_cb()` -> `mxfs_v5_dlm_is_poisoned()`.

`dlm_note_release_while_poisoned()` uses it at the two primitives every release
funnels through — `mxfs_dlm_unlock_gen()` and
`mxfs_dlm_send_unconditional_release()` — printing

    P945-RELEASE-WHILE-POISONED fn=… type=… ino=… ag=… comm=… n=… caller=%pS

**It logs; it does not refuse.**  Whether a release while poisoned is a defect
depends on which path it is: `mxfs_dlm_caw_purge_node()` releases a DEAD PEER's
slots from a survivor — the opposite operation — and gating it would be a new
defect.  The refusals stay at the wrappers; this says where one is still owed.
Capped (first 64, then every 256th) and reachable only after a shutdown.

### Why the choke point and not another read of the callers

The wrapper-level gate is one gate per caller, so it is one gate to forget, and
a caller nobody thinks of has no missing gate to notice.  Reading is what missed
D-0945 for as long as it existed.  Full rationale and the general pattern:
ccmemory `technique-ask-the-invariant-at-the-choke-point-not-at-each-caller`.

### Release call sites outside `v5_mount.c` (the audit this instrument replaces)

- `dlm.c` `mxfs_dlm_unlock()` — thin `unlock_gen(…, 0)` wrapper; in-kernel
  callers are the TAUTH page-import **residue** release (`dlm.c` ~1959, releases
  *this* node's own residue records) and `dlm_wire_release_all()`.
- `dlm.c` `mxfs_dlm_release_orphan_if_unheld()` — sends an unconditional
  release; reached from `unlock_gen`'s own AG ENOENT arm.
- `mxfs_dlm_withdraw_release_all()` — **declared and defined, no caller.**
- `mxfs_dlm_release_all()` — the clean-departure path; correctly gated at
  `v5_mount.c` by `if (ctx->dlm && !ctx->withdrawn)`, and POISONED implies
  withdrawn, so this is *not* a second hole.

### The emitter census (0.83.1) — where a LOCK_RELEASE can be built at all

Enumerated by primitive, not by scenario: a `MXFS_MSG_LOCK_RELEASE` is stamped
in exactly two functions.

| builder | reached from | poisoned-session disposition |
|---|---|---|
| `dlm_send_release_msg` | `mxfs_dlm_unlock_gen` (every `v5_mount.c` wrapper, `mxfs_dlm_unlock`, residue release, `dlm_wire_release_all`) | refused at the wrapper by `v5_tcp_release_gate`; noted at the primitive by `P945-RELEASE-WHILE-POISONED` |
| `dlm_send_release_msg` | `mxfs_dlm_release_retry_tick` (re-send of an un-ACKed pending release) | refused by `dlm_refuse_release_while_poisoned("release_retry")`, `P945-RELEASE-REFUSED-POISONED`; the pending list is left intact — those records are manifest evidence and the recovery purge retires them |
| `dlm_send_release_msg` | `mxfs_dlm_process_remote_grant` unsolicited-grant reject | refused by `dlm_refuse_release_while_poisoned("grant_reject")`; the fence's purge drops the phantom entry and promotes the waiter |
| `mxfs_dlm_send_unconditional_release` | `mxfs_dlm_release_orphan_if_unheld`, `mxfs_v5_dlm_inode_release_unconditional` | refused at the wrapper (`"ino"`); noted at the primitive |

`dlm_release_redrive_tick` and `dlm_purge_redrive_tick` are MASTER duties over
other owners' records and a survivor's purge of a dead peer respectively — the
opposite operation — and are deliberately not gated.

### What the positive control measured (tests/d0945_chokepoint_positive_control.sh)

- The free this defect is about is a **reclaim**: the previous incarnation of a
  just-unlinked inode, ifree committed and destaging deferred (`P128-INACT-DEFER`),
  reclaimed after the shutdown.  A workload that only creates never leaves one
  cached, which is why eight earlier control laps were vacuous.  The harness
  primes one (create, sync, unlink, sync) and forces the reclaim with
  `drop_caches` right after the trigger.
- The window: the survivor seals the fence ~2.4 s after the shutdown (explicit
  withdrawal, no lease wait).  The periodic reclaim landed at 2.65 s and the
  master refused it as a sealed-owner release; the forced reclaim lands inside
  the window and the master accepts it — the manifest then seals one entry
  short (3 vs 4).  A control that reproduces the cause outside its window is
  answered by the second line of defence and reads as if the defect were
  unreachable.
- Gate on: `P945-INO-FREE-RELEASE gated=1`, one `P-TCP-RELEASE-POISONED
  ino-free=`, no choke-point line, survivor `notheld=0`, no ATOMIC-SKIP, no
  torn refusal, no quarantine, `P163-RECOVERY-COMPLETE`.  Gate off: the choke
  point names `mxfs_v5_dlm_inode_unlock_free` — the instrument is live at
  `unlock_gen`.  The `uncond_release` primitive's probe is not exercised by this
  control.

Still open, and not this defect's (design consult ruling, sess581): the
**publish side** — whether a grant installed on one transport and not the
other exists anywhere — has never been audited.  No such asymmetry has been
observed; it is an audit item, not a defect record.

### PITFALL — a gate that only logs on refusal cannot be shown to work

`v5_tcp_release_gate()` prints only when it refuses.  With the gate disabled the
log is silent, so "the gate did not refuse" and "no inode was ever freed here"
are the same observation — which is why this defect was reasoned about for a
session without ever being reproduced on demand.  The fix is a probe that fires
in **both** arms (`P945-INO-FREE-RELEASE ino=N poisoned=1 gated=0|1`, in
`mxfs_v5_dlm_inode_unlock_free`), so the failing arm states its own failure and
a lap that never took the route is reported as untested rather than as clean.
`tests/agmeta_shutdown_retire.sh` asserts on it and says so explicitly when the
route was not exercised.

## 0.82.0-0.82.1 — the logical-acquisition table, and what it can and cannot carry

A lock acquire is a WAIT that outlives every transport attempt inside it: three
descents of sixty one-second re-sends, and then however many times the acquire
classifier in `xfs_mxfs_dlm.c` restarts `mxfs_dlm_lock_retries` entirely.  Two
sites used to destroy the wait's identity on every attempt — the remote master's
`process_remote_request` freed and re-inserted the requester's WAITING entry,
and `dlm_lock_impl`'s local-master branch freed and re-allocated its own.  Both
therefore re-stamped the entry's queue time once a second and re-notified a
holder that was already draining once a second.  Measured at ~238 notifications
for ONE 244 s wait on each path.

`ctx->acq[]` (dlm.h, `MXFS_DLM_ACQ_SLOTS` 64) is the state that outlives the
entry: `acq_seq`, `first_ms`, `bast_ms`, keyed on **resource + mode**.

### The key is per-resource-and-mode ON PURPOSE, and this is the part to read before "fixing" it

It is tempting to make the name unique per acquisition or per task.  Do not do
that without reading `process_remote_request` first.  The master's lookup is
`resource_equal(&lk->resource, resource) && lk->owner == sender`, so **the master
models one wait per (resource, sender NODE)** and has done since long before
this table existed.  A per-task name makes a second task's re-send fail the
master's `{acq_seq, owner_inc, mode}` identity test, which drops it onto the
original replace-and-requeue path — i.e. it REINTRODUCES one notification per
re-send for that shape.  The per-node name is the correct name for the wire.

Where the shared key genuinely costs something is the **local** path only: two
local tasks waiting on one resource really do allocate two entries (each
`lock_alloc`s its own, both owned by `ctx->local_node`), and both then take
their queue time from the same acquisition record.  Measured reachable, not
theoretical — `tests/live_holder_wait.sh` at `READERS=2` produced 55
`P958-ACQ-KEY-COLLIDE` events in a single wait.

### `queued_at` means "when the WAIT began", and exactly one thing reads it

Audited: the only semantic reader of `queued_at` is `waiter_cmp`, the promotion
sort (oldest first).  `find_conflicting_waiter`'s arrival barrier reads it only
to print an age in `P6-FAIRQ`.  No expiration, deadlock heuristic or cleanup
path reads it.  So redefining it from entry-residence-time to logical-wait-age
changes promotion order and one log line, and nothing else.

**But the tie is now reachable and it is not FIFO.**  `mxfs_pal_sort` is the
kernel's `sort()`, which is heapsort — *not stable*.  Two local waiters sharing
one acquisition record get IDENTICAL backdated `queued_at`, `waiter_cmp` returns
0, and their relative promotion order becomes arbitrary rather than
insertion-ordered.  Before backdating their stamps differed and the tie never
arose.

### The table degrades in three ways, all of them fail-open, all of them counted

`acq_key_collide`, `acq_evict_live`, `acq_idle_live` (probes
`P958-ACQ-KEY-COLLIDE`, `P958-ACQ-EVICT-LIVE`, `P958-ACQ-IDLE-LOST`, each
carrying its own running `total=` so a ratelimited line count is never mistaken
for an event count).  Sixty-five contended resources on one node evict a live
record; a record untouched for `MXFS_DLM_ACQ_IDLE_MS` (15 s) is retired as
abandoned even if its owner is merely slow.  In every one of those cases the
next call mints a fresh name, does **not** backdate (`acq_first` equals now, so
the pull-back test fails) and fires — which is precisely the behaviour the table
replaced.  The fix stops applying; it cannot hang or corrupt.

### The notification gate is a suppression interval, not a delivery guarantee

`dlm_acq_bast_due` only means "no further fire permitted for
`MXFS_DLM_ACQ_BAST_REFIRE_MS` (10 s)".  It does not mean every blocker is
notified within 10 s.  It is keyed on the REQUESTER's wait, not on which
blocking grant has been told, so if a holder releases and a DIFFERENT
conflicting holder appears inside the interval, that new holder's first
notification is suppressed for the remainder of it.  Bounded, because the
blocker list is re-collected unconditionally on every attempt and only the fire
is gated.

That last clause is load-bearing and was audited rather than assumed: BAST
**collection** (the inline loop in `dlm_lock_impl`, and `demand_collect_holders`)
copies `owner` and `requested_mode` into a local array and mutates no lock
state; `fire_bast_records` takes no references and clears no flags.  If
collection had consumed the notification obligation — set a "notified" bit,
cleared a pending flag, taken a reference released only by the fire — then a
suppressed fire would have lost it permanently and later collections would
return `bast_count == 0`, which is an indefinite wait.  It does not.  Anything
added to that collection loop later must preserve this property.

## 0.84.0-0.84.2 — acquisition lifetime, exact abandonment, fallible-boundary oracle

### The acquisition record outlives the attempt (0.84.0)
A remote acquire registers a pending entry only for the one second each
attempt waits; the acquisition record (`dlm_acq_*`, keyed per resource and
mode) is what carries the wait across attempts and classifier restarts.  A
first GRANT that completes no pending entry is offered to the live acquisition
for that resource (`P958-ACQ-GRANT-ADOPTED`) and claimed by the wait's next
attempt (`P958-ACQ-GRANT-CLAIMED`) after re-checking under the table lock that
the mirror is still ours at that grant generation.  A grant with no pending
entry AND no live acquisition is still bounced (`P958-ACQ-GRANT-BOUNCED`).  The
nonce ring a receipt is judged against is 16 deep (allowance × rate).

### LOCK_CANCEL (0.84.1) — `mxfs_dlm_acq_abandon` / `mxfs_dlm_process_cancel`
Sent when a fallible caller gives up.  Master side, under `table_rwlock`:
tombstone `{sender, owner_inc, acq_seq}` (`cancel_tomb[64]`, consulted by the
remote-request path so a late re-send cannot recreate the waiter), remove a
WAITING/BLOCKED entry (outcome 2), retire a GRANTED/CONVERTING entry through a
release transition and promote (outcome 3), mark a PENDING_DURABLE entry
`cancelled` so `dlm_retire_cancelled_grant` retires it at finalize instead of
delivering (outcome 4); ABSENT (1), NOT_MASTER (5).  Always acked
(`MXFS_MSG_LOCK_CANCEL_ACK`); unacked cancels re-send from the release tick
(`dlm_cancel_retry_tick`) and are dropped after the release send budget.
Cleanup is engine-owned: the abandoning task may be gone.  Counters:
`cancel_sent/acked/rx/absent/waiters_removed/grants_retired/grants_retiring`.
The pre-existing second defence — the requester's phantom reconcile
(xfs_mxfs_dlm.c bast_notify: two no-mirror BASTs inside 15 s queue a
mirror-bypassing release) — still exists and retired the same orphan in
10-11 s in the control laps; the cancel does it in ~3.5 ms and without needing
a notification to arrive.

### The consumed tombstone (0.84.13) — `acq_done` on LOCK_RELEASE
The gap the cancel ring does not cover: a re-send that left BEFORE the grant
arrived, was consumed (grant taken, BAST, released) and reaches the master
AFTER the release.  With the sender's entry gone the master queued it as a
fresh request and, when compatible, granted it at once to a wait that no
longer existed; the requester bounced it (`P958-ACQ-GRANT-BOUNCED`, caught in
s594c), and between the phantom grant and the bounce the master believed the
sender held a lock it knew nothing about.  Closure: `mxfs_dlm_lock_release`
sets `rel.acq_done = !dlm_acq_live(res, mode)` (no live acquisition record for
that resource AND mode — a wait still re-sending under that name, whose grant
was released under it before the claim, keeps `acq_done=0` and is still
served); `process_remote_release` on a GRANTED entry with `acq_done` adds
`{sender, owner_inc, lk->acq_seq}` to `consumed_tomb[256]`
(`dlm_consumed_tomb_add`, under `table_rwlock`, AFTER the stale-gen and
incarnation checks — an overtaken release can never tombstone the name a
re-affirm re-stamped onto a live entry); `process_remote_request` refuses a
request whose name is tombstoned with the same SILENCE as a cancelled one
(`P958-CONSUMED-RESEND-REFUSED`, counter `consumed_resend_refused`): a DENY
would complete the sender's NEXT pending entry on that resource with the old
one's error.  `acq_seq` is `++ctx->acq_seq_next`, strictly increasing per
requester, so a fresh acquisition never collides with a tombstone.  The ring
has no age bound, like the cancel ring: a stale re-send that outlives 256
later consumed releases at one master (it follows the release inside one 1 s
re-send cadence) falls back to the bounce, which is harmless as measured.
Test-only: `dl_stale_resend_ino` (W keeps its last LOCK_REQ for that inode and
re-sends it once right after its next LOCK_RELEASE of it, `P958-STALE-RESEND-SENT`,
counter `dl_stale_resend_n` reset on write) and `dl_no_consumed_tomb` (the
master ignores the ring — the control arm).  Harness `tests/tcp_stale_resend.sh`
(s596a fix / s596b control, both fails=0 on 0.84.13).

### `acq_fallible_cb` (0.84.2)
`ctx->acq_fallible_cb(cb_data, resource)` asks the XFS layer whether the
CURRENT task registered the named inode as a fallible boundary.  Only then
does `mxfs_dlm_lock_retries` leave a timed-out attempt early on
`mxfs_pal_fatal_signal_pending()` with -EINTR (`P958-ACQ-FATAL-SIGNAL`); an
unregistered task is never interrupted.  Wired in v5_mount.c
(`v5_acq_fallible_cb` → `mxfs_acq_task_fallible_for`).

### Test-only knobs (never in production)
`dl_drop_lockreq_ino` (sender discards LOCK_REQ for one inode),
`dl_drop_grant_ino` (master records but never delivers a GRANT for one inode),
`dl_no_cancel` (abandon without LOCK_CANCEL — the control arm),
`dl_acq_gap_ino`/`dl_acq_gap_ms` (widen the between-attempt gap).  Each drop
knob is a `module_param_cb` whose set-callback resets a readable per-arm
counter (`dl_drop_lockreq_n`, `dl_drop_grant_n`) and the probe's print budget
(n<=8, n%64).  Harnesses read the COUNTER, never the printed lines.
`dlm/dlm_user_compat.h` stubs the parameter macros for the tests/tauth build
(before 0.84.2 that build did not compile once the first knob landed in dlm.c).

## 0.84.3 — the departure worker and unmount teardown (D-0953)

**The invariant:** nothing the departure worker can reach — engine,
`page_state`, ledger, slot map, transport, peer, mutexes — is freed before the
worker has returned.  The worker runs minutes-long ledger passes (one durable
prepare + one durable activate per page, ~15-30 ms; 8000 pages behind 16000
creates took 117 s on the QNAP LUN) and three of them run OUTSIDE any recovery,
on `v5_depart_worker_fn`: the goodbye/clean-release takeover of a departed
peer, the takeover-only named takeover of THIS node's own previous incarnation
queued by `v5_settled_incarnation` when a node remounts after leaving as the
last member (its pages stayed under it: `mxfs_dlm_handoff_depart` hands pages
to peers only), and the orphan sweep queued after every departure.  The fourth
— a dead peer's takeover — runs synchronously inside the elected replayer's
recovery (`P-TAUTH-TAKEOVER-RUN why=recovery-complete`), and put_super waits
for that recovery to complete before the DLM teardown starts (measured s588a:
an unmount issued 139 s into a 7999-page pass returned after 105 s with the
pass complete) — so that shape cannot reach the worker's teardown at all.

**The crash (s574xm, 0.75.128, netconsole):** the sole survivor remounted alone,
settled its own predecessor, and the worker was at page 9569 of the
takeover-only pass when the node was unmounted.  Teardown joined the worker
for `V5_DEPART_JOIN_MS` (30 s), printed `P-DEPART-WORKER-STUCK`, "quarantined"
the context but then destroyed the engine, closed the ledger and freed the
context anyway; the worker's next `page_state` byte store
(`dlm_page_now_mine`, `movb $1,(%rax,%rdx)`, RDX=9569) faulted on the freed
vmalloc array and the guest panicked (`panic_on_oops`).

**The fix (design consult ruling
`ruling-departure-worker-teardown-cancel-between-pages-unbounded-join-no-quarantine-by-deadline`):**
- `ctx->shutting_down` (set by `v5_tcp_dlm_teardown` before the worker stop)
  is consulted BETWEEN pages by `mxfs_dlm_handoff_takeover`
  (`P-TAUTH-TAKEOVER-INTERRUPTED ... remaining=`) and by
  `mxfs_dlm_takeover_orphans` (`P-TAUTH-ORPHAN-SWEEP-INTERRUPTED`), never inside
  a page (prepare + activate + purge + import must complete or not start: a
  page activated but not imported is one this node claims and cannot serve).
  Both return -EINTR and count `handoff_takeover_interrupted`.  The
  ledger-successor write path and the settle-wait loops answer -ESHUTDOWN once
  the flag is set.
- `v5_depart_run` refuses new work once `depart_stop` is set
  (`P-DEPART-WORK-REFUSED`), and the FROZEN receive case refuses to activate a
  page handed to a leaving mount (`P-TAUTH-HANDOFF-REFUSED-LEAVING`,
  `handoff_refused_leaving`): it stays PREPARED to this incarnation and the
  successor's takeover of our goodbye retargets it.
- `v5_depart_worker_stop(ctx, bounded)`: the normal unmount joins WITHOUT
  bound (`P-DEPART-WORKER-SLOW` every 30 s is diagnostic only); only the
  refused-mount unwind keeps the 30 s bound + quarantine, and
  `depart_quarantined` now gates `mxfs_dlm_destroy`, the ledger close,
  `peer_shutdown` and `disklock_destroy` — the whole closure the worker reads,
  not just the context.
- Every departure ends by queueing the orphan sweep (`v5_orphan_sweep_queue`
  from `v5_depart_run`, not after the sweep itself), so pages an interrupted
  pass left are picked up by a survivor that stays mounted, not only by the
  next bootstrap.

**Harness:** `tests/depart_takeover_unmount.sh` — `DEATH=ghost` (default) is
the s574xm shape (B leaves, A builds NFILES alone, A unmounts as last member,
A remounts alone, A is unmounted while the takeover-only pass is in flight);
`DEATH=destroy` is the recovery-embedded shape kept as the regression check of
put_super waiting for the recovery.  A lap is valid only if activations were
still arriving when the unmount was issued and, on the fixed build, the
interruption line reports `remaining >= 1`.

## 0.84.6 — the join install refuses a retired identity (D-0961)

`v5_join_transition` (the join worker) calls `v5_join_sighting_retired(ctx, s,
where)` — `v5_node_is_dead` on the sighting's node id — before each prepare
attempt and again after a prepare returns 0, and `v5_join_install` calls it
too; a hit logs `P961-JOIN-SIGHTING-RETIRED ... at=before-prepare|
after-prepare|install`, drops the sighting, and (after a prepare) still runs
`join_commit_fn` so the frozen mount thaws.  Measured s591a: B's refused mount
left (GOODBYE → `v5_note_dead_node_locked`) while A's prepare was parked on the
SB summary lock; the install 4 s later registered the dead id, A's view went to
three members when B's next incarnation joined, and both nodes' EX acquires
were refused by the settle gate for ever.  Every membership entry point now
consults the dead set: connect (`P164-DEAD-REJECT connect`), announce
(`P164-DEAD-REJECT announce`), GOODBYE, and the join install.

0.84.7: in `v5_join_install` the dead-set check and the lease registration
are one critical section under `member_lock` — the lock the GOODBYE receiver
holds across its unregister + `v5_note_dead_node_locked` — so the two
claimants of a peer's membership are ordered, not raced.  Lock order is
member_lock → lease lock, the same as the GOODBYE path.  The lease layer is
no defence here: a registered id that never renews goes SUSPECT after 150
missed 2 s monitor scans past its 60 s duration and DEAD only at the 600 s
timeout (`MXFS_LEASE_TIMEOUT_DEFAULT_MS`), so a departed identity installed
into the view hangs both nodes for ten minutes at least (s591a measured four
with no expiry, death or fence).

Harness precondition (`tests/join_during_takeover.sh`): the ledger records
grants and a lone mount takes none, so the authority is built while both
nodes are members (creates, or a stat of every entry: `P-TAUTH-PREPARED`/
`P-TAUTH-ACTIVATE` per inode, ~10 ms) before B leaves; on a fresh filesystem
the old order left the pass `cand=4` and 2.3 s long (s591d, s592a).

## 0.84.5 — a request on a page whose dead authority is being taken over (D-0960)

**The defect (s588b/c, and a plain `module_swap_deploy.sh`):** a node that
joins while the bootstrap node's takeover-only pass over its OWN previous
incarnation's pages is in flight (~15k pages, ~157 s) makes its first cluster
acquire — the root inode's EX at mount — on a page the pass has not reached.
`dlm_ledger_prepare`'s on-demand branch (0.75.9) tested `dlm_owner_purged`,
which is keyed by node id and can never name the bootstrap's own id (that
would retire its live records), so the request fell to the "ask the
bootstrap" branch with `bn == us`, the ask went to the other members (who
answered NOT_OWNER), and the master answered REMASTER until the pass reached
the page.  Sixty REMASTER retries take ~6 s; three descents in 18 s; the
acquire classifier's arm (3) shut the joiner's filesystem down at mount, the
mount withdrew, retired its PR key and was fenced and replayed by the node it
had joined.  Which node masters ino 128 is a hash of the view, so the same
shape also arrives as the joiner's own `dlm_ledger_prepare` parking
(prepare=60) when the joiner is the master.

**The fix (design consult ruling
`ruling-joiner-during-authority-takeover-priority-service-progress-aware-wait-staged-mount-abort`:
A priority service + B progress-aware wait + C staged mount abort; A alone
must not close it):**
- **A.** `ctx->settled_auth[]` records every {node, inc} handed to
  `mxfs_dlm_handoff_takeover` (`dlm_authority_settle_record`, keyed by
  incarnation, never by node id); `dlm_authority_dead` answers true for them.
  The on-demand branch in `dlm_ledger_prepare` now asks `dlm_authority_dead`
  (the same question the FREEZE_REQ handler asks since 0.75.69), so the
  bootstrap takes the requested page over ahead of the pass
  (`P-TAUTH-TAKEOVER-ONDEMAND via=takeover-ondemand`, or
  `via=takeover-request` for a FREEZE_REQ from a joiner that masters the
  page itself).  `dlm_takeover_page` already tolerates the bulk pass and the
  on-demand path racing on one page (a stale-base prepare re-reads and
  yields to the writer that won).
- **B.** `dlm_ledger_prepare` returns -EINPROGRESS (not -EAGAIN) when the
  page is in a transition someone live is making: the bootstrap's on-demand
  takeover prepared it to another owner or was skipped, or (not the
  bootstrap) the authority is dead and a bootstrap is in view.  The master
  answers `MXFS_ERR_AUTH_TRANSITION` with its `takeover_pages_done` (a
  monotonic per-page completion count incremented once at the end of
  `dlm_takeover_page` by every path) in the deny's `grant_gen`
  (`P960-AUTH-TRANSITION-TX`); a FREEZE_REQ decline for a dead authority
  relays the same count in NOT_OWNER's `prepared_seq`; the receiver keeps
  the highest in `transition_progress_rx`.  `dlm_lock_impl` returns
  `MXFS_DLM_RETRY_TRANSITION` with the count, and `mxfs_dlm_lock_retries`
  does not consume its budget while the count advances
  (`P960-AUTH-TRANSITION-WAIT`); `MXFS_DLM_TRANSITION_STALL_MS` (30 s)
  without an advance is `P960-AUTH-TRANSITION-STALLED`, which returns
  -EREMCHG ONLY to a caller the fallible oracle (`acq_fallible_cb`) names;
  every other caller keeps waiting and repeats the line every 30 s (an AG
  acquire inside a dirty transaction handed an error would cancel dirty and
  shut down — the escalation this path exists to avoid).  A NOQUEUE request
  never waits on a transition: `P960-AUTH-TRANSITION-NOQUEUE`, -EAGAIN at the
  first answer (measured s590g: the blocking AG acquire's non-blocking probe
  had waited 52 s before the blocking acquire started).  The wait is
  cancellable (fallible caller + fatal signal → -EINTR; engine shutting down
  → -ESHUTDOWN) and holds nothing the takeover needs.  The oracle
  (`v5_acq_fallible_cb`) answers for AG resources too, through
  `mxfs_acq_task_fallible_for_ag`: only an AG acquire the XFS layer
  registered as a boundary (the untrusted iget of an inode the task may
  already fail) is fallible.
- **C.** The acquire hook classifies -EREMCHG before the quarantine and
  pending-recovery arms: a fallible caller fails THIS operation with -EAGAIN
  (`P960-AUTH-TRANSITION-FAIL`, via `mxfs_acqfall_give_up_rc`, so
  `mxfs_ilock_fallible` now returns the errno the arm named); a caller that
  cannot be failed parks with backoff and restarts
  (`P960-AUTH-TRANSITION-PARK`), never arm (3).  The mount's root inode
  lookup + lock (`xfs_mountfs`, previously `xfs_iget(..., XFS_ILOCK_EXCL)`)
  is now `mxfs_iget_root_fallible`: the task registers the root inode, the
  untrusted iget's AG 0 acquire (`xfs_icache.c`, now
  `mxfs_ag_dlm_lock_fallible_for`) registers the AG for the same task, and
  `mxfs_ilock_fallible` follows the lockless iget.  Measured s590g: AG 0's
  lock is the FIRST cluster acquire of the mount, ahead of the inode's — a
  root-lock-only boundary would have left the mount waiting on it.  A
  refusal fails the MOUNT ("Failed to read root inode ... a cluster acquire
  was refused; the mount is refused, not shut down", -EREMCHG from the AG
  path, -EAGAIN from the inode path), and the fill_super unwind commits the
  slot release only when the filesystem was not shut down — that is what
  turns the observed withdraw-and-fence into a clean departure.  Other
  mount-time acquires (rt/quota inodes, the summary counts) are plain
  callers: they wait on a stalled transition rather than shut down.  The
  refused mount's UNWIND takes no cluster acquire either: `xfs_log_quiesce`
  skips the SB summary cover for a mount that never set
  `m_mxfs_mount_complete` (`P960-REFUSED-MOUNT-NOCOVER`; measured s590j the
  summary lock's page was itself in the transition and the unwind parked on
  it for 70 s, until the knobs were cleared).  Details in `xfs.md` 0.84.5.

**Measured shapes (s590i/s590j, `tests/join_during_takeover.sh`):** which
node masters the mount's first requests (AG 0's page, then the root inode's)
is a per-incarnation hash.  A-mastered: the bootstrap's own prepare answers
(`P960-ONDEMAND-SERVED` / `P960-AUTH-TRANSITION-TX type=3 ino=0 ag=0`).
B-mastered: the joiner parks and asks by FREEZE_REQ, and the bootstrap
answers `P-TAUTH-HANDOFF-DEFER ... my_view=0x0/0` until it installs the
two-node view (`MXFS-MEMBERSHIP active_count=2 view=`, ~7-10 s after the
first ask in s590i, three of three), only then `P960-AUTH-TRANSITION-DECLINE`
with a count; a DEFER carries no progress, so the joiner's relayed count stays
0 through that window.  Why the install waits: it runs on the join worker
(`v5_join_transition` → `peer_joined_notify_fn` = the D-0959 join_prepare,
which FREEZES the bootstrap's superblock; the freeze's `xfs_log_quiesce` takes
the SB summary cluster lock, `mxfs_sb_summary_key`), and with
`dl_no_ondemand_takeover=1` that lock's page is served only when the pass
reaches it (page 5115 of ~15.6k on the rig LUN, ~50 s in) — s590j A logged
`P960-AUTH-TRANSITION-WAIT type=1 ino=754974721 comm=mxfs-worker` for exactly
that.  In production the on-demand takeover serves it at once.  Under
`dl_takeover_pause_ms` the install therefore did not happen for the whole
paused pass (100 s, s590j iterations 1/2/4/5), so the stall arm's B-mastered
shape is refused by the watchdog with progress=0 rather than by a count that
stopped: the arm measures the A-mastered shape.

**Test knobs (never in production):** `mxfs.dl_no_ondemand_takeover=1`
disables A on the node it is set on; `mxfs.dl_takeover_pause_ms=N` holds
both bulk passes between pages (`dlm_takeover_pause`, 100 ms slices, ended
by the mount leaving or the knob being cleared).

**Harness:** `tests/join_during_takeover.sh` — B leaves, A holds the
authority (NFILES entries, reused across laps), A unmounts as the last member
and remounts alone, and B mounts once the takeover-only pass is proven in
flight.  `EXPECT=death` asserts the old build's shutdown + withdraw;
`EXPECT=clean ARM=ondemand|nodemand|stall` asserts A, B and C respectively,
each with the other defences held off by the knobs.

## 0.84.8 — the settle gate records the incumbent's zero view (D-0960, the DEFER window)

**The hole (measured s592e B-mastered, s593a A-mastered, both nodemand):**
the settle gate (`dlm_membership_settling`, 0.83.4) is fail-closed only
against a live member whose beacon reports a *different* view.  An
incumbent that has not finished its join prepare beacons view `{0, 0}`
("no multi-node view installed"), and that report was dropped twice on the
way in — `lease.c` forwarded only a non-zero hash and
`mxfs_dlm_report_peer_view` returned on hash 0 — so `dlm_view_pending_live`
saw no report at all, and at the 20 s window the joiner's first acquire
went through unconfirmed (`P-D7-SETTLEGATE waited=18000ms confirmed=0`).
Every request the joiner then made met the incumbent's page-handoff
handler under a view mismatch and was answered `P-TAUTH-HANDOFF-DEFER`
(`my_view=0x0/0`) at the 500 ms cadence: a DEFER carries no progress and is
a plain park on the joiner, so the retry budget went on it (s592e: nine
60-retry budgets of `prepare=60`, the AG 0 acquire's five untrusted-iget
budgets, `Failed to read root inode ... error 5`), or the transition
watchdog fired with the relayed count frozen (s593a: the root inode's page
was B-mastered, `P960-AUTH-TRANSITION-STALLED progress=2463 stalled_ms=30029`,
mount refused with -EAGAIN).  Clean refusals both times — defence C held —
but a join refused while the cluster was healthy.  The window is the
incumbent's prepare: writeback + freeze + the SB summary cluster lock, 55 s
in s591a and the whole bulk pass under `dl_no_ondemand_takeover`.

**Now:** a zero view signature is forwarded and recorded like any other
(`peer_views[].hash = 0`, `rx_ms` stamped), so an incumbent beaconing it
since the joiner's membership change is a live member reporting another
view and the gate stays closed until its beacon carries the installed
two-node view — the positive proof that opens it.  The 60 s backstop
(`MXFS_DLM_SETTLE_MAX_WAIT_MS`) still refuses the acquire (-EAGAIN,
retryable; the mount's untrusted iget retries it), so a prepare that never
completes ends in a refused mount, never a hang.  `P-D7-SETTLEGATE` now
prints `pending_live=`.  The DEFER path is unchanged: it is the safety net
behind the gate, not a wait.

**Measured shapes on 0.84.8 (`tests/join_during_takeover.sh`, s593b-e):**
production (`ARM=ondemand`) — the incumbent installs the two-node view
before the joiner's first acquire (no gate line at all) and the join
returns in 3-13 s with the root's page served on demand or by
takeover-request; on-demand off (`nodemand`) — the incumbent's install
waits on the pass for its SB summary lock's page (214 s at ~16k pages),
the gate refuses the joiner's AG 0 acquire at the 60 s backstop up to three
times (each retried by the untrusted iget) and opens on `confirmed=1`, the
join returning in ~220 s; the pass held (`stall`) — the install never comes,
ten backstop refusals (the untrusted iget's five budgets × the non-blocking
probe and the blocking acquire) and the mount is refused at the root lookup
628 s after issue, cleanly.  The harness scores the gate-admitted join as
the shape `gate`.

**Open (design, not a defect):** a no-queue acquire waits the gate's full
backstop before answering would-block, which is what makes the stall
refusal 628 s rather than ~300 s.  The transition wait already answers a
no-queue request at once (`P960-AUTH-TRANSITION-NOQUEUE`); the gate could do
the same, fail-closed either way.  And the joiner's wait on a LIVE
incumbent's prepare is bounded by five 60 s refusals rather than by the
incumbent's liveness; a prepare longer than that (a very large dirty set)
would refuse a healthy join.

## Slice lifecycle: the claim-time FUA zero (0.88.0, `docs/slice-lifecycle.md`)

D-SLICE-CLAIM-TIME-INIT-UNTRUSTED-ZERO-531.  mkfs's zero of the log region is a
userspace write the target stack does not promise to persist; a slice still carrying a
previous incarnation's CRC-valid records mis-steers the cycle-number head search and the
committed tail is lost (s60j: 0/40 files back, node unmountable).  The fix is a durable
per-slice record in a new envelope region (`MXFS_FORMAT_F_SLIFE`, gen 20) and a claim-time
zero:

- `dlm/bootstrap.c`: `mxfs_slife_read` (magic, version, slice index, state range, crc,
  this volume's uuid; a zero sector is UNFORMATTED → -ENODATA, foreign uuid → -EXDEV,
  malformed → -EUCLEAN) and `mxfs_slife_claim_init`: READY → return; else write ZEROING
  FUA + readback, zero the payload with `mxfs_pal_bdev_write_fua` in 64 KiB chunks,
  `mxfs_pal_bdev_flush`, read EVERY byte back through `mxfs_pal_bdev_read_prio` and
  compare, then READY FUA + readback with `generation++`.  Any failure leaves ZEROING.
  Log lines: `P-SLIFE-ZEROING`, `P-SLIFE-READY`, `P-SLIFE-ZERO-IO`, `P-SLIFE-FLUSH`,
  `P-SLIFE-ZERO-READBACK`, `P-SLIFE-READBACK`, `P-SLIFE-UNFORMATTED`, `P-SLIFE-INVALID`,
  `P-SLIFE-FOREIGN-VOLUME`, `P-SLIFE-PAYLOAD`.
- `dlm/v5_mount.c`: `slife_offset/size` in `mxfs_v5_dlm_opts` and the ctx;
  `mxfs_v5_dlm_slice_lifecycle_claim(ctx, slice, payload_off, payload_len, &before,
  &after, &zero_ms)` uses `ctx->dev` (absolute device offsets, base 0), `ctx->volume_uuid`,
  `disklock->local_node/epoch`; `mxfs_v5_dlm_slice_lifecycle_state` for recovery.
  -ENODEV = no region on this volume.
- `pal/linux/xfs_super.c`: after the slot claim (`m_mxfs_node_slot`) and BEFORE
  `xfs_mountfs`: payload = `BBTOB(bt_sector_offset + XFS_FSB_TO_DADDR(sb_logstart) +
  slice * m_mxfs_log_slice_bblks)`, length `BBTOB(m_mxfs_log_slice_bblks)`; the file needs
  `xfs_bit.h` for that macro.  `P-SLIFE slot= slice= before= after= zeroed_bytes= zero_ms=`
  on success, `P-SLIFE-REFUSED` refuses the mount, `P-SLIFE-LEGACY` on a volume without
  the region (old behaviour, loud).
- `xfs/xfs_log.c` (`mxfs_xlog_recover_foreign_slice`): a slice whose record is not READY
  is skipped — no snapshot, no replay (`P-SLIFE-FOREIGN-UNINIT`), record left for the next
  claimant; an unreadable record is a retryable error (`P-SLIFE-FOREIGN-UNREADABLE`);
  -ENODEV replays as before.
- **I/O trap**: the readback is a SCSI READ(16) passthrough — the block layer refuses a
  transfer above the LUN's `max_hw_sectors_kb` (512 on the 2-node rig) and maps the buffer
  by virtual address, so the chunk is 64 KiB of `mxfs_pal_alloc_io` (kzalloc) memory, never
  `mxfs_pal_alloc` (vzalloc above 16 KiB).
- **Never zero from inference.**  No path may bring a slice to READY except this claim on
  an `INIT_REQUIRED`/`ZEROING` record of this volume's uuid, and nothing synthesises
  `INIT_REQUIRED` for a slice on a volume without the region.

## 0.89.0 — open-holder marks on the TCP authority ledger (D-0977)

Design: `docs/tcp-authority-ledger.md` "Open-holder marks".  The surfaces:

- `struct mxfs_tauth_entry.open_holders` (byte 104, replaced the per-record forensic
  clock; `MXFS_TAUTH_VERSION` 4, `MXFS_PROTO_GEN` 21 — a v3 region is refused and
  reformatted by prep).  `page_find_entry` never allocates a FREE tombstone whose mask
  is non-zero for another resource; a same-resource reclaim preserves the mask.
- `struct mxfs_tauth_op.open_op` / `.open_holders_out`; `MXFS_TAUTH_OPEN_{NONE,SET,
  CLEAR,ZERO}` (+1/-1/-2/0); a new op kind `MXFS_TAUTH_OP_OPEN_MARK` (a mark change with
  no grant to ride: existing record only, never allocates, ZERO refused).  `apply_op`
  applies the op inside RELEASE_EX/RELEASE_PR and reports the mask after the op; a
  GRANT_EX's `open_holders_out` is the snapshot the grant reply carries.
  `tauth_purge_page` strips the departed slot's mark from ACTIVE records and from
  tombstones; with `bit == 0` (slot already re-tenanted) marks are left alone.
- Wire: `mxfs_dlm_lock_release.open_op` (was padding), `mxfs_dlm_lock_resp.open_holders`
  (the struct grew 8 bytes).
- Engine (`dlm/dlm.c`): `mxfs_dlm_unlock_open(ctx, res, gen, open_op)` (`unlock_gen` is
  the NONE form); the op is stored on the pending entry (`mxfs_lock.open_op`) and on the
  un-ACKed release (`mxfs_dlm_pending_release.open_op`) so every re-send carries it;
  `dlm_txn_item.open_op` → `mxfs_tauth_op.open_op` in `dlm_txn_commit`; `dlm_grant_ids
  .open_holders` → `send_grant` → the grantee's mirror (`mxfs_lock.open_holders`,
  `open_snap` = an exclusive grant carrying a valid snapshot; local grantees get it in
  `dlm_txn_finalize`).  `mxfs_dlm_open_holders(ctx, res, &mask)`: 0 + the snapshot on
  the held EX/PW entry, `-EIO` otherwise.  `mxfs_dlm_process_remote_release`'s ENOENT
  arm applies SET/CLEAR through `dlm_open_mark_only` before ACKing
  (`P977-OPEN-MARK-ONLY`, counter `open_mark_only`).
- Wrapper (`dlm/v5_mount.c`): `mxfs_v5_dlm_inode_unlock_open` passes the op on TCP;
  `mxfs_v5_dlm_inode_unlock_free` sends ZERO; `mxfs_v5_dlm_inode_open_holders` masks the
  snapshot by slot occupancy (`v5_slot_node_cb`; `P977-OPEN-RESIDUE` when it drops a
  bit); `mxfs_v5_dlm_inode_open_clear` is a no-op on TCP and
  `mxfs_v5_dlm_open_clear_rides_release(ctx)` tells the XFS layer to clear by releasing.
  `-EOPNOTSUPP` from `open_holders` is left only for a cluster-ROUTED inode on TCP.
- 0.89.1: every path that constructs a grant carries the snapshot.  The REAFFIRM arm of
  `process_remote_request` (the answer to the unlinker's certify re-acquire, taken on
  every unlink) sends `ids.open_holders = lk->open_holders`; `dlm_import_holder` stamps
  `e->open_holders` on the imported entry.  The grantee's mirror update replaces
  `open_holders` only when the grant names a NEW `grant_seq64`/`authority_epoch` (a fresh
  commit) and ORs a same-id re-affirm's mask into the snapshot it has.  Before this the
  re-affirm's `dlm_grant_ids` left the field unassigned and the guard read 0 (s64a).
  The XFS side: `i_mxfs_open_inflight` (opens still inside `mxfs_dlm_open_protect`)
  and `mxfs_inode_exposed()` — the poison tests count usable descriptors only, the
  mark-publication tests keep counting in-flight opens.
- Not changed: the CAW registry (slot bitmap + release CAS), ICLUS gating.
- Known bound (recorded, not accepted): a home page whose 31 entries are all pinned by
  marks refuses grants of the resources hashing to it until a close or a fence purge
  frees one (`P-TAUTH-PAGE-FULL open_pinned=`, counter `open_pinned`).

## 0.89.15 — a certificate needs a RETIREMENT proof, and a clause covers one observed transition

Design ruling: `docs/rulings/retirement-proof-obligation-and-observed-transition-classes.md`
(it corrects `fence-gate-and-self-succession-retirement-basis.md` and the
0.89.13 package). Read it before touching any fence kind.

- **The obligation lives at the constructor.** `mxfs_disklock_recovery_fence_certify()`
  now takes `retire_basis, retire_claim, retire_obs` and refuses (`-EPERM`,
  `P236-FENCE-NO-RETIREMENT`) any replay-authorising kind arriving with
  `MXFS_RETIRE_BASIS_NONE`. `v5_pr_fence_dead_node_rc` checks the same thing
  before its publish loop (`P238-FENCE-NO-RETIREMENT`) so a missing proof is a
  classification outcome, not a publication failure that retries forever.
  `SINGLE_NODE_EXCLUSIVE` was the one admitted exception, logging
  `P236-FENCE-TOPOLOGY-NO-RETIREMENT` every time. **0.89.18 removed it**, so
  the gate has no exception at all — which is the only shape in which it is a
  choke point. Kind 17 is revoked in `mxfs_fence_durable_kind_supported`, no
  producer mints it, and every reader refuses it, including the
  untagged-replay authority (`mxfs_v5_dlm_victim_untagged_authority`), which
  compared `desc.fence_kind` directly instead of asking the classifier and now
  returns `cert_sn_excl` constant-false with a `P227-SN-CERT-REVOKED` line.
- **Three new enums in `dlm/scsipr.h`**, carried on `struct mxfs_fence_result`:
  `mxfs_retire_observation` (what was seen: registration present / no MXFS
  successor / replacement same boot / replacement different boot / UNKNOWN),
  `mxfs_retire_claim` (the proposition asserted), alongside the existing
  `mxfs_retire_basis`. An observation is never a claim; UNKNOWN is a refusal.
- **`mxfs_scsipr_retire_basis_nexus_loss()` is gone** — it is
  `mxfs_scsipr_retire_proof(ctx, contract, obs, &claim, why, whysz)`. The clause
  it accepts is `unreplaced-registration-absence-retires-before-purge`, whose
  premise is `MXFS_RETIRE_OBS_NO_MXFS_SUCCESSOR` and nothing else. 0.89.13's
  `nexus-loss-retires-before-registration-purge` is still RECOGNISED and always
  refused with its reason printed: it is conditional on a nexus loss no
  initiator can witness. `data/rigs.json` re-asserts the new clause with the
  measurement that backs it.
- **`v5_retire_observation()`** (dlm/v5_mount.c) classifies from the death
  snapshot identity + `mxfs_prledger_find_successor`, which gained a
  `new_boot[16]` out-param so a same-boot replacement is distinguishable from
  one across a boot boundary. Both replacement classes are REFUSED by the
  shipped clause — that is what stops kind 19's refused case being certified by
  kind 20 or 21 instead.
- **Call sites that must all agree**: the gate (`P238-FENCE-GATE-BASIS` on
  success, `P238-GATE-NO-RETIRE-BASIS` on refusal, checked BEFORE the PROUT so
  an uncertifiable gate is never installed), boot succession
  (`P238-BOOTSUCC-NO-RETIRE-BASIS`), the lost-certificate republish
  (`P238-FENCE-REPUBLISH-NOBASIS` — it re-derives the proof, it does not carry
  it), and the ordinary preempt, which sets `TARGET_OP` in `dlm/scsipr.c` where
  kind 16 is assigned.
- **Test-only knob** `mxfs.fence_retire_obs_inject=1..4` forces the observation
  (`P238-RETIRE-OBS-INJECTED`), because this target purges a registration within
  ~34 s while a node needs ~150 s to return, so the replacement transitions
  cannot be produced on this rig by timing.
- **Harness**: `tests/fence_gate_basis.sh <label> <qualified|none|wrongfw|oldclause|sameboot|diffboot>`.
  Note the arms differ in non-vacuity: the certifying arm needs
  `P238-FENCE-GATE-TRY`, a refusing arm needs the refusal and must NOT show the
  try.
- **Still open, recorded in the queue**: the certificate carries none of this on
  the platter, so a corrected build still honours one minted under the rejected
  rules (on-disk format work, design it once).

## 0.89.16 — the deployment clause is withdrawn, and a fence kind becomes a proof contract

Two design rulings, both banked, both to be read before touching any fence
kind: `docs/rulings/retirement-witness-routes-lu-reset-early-preempt-or-refuse.md`
(what may serve as a retirement witness, and why refusal is the default) and
`docs/rulings/fence-certificate-proof-profiles-and-legacy-revocation.md` (why a
kind IS the proof contract). Operator-facing:
`docs/retirement-witness-and-what-refusal-means.md`.

- **`mxfs_scsipr_retire_proof()` now returns `MXFS_RETIRE_BASIS_NONE` for every
  clause.** The deployment qualification is withdrawn in code, not in
  configuration: no value of `target_retire_contract`, no interval, no retry and
  no operator override re-enables it. The parameter is still READ so a
  configured contract is REJECTED BY NAME on its own line
  (`P303-RETIRE-CONTRACT-REJECTED`) rather than ignored — it goes on its own
  line because inside a `why` buffer it is the part that truncates away.
  `data/rigs.json` keeps the string and its measurements under
  `task_retirement_contract_withdrawn*`, which nothing ships; `run.sh` and
  `tests/lib/rig.sh` gained `mxfs_rig_retirement_contract_withdrawn` so a
  harness can still load a module WITH it and prove the refusal is in the code.
- **The constructor requires `MXFS_RETIRE_BASIS_TARGET_OP`**, not merely "not
  NONE". `SINGLE_NODE_EXCLUSIVE` remains the one exemption (its own queue
  record, and the next step of the second ruling is to remove it).
- **Fence kind 16 is RETIRED; `MXFS_FENCE_KIND_PREEMPT_ABORT_PROVEN_V1` = 23
  replaces it.** A fresh code point, not a tightened 16, because 16 had TWO
  producers: the fence path after a completed, verified PREEMPT AND ABORT, and
  `v5_boot_tk_fence_key` after reading this node's own PR ledger with no
  operation run. A reader cannot tell those apart, so a durable 16 is
  unclassifiable and no tightening repairs the ones already written. 16 is kept
  in the enum (it decodes as `PREEMPT_ABORT_DONE_RETIRED16`) and is out of
  `mxfs_fence_kind_proves_exclusion`.
- **One classifier, and every non-minting reader calls it:**
  `mxfs_fence_durable_kind_supported(enum mxfs_fence_record_family, kind, &why)`
  in `dlm/scsipr.c`. Families are `MXFS_FENCE_RECORD_RECOVERY_DESC` and
  `MXFS_FENCE_RECORD_BOOTSTRAP_OWNER`. Callers: `mxfs_recov_cert_proves_exclusion`
  (dlm/disklock.c), `mxfs_bootstrap_reseal` (dlm/bootstrap.c), and the
  mount-time takeover check on slot K's descriptor (dlm/v5_mount.c,
  `P-BOOT-TAKEOVER-KIND-REFUSED`). The old shape was three independent
  `kind == 16 || kind == 19` tests. Refusal is the default for anything
  unclassifiable, including an unknown kind, and every refusal names the class.
  `tools/chk_mxfs` only PRINTS `fence_kind` and makes no authorisation
  decision, so it needed no change.
- **Revoked at CONSUMPTION, not only at mint**: retired 16, kind 19
  (`SELF_SUCCESSION_DONE` — a REGISTER AND IGNORE replacing a key on the same
  nexus forces no session outcome), kind 20 and kind 21 (both reachable only
  from the victim's registration already being absent, so neither can ever have
  rested on a completed operation). Kind 17 is carried unchanged.
- **`v5_boot_tk_fence_key` lost its three fabricating branches** — ledger
  FENCED, ledger RETIRED, and the boot-boundary self-succession. Only the
  branch that issues the PREEMPT AND ABORT and requires kind 23 back survives;
  everything else is `P-BOOT-TAKEOVER-FENCE-UNPROVEN`. Consequence on a purging
  target: a bootstrap takeover whose victim key is already gone now always
  refuses.
- **Test-only knob** `mxfs.dl_fence_cert_kind_inject=<kind>` (dlm/disklock.c)
  writes that kind into the durable certificate INSTEAD of the proved one,
  logging `P236-FENCE-CERT-KIND-INJECTED proved=... written=...`. Every
  constructor check still runs against the proved kind; only the value that
  lands on the platter is replaced, and the values worth injecting are the ones
  the consuming side refuses — so an injected lap is strictly more
  conservative. It exists because a guard against records an OLDER build wrote
  is otherwise unreachable.
- **Harnesses.** `tests/fence_retire_basis.sh <label> <declared|none>` and
  `tests/fence_gate_basis.sh <label> <declared|none>` — both arms now REFUSE,
  and `declared` loads the exact string that used to certify, which is what
  proves the withdrawal is in the code. The arms that used to differ by
  contract field (`wrongfw`, `oldclause`, `sameboot`, `diffboot`) are gone: with
  no clause accepted they all produce the identical refusal. Both harnesses
  ABORT if `data/rigs.json` ever declares an active contract again.
  `tests/fence_strong_basis.sh <label> [proven|legacy16|legacy19]` is new and
  runs the OTHER direction — it silences the victim with
  `dl_inject_hb_pause_ms` instead of power-cutting it, so its registration is
  still in the target's table and the preempt can name it. `proven` requires the
  fence to certify kind 23 with `retire_basis=completed-target-op`, the slice to
  replay, and the victim's fsynced files to read back from the SURVIVOR
  byte-identical; `legacy16`/`legacy19` inject a revoked kind onto the platter
  and require the consuming side to refuse it by class and replay nothing.

## 0.89.17 — minting is a subset of consumption, and a forged certificate is how the revoked classes get tested

- **The certificate constructor asks the DURABLE classifier.**
  `mxfs_disklock_recovery_fence_certify()` gated on
  `mxfs_fence_kind_proves_exclusion()` — a second, hand-maintained list of code
  points that still admits 19, 20 and 21, the classes consumption revokes. It
  now calls `mxfs_fence_durable_kind_supported(MXFS_FENCE_RECORD_RECOVERY_DESC,
  …)`, the same function every consuming reader uses. The asymmetry is what
  made it worth changing: a build that can MINT a kind it would REFUSE to read
  seals a descriptor nothing will act on, and a sealed descriptor answers
  `-EEXIST` to every later prover, so that slice could never be certified by
  anybody again. `mxfs_fence_kind_proves_exclusion()` survives and is now
  documented for what it is — "did this attempt just now prove anything", a
  question about a fresh result in the caller's stack, never an authorisation
  gate and never upstream of a durable write. Its remaining callers are all in
  `dlm/v5_mount.c` and all decide whether an attempt got far enough to be worth
  certifying.

- **Every authorisation decision on a durable fence kind now routes through the
  one classifier, audited by enumerating writers as well as readers.** The
  takeover's copy at `v5_mount.c` (`fence_kind = desc.fence_kind`) sits behind
  `P-BOOT-TAKEOVER-KIND-REFUSED`; `bootstrap.c`'s `want.prev_fence_kind =
  a->prev_fence_kind` behind `P-BOOT-TAKEOVER-UNPROVEN`; the replay gate only
  hands a kind out through `out_fence_kind` after
  `mxfs_recov_cert_proves_exclusion` has passed. The remaining direct
  comparisons on a durable `fence_kind` (`disklock.c` gate-owed scan,
  `v5_mount.c` exclusive-write-gate sites) are OBLIGATION tests — "did we
  install a single-holder reservation that must still be released" — and must
  NOT be classifier-gated, or a revoked record would strand the reservation it
  names. `tools/chk_mxfs` prints `fence_kind` and makes no authorisation
  decision (re-derived 0.89.17: all fourteen sites are struct fields, printf
  arguments, one offset assertion, and one write of `prev_fence_kind = 0` for
  `--clear-bootstrap`).

- **`tools/recov_forge` can write a CERTIFICATE, not just a recovery lease.**
  `--fence-kind K` with `--fence-resv/--fence-key/--fence-prover/
  --fence-prover-epoch/--fence-term`, plus `--desc-version V` for a record from
  a build that does not exist. `--fence-kind` implies `--stage 3` unless a
  stage is given, because a certificate below FENCED is refused at the stage
  gate and would grade the wrong thing. This is the only way to reach a durable
  revoked class: a build only ever mints the kinds it still supports. Two
  long-standing hazards in that tool were fixed at the same time — its help
  said `--stage 2` meant FENCED (2 has been SNAPSHOTTING since the stage was
  inserted; FENCED is 3), and it set FUA in every CDB, which THE SHIPPING LUN
  REJECTS with ILLEGAL REQUEST 24/00, so nothing it issued ever completed
  there. It now mirrors the kernel's fallback: drop FUA, retry once, latch it,
  and say on stderr what was given up. **No Makefile builds this tool** — a
  harness that uses it must `cc` it first.

- **`tests/fence_kind_matrix.sh <arm>`** forges one class into an unused
  heartbeat slot, has a node mount into it, and grades the refusal: the class
  named in words, the kind on the platter named, nothing replayed on either
  node, and the certificate NOT relabelled. Arms `retired16 revoked19 gate20
  boot21 unknown99 oldversion single17 proven23`. The last two are the
  discriminator and the reason the matrix means anything — they carry kinds
  this build SUPPORTS with `--fence-prover 0`, so they must refuse for the
  missing field and name no revoked class. No arm presents a fully valid
  certificate on purpose: an accepted one would authorise replaying a slice
  belonging to a live filesystem.

- **A mount that meets a certificate it cannot classify is BOUNDED, and the
  bound is 122 s.** Measured rc=32 at 123-124 s on every classifying arm. The
  barrier prints its own deadline —
  `P-BARRIER-GHOST-EXTEND undeclared=1 window_ms=62000 bound_ms=122000` — because
  a guard slot with no live heartbeat is an undeclared death, which buys the
  one-time extension `MXFS_BARRIER_ADMISSION_WAIT_MS` + dead window +
  `MXFS_BARRIER_ADMISSION_WAIT_MS`. Derive a mount budget from that line or
  those constants, never from the observation windows in the design comments.
  A descriptor whose VERSION cannot be validated is different: refused in 1-2 s,
  because the barrier waits for a certificate it understands and rejects (a
  prover might yet appear) and does not wait for one it cannot parse.

## 2026-09-20 (0.89.19): the only retirement basis is a completed target operation, and what that forecloses

**The invariant.** A fence certificate needs ADMISSION (the victim cannot get
permission to write) *and* RETIREMENT (writes the target already accepted from
the victim are finished). Since 0.89.16 the only accepted retirement basis is
`MXFS_RETIRE_BASIS_TARGET_OP`: our own PREEMPT AND ABORT **named a registration
that was in the target's table**, completed, and the post-state was verified.
`MXFS_RETIRE_BASIS_QUALIFIED_CONTRACT` (a deployment clause) is withdrawn in
code — the value still decodes so old records and log lines read, and it is
never produced or accepted again.

**What that forecloses on a purging target, measured 2026-09-20.** This rig's
QNAP purges a registration with its iSCSI session 30-46 s after a power cut,
while death is not declared for ~66 s (disklock death window 31 × 2000 ms, plus
`tcp_death_grace_ms=40000` on the TCP path). So by the time anything fences, the
victim's key is gone and there is nothing for a PREEMPT AND ABORT to name. The
observation `MXFS_RETIRE_OBS_NO_MXFS_SUCCESSOR` is not a basis, and neither is
`REPLACEMENT_DIFFERENT_BOOT` — a host lifetime boundary is not a target-side
ordering witness. Both the boot-succession route and the sole-survivor
exclusive-write gate refuse (`P238-BOOTSUCC-NO-RETIRE-BASIS`,
`P238-GATE-NO-RETIRE-BASIS`, `obs=no-mxfs-successor-observed`), the fence
classifies `KEY_ABSENT_UNPROVEN`, and **no node can mount**: the peer's mount
and the dead node's own next boot both return 32.

**The consequence for testing, which cost a session to find.** Every cut in the
fence crash matrix destroys the PROVER, so every one of them now ends with a
purged registration and a successor that cannot certify it. The matrix's banked
12/12 PASS was measured on 0.89.10, before the withdrawal — cut 1, re-run
unchanged on 0.89.19, fails with `fails=10`
(`tests/evidence/20260920T135544Z_fcut1_s86c_cut1`). **Do not plan a lap that
needs a power-cut node to be recovered until one of the retirement routes
exists.**

**The two detection paths for a fenced-but-alive node**, because they are easy
to assume and were assumed wrong once:
- reactive — `mxfs_v5_dlm_note_resv_conflict()` (`dlm/v5_mount.c`) counts SCSI
  RESERVATION CONFLICTs on data-path writes and launches the inspection thread
  at `MXFS_RESV_CONFLICT_INSPECT_THRESHOLD=3`;
- proactive — `v5_resv_health_tick()` does a periodic PR IN in which SELF_GONE
  is ranked AHEAD of ABSENT, so a node whose own registration is missing takes
  the withdraw path and never reaches the repair path. Repair there is RESERVE
  by a node that has just verified its own key is present; **it is never
  REGISTER**, because a node that re-registered to fix "my key vanished" would
  be undoing its own fence.

Its cadence is the thing to know: `V5_RESV_HEALTH_LEAD_MS=5000` for the elected
maintainer (the lowest live heartbeat slot) but `V5_RESV_HEALTH_AUDIT_MS=60000`
for an auditor — which in a two-node cluster the victim often is.
