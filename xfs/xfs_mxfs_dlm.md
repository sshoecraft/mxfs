# xfs_mxfs_dlm — XFS-Side DLM Lock Caching + AG Allocation Locks

## Purpose

Three DLM lock subsystems for MXFS v5:

1. **Per-inode lock caching** (Phase 3): Holds DLM lock grants across
   operations, releasing only on BAST, eviction, or unmount. Eliminates
   the 591µs CAW round-trip per I/O that Phase 2 had.

2. **Per-AG allocation locks** (Phase 4): DLM EX locks on allocation groups
   to prevent double-allocation of blocks/inodes across nodes. Node-local
   holder counting handles nesting (inode alloc → block alloc in same AG).

3. **Inode-cluster locking** (ICLUSTER, Phase 1 — opt-in, `mxfs.icluster_dlm`,
   default 0): mediates regular-file dinode coherence through ONE on-disk
   DLM resource per XFS inode cluster instead of one per inode, on the CAW
   transport. Added 2026-07-18 (v0.11.16) to fix a per-file-touch device-op
   wall that per-inode granularity hit no matter how many individual op
   counts were shaved (see History). See "Inode-Cluster Granularity" below.

## Architecture

Based on GFS2 glocks (fs/gfs2/glock.c), OCFS2 dlmglue (fs/ocfs2/dlmglue.c),
and mxfs.1 inode_cache (libmxfs/inode_cache.c).

### Lock Ordering
DLM outer, VFS i_rwsem inner. Same as GFS2/OCFS2.

### Per-Inode State (in struct xfs_inode)
- `i_dlm_lock` — spinlock protecting all DLM cache fields
- `i_dlm_wait` — wait queue for threads blocked by DEMOTING state
- `i_dlm_bast_work` — work_struct for deferred BAST processing
- `i_dlm_mode` — cached DLM mode (NL/PR/EX)
- `i_dlm_state` — NONE/CACHED/BAST/DEMOTING
- `i_dlm_ex_holders` — active IOLOCK_EXCL holder count
- `i_dlm_pr_holders` — active IOLOCK_SHARED holder count

### State Machine
```
NONE → (ilock_begin, cache miss) → CACHED
CACHED → (BAST, no holders) → DEMOTING → (flush complete) → NONE
CACHED → (BAST, holders active) → BAST → (last holder unlocks) → DEMOTING → NONE
DEMOTING → blocks new ilock_begin callers via wait queue
```

### BAST→Inode Lookup
Uses `xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0, &ip)` — XFS's existing
per-AG radix tree. No custom hash table. Does igrab(), must xfs_irele() after.

## Files

| File | Role |
|---|---|
| `xfs/xfs_mxfs_dlm.h` | Public API declarations |
| `xfs/xfs_mxfs_dlm.c` | Implementation. ~380 lines at Phase 3/4 inception (2026-03); ~33,600 lines as of 0.11.39 (2026-07-20) — the growth is almost entirely the op-ledger/wedge-diagnosis/ICLUSTER work in History below, expressed as per-fix `module_param` knobs (hundreds; grep `module_param_named` for the current set) plus the ICLUSTER block at the tail of the file. |
| `xfs/xfs_inode.h` | Per-inode DLM fields + state defines |
| `xfs/xfs_inode.c` | Hook sites: xfs_ilock, iunlock, ilock_nowait, ilock_demote |
| `xfs/xfs_icache.c` | Init in xfs_inode_alloc, eviction in xfs_reclaim_inode |
| `xfs/libxfs/xfs_ag.h` | Per-AG DLM fields (pag_dlm_lock, pag_dlm_holders) |
| `xfs/libxfs/xfs_ag.c` | Mutex/holder init in xfs_perag_alloc |
| `xfs/libxfs/xfs_alloc.c` | AG lock hooks in prepare_ag, finish, __xfs_free_extent |
| `xfs/libxfs/xfs_ialloc.c` | AG lock hooks in xfs_dialloc_try_ag, affinity in pick_ag |
| `dlm/v5_mount.h` | bast_notify callback, inode_lock_try, get_node_slot |
| `dlm/v5_mount.c` | BAST dispatch, AG lock stubs, get_node_slot |
| `pal/linux/xfs_super.c` | DLM init, m_mxfs_node_slot population |

## Functions — Inode Lock Caching (Phase 3)

| Function | Purpose |
|---|---|
| `mxfs_dlm_ilock_begin` | Cache check + DLM acquire. Called from xfs_ilock. |
| `mxfs_dlm_ilock_end` | Decrement holders + deferred BAST. Called from xfs_iunlock. |
| `mxfs_dlm_ilock_try` | Non-blocking version for xfs_ilock_nowait. |
| `mxfs_dlm_ilock_demote` | Adjust EX→PR holder counts. |
| `mxfs_dlm_bast_notify` | BAST callback from DLM layer. |
| `mxfs_dlm_bast_process` | Flush + invalidate + DLM unlock. |
| `mxfs_dlm_evict` | Release cached lock on inode reclaim. |
| `mxfs_dlm_cache_init` | Register BAST callback with DLM. |
| `mxfs_dlm_inode_init` | Init per-inode DLM fields. |

## Functions — AG Allocation Locks (Phase 4)

| Function | Purpose |
|---|---|
| `mxfs_ag_dlm_lock` | Acquire per-AG DLM EX lock; on fresh acquire (no cached deferred-release to cancel), invalidates AG-meta buffers in `pag_bcache` so cached views are dropped before the next access re-reads from disk. |
| `mxfs_ag_dlm_unlock` | Release per-AG DLM lock; defers the actual CAW release until `pag_dlm_meta_pending` drains to zero (i.e. all AG-metadata writeback has completed) so peers cannot acquire and observe stale on-disk bytes. |
| `mxfs_buf_is_ag_metadata` | Discriminator for AG-metadata buffers by `b_ops` (agf/agi/agfl/bnobt/cntbt/inobt/finobt/rmapbt/refcountbt). |
| `mxfs_ag_meta_track` | Called from `xfs_trans_log_buf`. Pins buffer, increments `pag_dlm_meta_pending`, installs `mxfs_dlm_ag_meta_iodone` as `bp->b_iodone`. Idempotent within a dirty epoch via `XFS_BLI_MXFS_AGMETA_TRACKED`. |
| `mxfs_dlm_ag_meta_iodone` | Per-buffer write-completion callback. Decrements pending counter; fires deferred `mxfs_v5_dlm_ag_unlock` when counter hits zero AND release was deferred AND no local holder. |
| `mxfs_dlm_invalidate_ag_meta` (static) | Walk `pag_bcache.bc_hash` rhashtable and stale every clean AG-metadata buffer. Filters out buffers with attached `b_log_item` or queued for delwri to avoid losing in-flight dirty state. |

## Performance

Two-node DLM with lock caching (test2 idle):
- rand_write_4k: **8,447 IOPS** (Phase 2 was 1,582 — **5.3x improvement**)
- rand_read_4k: **6,538 IOPS** (Phase 2 was 1,722 — **3.8x improvement**)
- Cache hit rate: **99%** (281,810 hits, 2 misses)
- Within noise of single-node performance

## AG Allocation Lock Design (Phase 4)

Based on GFS2 rgrp locking (fs/gfs2/rgrp.c) and OCFS2 suballoc (fs/ocfs2/suballoc.c).

### Hook Points
1. **Block alloc**: `xfs_alloc_vextent_prepare_ag()` (acquire) / `xfs_alloc_vextent_finish()` (release)
2. **Extent free**: `__xfs_free_extent()` (acquire/release around entire operation)
3. **Inode alloc**: `xfs_dialloc_try_ag()` (acquire/release around entire operation)

### Nesting
Inode allocation calls block allocation within the same AG. Holder counting
in `struct xfs_perag` (pag_dlm_lock mutex + pag_dlm_holders int) prevents
deadlock: nested acquire increments counter without CAW I/O, nested release
decrements without CAW release.

### AG Affinity
`preferred_ag = (node_slot + rotor) % ag_count`. Each node starts allocation
searches from a different AG, reducing DLM contention in the common case.

## AG-Metadata Coherency (v0.2.5, 2026-04-25)

The Phase 4 AG locks are *coordination* locks — they do not by themselves guarantee that on-disk AG metadata (AGF/AGI/AGFL/btree blocks) is consistent across nodes.  Two complementary mechanisms fix that:

**Release side — defer the actual DLM release until our writeback lands.**
Every AG-metadata buffer logged via `xfs_trans_log_buf` is registered with `mxfs_ag_meta_track`: an extra hold ref + atomic counter increment + `b_iodone` install.  When the last local holder calls `mxfs_ag_dlm_unlock` while `pag_dlm_meta_pending > 0`, we set `pag_dlm_release_pending = true` and skip the CAW release.  As each tracked buffer's writeback completes, `mxfs_dlm_ag_meta_iodone` decrements the counter; when it hits zero (and no local re-acquire has happened in the meantime), it fires the actual `mxfs_v5_dlm_ag_unlock`.  Local re-acquires while the release is deferred just clear the flag — we still hold EX on disk, so CAW lock fast-paths to success without I/O.

**Acquire side — drop our stale local cache.**
On a true fresh acquire (real CAW lock, not a deferred-release cancel), `mxfs_dlm_invalidate_ag_meta` walks `pag->pag_bcache.bc_hash` and `xfs_buf_stale`s every AG-metadata buffer that is fully clean (no `b_log_item`, no `_XBF_DELWRI_Q`).  The "fully clean" filter is essential: a buffer with an attached bli has un-flushed in-memory writes that staling would discard.  Such buffers cannot have been modified by a peer (deferred-release guarantees we held EX continuously while writeback was outstanding), so leaving them cached is safe.

**Why `b_iodone`, not `iop_committed`** (the v0.2.5 attempt-1 hook): `iop_committed` fires from `xlog_cil_ail_insert` at AIL-insert time — WAL is durable but the buffer's home-location bytes are not yet on disk.  A peer reading from the home block would still see stale data.  `bp->b_iodone` (called from `__xfs_buf_ioend`) fires after the actual write completes, which is when peers can safely read.  AG-metadata buffers do not use `b_iodone` upstream (only inode/dquot do via `xfs_trans_inode_buf` and `xfs_dquot_buf_ops`), so the slot is free for our use.

**Closes**: regular-file dd corruption bug (`xfs_alloc.c:2105 ltbno+ltlen>bno` shutdown), open since v0.2.2.

## Inode-Cluster Granularity (ICLUSTER, Phase 1 — opt-in)

Landed v0.11.16 (2026-07-18), implemented entirely in `xfs/xfs_mxfs_dlm.c`
(the ICLUSTER block is the tail of the file, from the
`mxfs_icluster_dlm` module param onward — self-contained, no new files).
Gated behind `module_param_named(icluster_dlm, mxfs_icluster_dlm, int,
0444)` — **load-time only** (0444, not 0644): a runtime flip would let
inodes acquired via one granularity release via the other, orphaning a
slot. Default 0 (off); set via `insmod`/`modprobe` at mount time.

**Why**: the per-file-touch device-op wall. A five-fix op-shave series
(v0.11.12–0.11.15 — 16-slot span probes, throttled held-verify, UDP grant
nudge, grant-time heldchk stamping, close-demote suppression for unlinked
inodes — see History) left `dir_reuse_coherency` flat, because the wall was
per-inode *lock granularity*, not probe count: touching N files in a
directory means N separate on-disk DLM resource acquire/release cycles no
matter how cheap each individual cycle gets.

**Design — coverage-sweep, not refcounts.** The obvious per-cluster
refcount design (ex_refs/pr_refs, bump on grant/drop on release) was
implemented first and then reworked after a design audit found it
structurally fragile: PR→EX upgrade is lock-lock-unlock (two counts, one
drop), `ilock_try` counts one-sided, the deferred-publish walker pops
before locking, and roughly half a dozen recovery paths
(P72 orphan-escape, P106 phantom-bail, unmount teardown, single→multi
wipe) set `i_dlm_mode = NL` without going through a release call at all.
Any resulting counter imbalance either leaks (cluster resource never
releases) or steals (releases under a still-live sibling grant — split
brain). The replacement, `mxfs_iclus_covered_active()`, makes the release
decision by **sweeping the in-core inodes covered by the cluster** at
release time (iget each, check `i_dlm_mode != NL || i_dlm_acq_inflight`,
routed inodes only) instead of trusting a counter — imbalance becomes
structurally impossible because there is nothing to imbalance.

**Sticky per-inode routing.** `ip->i_dlm_routed_iclus` (added to
`struct xfs_inode`, `xfs/xfs_inode.h`) is stamped at every acquire and is
the single source of truth for which resource — the inode-cluster resource
or the legacy per-inode slot — backs an inode's *current* grant. Every
release, sweep, and fan-out decision routes by this sticky bit, never by
re-evaluating `S_ISREG` at release time. This matters because a mode-0
dead-shell recycle acquires on the legacy per-inode path even when
`icluster_dlm=1` (before the reload knows the inode's real type); routing
release decisions off a fresh `S_ISREG` check instead of the sticky bit
orphaned exactly this class of grant permanently (proven live: a per-inode
EX lock held 220s with 7 nodes queued behind the covering directory).
`mxfs_dlm_inode_lock_routed()` also does the one-time conversion: on the
first *routed* acquire of an inode that still holds a live mode-0-era
per-inode PR grant, it drops the stale per-inode slot under `i_dlm_lock`
(`P-ICLUS-CONV`) before switching the sticky bit — gated off for
unpublished/self-created grants (nothing was ever claimed for those, so
skip the wasted device CAS).

**Routed call sites**: central `ilock_begin` slow-path acquire,
publish-on-create, deferred-publish walker 1 (walker 2 is dir-only — dirs
always keep per-inode resources, never route to ICLUSTER), both
`bast_process` release branches, evict/free release (`is_free` piggybacks
the tombstone CAS iff the call performs the cluster release),
unmount-teardown release skip, `xfs_ilock_nowait`/IOLOCK try-admit
(fast-coverage only, bracketed by `i_dlm_acq_inflight` so a concurrent
sweep can't miss the acquire window), an EDEADLK upgrade standoff mapped
to a self-BAST (drain + release + clean re-acquire), the iget visibility
nudge (gains a cluster-PR nudge), ioend nested-EX admit, and reload's
`sc_grant_held` consult (both now consult the cluster grant so they don't
false-negative on routed files and adopt stale on-disk state). With the
knob at 0 every routed predicate compiles to the legacy call exactly —
inert scaffolding.

**Release-side durability**: `mxfs_iclus_make_durable(mp, base)` runs
before every cluster disk release — log-force SYNC plus a cluster-buffer
settle loop — because the sweep design has no per-inode mirror to fall
back on if a writer's dirty dinode gets evicted before any BAST fires (a
proven root: writer evicted → size update lives only in the log → platter
dinode size stays 0 → sweep sees "clean" → cluster releases with no
drain → a reader on another node reads 0 bytes).

### Functions — ICLUSTER (Phase 1)

| Function | Purpose |
|---|---|
| `mxfs_iclus_routed` (static inline) | True iff this inode's dinode coherence is carried by the inode-cluster resource: `icluster_dlm=1` && regular file && CAW transport. |
| `mxfs_dlm_iclus_covered` | Non-static twin of the above for out-of-file callers (e.g. `xfs_inactive`'s double-free guard in `xfs_inode.c`). |
| `mxfs_dlm_inode_lock_routed` | Acquire dispatcher: routes to `mxfs_iclus_lock` or the legacy `mxfs_v5_dlm_inode_lock`; stamps `i_dlm_routed_iclus`; performs the mode-0-era per-inode grant conversion (`P-ICLUS-CONV`) and de-lists the inode from the unpublished walker on a routed claim. |
| `mxfs_iclus_lock` / `mxfs_iclus_unlock` | Acquire/release the per-cluster on-disk DLM resource. `unlock` returns an honest rc (0=cleared/no-op, -EBUSY=declined by the coverage sweep, other=wire failure) — an earlier version hardcoded rc=0 on decline, which was one of four defects in the sess7 470s ABBA wedge (see History). |
| `mxfs_iclus_covered_active` | The coverage sweep: walks in-core inodes covered by the cluster base, true if any is granted or has an in-flight acquire. Release only proceeds when this returns false. |
| `mxfs_iclus_make_durable` | Log-force SYNC + cluster-buffer settle before every cluster disk release; the durability backstop the sweep design needs (no per-inode mirror). |
| `mxfs_iclus_pi_reconcile` | Post-drain cleanup of a sticky-routed inode's orphaned per-inode holder bit, for entry-orphan pipelines only (`p_held_mode==NL`) — gated that way because an unconditional wire read on every routed release cost 10-15s at 32 nodes. |
| `mxfs_iclus_bast_notify` | BAST callback for the ICLUSTER resource; fans out to every covered in-core granted inode (absent/NL inodes are skipped — their no-slot recovery paths issue per-inode device ops that don't exist under cluster granularity). |
| `mxfs_iclus_base` / `mxfs_iclus_hashfn` | `ino & ~(inodes_per_cluster-1)` cluster-base computation and its hash-table slot for the per-cluster local state table. |

## History

- 2026-07-20: **All 4 deployment conditions (tcp/cawp/cawd/caw) pass the
  full test matrix at 1-32 nodes on ONE build**, v0.11.39
  (srcversion `420FBA2893A16457AEFA58C`) — `matrix_check.py --cond all`
  reports 100% PASS, 519 non-xfs cells, verified as real budget-enforced
  runs (not the 20×-inflated calibration mode). This is the point where
  everything in this History section below through v0.11.16 had
  cumulatively converged: no wedges, no shutdowns, no over-budget cells
  at any node count on any transport.
- 2026-07-19: **Freed-inode / write-once churn corruption class killed**
  (v0.11.18). Root (RULE-4 proven, `xfs_inode.c`, not this file, but the
  bug lived in this file's release-side contract): an idle EX demote
  during the droplink→inactivation gap stripped an inode's EX lock, so
  the subsequent truncate/ifree ran at mode=NL; the non-EX release guard
  (`P119-NONEX-FLUSH-SKIP`) then discarded the dinode flush entirely,
  leaving the platter holding the pre-free dinode; a later local realloc
  adopted that stale gen-blind disk image, producing a Frankenstein
  dinode (`mode=0 nblocks=1`) → `-EFSCORRUPTED` shutdown. Fix: `xfs_inactive`
  now sets `MXFS_IF_DLM_RELFLUSH` while inactivation holds DLM EX, which
  the P119 guard honors as a sanctioned forced flush regardless of the
  demoted mode.
- 2026-07-19: **470s ABBA wedge chain diagnosed and fixed**, 4 stacked
  defects (v0.11.22–0.11.26, "MHT quiet-age gate" build line). One node
  held a directory EX and waited on a per-inode EX on a recycled file;
  the file's holder had that per-inode bit orphaned (in-core NL, sticky
  `i_dlm_routed_iclus=true`) and was itself waiting on the directory —
  classic ABBA, plus the orphaned bit could never self-heal because (1)
  the sticky bit routed its release cluster-ward, where the coverage
  sweep declined (a covered sibling was busy) and the release path lied
  `rc=0` on that decline (the "honest unlock rc" class, 3rd site found —
  fixed: `mxfs_iclus_unlock` returns a real rc); (2) the lie made a
  resource-scoped rescue clock (added earlier this cycle, see below)
  clear itself, so the 3s starvation-force rescue that would otherwise
  have broken the wedge never armed; (3) `P135-GRANTWIN-PARK` parked
  BASTs on a frozen leftover `grant_seq` field that the code comment
  claimed was "always 0 on CAW" but wasn't — fixed: gated TCP-only, CAW's
  real mid-completion signal is `i_dlm_acq_inflight`; (4) the
  sticky-routing conversion site dropped a live per-inode grant only
  when `mode != NL`, so an NL-orphaned per-inode EX bit had no drop path
  at all. Same build line also landed the **adaptive MHT quiet-age gate**:
  `i_dlm_tenure_lastop_ns` is stamped at every `ilock_end`; the deferred-BAST
  dwork now releases a young-window tenure once it has been quiet ≥
  `dir_ex_batch_grace_ms` (default 40, tuned from a 25/40/60 A/B) instead
  of always sleeping out the full `inode_mht_ms`/`dir_sf_mht_ms` hold-time
  floor — idle grants no longer pay the full batching window when a peer
  is parked waiting. Net effect at 32 nodes: cache_coherency wall
  79s → 60-62s, with the wedge's ~1-in-3 recurrence rate gone in 6+
  subsequent runs.
- 2026-07-19: **Sticky per-inode routing fix** — `i_dlm_routed_iclus`
  extended to cover a second orphan class beyond the ICLUSTER-conversion
  case below: mode-0 dead-shell recycle acquires happened to route via
  the legacy per-inode path (their `S_ISREG` check is false pre-reload),
  but release re-evaluated `S_ISREG` fresh and routed cluster-ward,
  orphaning the per-inode slot permanently (observed: one per-inode EX
  held 220s, 7 nodes queued on the covering root directory). Fixed by
  making every release/sweep/fan-out decision consult the sticky bit
  stamped at acquire time, never a fresh type check.
- 2026-07-19: **BAST/release-path rearchitecture** (v0.11.17, builds
  between the AB52387F base and `2D16C7289B814113AC40EEE`): bounded
  publish batch (publish-drain workers self-free, capped at a 5s
  `wait_for_completion_timeout`, so a cross-node bast-worker cycle can no
  longer queue one release behind another's remote wait forever);
  eager-demote publish (routed children run their own `bast_process` at
  publish time — platter authoritative before dirent exposure — instead
  of claiming the contended cluster resource, closing a pop-then-fail
  claim hole); a "Wave A" pre-pass in `publish_unpublished` that
  async-writebacks every in-scope routed child plus a single log force
  before the per-child pipeline (per-child cost dropped from
  low-single-digit ms to single-digit µs); `caw_unlock_backoff` default
  flipped to 1 (a measured stuck orphan bit had exhausted 100 tight CAS
  retries against 8-node waiter churn with the `-EIO` swallowed
  silently); and `P15-ORPH-PROCEED`, which lets an idle-orphan unlock
  (zero holders, generation unmoved) proceed once a resource-scoped
  clock shows ≥250ms persistence, replacing a per-handoff 3s
  starvation-force tax that had been the root of a multi-node mkdir/stat
  convoy.
- 2026-07-18: v0.11.16 — **ICLUSTER Phase 1** (inode-cluster DLM
  granularity for regular files, opt-in via `mxfs.icluster_dlm=1`,
  default 0). See "Inode-Cluster Granularity" section above for the
  coverage-sweep design and sticky-routing details.
- 2026-07-18: v0.11.12 → v0.11.15 — per-file DLM device-op reduction
  series (a kprobe op-ledger over `dir_reuse_coherency` attributed every
  SCSI command in the hot paths): 16-slot-span slot probing (one
  `READ(16)+FUA` per span instead of per slot); dir-EX fast-path
  held-verify re-throttled to 100ms/inode on the CAW transport; a UDP
  grant-nudge multicast so a blocked acquirer wakes on a PAL condvar
  instead of eating the poll backoff (an 8-node create phase's
  acquire-poll sleep dropped from 4.6s to ~6ms, poll remains the lossless
  backstop); grant-time stamping of `i_dlm_heldchk_j` so a fresh grant
  skips redundant on-disk held-verifies; close-demote suppressed for
  unlinked inodes (an earlier close-demote default had forced
  `xfs_inactive` to re-acquire EX from scratch on every removed file).
  This series left `dir_reuse_coherency` flat overall — the wall was
  lock *granularity*, not probe count, which motivated ICLUSTER above.
- 2026-07-18: v0.11.10 — CAW lock-wait liveness extension. The 120s CAW
  acquire timeout existed to catch dead holders, but dead holders are
  already detected via disklock lease expiry; under 32-node saturation
  the hold-time tail of genuinely *live* holders (dio-completion convoys
  feeding AG/extent-conversion chains) crossed 120s and got errored as
  timeouts, which cascaded into force-shutdowns. Fix: the wait now
  extends past the base timeout while every blocking holder is provably
  alive (cross-checked against the disklock heartbeat tracker), capped by
  a hard `MXFS_CAW_WAIT_HARDCAP_MS` (480s) so a live-but-wedged holder
  still eventually surfaces as a timeout.
- 2026-07-18: v0.11.8 — mmap-fault vs bast-drain ABBA deadlock fix. A
  page-fault's readahead path locked a folio then took the per-inode
  cluster DLM without any outer counted hold; that acquire could sleep
  behind the inode's own BAST drain, which was itself waiting on the same
  locked folio — mutual, permanent wait. Fixed in `pal/linux/xfs_file.c`
  (counted cluster-ilock hold across the whole fault, mirroring the
  buffered-read ordering: DLM hold before any folio lock); `bast_notify`
  in this file already deferred correctly (state=BAST, no work queued)
  while holders were counted — the fix was entirely in establishing that
  counted hold at the fault call site.
- 2026-04-25: v0.2.5 — bidirectional AG-metadata coherency added (deferred
  release + acquire-side invalidate via b_iodone callback).  Validated by the
  2-node concurrent dd reproducer; no `Internal error` or `SHUTDOWN_CORRUPT_INCORE`.
  Also: rewrote attempt-1 hook (which used `iop_committed`) — that hook fires
  before on-disk writeback so it would have left peers reading stale bytes.
- 2026-03-24: Phase 6f — self-BAST on PR→EX upgrade fix. Root cause:
  mxfs_v5_dlm_inode_lock always called mxfs_dlm_caw_lock (fresh acquire).
  For PR→EX upgrades, is_compatible saw our own PR as conflicting with EX,
  triggering a self-BAST. The self-BAST work thread raced with
  mxfs_dlm_ilock_begin's spinlock section — if ilock_begin set mode=EX
  first, the BAST work thread overwrote it with mode=NL/state=NONE. A
  subsequent external BAST found state=NONE and released the DLM lock
  without flushing dirty data, letting the other node read stale directory
  content. Fix: (A) dlm_caw.c: use compatible_excluding_self when
  our_mode != NL so upgrades don't trigger self-BAST. (B) xfs_mxfs_dlm.c:
  safety net in mxfs_dlm_bast_notify — if state=NONE but mode!=NL (race),
  defer BAST instead of releasing without flush.
- 2026-03-23: Phase 4b ILOCK data loss fix. Root cause: BAST handler called
  xfs_log_force (writes to log) but didn't checkpoint inode buffer to home LBA.
  Other node read stale buffer. Fix: (A) add xfs_ail_push_all_sync after
  xfs_log_force in BAST handler to force all dirty buffers to disk, (B) stale
  the local buffer cache entry in reload path via xfs_buf_stale so
  xfs_imap_to_bp re-reads from disk. Verified: sequential mkdir 6/6 persist,
  concurrent mkdir 19/20 persist (1 failure is shared-log LSN race, not ILOCK).
- 2026-03-23: Phase 4b ILOCK DLM coverage added. Extended DLM hooks to ILOCK
  in xfs_ilock/xfs_iunlock (not nowait). BAST handler enhanced with
  xfs_log_force + stale flag. Inode reload on DLM cache miss via
  xfs_inode_from_disk. Guards for atomic context and holder underflow.
- 2026-03-23: Phase 4 implemented. Per-AG DLM EX locks with node-local holder
  counting. Hooks in xfs_alloc_vextent_prepare_ag/finish, __xfs_free_extent,
  xfs_dialloc_try_ag. AG affinity in xfs_dialloc_pick_ag.
- 2026-03-23: Phase 3 implemented. Research-driven design from GFS2/OCFS2/mxfs.1.
  BAST deferred processing, holder counting, DEMOTING state blocking.
  Tested: single-node (no regression), two-node idle (5.3x improvement),
  two-node contention (BAST fires, data coherence confirmed).

## Known Limitations

1. **VFS dentry cache not invalidated on BAST — UPDATE (2026-07)**: not
   fixed as originally written (outright dcache invalidation in the BAST
   handler, GFS2/OCFS2-style), but mitigated by a different mechanism that
   landed outside this file: `pal/linux/xfs_super.c` installs
   `mxfs_dentry_operations` with a `d_revalidate` hook that fast-paths a
   cached dentry as valid only while `dentry->d_time == i_dlm_epoch` (the
   epoch bumps whenever the directory's cached grant drops to NL), forcing
   a fresh lookup otherwise. This covers the common "peer created a file
   under a directory I'm holding" case without full invalidation. Separately,
   this file's own directory-content coherence has its own (distinct)
   epoch-based adoption logic for cross-node handoff visibility
   (`dir_grant_epoch` / `P63-HANDOFF`, ~line 17150) with a documented lossy
   edge on the TCP transport that is under active investigation as of
   2026-07-19 (state.md) — not yet closed, does not gate the 4-condition
   matrix pass since it self-heals within one further epoch bump.

2. **Yield quantum — DONE, superseding the original "deferred to Phase 3b"
   note.** `mxfs_inode_mht_ms` (default 300ms) and `mxfs_dir_sf_mht_ms`
   (default 40ms, shortform dirs) are minimum-hold-time floors that batch
   multiple ops into one EX tenure before yielding to a parked BAST — the
   mxfs.1-style burst optimization this limitation used to describe.
   Landed with an **adaptive** floor on top (`i_dlm_tenure_ops`,
   `i_dlm_tenure_lastop_ns` in `xfs_inode.h`): a tenure that has served
   only one op yields after a short grace instead of sleeping out the full
   floor, while multi-op bursts keep the full batching window. See History
   (adaptive MHT quiet-age gate, 2026-07-19) for the mechanism and the
   wedge-chain defect it was implicated in. A companion fairness mechanism,
   `mxfs_caw_fair_handoff` (default 1, `dlm/dlm_caw.c`), rotates the
   single-winner slot via a yield ticket instead of free-for-all CAS
   contention — required at high node counts (free-for-all left waiters
   starved indefinitely at 32 nodes) but a net regression at low node
   counts if enabled naively without a live-ticket check, so ticket hygiene
   (drop stale bits promptly at grant/exit) matters more as the fleet
   grows.

3. **Two-thread cache miss race** — if two threads on the same node both see
   a cache miss for the same inode, both do CAW lock (second is idempotent
   but wasteful). Acceptable for first impl.

4. **ICLUSTER mode-0-shell double-EX class (GPT-flagged, known hole,
   2026-07-19)** — during the narrow window where a dead-shell inode is
   being recycled (in-core `i_mode==0`, not yet reloaded from disk), nodes
   can disagree on whether a given inode is per-inode-routed or
   cluster-routed for the same acquire, because the routing decision
   depends on `S_ISREG` which isn't yet known. Existing coresident-clobber
   guards prevent corruption, but the class isn't structurally closed the
   way the sticky-bit fix closed the release-side version of this problem.
   Designed fix (not yet implemented): acquire-side re-route validation
   after the dinode read confirms the real inode type.
