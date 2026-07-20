# MXFS — Design & Architecture (complete reference)

> This document is written to be self-contained: everything you would
> need to understand, build, run, and continue developing MXFS if you
> were starting from scratch. It reflects the v5 codebase
> (`/src/mxfs`, a fork of Linux kernel XFS 6.19-rc0 plus an MXFS
> coordination overlay). Last substantive update: 2026-06-06.

---

## 1. What MXFS is

**MXFS (Multinode XFS)** is a **shared-LUN clustered filesystem**: multiple
nodes mount the *same* block device (a shared iSCSI/FC LUN) read-write at the
same time, and the filesystem coordinates concurrent access so that every node
sees a coherent, POSIX-correct view.

It is delivered as a **single kernel module, `mxfs.ko`** — all coordination is
in-kernel; there is **no userspace daemon**. (Userspace exists only for format
/ check / resize tools.)

The design lineage:

- **`xfs/`** — a near-verbatim fork of the upstream Linux 6.19-rc0 XFS tree
  (~211K LOC). On-disk format, journaling, b-trees, inode/dir/attr code are XFS.
- **MXFS overlay** — `xfs/xfs_mxfs_dlm.{c,h}` plus targeted hooks inside the
  forked XFS (in `xfs_icache.c`, `xfs_da_btree.c`, `xfs_buf.c`, `xfs_super.c`,
  allocation paths, etc.). This is where cluster coordination is injected into
  XFS's lock/buffer/inode paths.
- **`dlm/`** — the distributed lock manager and cluster services (~21K LOC):
  CAW (disk-based) and TCP transports, peer discovery, disk heartbeat + node
  slot claiming, lease, SCSI PR fencing, journal slicing.
- **`pal/`** — platform abstraction layer (~27K LOC): wraps everything
  OS-specific (block device I/O, threads, locks, time) behind `mxfs_pal_*` so
  `dlm/` and `tools/` can also build in user space. Also hosts the upstream-fork
  glue (`xfs_super.c`, `xfs_buf.c`, module init).
- **`tools/`** — userspace binaries: `mkfs_mxfs`, `chk_mxfs`, `resize_mxfs`,
  `caw_verify`, `fua_verify`.

**Goal / ship gate:** be a correct, near-native-XFS-performance clustered FS.
The exact acceptance criteria live in `SUCCESS_CRITERIA.md` and are verified by
`tests/criteria/*.sh` (run `tests/criteria/verify_ship.sh`). As of this writing
**11 of 12 criteria pass; the lone failing one is `cache_coherency`** (see §11).

> **IMPORTANT — use MXFS tools, never XFS tools.** MXFS wraps the XFS region in
> an on-disk *envelope* (see §3). `xfs_db`, `xfs_info`, `xfs_repair`,
> `xfs_admin` read the wrong sectors and return empty/garbage. Use
> `tools/mkfs_mxfs`, `tools/chk_mxfs -v` (fsck + geometry), `tools/resize_mxfs`.

---

## 2. Why this is hard (the core problem)

A single-node filesystem owns its block device exclusively: its in-core caches
(buffer cache, inode cache, dentry cache, page cache) are authoritative because
nobody else writes the disk. A **shared-LUN** filesystem breaks that assumption:
node A can durably change metadata that node B has cached. Correctness requires:

1. **Mutual exclusion** — two nodes must not modify the same metadata
   concurrently (or one silently clobbers the other → lost update / on-disk
   corruption).
2. **Cache coherency** — when node A durably changes metadata, node B must not
   keep serving a stale cached copy.
3. **Durability ordering** — node A's change must be *on the platter* before any
   other node is allowed to read that location, and before A's lock is released.

Most clustered filesystems (GFS2, OCFS2) get (1)–(3) by sitting on a **reliable
DLM** (the kernel `dlm` module) with **guaranteed BAST delivery** (blocking-AST:
"someone wants your lock, release it") and a **Lock Value Block (LVB)** that
versions the data each lock protects. MXFS's twist is that its primary transport
is **disk-based (CAW)**, which is *polled*, with only best-effort network hints.
That changes the engineering: the reliable channel is the shared disk itself, and
any coherency mechanism that depends on a *push* notification is unreliable.

---

## 3. On-disk layout (the "envelope")

`mkfs_mxfs` writes an envelope that *precedes* the XFS region:

```
byte 0                                                        device end
+----------------+----------------+-------------------+--------------------+
| MXFS super 4KB | journal region | disklock region   | XFS data region    |
+----------------+----------------+-------------------+--------------------+
                 ^journal_offset  ^disklock_offset    ^xfs_data_offset
```

All offsets are absolute byte offsets, native (little-endian on x86).

### 3.1 MXFS superblock — first 4 KB

`struct mxfs_ondisk_super` (`include/mxfs/mxfs_super.h`), exactly 4096 bytes:

- `magic = 0x5346584D` ("MXFS" in LE hexdump), `version`, `crc` (CRC32C).
- `fs_uuid[16]` (copy of the XFS sb UUID).
- `device_size`, `xfs_data_size`, `xfs_data_offset`.
- `journal_offset` / `journal_size`, `journal_slot_sectors`.
- `disklock_offset` / `disklock_size`.
- `max_nodes` (at format time).
- `xfs_log_node_count` / `xfs_log_slice_bblks` — **per-node XFS log slices**
  (each node journals into its own slice so a survivor can replay a dead node's
  log; 0 = legacy single-log).

The mount path reads this 4 KB to learn where everything is, then mounts XFS at
`xfs_data_offset` (this is the `bt_sector_offset` shift that makes raw XFS tools
read the wrong place).

### 3.2 Journal region

Per-node journal slices used by the journal-recovery service. A surviving node
replays a dead node's slice during fencing/recovery
(`MXFS_LTYPE_JOURNAL`, `mxfs_dlm_journal_msg`, `dlm/journal.h`).

### 3.3 Disklock region (`dlm/disklock.h`)

Layout *relative to* `disklock_offset`:

```
offset 0       .. 32767 : heartbeat records  (64 slots × 512 B)
offset 32768   .. end   : lock records       (65536 slots × 512 B)
```

This region hosts **two distinct things** that are easy to confuse:

**(a) Heartbeat records — `struct mxfs_disklock_heartbeat`, 512 B, one per node
slot (0..63).** Each node writes its OWN slot every `MXFS_DISKLOCK_HB_INTERVAL_MS`
(2000 ms). Contains `node_id`, `timestamp_ms`, `epoch`, `lock_count`, and:

- **The eviction ring** (`struct mxfs_evict_ring`, 464 B carved from the record's
  reserved tail; magic `"MXER"`). A single-writer-per-slot ring of up to
  `MXFS_EVICT_RING_ENTRIES = 28` `{ino, gen, type}` entries. `head_seq` is a
  monotonic publish counter; peers keep a per-peer tail and diff to consume new
  entries while they scan the HB area for liveness. Types:
  - `MXFS_EVICT_TYPE_INODE_FREE (0)` — a peer freed inode `ino` (now di_gen
    `gen`); consumers flag any NL-cached in-core copy `XFS_ISTALE_CAW` so the
    next lookup re-reads the (possibly reused) dinode.
  - `MXFS_EVICT_TYPE_DIR_MODIFY (1)` — a peer modified directory `ino`;
    consumers bump that dir's in-core `i_dlm_dir_gen` so the next readdir
    FUA-re-reads stale-but-clean cached dir blocks.

  > **This ring is "lossy":** it is a fixed-size ring buffer. If a writer
  > publishes faster than a peer polls (2 s cadence), entries are overwritten
  > before that peer observes them (head_seq gap). It is therefore an
  > *optimization/hint channel*, NOT a correctness-bearing channel. (Historically
  > this lossiness is the source of much of the residual cache-coherency pain;
  > see §11.)

  Liveness thresholds: `LIVE_THRESHOLD = 2`, `DEAD_THRESHOLD = 31` heartbeat
  misses → node considered dead → fencing/journal replay.

**(b) Lock records — `struct mxfs_disklock_record`, 512 B × 65536.** A
secondary, simpler persistence of grants `{resource, owner, mode, state, epoch}`.
(The hot path uses the CAW slot table; see §4.)

### 3.4 CAW slot table — the lock table (`dlm/dlm_caw.h`)

The **primary lock state** lives in the CAW (Compare-And-Write) slot table:
**65536 fixed slots, 512 B each** (`MXFS_CAW_MAX_SLOTS`, `MXFS_CAW_SLOT_SIZE`).
This table lives in the disklock region (slots start after the heartbeat area).

`struct mxfs_caw_lock_slot` (512 B, one sector — atomically CAS-able):

```c
uint32_t magic;            // MXFS_CAW_MAGIC "MXCW" (0x4D584357) = live slot
uint32_t generation;       // ABA-prevention counter, ++ on every CAS
struct mxfs_resource_id resource;  // 32B: {type, ino/agno, volume_id, ...}
uint64_t holders_ex;       // bitmap: nodes holding EX  (1 bit per node, 0..63)
uint64_t holders_pw;       // bitmap: nodes holding PW
uint64_t holders_pr;       // bitmap: nodes holding PR
uint64_t holders_cw;       // bitmap: nodes holding CW
uint64_t holders_cr;       // bitmap: nodes holding CR
uint64_t waiters;          // bitmap: nodes waiting
uint8_t  granted_mode;     // highest mode currently held
uint8_t  waiter_mode;      // highest mode any waiter needs
uint16_t pad; uint32_t pad2;
uint64_t last_modified_ms;
uint64_t yield_to;         // bitmap: priority nodes for next acquire (anti-starvation)
uint64_t yield_set_ms;     // when yield_to was set
uint8_t  reserved[392];    // pad to 512  (room here for future fields, e.g. an LVB epoch)
```

Resource identity (`struct mxfs_resource_id`, `include/mxfs/mxfs_dlm.h`):
`type` ∈ {`MXFS_LTYPE_AG`, `MXFS_LTYPE_INODE`, `MXFS_LTYPE_JOURNAL`, ...},
plus the AG number or inode number and the volume id. A resource is hashed to a
slot index; `find_slot()` walks a short probe chain to locate the live slot or an
empty one to claim.

> The 65536-slot, 512-B layout is **fixed on disk** (architectural invariant).
> Per-mount caching is capped by `max_held` (default `MXFS_CAW_MAX_HELD = 32768`),
> which must be ≤ 65536. There is ample room in `reserved[392]` to add fields
> (e.g. a version epoch / LVB) **without** changing slot size or table layout.

---

## 4. The DLM — distributed lock manager

### 4.1 Lock modes (`enum mxfs_lock_mode`)

```
NL=0  CR=1  CW=2  PR=3  PW=4  EX=5
```
Standard VMS/DLM lattice. The ones that matter in practice:
- **PR** (protected read) — shared read lock. Multiple nodes can hold PR.
- **EX** (exclusive) — single holder, for modification.
- **NL** (null) — placeholder / not held.

Compatibility: EX excludes everything; PR is compatible with PR/CR but not
EX/PW. (`lock_compat[][]` table in `dlm/dlm_caw.c`.)

### 4.2 Resource granularity

- **Per-AG locks** (`MXFS_LTYPE_AG`) — guard allocation-group metadata
  (free-space btrees, inode btrees, AGF/AGI). AG affinity:
  `preferred_ag = node_slot % ag_count`, so each node tends to allocate from its
  own AG, reducing cross-node AG contention.
- **Per-inode locks** (`MXFS_LTYPE_INODE`) — guard a single inode (and its
  directory data blocks / file content). **Per-inode lock caching is an
  architectural invariant:** once a node acquires an inode lock it *keeps it
  cached* (does not release at op end) until a BAST, eviction, or unmount. This
  is what makes repeat access cheap.

### 4.3 CAW acquire algorithm (`mxfs_dlm_caw_lock`, `dlm/dlm_caw.c`)

For up to `MXFS_CAW_MAX_RETRIES = 100` attempts:

1. `find_slot()` for the resource (or an empty slot).
2. **Empty / -ENOENT** → claim an empty slot: build a fresh slot with our bit set
   in `holders_for_mode(mode)`, `generation=1`, CAS it in (`caw_slot()` =
   read-compare-write on the sector). On CAS miscompare (`-EAGAIN`) retry.
3. **We already hold the mode** (our bit set) → success (with a divergence guard:
   if our bit is set but a peer holds an *incompatible* mode, our bit is provably
   stale → clear it via CAS, untrack, retry through the normal conflict path).
4. **We hold a higher mode** that subsumes the request → success.
5. **Compatible** (no incompatible holder) → add our bit via CAS; success.
   Honors `yield_to` (back off if another node has priority).
6. **Incompatible** → register as a waiter (set our `waiters` bit + `waiter_mode`
   via CAS), send a **best-effort UDP multicast BAST hint**
   (`caw_send_bast_mcast`), then **`caw_wait_for_grant()`** — poll the slot until
   the conflicting holders drain, then loop to acquire.
   - **The acquire path never *steals* a peer's bit.** A waiter waits; the holder
     must release. (Upgrade deadlock is broken by releasing our own lower mode
     first before waiting.)
7. Exhausting all retries → **`-ETIMEDOUT`** (and the inode-lock caller force-
   shuts-down the FS — see §6 invariant). `MXFS_CAW_WAIT_TIMEOUT_MS = 120000`.

There is also a per-INODE **jittered backoff** (`caw_inode_backoff`,
node-phased) to desync CAS storms on a hot slot (added sess39), and a sess50
**anti-starvation** rule: a *fresh* compatible reader will NOT grab a PR if a
peer is already waiting for an incompatible EX/PW (otherwise continuous PR
re-grants starve the EX writer forever — the proven cause of ~60–120 s barrier
stalls).

### 4.4 BAST (release-on-demand): how a holder learns to release

Two channels, one reliable, one fast:

- **Disk poll (reliable backstop) — `bast_poll_fn`.** A per-mount thread that
  every `BAST_POLL_MS` (100 ms, or `BAST_POLL_FAST_MS` 10 ms under contention)
  reads the slots **this node currently holds** (`ctx->held`). For each, if a
  peer has set the `waiters` bit for an **incompatible** mode, it fires the BAST
  callback → the inode is demoted. Because `waiters` is **on disk**, this works
  even if the network is down. *This is the correctness-bearing demotion path.*
- **UDP multicast BAST (fast hint) — `caw_send_bast_mcast` / `bast_recv_fn`,
  port 7602.** Best-effort wake so a holder demotes in ms instead of waiting for
  the next poll. **Not correctness-bearing** — `dlm_caw.h` states plainly:
  *"UDP multicast BAST is the primary fast path; disk polling is just a backup
  for dropped packets."* Unplug the LAN and coordination still works, just
  slower.

`bast_poll_fn` also runs the **SESS50-COHOLD detector** (logs when this node and
a peer hold *incompatible* modes simultaneously — a broken-exclusion bug) and the
**SESS50-STARVE** probe.

> **Network role, precisely:** correctness rests entirely on synchronous disk
> CAW + the disk-polled `waiters` bit. The network (UDP multicast for BAST,
> plus UDP multicast *discovery*) is purely a latency optimization. TCP is an
> *alternate transport* (see §4.7), not part of CAW.

### 4.5 Per-inode in-core lock state machine

Each `struct xfs_inode` carries MXFS fields (`xfs/xfs_inode.h`):

- `i_dlm_mode` (uint8) — cached mode we believe we hold (NL/PR/EX).
- `i_dlm_state` (uint8) — `MXFS_DLM_ISTATE_*`:
  - `NONE (0)` — no cached DLM lock.
  - `CACHED (1)` — lock held, no BAST pending (the fast-path-eligible state).
  - `BAST (2)` — lock held, a peer BAST is pending but *deferred*.
  - `DEMOTING (3)` — flushing/invalidating in order to release for a BAST.
- `i_dlm_ex_holders` / `i_dlm_pr_holders` — local holder refcounts (how many
  threads on *this* node are currently inside the lock).
- `i_dlm_pin_count` — "D9 pin": when >0 an incoming BAST is *deferred* (we are
  mid-allocation holding an AGF, etc.); the token stays held.
- `i_dlm_stale` — set on release/demote; forces a reload from disk on next miss.
- `i_dlm_dir_gen` / `i_dlm_dir_loaded_gen` — directory generation counters (see
  §5.3). `i_dlm_unpublished` — deferred-publish flag (see §4.6).
- `i_dlm_demoter` — the task currently driving `bast_process` (so it can
  re-enter the lock without self-deadlock).

**Acquire entry point: `mxfs_dlm_ilock_begin(ip, mode)`** (`xfs/xfs_mxfs_dlm.c`),
called from `xfs_ilock()` before the VFS rwsem:

1. Single-node mount → bypass (no cluster work).
2. **Fast path** (under `i_dlm_lock` spinlock): if `i_dlm_mode` already
   satisfies the request *and* (for directories) `state == CACHED`, just bump the
   holder count and return — **zero disk I/O**. (Directories are "dir-strict":
   they require `state == CACHED` to fast-path, because a dir mutation slipping
   through during a demote window causes a peer to read a stale dir.)
3. **Slow path:** wait out any `DEMOTING`, then `mxfs_v5_dlm_inode_lock()`
   (CAW round-trip). On success: set `i_dlm_mode`, mark `i_dlm_stale`, **reload
   the inode from disk** (`mxfs_dlm_reload_inode`) when it had populated state,
   bump `i_dlm_dir_gen` for dirs, **drain-evict stale cached dir data blocks**,
   set `state = CACHED`. On failure after retries: **force-shutdown**
   (`SHUTDOWN_CORRUPT_INCORE`) — proceeding uncoordinated would corrupt shared
   metadata.

**Release/demote: `mxfs_dlm_bast_process(ip)`** — the heart of invariant #1:

1. `filemap_write_and_wait` + `invalidate_inode_pages2` (flush & drop page cache).
2. `i_dlm_stale = true`.
3. Set `i_dlm_mode = NL` **under spinlock, BEFORE the on-disk unlock** (so a
   concurrent fast-path can't see a now-released lock as held).
4. For dirs: a bounded **durability drain** loop — wait until the dinode AND its
   dir DATA blocks are no longer pinned / in-AIL / in-flight (drive per-AG pushes
   each round). Only then proceed. **Never release while still dirty.**
5. `mxfs_v5_dlm_inode_unlock()` clears our on-disk bit; set `state = NONE`.

### 4.6 Deferred publish (new-inode optimization)

When a node *creates* a new inode (`IGET_CREATE`), `mxfs_dlm_grant_local_new`
grants it **EX locally only**: `i_dlm_mode = EX`, `state = CACHED`,
`i_dlm_unpublished = true`, placed on the `m_mxfs_unpub_list` — **with no on-disk
CAW slot**. The real on-disk slot ("publish") is acquired lazily, only when an
incoming BAST arrives (`mxfs_dlm_publish_unpublished`). The intent is to avoid a
CAW round-trip for short-lived files that never get shared.

> **This optimization is a known correctness hazard** (see §11): an unpublished
> inode has no on-disk slot, so a peer that reaches it (e.g. via a cached parent
> dirent) acquires the empty slot *cleanly* and never BASTs the creator → both
> nodes believe they hold EX → broken mutual exclusion. A backstop (sess107)
> forces a real on-disk acquire when an unpublished dir is modified.

### 4.7 Transport selection (CAW vs TCP)

- **Joining an existing cluster:** adopt whatever transport the live peers use
  (no choice).
- **Forming a new cluster (no peers in a 3 s discovery window):** try **CAW
  first**; if the CAW probe fails (hardware/target doesn't support SCSI CAW
  reliably), fall back to TCP.
- Command-line override (`mxfs.force_transport=1` for TCP) applies **only** in
  the forming-new-cluster case.
- **CAW is the load-bearing primary.** TCP DLM exists but is perf-limited beyond
  ~16 nodes and is not a drop-in replacement. Do not propose replacing CAW with
  TCP or with an asymmetric metadata server (that pivot was explored and
  abandoned — sess67).

---

## 5. Cache coherency mechanisms

Coherency is *the* hard part. Several mechanisms cooperate:

### 5.1 The durability drain pipeline (invariant #1)

**No on-disk DLM unlock until dirty data is flushed.** `bast_process` (inodes)
and `bast_work_fn` Phase 2 (AGs) must complete the drain
(`drain_meta_buffers` + `drain_alloc_buflist` + `drain_inode_buffers` +
`blkdev_flush`) **before** the on-disk unlock. Skipping any step lets a peer read
stale data (the "Mode A" regression family). For directories the drain explicitly
covers the dir DATA blocks (not just the dinode), including cross-AG dir extents.

### 5.2 FUA reads (forced fresh reads from the platter)

The LIO/SCST iSCSI target **drops the SCSI FUA bit**, so a normal read can be
served from a stale target-side cache. Workaround:
`mxfs_pal_scsi_read_fua_bdev` issues an explicit **SCSI READ(16) with FUA** via
the PAL. XFS buffers carry an `_XBF_FUA_FRESH` flag to gate which buffers get the
FUA treatment (so we don't FUA-read everything). A `fua_disable=1` mode (sess94)
uses plain reads where the transport has been proven byte-coherent across
initiators.

### 5.3 Directory generation counters (`i_dlm_dir_gen` / `i_dlm_dir_loaded_gen`)

The mechanism that lets a node lazily refresh a *cached* directory whose blocks a
peer modified:

- `i_dlm_dir_gen` is bumped **(a)** on a slow-path DLM acquire of a dir, and
  **(b)** when the **DIR_MODIFY eviction-ring** hint from a peer is consumed.
- `i_dlm_dir_loaded_gen` is set to `i_dlm_dir_gen` whenever we (re)load the dir
  from disk (`mxfs_dlm_reload_inode`).
- The block-dir read path (`xfs_da_read_buf`) **lazily invalidates** a cached dir
  DATA block whose stamp is older than `i_dlm_dir_gen` (clear `XBF_DONE` +
  `_XBF_FUA_FRESH` under `XBF_TRYLOCK`, guarding against dirty/pinned/delwri
  buffers — clearing DONE on a dirty buf would trip a CORRUPT_INCORE shutdown),
  forcing the sanctioned read path to cold/FUA-fetch the peer's committed block.
- A slow-path dir acquire also runs `mxfs_dir_drain_evict_data_blocks` to refresh
  cached blocks proactively.

> **The weakness:** the *delivery* of "a peer modified this dir" is the **lossy
> eviction ring**. If a reader misses the ring entry, its `i_dlm_dir_gen` is not
> bumped and it serves stale dir blocks. The reliable disk truth is the CAW slot,
> which a cached holder doesn't re-read. Closing this gap (a version epoch / LVB
> *in the CAW slot*, compared during the acquire that already happens) is the
> current most-promising direction (see §11).

### 5.4 Publish-before-notify (writer durability ordering)

On commit of a dir/inode mutation, the writer performs (while holding EX):
`log_force` + `bwrite` each dir DATA block + `blkdev_issue_flush` **before**
bumping any peer's gen via the eviction ring (`mxfs_dlm_dir_durable_signal`,
called in `xfs_remove`/`xfs_create`/`xfs_rename`). This guarantees a peer that
later refreshes reads a *durable* image — it fixed the case where a peer's
cold-read returned an image missing the writer's own not-yet-flushed change.

### 5.5 Inode-reuse coherency (eviction ring, INODE_FREE)

When an inode number is freed and reused, a passively-caching peer (NL-cached,
no DLM grant) could serve the stale prior incarnation (wrong type/content). The
`INODE_FREE` eviction-ring entry flags any NL-cached copy `XFS_ISTALE_CAW` so the
next lookup re-reads the (possibly recycled) dinode. Cache-miss reads in
`xfs_iget_cache_miss` also invalidate a stale inode-cluster buffer for multi-node
mounts (so a reused inode's allocation becomes visible).

---

## 6. Architectural invariants (never violate)

1. **No on-disk DLM unlock without a completed drain pipeline** (§5.1).
2. **CAW slot table is fixed at 65536 × 512 B on disk.** `max_held` ≤ 65536.
3. **Disklock node slot 0..63 is unique per live node.** Two nodes on one slot =
   corruption.
4. **No direct kernel API outside `pal/`.** `dlm/`, `tools/`, `mxfs_clayer/`
   must build in user space too; everything OS-specific routes through
   `mxfs_pal_*`.
5. **Per-inode lock caching** — hold until BAST/eviction/unmount.
6. **Per-node journal slices** — a survivor replays a dead node's journal.
7. **A failed mandatory DLM acquire force-shuts-down the FS** rather than
   proceeding uncoordinated (better a clean shutdown than silent corruption).

---

## 7. Fencing, liveness, recovery

- **Heartbeat** (`disklock`): each node writes its HB slot every 2 s; peers read
  the HB area for liveness. `DEAD_THRESHOLD = 31` missed beats → dead.
- **Lease** (`dlm/lease.h`): time-bounded membership; expiry triggers recovery.
- **SCSI PR fencing** (`dlm/scsipr.h`): SCSI-3 Persistent Reservations to fence a
  dead/partitioned node off the LUN (three-layer fencing = SCSI PR + disk
  heartbeat + DLM).
- **Mount-time purge:** on mount, a node scans the CAW table for a `dead_mask`
  and clears dead nodes' holder/waiter bits (`P-H22-PURGE-MASK`), batched in
  32 KiB chunks.
- **Journal replay:** a survivor replays the dead node's XFS log slice
  (`MXFS_MSG_JOURNAL_RECOVER` / `_DONE`).

---

## 8. Build, deploy, test

### 8.1 Build

```bash
cd /src/mxfs
make modules         # build mxfs.ko (kernel 6.8.0-101-generic, Ubuntu 24.04)
make tools           # build userspace tools
make clean && make modules   # when changes span .c + .h (incremental can leave a stale .ko)
modinfo mxfs.ko | grep srcversion   # build identity (always verify what you deployed)
```

The full kernel source is at `~/src/linux/` (6.19.0-rc0) — **never download
kernel source**; read XFS reference code there.

### 8.2 Test cluster

- 4 KVM guests **test1..test4** (the v5 cluster; mxfs.1 uses test17..test32).
  All nodes UTC; the dev host shell may be CDT — use `date -u`.
- The repo is **NFS-exported to the nodes at the same path `/src/mxfs`**, so a
  freshly built `mxfs.ko` is visible to all nodes immediately (no copy). The
  criteria/`reset4.sh` helpers `insmod /src/mxfs/mxfs.ko` on each node.
- Shared LUN = `/dev/sda` (SCST iSCSI target — supports SCSI CAW, unlike LIO),
  mounted at `/mnt/shared`.
- SSH helper: **`tools/mxfs_sshpass.sh <host> <PASSFILE> <cmd>` — THREE args**
  (a 2-arg call hangs on a password prompt and *looks* like the node wedged).
  Pass file at `/tmp/.mxfs_pass`.
- Recover a wedged node via libvirt: `virsh -c qemu:///system destroy testN &&
  virsh -c qemu:///system start testN` (NOT the default session URI).

### 8.3 Reset / run

```bash
tests/reset4.sh 4                 # teardown + fresh mkfs + mount on test1..test4
scripts/cluster_reset.sh          # robust reset (retries rmmod-busy)
tests/run_tests.sh --nodes 4 --phase cluster --test <name> \
    --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared
tests/criteria/verify_ship.sh             # the ship gate (stops at first FAIL)
tests/criteria/verify_ship.sh --status    # last result per criterion (from .criteria_results.json)
```

A **clean full reboot** (`virsh destroy`+`start` all nodes) before trusting any
*slow* result — stale orphaned processes / contaminated cluster state produce
false failures. Per-iteration foreground waits (≤10 min each), not a backgrounded
batch.

### 8.4 Userspace tools (`tools/`)

- `mkfs_mxfs <dev>` — format (writes the envelope + XFS region).
- `chk_mxfs -v <dev>` — fsck **and geometry** (agcount/agblocks/isize). Use this,
  not `xfs_info`, for AG-distribution / inode-span analysis.
- `resize_mxfs` — grow (claims new device space; current impl is offline).
- `caw_verify` / `fua_verify` — transport sanity checks.

---

## 9. The success criteria (ship gate)

`SUCCESS_CRITERIA.md` defines 12 criteria across CORRECTNESS, SCALE,
PERFORMANCE, ROBUSTNESS, TOOLING. Each has a verifier under `tests/criteria/`
that prints `RESULT: PASS|FAIL criterion=... measured=... threshold=...` and
records to `.criteria_results.json`. The gate is green only when
`verify_ship.sh` exits 0 with **every** criterion PASS in **one** end-to-end run.

**Timing is a first-class correctness concern:** "slow" is a failure, not just
overhead. Coherency must be prompt (~ms), not eventually-consistent. A 100×-over-
single-node result is a ship FAIL even if it eventually returns the right answer.
Never widen a threshold to mask a real failure.

Current state: **11/12 PASS.** The holdout is `cache_coherency`.

---

## 10. `cache_coherency` — the criterion and its sub-tests

`tests/criteria/cache_coherency.sh --nodes 4` does **one** fresh 4-node mount,
then runs four cluster sub-tests in sequence on that mount (state accumulates):

1. **`test_cross_visibility`** — nodes create files; peers must see them.
   *(currently PASS)*
2. **`test_rename_visibility`** — concurrent same-dir renames; result must be
   coherent. *(currently PASS — fixed via publish-before-notify + the deferred-
   publish backstop)*
3. **`test_unlink_visibility`** — all nodes create 30 files each in ONE shared
   directory (~120 dirents → block/leaf-format dir), each node deletes its own
   files + `sync`, then every node `lstat`s all 120 expecting `ENOENT`.
   *(currently FAIL)* — failure signature: a node still **sees a peer's
   durably-deleted dirent** ("file unexpectedly exists"), i.e. a stale cached
   directory data block on the reader (a PR-mode lookup).
4. **`test_cross_write_read`** — each node writes a 1 MB file + a tiny `.md5`
   sidecar + `sync`; peers read round-robin and verify md5. *(currently FAIL)* —
   failure signature: a node reads a peer's **small file as empty content** (the
   file exists, `cat` returns empty), i.e. a stale cached inode-cluster / `di_size=0`.

---

## 11. The remaining bug: read-side coherency under CAW (deep dive)

This is the active blocker. The proven picture (RULE 4 — instrumented, not
guessed):

### 11.1 Two failing mechanisms, one family

- **`unlink_visibility`** = **read-side directory-block staleness.** A reader's
  cached dir DATA block still holds a dirent that a peer durably removed. The
  reader's `lstat`/readdir (PR) serves the stale block.
- **`cross_write_read`** = **read-side inode/content staleness.** A reader's
  first read of a peer's small file (cache miss → slow path) reloads from a
  **stale inode-cluster buffer** (cached `_XBF_FUA_FRESH` from a prior cycle,
  `di_size = 0`).

Both are the same family: a reader serving a stale cached view of metadata a peer
durably changed, because the *notification* of the change (the disklock eviction
ring) is **lossy**, and the reliable channel (the CAW slot) is not consulted on
the paths that serve stale data.

### 11.2 P106-STALE-EX (directly probed, accurate)

On the dir-EX fast path, verifying the on-disk CAW slot with `caw_held()` (reads
the slot, checks this node's mode bit — accurate) returns **held=0 while in-core
`i_dlm_mode == EX`, `state == CACHED`** (`unpub=0`, `pin=0`). It fires ~11×/run
on the busiest node. Meaning: **a node believes it holds EX (cached, no BAST
pending) on a dir inode whose on-disk slot it does NOT hold.** Since the acquire
path never steals (a waiter waits), and the demote path sets `i_dlm_mode = NL`
before clearing the on-disk bit, this state implies a *re-acquire-then-lose* race
or a third path that clears the on-disk bit without resetting in-core state. The
next fast-path op then RMWs/reads a stale cached block with no real exclusion →
the lost update / stale read.

### 11.3 The starvation failure mode

Under sustained hammering, a **PR-read CAW acquire times out (`-110` ETIMEDOUT)
→ force-shutdown** (a reader can't get the shared lock because a peer holds EX and
never releases within the window). Bounded handoff fairness (re-transmitting the
demote request / using the existing `waiters`/`yield_to` bits) is needed so
readers never `-110`.

### 11.4 What has been tried and keeps regressing (~sess79–108)

- **Per-op FUA re-read of all dir blocks** on every cached dir re-acquire →
  TIMES OUT `rename_visibility` (>180 s). The timing wall: per-op full-FUA
  refresh is far too slow at 4-node scale. (sess43)
- **Drain/evict-on-acquire schemes** that skip in-AIL/dirty/pinned blocks (to
  avoid CORRUPT_INCORE when clearing DONE on a dirty buf) — but skipping a
  transiently-pinned stale block leaves it stale → lost update. (sess101)
- **Keying refresh on the lossy eviction ring (`i_dlm_dir_gen`)** — misses cases
  where the ring entry wasn't observed by the reader (the lossiness itself).
- **A per-op `caw_held()` guard on the dir fast path** (this session, build
  `EED6A769`, probe tag `P108-REACQUIRE`): correct in principle (verify on-disk
  truth before trusting a cached lock; demote in-core to NL/NONE if not held so
  the slow path re-acquires + reloads) **but re-introduces the timing wall** —
  adds a 512 B slot read to every dir op; the contended unlink delete-phase went
  slow. *Wrong shape; to be removed in favor of the epoch.*

### 11.5 The promising direction: a version epoch (LVB) in the CAW slot

Endorsed by both the GFS2/OCFS2 precedent and a Gemini design consult. Replace
the lossy ring with the **reliable on-disk slot**:

- Carve a `uint64_t version_epoch` from `mxfs_caw_lock_slot.reserved[392]` (no
  slot-size / table-layout change).
- **Writer at release** (after the §5.4 durability flush, as part of the CAS that
  clears its EX/PW bit): `version_epoch++`. Record locally.
- **Reader at acquire** (the slot read it already does): if
  `slot.version_epoch > ip->i_dlm_epoch`, invalidate cached metadata (dir DATA
  blocks for dirs; the inode-cluster buffer / `di_size` for files), then set
  `ip->i_dlm_epoch = slot.version_epoch`.
- Cost: **zero extra I/O** — the epoch rides the acquire round-trip, and a
  refresh happens *only once* after an actual peer change (subsequent acquires
  see an equal epoch and skip). This is the GFS2 "never trust a cached lock the
  DLM hasn't versioned" principle, realized on disk.

To make it bite for a **cached holder** (which doesn't re-read the slot), it must
compose with **reliable demotion**: when a peer takes EX, the holder must be
demoted (→ NONE → next access is a slow-path acquire that reads the epoch). The
reliable demotion channel already exists — the disk-polled `waiters` bit
(`bast_poll_fn`); the open question is closing whatever race lets a holder keep
`state=CACHED` after losing its on-disk slot (the P106 condition), e.g. an
intermediate `RELEASING` state that prevents a fast-path re-grant from racing a
mid-flight release.

### 11.6 Reproducers & probes

- `tests/reset4.sh 4`, `tests/repro_rename_concurrent.sh`, `tests/char_rename.sh`,
  `tests/cwr_repro.sh`, `tests/uv_disktruth.sh`, `tests/dirvis_probe.sh`.
- Probe tags to grep in `dmesg` (gated behind `mxfs.instr` where noisy):
  `P106-STALE-EX` (stale cached EX), `P106-EXGRANT`/`EXREL` (cross-node EX
  window), `P107-PUBLISH` (deferred-publish backstop firing), `P108-REACQUIRE`
  (this session's on-disk-truth guard), `P-DIR-SEQ` (dir acquire/release
  sequence), `SESS50-STARVE` / `SESS50-COHOLD` (starvation / broken exclusion),
  `CAW-DUP-SLOT` (same resource in >1 live slot), `P-H22-PURGE-MASK` (mount-time
  dead-node purge).

---

## 12. Subsystem map & where to look

| Area | Files |
|---|---|
| Inode DLM, fast/slow path, BAST, reload, dir-gen, deferred publish | `xfs/xfs_mxfs_dlm.{c,h}` |
| CAW slot table, acquire/release, BAST poll, anti-starvation, fencing purge | `dlm/dlm_caw.{c,h}` |
| DLM facade, inode/AG lock/held/unlock, eviction-ring bridges | `dlm/v5_mount.c`, `dlm/mount.h` |
| Disk heartbeat, eviction ring, node slots, liveness | `dlm/disklock.{c,h}` |
| Lease / membership | `dlm/lease.{c,h}` | 
| SCSI PR fencing | `dlm/scsipr.{c,h}` |
| Peer discovery (UDP multicast) | `dlm/discovery.{c,h}`, `dlm/peer.{c,h}` |
| Journal slicing / replay | `dlm/journal.{c,h}` |
| On-disk envelope / super | `include/mxfs/mxfs_super.h`, `tools/mkfs_mxfs.c` |
| FUA reads, buffer cache glue, block dev | `pal/xfs_buf.c`, `pal/` |
| Mount / module init / super ops | `pal/xfs_super.c` |
| Dir read-time invalidation hook | `xfs/libxfs/xfs_da_btree.c` (`xfs_da_read_buf`) |
| Inode cache-miss / reuse coherency | `xfs/xfs_icache.c` (`xfs_iget_cache_miss`) |
| Criteria verifiers | `tests/criteria/*.sh` |
| Per-session lessons (deep history) | `~/.claude/projects/-src-mxfs/memory/sessNN_lessons.md` + `MEMORY.md` index |

---

## 13. Design tensions to keep in mind

- **`_XBF_DELWRI_Q` collision.** MXFS queues fresh cluster buffers to
  `pag_mxfs_alloc_buflist` with `_XBF_DELWRI_Q` already set; xfsaild's
  `xfs_buf_delwri_queue` then returns false and parks items in `XFS_ITEM_FLUSHING`
  forever. Distinguished by `_XBF_MXFS_ALLOC_QUEUED` (MXFS-managed vs
  xfsaild-managed).
- **ILOCK held across CAW poll.** Upstream XFS holds inode/dir ILOCK across alloc
  paths that bottom out in a CAW poll (up to 120 s). If the held inode lives in
  the AG a peer is BAST-ing, the peer's xfsaild can't trylock and the AIL drain
  wedges. Mitigated by dropping dp ILOCK across `xfs_dialloc` in `xfs_create`;
  the same pattern may recur in the file-write alloc path.
- **Coherency vs timing.** Every coherency mechanism must be ~ms. FUA storms /
  per-op full refreshes hit the timing wall. The epoch-in-slot approach is the
  attempt to get reliability without that cost.
- **Deferred publish vs correctness.** The new-inode local-EX optimization
  trades a CAW round-trip for a mutual-exclusion hazard; it needs the publish
  backstop (and arguably a proactive publish at commit) to be safe.

---

## 14. One-paragraph summary

MXFS is XFS forked onto a shared LUN, with cluster coordination injected into
XFS's lock/buffer/inode paths and backed by a disk-resident DLM. Locks are
512-byte CAW slots in an on-disk table (before the XFS region in the envelope);
acquire/release is SCSI compare-and-write, demotion is driven by a disk-polled
`waiters` bit (UDP multicast is only a speed hint, never required for
correctness). Per-inode locks are cached until a BAST; releases flush dirty data
before unlocking (invariant #1); writers publish durably before signaling peers;
FUA reads defeat the target's dropped-FUA cache. The single remaining failure is
read-side cache coherency: a reader can serve a stale cached dir block or inode
because the *notification* of a peer's change rides a **lossy** disk ring while
the **reliable** channel (the CAW slot itself) isn't consulted on those paths.
The fix under construction is a GFS2-style **version epoch (LVB) inside the CAW
slot**, compared on each acquire, composed with reliable demotion — closing the
gap without the per-op I/O that has repeatedly hit the timing wall.
