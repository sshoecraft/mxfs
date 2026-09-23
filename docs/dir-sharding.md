# Symmetric directory sharding — design (sess436, stage 1-2 shape sess463)

Status: stage 1 is landed and, since 0.64.24, healthy on the rig; stage 2 is
unbuilt and the sharded path stays opt-in.

**Off by default, behind two switches.**  `mkfs.mxfs` sets neither on-disk gate
(XFS sb incompat bit 29, envelope `MXFS_FORMAT_F_DIRSHARD`) unless given `-D`,
and a format without them can never hold a sharded directory: the mkdir path
refuses on `mxfs_dirshard_enabled()`, the inode verifier rejects a PARENT or
CONTAINER flag, and `chk_mxfs` reports one as an error.  Independently, the
module refuses `MXFS_IOC_DIRSHARD_MKDIR` with `-EOPNOTSUPP` unless the
`dirshard_mkdir_enable` parameter is set, which covers volumes formatted before
the gates became optional (every one of them carries both).  The gates stay
optional rather than removed because a gen-18+ node that meets a sharded
directory must still understand it.  Sharding harnesses prep with
`MXFS_MKFS_OPTS=-D` and set the parameter themselves.  Whether sharding actually removes
the pace is still UNMEASURED — see "What is still unmeasured" below, and do not
read the sharded columns of the 0.64.7 matrix as an answer.
Owner defect: D-32NODE-SHARED-DIR-CREATE-PACE
(and its board face D-CRASH-CONSISTENCY-FLEETWIDE-BARRIER-TIMEOUT-401).
Design-consult rulings: `docs/rulings/symmetric-directory-sharding-design.md`
(overall shape, below) and `docs/rulings/dirshard-stage1-2-concrete-shape.md`
(the concrete stage 1-2 shape, "Stage 1-2 concrete shape" section).

Since sess463 this design is on the critical path of
D-FOREIGN-REPLAY-UNGATED-IMAGES: that record's "board clean" criterion was
ruled literal, and the only red row left is crash_consistency, which fails
on this pace defect (105/105 checks pass, budget exhausted).  The 90 s
budget is unchanged (budget); the fix is this design.

## Why

Measured on 0.41.8 at 32/caw (`docs/perf.md`, sess436):

| workload | wall | test9 INODE acquire sum |
|---|---|---|
| 32 nodes × 100 O_SYNC creates into ONE directory | 70-100 s (FAIL) | 72 s |
| same, one private subdirectory per node | **17 s (PASS 32/32)** | 1.7 s |

The single directory inode's EX lock rotates node to node at a ~20 ms floor
per handoff (adopt + dir re-read ~6 ms, release drain ~10 ms, transfer ~7 ms);
the `inode_mht_ms` batching quantum only chooses whether the serialized cost
is the handoff or the holder's own O_SYNC latency (sweep: 0/10/50 ms FAIL,
300 ms PASS at 86 s).  Unsharded, the best case is ~20-30 s.

The user directive of sess68 (`docs/history/decision-reversal-stay-v5-port-mxfs1-coherency.md`)
bars an asymmetric metadata server and any per-operation network RTT: MXFS
stays symmetric shared-disk.  The only symmetric fix that removes the
serialization is more lock domains per directory — sharding.

## Shape (v1)

- A **logical directory** is one VFS/XFS directory inode (the visible parent)
  whose entries live in **N shard containers**: real XFS dir2 directory
  inodes, DETACHED from the namespace (never a named child), referenced only
  by a **manifest** owned by the parent.
- `N` fixed at mkdir (benchmark 32 and 64); no online resharding; no
  conversion of populated directories in v1.
- Routing: `shard = H(seed, name-equivalence-key) mod N`; seed, hash id and N
  are durable in the manifest; names equal under XFS lookup semantics
  (casefold) must hash identically.
- Locks: an ordinary mutation takes the parent's DLM lock in **PR** (pins the
  manifest generation) and the target shard's DLM lock in **EX**; lookups
  take parent PR + shard PR.  The parent's **EX** is reserved for barriers
  (fsync, rmdir, manifest changes, repair) — it must never be taken per
  create, or the hotspot is merely moved.
- **Per-shard summary** (mtime/ctime, change counter, child-directory count,
  accounting) updated in the SAME transaction as the dir2 mutation; the
  visible parent's stat is synthesized as base + aggregate under one manifest
  generation (i_version monotonic, timestamps by a monotonic rule,
  `nlink = 2 + Σ child dirs`).
- **Parent fsync** is a cross-shard barrier: parent EX → recall/drain every
  shard authority that may hold pre-barrier changes → dir buffers and
  summaries home → force every relevant local/foreign log slice → manifest
  durable → release.
- **Lifecycle** `ALLOCATING → COMPLETE → PUBLISHED → DELETING → FREE`, every
  reference `ino + gen + shard UUID`; the parent name is published LAST;
  recovery resumes/frees ALLOCATING and never exposes an incomplete set.
- **Child directories** inside a shard have a logical `..` = visible parent;
  cycle checks, getcwd, exportfs parent reconstruction and parent-pointer
  records are virtualized to the logical namespace.
- **Rename** inside one parent across shards = one XFS transaction under both
  shard EX locks in canonical order (NOREPLACE/EXCHANGE honoured);
  cross-parent rename = global canonical lock order, one transaction or a
  durable replayable intent — never remove+add.
- **readdir** merges shards one at a time under shard PR; cookies either a
  proven bit partition or a per-open cursor; internal objects never returned.
- **Incompatible feature bit** in the MXFS superblock envelope; `mkfs_mxfs`
  and `chk_mxfs` understand the manifest (one shard per index, markers,
  ino/gen match, name-in-right-shard, summaries == contents, aggregate
  nlink, no unreferenced internal shards).

Rejected by the ruling: per-dir-block locking over unchanged dir2 (leaf/free/
node blocks are shared, XFS helpers assume the inode ILOCK), sticky
node-private dir blocks (no sound index), hidden named subdirectories as
shards, high-bit cookies without proving the bit width.

## Build order (each increment rig-measurable, gate stays opt-in until 6)

0. Instrument the handoff (per-tenure ops, force reason/duration, unlock CAS
   attempts + poller count, adopt/FUA reads) and land only the
   sequence-proven optimizations (redundant-force skip, poller reduction,
   cached-copy validity by generation+epoch).  `P138-ACQ/ACQSUM/BAST` and
   `tests/cc_tenure_modesplit.py` already give most of the decomposition.
1. Feature bit + manifest + shard marker + `mkfs_mxfs`/`chk_mxfs` support +
   cleanup of unpublished sets.  Crash after every write; inode-reuse and
   stale-table tests.  No namespace use yet.
2. Opt-in sharded mkdir (mount option / ioctl): regular-file create, lookup,
   unlink, readdir, per-shard summaries, stat synthesis, internal filtering.
   Rig: 32 × 100 O_SYNC creates at N=16/32/64 with uniform, common-prefix,
   sequential and adversarial names — target near the 17 s baseline.
3. Durability: parent fsync barrier, per-shard durable sequences, dead-node
   handling, foreign-slice replay integration, crash matrix per stage.
4. Rename and hard links, staged; crash at every boundary.
5. Child directories and ancestry (logical `..`, derived nlink, dir rename,
   cycles, rmdir under 32-node creates, getcwd, exportfs).
6. Ecosystem: quotas/project inheritance, ACL/labels, xattrs, notify, export,
   backup, scrub/repair, freeze.

## Stage 1-2 concrete shape (sess463 ruling)

Verdict on the sess463 proposal: directionally acceptable, NOT code-ready as
proposed.  The invariant every ordinary operation must satisfy: **logical
parent pinned in PR + exactly ONE shard lock**; no metadata server, no
per-operation RPC.  Three explicit objects carry the design:

1. **Manifest pin** — parent DLM PR; the PUBLISHED manifest is immutable
   under it; a validated, cached shard table.
2. **Physical-directory resolver** — canonicalize + hash the name, internal
   iget of the shard with generation/owner check, take that ONE shard lock
   (PR for lookup, EX for mutation), return `{logical parent, physical
   shard}` BEFORE transaction setup.
3. **Parent barrier** — true parent DLM EX; blocks pins.  Used for the
   lifecycle transitions, rmdir/emptiness, parent-core metadata (chmod,
   chown, project, ACL, xattr, timestamps, flags), fsync, repair,
   resharding.

### On-disk identity: private flags + manifest xattr (no metadir tree)

- Two newly allocated MXFS-private `di_flags2` bits, **container** and
  **sharded parent** — audit the free bits first (do not assume bit 6); update
  every `XFS_DIFLAG2_ANY` user, formatter, copy/bulkstat/scrub path.
- Flags are legal only when the MXFS incompat sb bit, the envelope flag and
  the protocol generation agree, and only in clustered mode.
- The manifest is a reserved ROOT-namespace xattr on the visible parent.
  Fields: magic, version, exact length, `N ∈ {16,32,64}`, hash id, 128-bit
  hash key, set UUID, state, parent `{ino, gen}` binding, entry table of
  `{ino, gen}`, entry count / validity bitmap, reserved-zero, explicit
  length + digest.  Byte order specified; versioned.
- **Verifier split.**  The dinode verifier enforces dinode-visible facts
  only: container = `S_IFDIR` + container flag, requires the feature, is not
  also a parent, legal fork formats; parent = `S_IFDIR` + legal attr fork.
  `nlink == 1` on a container is a scrub check, not a verifier assertion
  (deletion/recovery pass through transient values).  Manifest validity is a
  separate `mxfs_dirshard_manifest_load()` under the parent lock: magic,
  version, exact length, N, hash id/key, set UUID, state, no duplicate inos,
  valid inos, nonzero gens, entry count consistent with state (COMPLETE and
  PUBLISHED have exactly N; ALLOCATING has a committed prefix or bitmap),
  parent ino+gen binding, reserved zero, digest.
- **Do NOT make generic `xfs_iget` refuse containers** (scrub, replay and
  inactivation need it).  Containers never have dirents (one found by lookup
  is corruption); exportfs/open-by-handle reject them; bulkstat, enumeration,
  handle, scrub and repair get explicit policies; an internal
  `mxfs_dirshard_iget()` validates `{ino, gen, flag, owner set}`.
- Hash: keyed strong hash — SipHash-2-4 with the per-directory 128-bit key
  from the manifest (crc32c + a public seed is adversary-weak).  Route on the
  exact canonical key dir2 comparison uses; `mkfs_mxfs` has no asciici today,
  so that is the exact bytes, but the manifest carries `name_canon_version`.

### Lifecycle (unlinked ALLOCATING parent as the anchor, transactionally closed)

- Each shard: allocate the container AND append `{ino, gen}` to the manifest
  in ONE transaction.  "Allocate, then append in the next transaction" is
  REJECTED — there is never a committed container with no manifest reference.
- Publication is one transaction: add the visible dirent, remove the parent
  from the unlinked list, normal link state, COMPLETE → PUBLISHED.
- Deletion is restartable: parent unreachable and unlinked-anchored, state
  DELETING; per entry verify `{ino, gen}`, free the container, atomically
  clear/mark the entry; the parent is freed LAST.  Restart distinguishes
  still-owned / already free / freed-and-reused (generation check ⇒ "already
  gone"; never free the new inode, never fatal).
- Unlinked-inode processing calls a shard-aware inactivation BEFORE generic
  truncate/free.  The foreign replayer: true parent DLM EX, load+validate the
  manifest, each container under its own authority, resume cursor, parent
  last.  Crash injection after every transaction boundary is part of the
  stage-1 test.

### Routing and locks

- The global ILOCK_EXCL → DLM PR remap is REJECTED (chmod/chown/ACL/xattr/
  project/timestamps/flags/repair/rmdir legitimately modify the parent core).
  Introduce explicit modes `MXFS_DIR_PARENT_PIN` (parent DLM PR, manifest
  immutable) and `MXFS_DIR_PARENT_BARRIER` (parent DLM EX); native
  ILOCK_EXCL is unchanged (= DLM EX).  Sharded create/lookup/unlink take pin
  + one shard lock explicitly; never infer the distributed mode from
  ILOCK_EXCL.
- Do NOT redirect inside `xfs_dir_createname` (too low: manifest load, iget,
  DLM acquire, ilock and ijoin there break reservation/join/lock
  assumptions).  Add an upper dispatch layer: pin → load manifest →
  canonicalize+hash → iget+lock shard → set up the transaction with the SHARD
  as the physical `dp` → call the unchanged dir2 primitive.  Lookup must not
  ijoin.
- Timestamps: the shard core changes; the parent core is not dirtied;
  getattr synthesizes into kstat ONLY (never copies synthesized values into
  the parent in-core inode); includes the parent's own core ctime.
- nlink with a container baseline of 1: `logical nlink = 2 + Σ(container
  nlink − 1)` (NOT −2).  A child directory's `..` is the visible parent, so
  child create/remove needs special handling (shard summary changes, parent
  persisted base nlink unchanged); generic `xfs_dir_add_child` cannot simply
  be handed the shard.
- True parent EX for: rmdir/emptiness (parent EX + all shards in canonical
  order + remove dirent + enter deletion atomically), chmod/chown/project/
  ACL/xattr/timestamps, manifest repair, fsync barrier, resharding,
  lifecycle transitions.
- Lock order (documented + lockdep before stage 2): (1) parent pin/barrier;
  (2) shard inode locks by ino/resource number; (3) target inode locks per
  XFS rules; (4) AG DLM / AGI / AGF in the established order.  Never iget or
  take a shard DLM lock while holding AG DLM/AGI; resolve and lock the shard
  before the inode-allocation section.

### stat, readdir, dcache

- stat is O(N): measure the cold path (N=64 × ~6 ms rebuild).  mtime/ctime =
  max(parent core, shards); define `st_size` and `st_blocks` policy.  No
  per-node "never go backwards" clamp (nondurable, skew-prone).  A folded
  `i_version` sum is not a monotonic change attribute — use a documented hash
  cookie or a durable logical sequence later; never the sole dcache
  mechanism.
- readdir: cookies 0/1 reserved for logical `.`/`..`; skip each shard's own
  `.`/`..`; unpack the logical cookie `{shard idx, local dataptr}`, pass only
  the local dataptr to the shard readdir, repack; 7 index bits or an
  explicit EOF sentinel (index 64 does not fit 6 bits); never set the sign
  bit; llseek/telldir/seekdir, partial buffers and resume at shard
  boundaries; test shortform/block/leaf/node formats including max-size.
- dcache: shard-keyed invalidation events do NOT reach visible-parent
  dentries.  One of: event translation `{shard ino, name}` → `{parent ino,
  name}`; `d_revalidate` that hashes the name to its shard and checks a shard
  change sequence; or negative-dentry lifetime pinned to a cached shard PR
  grant with BAST invalidation.  Cover negative and positive dentries after a
  peer unlink/rename/eviction, event-ring overflow (⇒ invalidate all
  dentries of the affected parents or force revalidation) and a missed
  notification.  STOP-SHIP: the board tests readdir/lookup coherency.

### Stage-2 exposure: Model A, strict opt-in

Default OFF.  Activation is narrow (ioctl or inheritance flag), NOT a
mount-wide "shard every mkdir" option — that would shard the rsync per-node
directories and break rename-over-existing.  Unsupported operations fail
deterministically with `-EOPNOTSUPP` (not `-EXDEV`) and never fall through
to the parent's empty dir2 fork.  Directory fsync is either real (parent EX
+ all-shard barrier) or `-EOPNOTSUPP` while the feature is nonproduction.
Child mkdir under a sharded parent: full `..`/summary semantics or refuse.
Model B (board-transparent) needs rename same/cross-shard/over-existing,
sharded↔unsharded rename, hard links, child dirs, rmdir, recreate, fsync
and crash handling — the later stages.  Quota/accounting: shard blocks are
charged to the visible directory's owner/project; containers are not
exposed.

### Ranked STOP-SHIP list (sess463)

1. explicit pin/barrier lock modes; 2. routing above dir2; 3. transactionally
closed lifecycle; 4. dcache correctness; 5. rmdir/emptiness barrier; 6. real
directory fsync before production exposure; 7. nlink formula + child `..`;
8. readdir cookies; 9. feature-bit + verifier audit; 10. namespace coverage
and gating; 11. written lock graph + lockdep; 12. quota/accounting policy.

### Pre-stage-3 rig evidence (N=16/32/64, plus unsharded and private baselines; ≥5 clean runs each)

- Perf: unchanged 32-node workload wall per run, median and worst, per-node
  distribution, 3200 count, cold checksums, zero retries/EIO/verifier
  errors/event overflow.  HARD GATE: every production-default board run
  < 90 s; the explicitly sharded run materially better than 70-100 s; N=32
  near the private baseline — stage gate p95 ≤ 30 s.  Report per N: parent
  DLM EX acquisitions in ordinary ops (expect 0), parent PR + cache hit rate,
  shard EX acquisitions/waits/BASTs/handoff latency, ops per shard
  min/max/sd, shard cold rebuild count/time, log-force/writeback/flush time
  from handoffs, transaction retries, manifest cache misses.
- stat/readdir: warm and cold stat p50/95/99, cold igets per stat, full
  readdir time, small-buffer repeats, telldir/seekdir at every shard
  boundary, all four formats, no duplicate or missing entries, exactly one
  `.`/`..`, peer mutation during readdir.
- dcache: A negative → B creates → A resolves without a drop; positive then
  peer unlink; replace; ring-overflow injection; shard eviction with parent
  negatives; BAST during lookup; drop caches everywhere and repeat.
- Lifecycle crash matrix: kill/fence after every transaction boundary
  (parent alloc/unlinked insert, manifest create, each shard append,
  COMPLETE, publication, PUBLISHED, namespace removal, DELETING, each
  container free/clear, parent free).  After replay: no partial visible
  directory, no lost published directory, no leaked container, no stale
  manifest freeing a reused inode, no parent stuck unlinked, chk clean; AGs
  spread; the allocating node fenced.
- Namespace (if board-enabled): rename incl. cross-shard/over-existing, hard
  links, child mkdir/rmdir + `..` traversal, rmdir+mkdir same name, create vs
  rmdir races, chmod/chown/ACL/project vs peer creates, fsync vs mutations.
  Otherwise prove the narrow opt-in refuses with `-EOPNOTSUPP` and that no
  board directory is sharded.

## Stage 1 implementation decisions (sess464)

Format header: `include/mxfs/mxfs_dirshard.h` (shared by the kernel and
`chk_mxfs`; the structure check is a pure inline so both sides run ONE
implementation).  Decisions taken there and for the kernel module
`xfs/xfs_mxfs_dirshard.c`:

- **Gates.** XFS sb incompat bit 29 (`XFS_SB_FEAT_INCOMPAT_MXFS_DIRSHARD`,
  next to PROTOGATE's 30), envelope `MXFS_FORMAT_F_DIRSHARD` 0x20, and a
  `MXFS_PROTO_GEN` bump 17 → 18 when the feature lands.  `mkfs_mxfs` sets all
  three unconditionally (like PROTOGATE); activation stays per directory.
- **Private inode flags.** `di_flags2` bits 60 (CONTAINER) and 61 (PARENT),
  added to `XFS_DIFLAG2_ANY`.  Audit result: upstream uses bits 0-5;
  `xfs_dinode_verify` does not reject unknown flags2 bits, so the verifier
  additions are ours to write.
- **Manifest placement — AMENDED by the sess464 ruling** (`docs/rulings/dirshard-manifest-block-s3-amendment.md`).
  The sess463 shape put the whole manifest in a ROOT xattr.  With 512-byte
  inodes (what `mkfs_mxfs` formats) a 1120-byte value is never shortform, and
  an in-transaction leaf-xattr write is a deferred attr intent that is atomic
  with the first commit only under LARP (logged ATTRI/ATTRD) — a NEW intent
  type in foreign-slice replay while the intents defect is open.  Rejected.
  Chosen shape S3:
  - the ROOT xattr `mxfs.dirshard` on the visible parent is an immutable
    12-byte **locator** `{manifest_ino, manifest_gen}`, written once in the
    parent's allocation transaction while the attr fork is empty (guaranteed
    shortform and synchronous: `xfs_attr_try_sf_addname` path, no roll);
  - the authoritative **manifest is one fsblock** of an internal HOLDER inode
    (`S_IFREG`, CONTAINER flag, `XFS_ICREATE_UNLINKABLE`, nlink 1), written
    as a LOGGED METADATA BUFFER in the symlink-remote pattern with its own
    block type: header `{magic, offset, bytes, crc32c, uuid, owner, blkno,
    lsn}` + reciprocal `{parent_ino, parent_gen, holder_ino, holder_gen}` +
    the 96-byte manifest header + 16-byte `{ino, gen}` entries (exactly N
    slots; `valid_mask` is the live bitmap, DELETING clears bits and entries
    keep their values for forensics).  Every lifecycle step is `memcpy` +
    `xfs_trans_log_buf` of that block in the SAME transaction as the
    container allocation / publication / deletion step: one commit, zero
    intents.  New `XFS_BLFT_MXFS_DIRSHARD_BUF` (slot 30, high to keep clear
    of upstream) so recovery restores the verifier; the replay authority
    classifier must place the block in the INODE class (it is serialized by
    the parent's inode DLM resource) so the D-0517 token-verdict override,
    not the raw cross-slice LSN compare, decides its replay.
  - Holder containment: no dirent, exportfs/handle refusal, no data-path
    access of any kind (the extent is only ever touched through `xfs_buf`
    with the manifest ops), exactly one mapped block, no COW/reflink, quota
    exempt as internal metadata, never truncated by inactivation for being
    unreachable, `nlink == 1` without a dirent is intentional for
    scrub/`chk_mxfs`.  Feature disabled on a block size smaller than the
    block header plus the N=64 manifest.
- **Container nlink baseline is 2** (the natural empty-directory value from
  `xfs_inode_init`: `.` plus one parent reference), so a container looks like
  an ordinary empty directory to every existing nlink invariant.  Logical
  parent nlink = `2 + Σ(container_nlink − 2)`; the parent's persisted nlink
  stays 2 and is never bumped by child directories inside shards.
- **ALLOCATING anchor.** The visible parent is created like an O_TMPFILE
  directory: `xfs_dialloc` + `xfs_icreate` with `XFS_ICREATE_TMPFILE`
  (nlink 0) + `xfs_dir_init` + `xfs_iunlink`, PARENT flag set, manifest
  ALLOCATING with zero entries — one transaction.  The rmdir'd-but-open
  directory is the precedent for a directory on the AGI unlinked list.
- **Container allocation.** `xfs_icreate` with `XFS_ICREATE_UNLINKABLE`
  (no parent pointer, never a dirent), CONTAINER flag, `xfs_dir_init(ip,
  parent)` so its `..` is the visible parent, then the manifest append via
  the deferred attr replace — one transaction per container, committed
  synchronously only at the end of the set.
- **Publication** is one transaction under the grandparent's and the
  parent's ILOCK_EXCL: `xfs_dir_createname(grandparent, name, parent)`,
  `xfs_trans_ichgtime(grandparent)`, `xfs_bumplink(grandparent)`, parent
  nlink 0 → 2, `xfs_iunlink_remove(parent)`, manifest COMPLETE → PUBLISHED.
  `xfs_link` refuses directories, so this is a dedicated path, not linkat.
- **Ioctls (stage 2 surface, defined with the format).**
  `MXFS_IOC_DIRSHARD_MKDIR` on the parent directory: `{nshards, flags,
  name}` → creates the sharded child atomically (no conversion of an
  existing directory).  `MXFS_IOC_DIRSHARD_INFO` on a directory: state, N,
  hash id, set UUID, per-shard `{ino, gen, nlink}` and, for an optional
  name, its hash and shard index — the cross-check `tests/dirshard_hash_
  vectors.sh` uses against `chk_mxfs --dirshard-hash` and the published
  SipHash-2-4 vector.
- **Userspace SipHash** lives inside `tools/chk_mxfs.c` (the tools Makefile
  lists sources explicitly and is not to be edited); the kernel uses
  `<linux/siphash.h>`.
- **dcache.** `xfs/xfs_mxfs_dentry.c` already revalidates by re-looking the
  name up under the parent's shared lock; under sharding that lookup routes
  through the resolver (pin + shard PR), so coherency comes from the shard
  grant/BAST exactly as it does today for the parent — no event translation
  layer.

## Stage 1 wiring checklist (compiled edits; the module is written unwired)

Files that exist unreferenced as of sess464: `include/mxfs/mxfs_dirshard.h`
(format + pure checks + ioctls), `xfs/xfs_mxfs_dirshard.h` (kernel API),
`xfs/xfs_mxfs_dirshard.c` (verifier, lifecycle, resolver, dispatch wrappers,
ioctls), `tests/selftest/dirshard_format_selftest.{c,sh}`.  To wire them:

1. `xfs/libxfs/xfs_format.h`: `XFS_SB_FEAT_INCOMPAT_MXFS_DIRSHARD (1<<29)`
   into `XFS_SB_FEAT_INCOMPAT_ALL`; `XFS_DIFLAG2_DIRSHARD_CONTAINER/PARENT`
   (bits 60/61, values from the mxfs header) into `XFS_DIFLAG2_ANY`.
2. `xfs/libxfs/xfs_log_format.h`: `XFS_BLFT_MXFS_DIRSHARD_BUF = 30` in the
   BLFT enum (the module pins it to `MXFS_DIRSHARD_BLFT` at build time).
3. `include/mxfs/mxfs_super.h`: `MXFS_FORMAT_F_DIRSHARD` into
   `MXFS_FORMAT_F_KNOWN`; `MXFS_PROTO_GEN` 17 → 18 with a Gen-18 note.
4. `xfs/xfs_mount.h`: `bool m_mxfs_dirshard_env`; `pal/linux/xfs_super.c`
   (envelope validation ~3493-3512) sets it from `msup->flags`.
5. `xfs/xfs_inode.h`: `struct mxfs_dirshard_cache *i_mxfs_dirshard` (NULL at
   inode alloc, `kfree` at inode free in `xfs_icache.c`).
6. `xfs/xfs_inode.c xfs_inactive`: for `S_ISDIR` + PARENT flag + nlink 0 call
   `mxfs_dirshard_inactive_parent()` BEFORE `xfs_inactive_truncate`/`ifree`;
   on error leave the inode on the unlinked list (next pass restarts).
   The unclaimed-bucket sweep (P99-UBSWEEP, survivor side) reaches the same
   `xfs_inactive`, so no second hook is needed — verify on the rig.
7. `xfs/libxfs/xfs_inode_buf.c xfs_dinode_verify`: CONTAINER ⇒ feature
   present, `S_IFDIR` or `S_IFREG`, not also PARENT; PARENT ⇒ feature
   present, `S_IFDIR`, legal attr fork.  Nothing about nlink.
8. `pal/linux/xfs_buf_item_recover.c`: `xlog_recover_validate_buf_type` case
   `XFS_BLFT_MXFS_DIRSHARD_BUF` (magic `MXFS_DIRSHARD_BLK_MAGIC`, ops
   `mxfs_dirshard_buf_ops`); `xlog_recover_get_buf_lsn` case for the magic
   (lsn/uuid from the block header); the mgen veto (refuse an image whose
   mgen ≤ the on-disk block's) alongside the token verdict.
9. `pal/linux/xfs_buf_item.c mxfs_buf_derive_owner`: branch for
   `mxfs_dirshard_buf_ops` + that BLFT → owner = `blk->parent_ino` (the
   authority that wrote the block is the PARENT's inode EX; `blk->owner` is
   the holder, for bmap identity only).
10. `pal/linux/xfs_iops.c`: on a PARENT `dir`, route `xfs_vn_lookup` →
    `mxfs_dirshard_lookup`, `xfs_generic_create` (non-dir, non-tmpfile) →
    `mxfs_dirshard_create`, `xfs_vn_unlink` → `mxfs_dirshard_remove`,
    `xfs_vn_getattr` → `mxfs_dirshard_stat` for nlink/size/blocks/mtime/ctime;
    `mkdir`/`rmdir`-of-child/`rename`/`link`/`symlink`/`tmpfile` under a
    PARENT return `-EOPNOTSUPP` (Model A).  `pal/linux/xfs_file.c
    xfs_file_readdir` → `mxfs_dirshard_readdir`; `xfs_dir_fsync` on a PARENT
    → `-EOPNOTSUPP` until the barrier fsync lands.  `pal/linux/xfs_ioctl.c
    xfs_file_ioctl`: `MXFS_IOC_DIRSHARD_*` → `mxfs_dirshard_ioctl`.
11. `xfs/xfs_mxfs_dentry.c mxfs_drevalidate`: on a PARENT `dp` resolve the
    name to its shard under the pin and look it up there (same lock as the
    real lookup path) instead of `xfs_dir_lookup(dp)`.
12. `xfs/xfs_mxfs_dlm.c`: call `mxfs_dirshard_cache_drop()` when the parent's
    inode grant is released/downgraded (the BAST/release path), so a peer's
    barrier invalidates our cached table with the grant.
13. `pal/linux/xfs_export.c`: refuse handles/`get_inode` for CONTAINER
    inodes; `xfs_itable.c` bulkstat skips CONTAINER inodes.
14. `Kbuild`: `xfs_mxfs_dirshard.o`.
15. `tools/mkfs_mxfs.c`: set incompat bit 29 and `MXFS_FORMAT_F_DIRSHARD`;
    `tools/chk_mxfs.c`: PARENT → locator → holder → block verification
    (`mxfs_dirshard_blk_check` with its own crc32c), CONTAINER inodes never
    named by a dirent, no unreferenced containers, `--dirshard-hash KEYHEX
    NAME` with an in-file SipHash-2-4 mirror; `tests/dirshard_hash_vectors.sh`
    pins tool, kernel (`MXFS_IOC_DIRSHARD_INFO`) and the published vector.
16. Bump VERSION (minor: new feature).

## Stage 1 landed (sess466, tree 0.64.0)

All 16 checklist steps above are applied in the tree; the module compiles
into `mxfs.ko` and the tools carry the gates.  Deviations from the checklist
as written, and the reasons:

- **Step 12 (cache drop with the grant).**  Instead of a hook at each of the
  eleven `i_dlm_mode = MXFS_LOCK_NL` release sites in `xfs_mxfs_dlm.c`, the
  manifest cache records the parent's `i_dlm_epoch` it was loaded under and
  is valid only while that epoch is unchanged (`mxfs_dirshard_manifest_load`).
  Every grant loss bumps the epoch (that is how epoch-stamped dentries are
  invalidated already), so a peer's barrier EX invalidates the table exactly
  as it invalidates the dentries.  `mxfs_dirshard_cache_drop()` remains for
  the barrier-side mutations (publish, teardown).
- **rmdir emptiness (STOP-SHIP 5) — a hole the checklist did not name.**  The
  visible parent's own dir2 holds only `.`/`..`, so `xfs_dir_remove_child`'s
  emptiness test passes on a directory full of files, and the inactivation
  would then free the containers around them (orphaned files).
  `xfs_remove` now calls `mxfs_dirshard_isempty(ip)` for a PARENT before
  `xfs_dir_remove_child`, with `ip` already ILOCK_EXCL (the barrier) and the
  transaction still clean: every live container must be `xfs_dir_isempty`
  (exported from libxfs for this) and `nlink <= 2`, else a clean
  `-ENOTEMPTY`.  `mxfs_dirshard_free_container` keeps its `nlink != 2`
  backstop.
- **d_revalidate (step 11)** goes through `mxfs_dirshard_lookup_ino()`
  (pin → resolver → shard ILOCK_SHARED → `xfs_dir_lookup`) so the lock
  discipline lives in the module.
- **Replay (step 8).**  `mxfs_dirshard_replay_mgen_veto()` runs at
  `mxfs_apply:` in `xfs_buf_item_recover.c`, after the LSN/token decision:
  a manifest image whose `mgen` is not newer than the on-disk block is
  skipped (`P-DIRSHARD-MGEN-VETO`, counted); an image not shaped as the
  module logs it (first dirty chunk not at 0) is named
  (`P-DIRSHARD-MGEN-SHAPE`) and applies on the token verdict alone.  Owner
  derivation (`mxfs_buf_derive_owner`) returns `blk->parent_ino` for the
  block, which places it in the INODE authority class as required.
- **Namespace gating (Model A).**  Under a PARENT: named non-directory
  create, lookup, unlink, readdir, getattr are routed; mkdir, O_TMPFILE,
  link, symlink, rename (either side), case-insensitive lookup, and
  directory fsync return `-EOPNOTSUPP`; rmdir of a child directory cannot
  arise (none can be created).  No board directory is sharded: activation
  is only `MXFS_IOC_DIRSHARD_MKDIR`.
- **6.8 rig kernel:** `<asm/unaligned.h>` before 6.12.

Tools and tests: `mkfs_mxfs` sets sb incompat bit 29 and
`MXFS_FORMAT_F_DIRSHARD` (gen 18 => the fleet re-mkfs's at the next prep);
`chk_mxfs` checks the two gates agree, walks every PARENT (locator → holder
→ block crc/uuid/blkno → `mxfs_dirshard_blk_check` → containers, lifecycle
vs nlink) and reports unreferenced containers (`Directory sharding ......`),
and `--dirshard-hash KEYHEX NAME|hex:HEX` mirrors SipHash-2-4 (published
vector `0xa129ca6149be45e5` verified).  `tests/dirshard_ioctl.py` drives the
ioctls; `tests/dirshard_hash_vectors.sh` pins kernel == chk == vector;
`tests/dirshard_stage1_selftest.sh` is the two-node functional contract
(mkdir N=16/64, PUBLISHED, Model-A refusals, routed create/lookup/unlink/
readdir/stat cross-node, rmdir barrier, 1500-entry multi-getdents listing,
zero `P-DIRSHARD-*` corruption lines); chain 97
(`tests/sess466_chain97_dirshard_stage1.sh`) runs them, unmounts the fleet
for the platter check, then the full 32/caw board.

Still owed before stage 2 exposure: the pace measurement itself (build order
item 2: 32 × 100 O_SYNC creates at N=16/32/64 vs the 17 s baseline), the
directory fsync barrier (build order 3), quota/accounting policy (STOP-SHIP
12), `chk_mxfs` decoding of a non-shortform locator (a parent that later
gained user xattrs) and the "no dirent names a container" walk, the
lifecycle crash matrix, and lockdep evidence for the written lock order.

## Recovery interaction

Shards reuse the per-inode replay and authority-token rules keyed by inode
number and lock epoch; add a manifest/topology authority on the parent, the
manifest generation in shard token validation, and multi-inode transaction
records for cross-shard operations.  The fail-before-purge intent census
(`xfs/xfs_mxfs_icensus.c`) must also count shard-set create/delete intents,
COMPLETE-but-unpublished parents, cross-shard rename intents and orphaned
internal shards (identified by UUID/gen, never by inode number alone).

## 0.64.4 → 0.64.6: two build-level roots before stage 1 ever ran (sess467-468)

Stage 1 as landed in 0.64.0 had never executed one ioctl.  Two roots, both
found by the stage-1 selftest and both invisible to the user-mode format
selftest:

- **0.64.4 — the ioctl dispatch was never compiled.**  The sess466 dispatch
  went into `pal/linux/xfs_ioctl.c`, which is not in `Kbuild`; the module's
  `xfs_file_ioctl` is the `xfs/xfs_stubs.c` stub (GOINGDOWN only), so every
  `MXFS_IOC_DIRSHARD_*` returned `ENOTTY` (chain 97).  The dispatch now lives
  in the stub; `objdump -dr --disassemble=xfs_file_ioctl` must show the
  `mxfs_dirshard_ioctl` relocation, and the chains assert it at install.
- **0.64.6 — step A refused every parent.**  `mxfs_dirshard_locator_set`
  demanded a `LOCAL` attr fork before the shortform add, but
  `XFS_ICREATE_INIT_XATTRS` initialises an *empty `EXTENTS`* fork
  (`xfs_inode_init` → `xfs_ifork_init_attr(ip, XFS_DINODE_FMT_EXTENTS, 0)`);
  `LOCAL` is what `xfs_attr_shortform_create` turns it into on that first add.
  Every `MXFS_IOC_DIRSHARD_MKDIR` returned `EUCLEAN` with nothing logged
  (chain 98b).  The guard is now the invariant the comment always stated:
  precondition `xfs_attr_is_shortform(dp)`, postcondition a `LOCAL` fork with
  no deferred work; both refusals are named (`P-DIRSHARD-LOCATOR-FORK`), and
  a step-A failure other than `ENOSPC`/`EDQUOT` is named at the mkdir
  (`P-DIRSHARD-STEPA-FAIL`) so a silent errno cannot cost another rig lap.

Chain 103 (`tests/sess468_chain103_dirshard_fix_pace_intentsB_ndr_board.sh`)
is the first run in which stage 1 can execute: selftest, platter walk, and
the build-order-2 pace matrix at N=16/32/64.

## 0.64.6 on the rig (sess469 harvest of chain 103)

The stage-1 selftest on the frozen 0.64.6 got past the ENOTTY (0.64.4) and the
EUCLEAN (0.64.5 locator fork) roots: `MXFS_IOC_DIRSHARD_MKDIR nshards=16` now
returns rc=0.  What follows FAILS: `INFO` prints nothing, `mkdir sub` / `ln`
under the sharded parent return `Not a directory`, readdir counts 308 entries,
lookups fail.  The crash_consistency `sharded32` variant then reported `sharded
dir state got=''` and `durable file count 0` on lap 1 (the `.md5` writes hit
`Not a directory`) while lap 2 PASSED 205/205 on the same module — the sharded
parent is usable sometimes and a plain non-directory other times.  Evidence:
tests/evidence/20260902T141126Z_dirshard_stage1, run_crash_consistency_20260902T143454Z
(test1: `P173-RELOAD-SELFREAD ... rd_last=mxfs_dirshard_readdir` with a stack
trace).  Root cause OPEN — see the D-32NODE-SHARED-DIR-CREATE-PACE ledger record.

## 0.64.11: the three stage-1 roots behind "0.64.6 on the rig" (sess470)

Read from tests/evidence/20260902T141126Z_dirshard_stage1, the chain-103 log,
the archived peer kernlog of run_crash_consistency_20260902T141742Z and the
test1 ring of the later cc laps (14:35-14:43Z); test1's own 14:11-14:16Z ring
was gone by the time it was swept.

1. **Creator: no inode operation tables.**  `xfs_icreate` -> `xfs_inode_init`
   installs only `xfs_setup_inode` (mode, mapping); `i_op`/`i_fop` come from
   `xfs_setup_iops`, which `xfs_generic_create` calls itself before
   `d_instantiate`.  `mxfs_dirshard_alloc_parent` / `alloc_container` never
   did, so on the creating node the parent kept the VFS `empty_iops`;
   `d_flags_for_inode()` saw S_IFDIR with no `->lookup` and typed the dentry
   `DCACHE_AUTODIR_TYPE`.  Every walk into the sharded dir, `open(O_DIRECTORY)`
   and every create/mkdir/ln under it returned **-ENOTDIR** on test1 (`cd $D`
   failed, so the selftest's `ls | wc -l` = 308 was the home directory).  The
   peer igets the parent from disk through `xfs_setup_existing_inode` and never
   saw this — which is why the cc sharded laps 2-3 passed while lap 1 (the
   creator's own view right after the mkdir) failed on every N.  Fix: run
   `xfs_setup_iops` on the parent, holder and each container before
   `xfs_finish_inode_setup` (both the success and the release paths).

2. **Peer: `XFS_IGET_UNTRUSTED` against an unlocked inobt.**  Every peer
   readdir/lookup/create returned a bare **-EINVAL**: `xfs_imap_lookup`'s
   "untrusted and free" refusal, answered from the AGI/inobt buffers this node
   last cached — read WITHOUT the AG DLM lock, so the creator's allocation of
   the holder/containers is invisible until the peer next takes that AG.
   Worse, `mxfs_dirshard_free_container` accepted -EINVAL as "already freed",
   cleared the manifest bit and left container 133 allocated with nlink 2:
   chk `ERROR: dirshard: container 133 ... named by no manifest and is not
   unlinked — leaked internal inode`, parent 131 DELETING `valid_mask=0xfffe`.
   Fix: a manifest entry is a dirent (CRC-covered {ino, gen} from a committed
   transaction) and gets the dirent's TRUSTED iget plus the existing identity
   check; `mxfs_dirshard_iget_probe` returns -ENOENT (free) / -ESTALE
   (stranger) and only those two mean "gone" to the deletion path — any other
   error leaves the set on the unlinked list for the next pass (the holder
   probe in `mxfs_dirshard_inactive_parent` no longer treats an I/O error as
   "restart after holder free").  `xfs_imap_lookup` now names both untrusted
   refusals (`P-IMAP-UNTRUSTED-FREE` / `-NOREC`) for the other UNTRUSTED users
   (bulkstat, handles) that share the coherency gap.  Residual: a set whose
   holder's whole inode CHUNK was freed and reused between the holder free and
   the parent free (crash in that window) now fails its restart probe with the
   cluster verifier's -EFSCORRUPTED instead of "gone" and stays on the unlinked
   list; log-visible (`P-DIRSHARD-INACTIVE ... err=-117`), not silent.

3. **Readdir: the container's IOLOCK, and the missing per-shard settle.**
   `xfs_readdir` asserts the directory's IOLOCK (the VFS i_rwsem, held on the
   PARENT by `iterate_dir`); a container has no dentry and nobody holds its
   i_rwsem, so the assertion WARNed (rwsem.h:80) 588 times in eight minutes on
   test1's cc laps.  The parent's i_rwsem IS the container's namespace lock
   (every container mutation runs under it EXCL), so the assertion is skipped
   for containers rather than a redundant nested lock being added.  Separately,
   `xfs_file_readdir`'s two pre-read steps — `mxfs_dlm_dir_consumer_refresh`
   (sess97) and the `i_dlm_stale` reload settle (sess11) — ran on the parent
   only, which holds no entries; the ring showed 20x `P173-RELOAD-SELFREAD
   ino=133 rd_last=mxfs_dirshard_readdir ... caller holds ILOCK_SHARED; reload
   deferred`, i.e. a peer-armed shortform-container reload could only fire
   inside `xfs_readdir` under our own ILOCK_SHARED, where it must bail, and the
   stale inline body was served.  `mxfs_dirshard_shard_settle` now runs both
   steps per container, lock-free, before the per-format lock rule
   (`P95D-READDIR-WAIT ... shard=1`).

Verification: tests/sess470_chain109_dirshard_06411.sh (frozen
tests/evidence/sess470_frozen_06411): stage-1 selftest on test1/test2, dmesg
capture of both nodes (zero WARNING / xfs_assert_ilocked / P-IMAP-UNTRUSTED /
P-DIRSHARD-IGET-FAIL wanted), fleet unmount + chk (errors=0, no leak), then
3 cc sharded16 laps.  Ledger: D-0526 (these three) and
D-32NODE-SHARED-DIR-CREATE-PACE (the campaign).

### 0.64.12: the design-consult review of the 0.64.11 fix (sess470)

GPT reviewed the three fixes before they reached the rig and returned three
stop-ship items, all landed in 0.64.12:

- **Probe classification.**  "Gone" is only *another generation* or *our
  generation with nlink 0* (already on an unlinked list — the sweep frees it);
  both return -ESTALE and only those clear a manifest bit in the deletion path.
  Our generation, still linked, but not a CONTAINER (or a PARENT) is a *live*
  inode with damaged metadata: -EFSCORRUPTED, never cleared over — the old
  -EINVAL misreading under a different errno would have reproduced the leak.
- **Locator removed with the holder.**  `mxfs_dirshard_free_holder` now joins
  the parent and removes the locator xattr in the same transaction as the
  holder's unlink (`xfs_attr_removename` shortform path, deferred-intent guard
  as at set time).  A crash between the holder free and the parent free
  restarts through the no-locator branch and never probes a number whose
  chunk may have been freed and reused.  The 0.64.11 residual above is gone;
  chk already accepts the shape (`no locator, nlink 0 — torn allocation`).
- **Cross-node namespace lock, confirmed.**  The container-IOLOCK exemption
  rests on the parent's i_rwsem *and* the parent's inode DLM: every container
  op (lookup/create/remove/readdir) runs under the parent ILOCK_SHARED pin =
  DLM PR, rmdir/inactivation under ILOCK_EXCL = DLM EX, so the substitution
  holds across nodes, not just on one.  Handle-based access to containers and
  the holder is already refused in `xfs_nfs_get_inode` (sess466).

The UNTRUSTED-iget coherency gap itself (NFS handles, bulkstat, the reap
retry, the orphan scan's post-unlock iget) is filed as its own record,
D-0527, with tests/d0527_untrusted_iget_peer.sh as the measurement.

### 0.64.14: the rmdir double unlock (D-0530, sess471-472)

Chain 109's stage-1 selftest on 0.64.12 WARNed once in `mxfs_ilk_note_unlock`
(xfs_inode.c:529) from `rmdir`: `mxfs_dirshard_free_container` and
`mxfs_dirshard_free_holder` joined the container/holder to the transaction
with `XFS_ILOCK_EXCL` — so `xfs_trans_commit`/`xfs_trans_cancel` already
release the ILOCK through `xfs_inode_item_release` — and then unlocked it
again explicitly on both the commit and the cancel path.  That is an
unpaired `up_write` on `i_lock` (P71-UNDERFLOW on the DLM count): a rwsem
released one time too many can admit a second writer beside the next
legitimate holder, or wedge.  Both explicit unlocks are gone; the join owns
the lock.  Verification is the chain-109 shape on the 0.64.14 freeze (zero
`mxfs_ilk_note_unlock` WARNINGs / P71-UNDERFLOW across repeated sharded
rmdir laps).  The same run's selftest FAIL (fails=17) and chk errors were
contaminated by D-0529 (the inactivation-certificate evict check shutting
the fs down on every deferred free, see docs/authority-certificate.md), so
the 0.64.12 stage-1 verdict is void and 0.64.14 is the first clean read.

### 0.64.15 → 0.64.17: the holder-free "deferred intent" refusal (D-0531, sess472)

With D-0530 out of the way, 0.64.14's rmdir reached `mxfs_dirshard_free_holder`
for the first time — and shut the creator down: `P-DIRSHARD-LOCATOR-DEFERRED`,
then `Internal error xfs_trans_cancel` (a DIRTY cancel), then the node lost
its PR key and withdrew (`P277-FENCED-SELF-WITHDRAW`).  The 0.64.12 review
item ("locator removed with the holder") had put the locator's
`xfs_attr_removename` after the holder's `xfs_trans_binval` + `xfs_bunmapi`
+ iunlink and then refused if `t_dfops` was non-empty.  But **freeing the
holder's real extent always queues a deferred extent free** (EFI —
`P3-EFREE-Q` on the holder sits right before the refusal in the log), so the
check fired on every holder free, blamed the locator, and cancelled a dirty
transaction.  The attr fork was never the problem.

What changed:
- **0.64.15** — the shortform check (`xfs_inode_has_attr_fork` &&
  `xfs_attr_is_shortform`) moved BEFORE the first dirty
  (`P-DIRSHARD-LOCATOR-NOTSF`, clean cancel, prints the fork state), and
  `mxfs_dirshard_inactive_parent` prints `P-DIRSHARD-INACTIVE-AF` at entry.
- **0.64.17** — the post-remove check counts `t_dfops` nodes immediately
  around `xfs_attr_removename` and flags only what the remove itself added;
  and it no longer refuses after the first dirty: it alerts and commits (the
  commit finishes any intent with a roll; the no-locator / holder-gone
  restart branches tolerate the split).  The set-time post-checks in
  `mxfs_dirshard_locator_set` — inside the parent's already-dirty allocation
  transaction — were the same latent shape and are now alert-and-commit too.

Rule this leaves behind (design-consult review, sess472): **every refusal that can
cancel a transaction must run before that transaction's first dirty**; after
it, the only honest outcomes are commit or shutdown.  And the "same
transaction, no roll" locator removal is guaranteed only while the parent's
attr fork stays shortform — a user xattr on a sharded parent would make it
leaf-format and the remove would defer by construction; stage 1 must refuse
xattr sets on a sharded parent (Model A) or accept the deferred intent with
idempotent restart branches.  **0.64.18 refuses them**: `xfs_attr_change`
(pal/linux/xfs_xattr.c — every xattr set/remove, POSIX ACL and security.*
included, funnels through it) returns -EOPNOTSUPP with
`P-DIRSHARD-XATTR-REFUSED` on a sharded parent, so the fork stays shortform
by construction and a `trusted.*` remove can never take the locator.

### 0.64.19: the peer's stale cached member shell (D-0533, sess472-473)

0.64.18 was the first build whose stage-1 selftest reached the N=64 stage,
and the PEER's listing of that directory failed `EUCLEAN` while the creator's
was correct.  `mxfs_dirshard_iget_probe` igets each manifest member with
`lock_flags=0`, so a number the peer still has CACHED from a previous
incarnation comes back as a cache hit with no inode DLM acquire and no stale
reload; its old generation then fails the manifest's `{ino, gen}` check
(`P-DIRSHARD-STRANGER ... want_gen=3559689165 have_gen=50462169` x8 — the
old value is the generation of the 16-shard PARENT that number carried before
the rmdir freed it and the next mkdir reused it as a container).  The peer had
cached that parent under a PR grant and released it before the free, so
nothing ever BASTed the shell (`i_dlm_stale` clear) and `xfs_iget_cache_hit`
had no reason to reload.  On the deletion path the same stale shell reads as
"already gone" and the manifest bit is cleared over a live container — the
D-0526 leak shape.

**Fix (`mxfs_dirshard_probe_revalidate`)** — the manifest entry is a stronger
identity than a dirent (it carries the generation), so the arbitration is
exact.  On a generation mismatch only: FUA-read the platter's dinode
(`mxfs_inode_disk_di_size`).  If the platter does not carry the manifest's
generation, BAST the creator once (`mxfs_dlm_force_peer_flush`, a PR
acquire, in case the new dinode is still unflushed under a sticky EX) and
re-read.  If the platter carries it, OUR shell is the stale one: arm
`i_dlm_stale` (src 28) and `mxfs_dlm_reload_inode(expect_ftype)` in the
bounded loop `xfs_lookup`'s P95-SAMETYPE-RELOAD uses, until the in-core
generation equals the manifest's (`P-DIRSHARD-SHELL-ADOPTED`).  A shell that
will not adopt (`P-DIRSHARD-SHELL-UNCONVERGED`) returns `-EBUSY`: neither
"gone" nor corruption, so the deletion path leaves the set for the next pass
and a reader retries.  `mxfs_dirshard_iget`/`_probe` now take `expect_ftype`
(DIR for containers, REG for the holder) so a REG<->DIR reuse passes the
reload's typeflip guard the way a dirent ftype does.  Match case: zero extra
I/O.  The diagnostic `P-DIRSHARD-SHELL` line (have/disk gen, disk mode, DLM
mode, stale src, refcount) prints on every mismatch, so the verification lap
is also the instrumented measurement of the mechanism.

Verification: chain 115 (`tests/sess473_chain115_d0533_dirshard_06419.sh`)
= the chain-109 shape plus `tests/dirshard_reuse_peer_list.sh` — 20 laps of
creator rmdir + sharded mkdir (number reuse) with the peer listing (arm A,
the budget rule < 300 ms) and the peer removing (arm B) the reused directory;
`P-DIRSHARD-SHELL-ADOPTED > 0` is required (zero = the reuse never landed on
a number the peer had cached: vacuous), `P-DIRSHARD-STRANGER = 0`.
The same run's creator-side "N=64 info" failure was the selftest piping the
info tool's header line into `json.load` (step 7 lacked the `sed` filter
steps 1 and 4 use); fixed in the harness.

**design-consult review of the first cut (sess473, STOP-SHIP with 12 findings) and
what 0.64.20 changed.**  Actioned: (1) "adopted" now requires the stale flag
CLEAR, the generation equal AND the in-core type equal to `expect_ftype` (a
bailed trylock reload could otherwise report a half-adopted shell as
converged); (2) the reload wait is short (20 x 10 ms) inside a transaction
(`current->journal_info`) or on the teardown path (parent ILOCK_EXCL + EX
from inactivation) — the reader paths keep the lookup path's 200 x 10 ms;
(3) a platter that holds a LIVE inode of a DIFFERENT generation is never
"gone": `P-DIRSHARD-STRANGER-LIVE` -> -EFSCORRUPTED, which a reader reports
as corruption (a live manifest naming a stranger) and the deletion path
treats as "leave the set for the next pass" (fail closed) — only a platter
that reads FREE after the forced flush is "gone"; (4) readers never see
EBUSY: `mxfs_dirshard_iget` maps the unconverged -EBUSY to -ESTALE (the
revalidate-and-retry contract `xfs_lookup` uses for an unresolved reuse).
Documented, not actioned here (tree-wide design, not this fix): the in-place
reload of a referenced shell is the tree's established same-type reuse
discipline (`xfs_lookup` P95-SAMETYPE-RELOAD); the reload's own
serialization is the trylock + bail contract every `mxfs_dlm_reload_inode`
caller relies on; the parent -> member acquisition order is safe because a
member's BAST/release drain never takes the parent (audit: the release
pipeline drains the member's own buffers only); an older image of the RIGHT
incarnation is acceptable because every caller ILOCKs the member (DLM PR +
normal stale reload) before reading its contents.  Review record: `docs/history/gpt-review-d0533-probe-revalidate.md`.
Review item 8 closed in the same build: `mxfs_inode_disk_di_size` reports a
failed read as `(u64)-1` with the mode left 0, which the "platter FREE"
verdict would have read as GONE — the revalidation now returns -EIO
(`P-DIRSHARD-SHELL-READFAIL`): never gone, never adopted, the deletion path
keeps the set.

### 0.64.21: the peer's stale cached manifest block (D-0534, sess473)

With D-0533's member shells adopting (chain 115 on 0.64.19/0.64.20: 31
`P-DIRSHARD-SHELL-ADOPTED` on the peer, including REG<->DIR type flips, all
in one round), the next stale object in the peer's caches surfaced: the
manifest block itself.  `mxfs_dirshard_blk_read` is a plain
`xfs_trans_read_buf` keyed by daddr; when a new set's holder allocates its
one-block extent at an address the peer cached from a previous set (the same
holder number, freed and reused, lands on the same fsblock once the
busy-extent window closes), the read is a buffer-cache HIT on the old block
(XBF_DONE, never invalidated: a REG holder's data buffer belongs to no
inode-DLM release drain) and `mxfs_dirshard_blk_check` refuses it on the
holder generation — `P-DIRSHARD-CORRUPT ... manifest-block reason=blk_owner
aux=<daddr>` x100 on the peer, EUCLEAN for every listing and for the peer's
rmdir.  The 0.64.20 stage-1 selftest's N=64 stage failed the same way once
the orphaned first run had filled the peer's cache with twenty sets' blocks.
Within one set's life the same hit would serve an OLDER mgen of the right
block to a node that takes the parent EX after a peer's mutation (lost
manifest update) — latent, its own arm in the D-0534 record.

**Fix**: `mxfs_dirshard_manifest_load_slow` — which runs exactly when the
per-parent manifest cache is invalid (first load, parent incarnation change,
grant handoff) and is therefore the block's coherency point — stales a CLEAN
cached buffer at the holder's daddr before the read (`xfs_buf_incore` ->
`xfs_buf_stale` + clear `XBF_DONE`, the `xfs_iget_recycle` pattern:
`P-DIRSHARD-BLK-REFRESH`) and keeps one carrying this node's own
uncheckpointed modification (`P-DIRSHARD-BLK-KEEP`, the P91-RECYCLE-PROTECT
rule).  Verification: chain 115 rerun on the 0.64.21 freeze with the reuse
harness now also failing on any peer `P-DIRSHARD-CORRUPT` and reporting
`blk_refresh` exposure.
0.64.22 factors the refresh into `mxfs_dirshard_blk_refresh` and calls it
from the second reader that starts at the holder's bmap —
`mxfs_dirshard_inactive_parent`'s direct block read (the peer-side rmdir of
a reused set, arm B of the reuse harness); the item-4 audit found no other
plain buffer read in the module (the two `xfs_trans_get_buf` are
allocations).  Chain 115 s473b runs on the 0.64.22 freeze
(sv C2E4707B5C3C4FD80A4C940).

### 0.64.23: the reused shell's phantom attr fork (D-0535, sess473)

With the peer-side teardown working (chain 115 on 0.64.22: laps 1-2 of the
reuse harness passed both arms), the creator shut down on lap 3:
`Metadata corruption detected at xfs_attr_shortform_verify ... attr fork`
from the release drain's flush of the reused PARENT.  Not a dirshard bug
but found through it: `mxfs_dlm_reset_inode_for_create` (a cached shell
reused for a create after a PEER freed the number) dropped the old attr fork
with `xfs_idestroy_fork`, which leaves `if_bytes` behind; the sharded
parent's 32-byte locator fork therefore persisted as a phantom length, the
new incarnation's locator add grew from it, and the header (totsize 32, one
entry) no longer matched the fork.  Fixed in 0.64.23 by zapping
(`xfs_ifork_zap_attr`, the `xfs_ifree` discipline) at that reset and at the
three other in-place attr-fork drops (reload adopt, recycle adopt, dead-shell
reset).  Verification: chain 115 s473c on the 0.64.23 freeze — the reuse
harness's arm B exercises exactly this shape on every lap.  Record:
D-REUSED-SHELL-RESET-LEAVES-ATTR-FORK-IF-BYTES-STALE-SHORTFORM-VERIFY-CREATOR-SHUTDOWN-0535.

## What is still unmeasured

The question this design exists to answer — *does sharding remove the
single-directory create pace?* — has never been measured on a build where
sharding works.

The only full `baseline / private / sharded16 / sharded32 / sharded64` matrix
was taken on 0.64.7, and on 0.64.7 a sharded parent was **not usable as a
directory** (the stage-1 selftest of that era fails: `INFO after mkdir: ''`,
`mkdir` under the parent returns `Not a directory`).  Its sharded columns
therefore measure a directory that never sharded, and they must not be read as
evidence either way.  Every later dirshard run has exercised `sharded16` only,
as a correctness lap, never the matrix.

What the 0.64.7 matrix does establish, and what remains useful, is the two
control columns: `private` passes all three laps at 19-24 s of the 90 s budget,
while `baseline` exhausts the budget on all 32 nodes on its first lap and then
passes laps 2-3 at 21-22 s.  That is the pace defect's shape — it is a
first-lap, cold-directory effect, not a steady-state one — and any candidate
fix has to be judged against lap 1, not against an average.

So the outstanding evidence is a rerun of the full matrix on a build whose
stage-1 selftest passes (0.64.24 or later), with enough laps that lap 1 is not
a single sample.  Until that exists, the pace defect has no measured fix, and
D-FOREIGN-REPLAY-UNGATED-IMAGES stays blocked behind it.
