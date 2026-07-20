# sess55 — Gemini architectural design for the NL-cached inode-reuse coherency root

**Date:** 2026-06-03 (sess55)
**Status:** DESIGN (not yet implemented). Obtained via `mcp__ask_gemini__query`
with `max_tokens` OMITTED (full default budget → `finish_reason: STOP`,
output 1815 tok / thoughts 11963 / total 14551 — complete, untruncated).

This is the fix for the blocker that has defeated sess40/48/52/53/54: the
`cache_coherency` / `cross_visibility` failure. PROVEN root (sess54): MXFS
caches in-core inodes / dcache / dir-blocks at **NL (no DLM grant)**. The
disk-polled CAW bast-poll thread only scans slots THIS node HOLDS, so a peer's
free/realloc/dir-modify NEVER BASTs an NL-cached holder → stale metadata served
forever. Invariant violated: *the VFS cache (dentry/inode/page/dir-block) must
be a projection of DLM state — never serve cluster-visible metadata without a
covering grant* (the GFS2/OCFS2 glock model).

Two observed failure faces (sess54):
- **Failure A** — inode-number REUSE type confusion. A peer freed inode N (was a
  DIR), this node reused N as a new reg file + wrote data; a PEER still holds a
  LIVE in-core cached inode of the OLD type (S_IFDIR) and serves it → `cat
  node3.txt` → "Is a directory" (EISDIR); `xfs_dir3_data_reada_verify` reads the
  reg-file data block as a dir block (non-fatal verifier error). dmesg:
  `INODE-REUSE-EVICT ino=6291584 incore_ftype=2(DIR) dirent_ftype=1(REG)`.
- **Failure B** — a file invisible even to its OWN creator. Concurrent
  shortform→block dir conversion lost-update on the shared parent dir: a node
  mutates a STALE cached shortform copy and drops a peer's just-committed entry
  on conversion.

## Constraints (do not relearn — proven across sess45-54)
- NO ILOCK_EXCL across the CAW poll (xfsaild AIL-drain wedge).
- NO in-place reload under ILOCK in path-walk lookup (D-state deadlock, sess45).
- NO per-op FUA / per-op DLM poll in the hot read/lookup path (barrier markers
  are empty files hit constantly → 120s barrier timeouts).
- instr=1 logging HIDES the race (100x slowdown) — use always-on detectors.
- Keep drain-before-unlock invariant (durable on DLM release).

---

## Gemini's design — 3-part mechanism

### Part 1 — CAW side-map invalidation ring (core fix for inode free+reuse → Failure A)

- **On-disk:** a dedicated `CAW_EVICT_RING` block in the CAW LUN metadata area —
  a ring of `{ino, gen}` entries with a `head_seq`.
- **Producer (node freeing the inode):** in `xfs_ifree()`, append `{ino,
  new_gen}` to an in-memory staging array; do NOT block — let the existing CAW
  disk heartbeat thread flush it, coalesced with normal slot updates. Zero
  fast-path I/O.
- **Consumer (passively-caching node):** in the existing `caw_poll_thread()`,
  read the ring, diff `head_seq` vs local tail, and for each entry do a lockless
  `radix_tree_lookup` on `pag_ici_root`; if the inode is incore at NL,
  `set_bit(XFS_ISTALE_CAW)` and queue a **background workqueue** item to do
  `d_prune_aliases` + `xfs_irele` — crucially OUTSIDE `xfs_iget`/ILOCK, which is
  what avoids the wedge.
- **Ring-wrap overflow** → fall back to a background sweep dropping all NL-cached
  inodes.

### Part 2 — VFS-layer staleness trap (closes the sub-poll-interval race)

- Move detection OUT of `xfs_iget` (where it deadlocks under ILOCK) and INTO
  `xfs_vn_lookup()` — there you hold the parent's `i_rwsem` but NOT the child's
  ILOCK.
- Check `XFS_ISTALE_CAW` OR the existing ftype mismatch; if stale, `xfs_irele` +
  `d_prune_aliases` + bounded retry. No DLM poll, no ILOCK → xfsaild stays free
  and peer-durability can't wedge it for 120s.

### Part 3 — "invisible to its own creator" (concurrent shortform→block dir conversion → Failure B)

- Different root: dir mods do NOT free the inode, so they never hit the ring.
- Fix at the **DLM lock-grant completion callback** on NL→PR / NL→EX: on upgrade
  from passive, you must invalidate the incore dir format — force a SYNCHRONOUS
  inode-cluster re-read (`xfs_iread_extents` / `xfs_trans_read_buf`) to refresh
  `di_format` / `i_size` BEFORE any transaction takes ILOCK. Safe because it runs
  inside the lock-acquisition state machine, before XFS ILOCKs.

---

## Why this matches our hard constraints
- No per-op DLM polling (ring is read by the existing CAW poll thread).
- No ILOCK_EXCL in the read/lookup hot path (eviction is a background worker; the
  VFS trap runs under parent i_rwsem only).
- The 120s peer-durability wait is sidestepped: eviction moves to a background
  worker + the VFS-lookup trap, instead of blocking the lookup on the peer's
  iflush.

## Implementation order (highest leverage first)
1. **Part 1** — `CAW_EVICT_RING` producer in `xfs_ifree()` + consumer in the CAW
   poll thread. Highest-leverage for the `cache_coherency` blocker (Failure A).
2. **Part 2** — VFS-layer staleness trap in `xfs_vn_lookup()` (move/extend the
   current `xfs_lookup` ftype-evict logic; add `XFS_ISTALE_CAW` check).
3. **Part 3** — synchronous dir-format re-read in the DLM NL→PR/EX grant callback
   (Failure B).

## Key code anchors (sess55 reconnaissance)
- Current consume-side point patch (to be superseded/extended by Part 2):
  `xfs/xfs_inode.c:701-738` `xfs_lookup` INODE-REUSE-EVICT (ftype mismatch →
  force_peer_flush + i_dlm_stale + d_prune_aliases + irele + retry_iget, bounded
  4×). It FIRES but the stale inode is exposed to VFS/dir-readahead before/around
  the evict, and falls through if a dentry can't be pruned.
- `d_revalidate` = `mxfs_drevalidate` at `pal/linux/xfs_super.c:1786`, wired via
  `s_d_op = &mxfs_dentry_operations` (L1965). Currently compares inode NUMBER
  only — does NOT catch same-number reuse (Failure A) and returns "valid" for
  own-AG positive dentries.
- `mxfs_dlm_reload_inode` `xfs/xfs_mxfs_dlm.c:1097` calls `xfs_inode_from_disk`
  (reparses shortform inline dirents) — so reload, IF it fires, refreshes
  correctly. Part 3's grant-callback re-read is where to wire the dir-format
  refresh.
- CAW poll thread + slot scan: `dlm/dlm_caw.c` (bast poll fn ~L1446 area, per
  sess50). Producer side: `xfs_ifree()` in `xfs/xfs_inode.c`.

## sess55 REFINEMENT — on-disk placement decision (resolves Part 1's biggest unknown)

Gemini's "dedicated CAW_EVICT_RING block in the CAW LUN metadata area" would need a
NEW on-disk region, which means a **mkfs format change** (shifts `xfs_data_offset`,
breaks existing filesystems). The disklock region is fully consumed: `[super 4KB]
[journal 64MB][disklock 32MB][XFS data]`, and disklock = 32KB HB (64 slots × 512B) +
32MB slot table (65536 × 512B, a FIXED layout invariant — can't shrink). No slack.

**Better placement (sess55 decision): embed the ring in each node's HEARTBEAT
record.** `struct mxfs_disklock_heartbeat` (dlm/disklock.h:67) is 512B with a
`reserved[472]` field. Every node ALREADY writes its own HB slot every
`MXFS_DISKLOCK_HB_INTERVAL_MS`=2000ms, and peers ALREADY read the whole HB area for
liveness (`node_track[]`, `mxfs_disklock_get_stale_slot_mask`). So:

- **Per-node ring in `reserved[472]`:** a small header `{uint32 evict_head_seq;
  uint16 evict_count; uint16 pad;}` + an array of `{uint64 ino; uint32 gen;}` (12B
  each) → ~38 entries/node in the remaining ~464B. Each node publishes its most
  recently freed inodes in its OWN HB record (single-writer per slot → no CAW
  needed, the HB write is already a plain sector write).
- **Producer:** `xfs_ifree()` → `mxfs_dlm_note_inode_freed(mp, ino, new_gen)` →
  routes to disklock ctx, appends to an in-mem staging ring + bumps a dirty flag;
  the existing HB thread serializes the ring into `reserved[]` on its next write
  (or force an immediate HB write for latency). Zero fast-path I/O.
- **Consumer:** extend the HB-scan side (bast_poll_fn `dlm/dlm_caw.c:2460`, or the
  disklock HB monitor) — for each PEER slot, diff peer `evict_head_seq` vs our
  per-peer last-seen tail; for each new `{ino,gen}` do lockless
  `radix_tree_lookup(&pag->pag_ici_root, agino)`; if incore at NL →
  `set_bit(XFS_ISTALE_CAW)` + queue a BACKGROUND workqueue item doing
  `d_prune_aliases`+`xfs_irele` (OUTSIDE xfs_iget/ILOCK). head_seq wrap (peer freed
  >38 since our last scan, or we missed a heartbeat) → fall back to a bg sweep of
  NL-cached inodes in that peer's AG.

**Advantages:** zero mkfs change, zero new on-disk region, reuses the existing HB
write+read machinery and its 2s cadence (already the BAST-poll fallback cadence).
**Trade-off:** ring depth ~38/node and 2s default latency — acceptable because
Part 2 (the VFS staleness trap in xfs_vn_lookup) closes the sub-poll-interval race
synchronously; the ring is the proactive bulk-invalidation, Part 2 is the backstop.

### sess55 LAYERING decision (the consumer can't touch XFS directly)
The HB monitor loop lives in `dlm/disklock.c` (`disklock_hb_fn`, ~L211 producer /
~L236 consumer) which MUST build user-mode too (Arch-Invariant-4). The invalidation
action (`radix_tree_lookup(&pag->pag_ici_root)` + `set_bit(XFS_ISTALE_CAW)` +
workqueue) is XFS-layer and CANNOT be called from disklock.c. So the consumer uses a
registered **callback**, exactly mirroring the existing `expire_cb`
(`mxfs_disklock_set_expire_cb` / `ctx->expire_cb` / `slot_node_id[]`):
- `mxfs_disklock_set_evict_cb(ctx, cb, data)`; `ctx->evict_cb`, `ctx->evict_cb_data`.
- `typedef void (*mxfs_disklock_evict_cb)(void *data, uint64_t ino, uint32_t gen);`
- Consumer in `disklock_hb_fn` monitor loop: after reading peer `rhb`, if
  `rhb->evict.magic==MXFS_EVICT_RING_MAGIC`, diff `rhb->evict.head_seq` vs new
  `node_track[slot].last_evict_seq`; for each new entry call `ctx->evict_cb`.
- XFS registers the cb (in mount, like expire_cb wiring); cb body in xfs_mxfs_dlm.c
  does the radix lookup + XFS_ISTALE_CAW + bg workqueue (the only XFS-touching part).

Producer ctx fields (in `struct mxfs_disklock_ctx`): a small in-mem staging ring
`struct { struct mxfs_evict_entry e[MXFS_EVICT_RING_ENTRIES]; uint32_t head_seq;
uint16_t count; } evict_stage;` + its own mutex (or reuse ctx->lock).
`mxfs_disklock_note_freed(ctx, ino, gen)` appends + bumps head_seq; `disklock_hb_fn`
serializes evict_stage → `hb->evict` (set magic) before each `write_sector_fua`.

New symbols to add:
- `xfs/xfs_inode.h`: `#define XFS_ISTALE_CAW (1 << 16)` (bits 0-15 are ALL used —
  XFS_IPINNED=1<<8 ... XFS_IREMAPPING=1U<<15; i_flags is unsigned long so 1<<16 is
  the next free bit). ADDED sess55.
- `dlm/disklock.h`: ring header/entry structs inside `reserved[472]`;
  `mxfs_disklock_note_freed(ctx, ino, gen)` + a consumer scan hook/callback.
- `xfs/xfs_mxfs_dlm.{c,h}`: `mxfs_dlm_note_inode_freed(mp, ino, gen)` bridge
  (xfs layer → dlm layer, keeps Arch-Invariant-4: no direct dlm API from xfs).

## RELIABLE REPRODUCER (instr=0, ~19s)
```
MXFS_TESTS_DIR=/src/mxfs/tests ./tests/run_tests.sh --nodes 4 --phase cluster \
  --test test_cross_visibility --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared
```
Per-node detail: `~/.mxfs/results/<ts>/test_cross_visibility/nodeN.log`.
Deploy a new build: `MKFS_OPTS=-f bash tests/reset4.sh 4`.
Build under test at sess54: srcversion `C2D30DB0A37A12264B76A35`.
