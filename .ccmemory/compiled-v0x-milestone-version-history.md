---
name: compiled-v0x-milestone-version-history
description: Compiled v0.1-v0.3 milestone build states across MXFS codebase generations (mxfs.2/session-64 rewrite + v5), plus VM-build debugging and v5/v3 projec…
metadata:
  type: project
tags: [compiled, version-history, milestones, vm-builds, project-history, dlm, xfs-format]
---

# Compiled: v0.x Milestone Version History

Shared topic: the early MXFS milestone build states leading up to and into the
v5 (kernel-XFS-fork) line. These notes span **three distinct codebase
generations** that all carry low `v0.x` numbers — do not conflate them:

1. **mxfs.2 line** (`v0.6.0 → v0.9.19`) — session 63 VM-build debugging. Custom
   hand-rolled libmxfs. See [[session63-vm-builds]].
2. **Session-64 rewrite line** (`v0.1 → v0.2.0 → v0.3.0`, 2026-03-18) — a
   ground-up "v0.1 rewrite" that walks real XFS btree structures directly but is
   still the OLD custom `libmxfs/` code (`ops.c`, `alloc.c`, `inode_cache.c`),
   NOT the kernel fork. See [[Session 64 - v0.1 rewrite progress]],
   [[Session 64 final state]], [[Session 64 v0.3.0 final state]],
   [[Session 64 complete state]].
3. **v5 line** (`v0.2.2 → v0.3.36`, 2026-04-25+) — the actual kernel-XFS fork
   under `xfs/` + MXFS DLM overlay; the current project. See
   [[v0.2.X-v0.3.X version history]] and rationale in [[MXFS v5 Project History]].

The `v0.3.0` in generation 2 and the `v0.3.x` in generation 3 are UNRELATED
builds on different code. Watch the date: 2026-03-18 = gen-2 rewrite;
2026-04-25+ = v5.

---

## Why v5 exists — prior-attempt post-mortem ([[MXFS v5 Project History]])

- **mxfs.1** (`v0.14.0`, `~/src/mxfs.1`): 34K-line custom libmxfs, hand-written
  block/inode/dir caches + custom btree + `alloc.c`. Single-node 19/19 PASS, 103
  bugs fixed, CAW DLM battle-tested at 32 nodes. **Fatal flaw: perf.** rsync 29s
  vs native XFS 7s. Root cause (session 71): all metadata I/O was synchronous
  `submit_bio_wait` — 43,000 small sync writes @ ~550µs each. Sessions 72-73
  added writeback caching + batched flush (60s→29s) but still 4× native.
  **Key salvageable asset: the DLM** (`dlm.c` 84K, `dlm_caw.c` 48K).
- **mxfs.2** (`v0.6.0→v0.9.19`, `~/src/mxfs.2`): began as a stacking FS wrapping
  XFS at the VFS layer, morphed into a btree rewrite on the XFS cursor engine.
  Abandoned to scope creep / no direction. (This is the codebase session 63 was
  debugging.)
- **mxfs.3** (`v0.3.2`, `~/src/mxfs.3` = `/src/mxfs.new`): tried to use
  `xfsprogs/libxfs` as the XFS implementation. **Critical mistake** — libxfs is
  the USERSPACE format library (mkfs/fsck/resize), NOT kernel XFS: no iomap, no
  `xfs_buf` async I/O, no page cache, no writeback. Result 45× slower (11.4 MB/s
  vs 509 MB/s).
- **mxfs.4** (inside mxfs.2, sessions 60-62): replaced `alloc.c` with the libxfs
  cursor btree engine → regressed concurrent PVE VM builds (stale dir cache,
  BASTs not firing). Rolled back to `v0.9.18`.

**v5 decision:** fork the ACTUAL kernel XFS from `~/src/linux/fs/xfs/` (6.19.0-rc0)
and put DLM hooks INTO `xfs_buf`/`xfs_icache`, never around them. The async
`xfs_buf.c`, `xfs_iomap.c`, `xfs_log.c`/`xfs_log_cil.c`, `xfs_aops.c`,
`xfs_icache.c` are exactly what made native XFS 4× faster. **Rule: never
reimplement XFS I/O paths.**

---

## Session 63 — mxfs.2 v0.9.19 VM-build debugging ([[session63-vm-builds]])

Ported Bugs 132 (DLM epoch check in `lock_ag`, double-alloc on membership
change), 133 (SB sector-only write in `flush_superblock_counters`), 134
(`recount_counters` from on-disk AGF/AGI for accurate df), 139
(`inflight_lock_ino` clear on DLM retry failure).

Kernel-compat layer added: `MXFS_EFFECTIVE_VERSION` macro (RHEL 9 → 6.2 frontend
/ 6.9 pal-bdev; Debian 12 → 6.1.99), `MXFS_HAS_MNT_IDMAP`,
`MXFS_ACL_BACKPORT_61`, `MXFS_USE_BLOCK_WRITE_FULL_PAGE`; bdev API threshold for
`bdev_file_open_by_path` moved 6.17 → 6.9. Verified builds: clyde (6.8), serv
(5.10), pve2 (6.17), Debian 12 (6.1), AlmaLinux (5.14/RHEL 9). New node Debian 12
`192.168.120.155` (kernel 6.1.0-39, iSCSI `/dev/sdb` 50GB QNAP LUN).

- **`FALLOC_FL_ZERO_RANGE`**: QEMU `detect-zeroes=on` calls it; we returned
  `-EOPNOTSUPP`. Routed to `punch_hole` (both zero). Key fix: ZERO_RANGE does NOT
  require `KEEP_SIZE` (unlike PUNCH_HOLE).
- **Bug 140 (io_uring race)**: QEMU io_uring submits write + fallocate
  simultaneously to the same file; two threads mutate `ci->extents` with no
  mutex → corrupt binary search + stale data; DLM returns `-EEXIST` on the second
  inode lock. Fix: per-inode `io_lock` mutex in `struct mxfs_cached_inode`, taken
  in `write_bulk` (around `write_pinned`), `mxfs_fallocate`,
  `mxfs_alloc_file_block`, and `flush_inode_to_disk` (guards fsync vs write).
  `-EEXIST` handled with retry in `cache_get_locked`.
- **Bug 141 (stale block data — ROOT CAUSE OF VM FAILURES)**: newly allocated /
  speculatively-preallocated physical blocks hold pre-mkfs garbage (XFS never
  zeroes the data area at mkfs, only metadata). Buffered I/O masks it (page cache
  has zeros via `set_buffer_new`); O_DIRECT reads (QEMU) hit disk directly and
  see old data → GRUB booting empty disk, RPM cpio "Bad file descriptor", guest
  FS corruption. **Temp fix:** `zero_new_blocks()` zeroes every newly allocated
  block before it's readable + `filemap_write_and_wait()` before O_DIRECT
  read/write. **Proper fix (still owed):** unwritten extents — allocate as
  unwritten, return zeros on read, convert-on-write
  (`MXFS_EXTENT_F_UNWRITTEN`/`read_bulk` zero path partially exists). Zeroing
  costs up to 8MB zeros/alloc under speculative prealloc; unwritten extents have
  zero overhead.
- End state: disk-label + grub-on-empty-disk FIXED; RPM scriptlet fix DEPLOYED on
  pve2 but UNTESTED (user went to bed). pve1/pve2 powered off, pve2 has
  v0.9.19+zeroing on fresh mkfs ready to test. Debug `pr_info`
  (DIRECT_WRITE/FALLOCATE/GET_BLOCK/BUFFERED_WRITE) + timing instrumentation +
  `extent.c` INSERT VERIFY still active — strip before release.

---

## Session 64 (2026-03-18) — the "v0.1 rewrite" line

Recovered from a crashed session (`2c198aa3`) via `history.jsonl`. This rewrite
walks real XFS btree structures directly (BNO btree allocator) to eliminate the
double-alloc and CRC-corruption bugs of the old hand-rolled btree. It progressed
v0.1 → v0.2.0 → v0.3.0 in a single day.

### On-disk offset constants nailed down (shared across all four session-64 notes)
Verified correct and reused thereafter:
- MXFS super CRC: `crc32c(~0U, data, len)` — raw, no complement (initial value
  fixed 0 → `~0U`).
- XFS AGF CRC @ offset **216** (was 56); AGI CRC @ **312** (was 56).
- XFS V5 btree block: header **64** bytes, CRC @ **56 (0x38)**, records @
  **64 (0x40)** — mkfs previously wrote records @0x38/CRC@0x34.
- XFS V3 dinode: atime **32**, mtime **40**, ctime **48**, size **56**, nextents
  **76**, forkoff **82**, CRC **100 (0x64)**; core size **176**, data fork @
  **0xB0**. (Shifted from the wrong 30/38/46/54/74/80.)

### v0.1 ([[Session 64 - v0.1 rewrite progress]])
Working: insmod/rmmod, mount/unmount (MXFS+XFS super + AGF/AGI CRC verify), stat,
inline (`FMT_LOCAL`) readdir, df, touch (inobt alloc + shortform dirent), write
(BNO alloc via page cache), read-back. Broken: **persistence** (inode flush
doesn't write back size/extents/times/dir entries → data lost on remount);
DLM in read/write_iter bypassed (taking `i_rwsem` via `generic_file_*_iter` hung
— so those paths use `generic_file_{read,write}_iter` directly);
`free_blocks`/`free_inode` leak; mkdir/rmdir/unlink/rename/block-format-dirs/
xattr(non-shortform) are stubs. Also fixed: DLM typedef → public header, Kbuild,
PAL errno aliases, mount.c PAL API mismatches, `alloc_file_block` direct icache
lookup (no re-lock), FNV-1a hash in `ops.c` matched to `inode_cache.c`.

### v0.2.0 ([[Session 64 final state]])
Single-node COMPLETE: all file ops (create/read/write/stat/chmod/chown/utimes/
truncate/fsync), all dir ops incl. block-format lookup + shortform→block
auto-convert, symlink/hardlink/mknod/rename/unlink, BNO first-fit alloc w/ AG
affinity, bitmap inobt alloc, inode writeback w/ correct dinode CRC @0x64.
**20/20 test battery PASS**, 60+ files/dir, md5 integrity across double remount.
Known issues: DLM bypassed (single-node only); `free_blocks`/`free_inode` leak
(recovered by xfs_repair); CNT btree not maintained (BNO only); xfs_repair
reports CRC errors (functional correctness proven, inconclusive); block-format
`removename` not implemented. Next planned: wire DLM from `mxfs.old` mount.c
lines 1850-2300.

### v0.3.0 ([[Session 64 v0.3.0 final state]] / [[Session 64 complete state]])
DLM wired into every VFS op. New files `libmxfs/cluster.{c,h}` (DLM/peer/
discovery/lease). DLM EX on parent dir for all dir writes; lookup/readdir/getattr
invalidate inode cache; read_iter invalidates + `truncate_inode_pages`; write_iter
flushes page cache + fsync; rename locks BOTH parents. CAW DLM tested working on
iSCSI LUN; TCP DLM also.

Session-64 bug fixes at v0.3.0 (the milestone set):
1. **`truncate_pagecache`** — ROOT CAUSE of both overwrite-corruption AND
   block-free-corruption: setattr didn't invalidate page cache on O_TRUNC, so
   stale pages wrote to freed blocks. Fixed with `truncate_pagecache(inode, size)`.
2. `dfork_size`: `forkoff*8 - core_size` → `forkoff*8` (core_size already
   accounted).
3. xattr persistence: `flush_inode` copies attr fork raw_buf → block buffer.
4. finobt sync on dynamic chunk alloc; inobt CRC magic corrected in
   `xfs_format.h`; dinode field offsets (as above); AGF/AGI CRC offsets 56→216/312;
   btree header 56→64 (CRC@56, records@64); mkfs btree records @0x40/CRC@0x38.

**Final test state:** 23/23 comprehensive single-node (all POSIX + xattrs + mmap
+ flock + space reclaim), 12/12 2-node cluster (cross-node CRUD + modify), 4-node
verified; `chk_mxfs` clean on inobt/finobt/AGF/AGI/superblock. Cross-node build
proof: node1 creates C project → node2 compiles + runs. Test VMs: test7/test8
(single), test4/test5 (cluster).

**v0.3.0 known limitations (carried, still custom-code era):** concurrent
large-file writers (>100 blocks) VFS writeback race; leaf/node dir format
unimplemented (>120 entries/dir); CNT btree not maintained (BNO only, xfs_repair
rebuilds); `free_blocks` DISABLED (freed extent re-inserted into BNO overlaps the
shrunk original → double-alloc; fix = merge-adjacent-on-free or overlap-check
before insert); post-mount cross-node inode reads have stale-VFS edge cases;
cross-node existing-file MODIFY needs extra VFS inode-size refresh (new-file reads
invalidate correctly).

---

## v5 line — v0.2.X → v0.3.36 ([[v0.2.X-v0.3.X version history]])

This is the current kernel-fork codebase (post-mxfs.4). Recurring theme:
per-AG/per-inode DLM coherency, and a long bnobt/AG-meta staleness fight.

### v0.2.X — initial v5 setup
- **v0.2.2**: per-AG delwri fix + peer_joined flush callback + 1.05ms blind delay
  → 20/20 clean-disk 2-node mkdir.
- **v0.2.3**: barrier-bio replaces the delay; Fix A stripped.
- **v0.2.4**: `i_ino==0` early-return guards in all four DLM ilock hooks
  (drop_caches → reclaim hook bug).
- **v0.2.5**: bidirectional AG-metadata coherency. Release defers
  `mxfs_v5_dlm_ag_unlock` via per-buffer `b_iodone` until AG-meta writeback done;
  acquire stales clean AG-meta bufs in `pag_bcache`.
- **v0.2.6**: cross-node dir + inode-free coherency (readdir hook, AG-DLM around
  `xfs_inactive_ifree`, inode-buffer staling, stale-cache reload trigger).
- **v0.2.7**: concurrent-dd hang FIXED — `mxfs_ag_dlm_lock` held `pag_dlm_lock`
  across the CAW poll (up to 120s); new `pag_dlm_acquire_lock` serializes
  fresh-acquires.

### v0.3.X — cached-AG DLM era (OCFS2-style)
- **v0.3.0** (2026-04-25 night): last-holder sets `pag_dlm_cached=true` instead of
  releasing; peer BAST → `mxfs_dlm_ag_bast_work_fn` drains + releases.
- **v0.3.1** inode-cluster buffer staling on fresh AG-acquire even when
  `b_li_list` non-empty. **v0.3.2** force inode reload on
  `iget_cache_hit`+multinode+CREATE. **v0.3.3** DLM acquire-failure handling.
- **v0.3.4/v0.3.5** bast_process deadlock fixes: `i_dlm_demoter` task tracking;
  set `i_dlm_mode=NL` BEFORE unlock, reorder `ilock_begin` cached-mode fast-path
  before the DEMOTING wait.
- **v0.3.6** cross-instance disklock stale-slot purge (snapshot HB timestamps,
  wait 10s, purge non-advancing slots).
- **v0.3.7 REVERTED by v0.3.8** — bast_work serialization via
  `pag_dlm_acquire_lock` caused AG starvation; net code = v0.3.6.
- **v0.3.9** AG-bast demoting state machine (`pag_dlm_demoting` +
  `pag_dlm_demote_wq`).
- **v0.3.10** AG-bast pre-flush (`xfs_log_force(SYNC)` +
  `xfs_ail_push_all_sync` + `blkdev_issue_flush`) before claiming demote slot;
  closes free-inode-not-marked-free family.
- **v0.3.11** CAW slot-table tombstone fix (`MXFS_CAW_TOMBSTONE_MAGIC=0x4D58444C`;
  find_slot skips tombstones, release writes them).
- **v0.3.12 REVERTED** bast_process NL-first for dirs (wrong placement).
- **v0.3.13** Bug A closed — dir-strict fast-path requires `state==CACHED`.
- **v0.3.14 WRONG SITE** (fixed v0.3.16): helper in `xfs_iget_cache_hit`
  IGET_CREATE block, rarely hit due to drop_caches between iters.
- **v0.3.15** CAW deadlock closed — TOCTOU between
  `mxfs_v5_dlm_inode_lock` success and state publication; publish `i_dlm_mode`
  immediately on success.
- **v0.3.16** Bug B residual closed — gate `mxfs_dlm_reload_inode` on
  `i_mode!=0 || i_nblocks!=0`; skip disk read for fresh ip.
- **v0.3.17** (P14-INSTR): AGI SKIP-on-bli-attached empirically wrong. Surfaced
  Mode A (dir-fork stale-on-disk) and Mode B (CAW slot exhaustion AG=1).
- **v0.3.18** (P15-INSTR): **priority-2 root cause** —
  `xfs_alloc_vextent_finish` calls `mxfs_ag_dlm_unlock` BEFORE trans commit;
  alloc→unlock→peer BAST→unlock_disk→peer reads stale→both alloc same range.
- **v0.3.19** alloc-path AG-DLM defer to `xfs_trans_free` (new `t_mxfs_ag_unlocks`
  list); 5/5 PASS was a lucky pass.
- **v0.3.20** free-path also needed the defer (`__xfs_free_extent` still did
  immediate unlock); iters 1-4 clean, iter-5 surfaces inode-side family.
- **v0.3.21** clear `XFS_AGSTATE_AGF_INIT`+`XFS_AGSTATE_AGI_INIT` in
  `mxfs_dlm_invalidate_ag_meta` → forces pag refresh; bnobt-corruption family
  closed; 15-iter soak fails iter-4 on `agi_unlinked[]` staleness (H1).
- **v0.3.22** H1 closed — `xfs_iunlink` (INSERT) wasn't acquiring AG-DLM; wrap
  with `mxfs_ag_dlm_lock` + deferred unlock. Soak iters 1-6 PASS, iter-7 fails
  bnobt-vs-AGF on-disk disagreement.

### Sess17-19
- **Sess17 DIAGNOSTIC**: hypothesis (b) RULED OUT — 100% of bnobt/cntbt/inobt/
  finobt P14 verdicts are STALED, no SKIP. CAW grant-divergence hypothesis:
  MXFS-level state diverges from CAW `holders_ex` bitmap.
- **Sess19 v0.3.29**: `mxfs_dlm_ag_drain_meta_buffers` filter at
  `xfs_mxfs_dlm.c:1337`. Old filter `list_empty_careful(&bp->b_li_list)` is ALWAYS
  empty for AG-meta bufs (`b_li_list` only holds inode/dquot items); new filter
  accepts bufs whose bli is in AIL. Priority-2 bnobt sub-race closed.
- **Sess19 v0.3.36**: 1 of 3 stress runs hit 15/15 PASS (first ever). Approach A
  (per-trans inode-DLM defer list) scaffolded for next session.

### v5-era standing lessons
- Any new `xfs_trans` field MUST be initialized in BOTH `__xfs_trans_alloc` AND
  `xfs_trans_dup`; skipping dup deadlocks via NULL-list iteration on the
  rolled-trans path (sess15).
- Deferred-unlock symmetry: adding deferred-unlock at one site requires auditing
  ALL `mxfs_ag_dlm_unlock` call sites — alloc/free symmetry isn't obvious (v0.3.19
  missed the free path).
- Synchronous waits in bast_process are dangerous: `xfs_buftarg_wait`, per-buf
  `xfs_buf_lock`, and `xfs_buf_lock` on shared cluster bufs all deadlock (multiple
  sess16 reverts).
- CLEAN rebuild when a change spans `.c`+`.h`: `make clean && make modules` —
  incremental builds leave a stale `mxfs.ko` (burned an hour in v0.2.6).
- Diagnostic timing pressure is a regression source: each `pr_warn` batch perturbs
  the race window (sess12 iter-4 → sess13+P14 iter-3 → sess14+P14+P15 iter-1).
  Strip ALL diagnostics before benchmarking.
- Log-capture gotcha: `truncate -s 0` on a file held by an open writer creates
  sparse NUL padding before subsequent appends (~91% NULs in sess17). Use
  `screen -dmS`, not `nohup` via sshpass, for `dmesg --follow` across disconnect.
- Verify list semantics before filtering: AG-meta bufs use `b_log_item` directly,
  not `b_li_list` (sess19).
