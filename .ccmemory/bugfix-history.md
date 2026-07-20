# MXFS Bug Fix History

## Bugs 1-28 (chronological)
1. **BAST cache invalidation** — membership_cb drops all caches on peer discovery (dlm.h/c, mount.c, inode_cache.h/c, dir_cache.h/c)
2. **Peer recv thread shutdown** — two-phase: kernel_sock_shutdown before close (pal.h, pal_linux_kern.c, pal_linux_user.c, peer.c)
3. **DLM lock timeout on unmount** — flush caches before NODE_LEAVE, shutting_down flag (dlm.h/c, mount.c)
4. **Extent serialization** — flush_inode_to_disk now serializes extent map to raw buffer (extent.c/h, inode_cache.c)
5. **nextents not updated** — ci->nextents never incremented during writes, flushed as 0 (mount.c)
6. **format field not serialized** — flush_inode_to_disk didn't write ci->format to raw buffer (inode_cache.c)
7. **VFS inode size stale** — mxfs_read_iter used cached i_size without refresh (frontend/linux/file.c)
8. **SCP deploy bug** — scp -r creates nested dirs when dest exists; must rm old + SCP to parent
9. **Node 203/204 insmod** — needs `modprobe libcrc32c` before insmod (crc32c symbol missing)
10. **Dir shortform-to-block upgrade** — flush_block_dir() in dir_cache.c converts SF to XFS block format when entries exceed inline limit (dir_cache.c/h, alloc wired in via set_alloc)
11. **AG affinity from node_id** — node_slot auto-derived from node_id in mount.c when not explicitly set (mount.c)
12. **Dir cache BAST flush for block dirs** — flush_block_dir() called in BAST path for FMT_EXTENTS dirs (dir_cache.c) [Bug G fix]
13. **Peer TCP reconnection** — discovery only fired peer_cb for new peers; after ECONNRESET no reconnect. Fixed: fire for all announcements + join old recv_thread (discovery.c, peer.c)
14. **DLM active node double-counting** — local node added twice to active list (manually + from lease). Fixed: removed manual addition (mount.c)
15. **Inode flush R-M-W race (Bug M)** — flush_inode_to_disk did 4K block R-M-W, nodes clobbered each other's inodes. Fixed: per-inode 512-byte direct write (inode_cache.c)
16. **Dead nodes in DLM active list (Bug N)** — peer disconnect didn't update active_nodes. Fixed: remove_node() helper in mount.c
17. **DLM active node dedup (Bug O)** — dedup after sort in dlm.c update_active_nodes
18. **Dir cache BAST refcount wait** — BAST handler raced with active dir modifications. Fixed: refcount wait loop in dir_cache.c
19. **Eager dir flush (Bug R)** — flush dir to disk immediately after modification, BAST handler just discards cache (dir_cache.c)
20. **Bug S — leaf-format dir detection** — load_dir_from_disk() used size heuristic, failed for 1-data-block leaf dirs. Fixed: check for leaf extent at XFS_DIR2_LEAF_OFFSET.
21. **readdir cache invalidation** — get_dir_mode() PR path never checked lock_gen. Fixed: added lock_gen mismatch check + block cache invalidation in PR path.
22. **Leaf-format extent growth** — flush_leaf_dir() assumed existing data extent large enough for num_data_blocks. Fixed: detect undersized extent, free+realloc larger.
23. **Debug logging in code** — ino 128 specific logging in inode_cache.c and dir_cache.c, remove after fixes confirmed
24. **DLM FIFO grant ordering (Bug T)** — promote_waiters granted in LIFO order (newest waiter first), causing starvation at 32 nodes. Fixed: added `queued_at` to struct mxfs_lock, sort by queued_at. (dlm.h, dlm.c)
25. **DLM batch limit hang (Bug U)** — fixed-size batch arrays silently dropped BASTs/grants beyond 16. Fixed: eliminated ALL batch arrays, replaced with embedded linked lists via `work_next`. (dlm.h, dlm.c)
26. **Bug X — rmdir on non-empty dirs** — nlink > 2 heuristic only caught subdirs. Replaced with actual dir entry scan via rmdir_count_cb() callback (mount.c)
27. **Bug Y — stale dir entries after bulk unlink** — flush_leaf_dir() never shrank extent map. Fixed: parser ci->size limit + extent shrink + block cache invalidation (dir_cache.c)
28. **Bug Z — inode cache self-deadlock** — cache_get_locked() in inode_cache.c enters BAST wait loop when bast_pending=true. If calling thread already holds refcount (nested call, e.g. dir_add_entry → flush_dir_immediate both call cache_get_locked on same dir inode), it self-deadlocks: wait loop needs refcount==0 but outer caller holds refcount==1. Fixed: skip BAST wait loop when refcount > 0 (nested get allowed, BAST completes when outermost put() drops to 0). Built clean on 6.8 — NOT yet built on 6.1 or tested on cluster. Reproducer: 4-node concurrent `touch` (50 files each).

## Bugs 29-41
(Documented in session logs; includes journal replay fixes, 4-node regression fixes, DLM transport flapping (Bug 41), and various multi-node stability improvements.)

## Bugs 42-43 + Architecture Changes (2026-02-20, Phase 5 Scale Testing)

42. **Inode/dir/block cache UAF in drop_all** — pinned entries freed while writers hold references. All three caches (inode_cache.c, dir_cache.c, block_cache.c) skip pinned entries during drop_all; pinned entries marked invalid for deferred cleanup when writer releases.

43. **Peer socket UAF in recv_fn** — socket freed (tcp_close) while recv thread blocking in sk_wait_data. Fixed: shutdown-before-close pattern in 3 locations: accept thread replacement, peer_connect_impl, peer_send failure. (peer.c) Verified: zero crashes across 16 nodes.

### Architecture Change: UDP Lease Renewals
- **Not a bug fix** — scaling improvement to eliminate TCP congestion at 16+ nodes
- Files: libmxfs/lease.c, libmxfs/lease.h, libmxfs/mount.c, pal/pal.h, pal/pal_linux_kern.c, pal/pal_linux_user.c
- Replaced per-peer TCP unicast lease renewals with single UDP multicast send on port 7602 (separate from discovery 7601)
- Added wire format with mxfs_cpu_to_le64/mxfs_le64_to_cpu PAL helpers
- Eliminates N TCP sends per renewal interval; critical for 16+ node clusters where TCP congestion was blocking lease renewals and causing false DEAD declarations

## Bugs 44-48 (2026-02-22, 4-Node Concurrent Metadata Stress)

44. **Dir entry loss race during concurrent multi-node creation** — multiple nodes adding entries to the same directory concurrently could lose entries due to BAST invalidation between read-modify-write. Fixed with lock_gen check in dir_cache.c (Bug 44).

45. **DLM lock timeout causes file loss under heavy contention** — 30s DLM timeout too short for 4-node concurrent directory writes. Increased to 120s. Retry-with-backoff approach reverted after causing duplicate entries and D-state deadlocks (Bug 45, take 2).

46. **Duplicate dir entries during membership change** — membership flap (4→3→4 nodes) during concurrent creates produces duplicate directory entries. Membership callback drops all caches, and in-flight add_entry operations may re-add entries already flushed to disk. (OPEN — low priority until happy-path testing is clean)

47. **Lease renewal starvation under heavy metadata I/O** — UDP recv thread was normal CFS priority while renew/monitor were RT. Under heavy I/O, recv thread starved for 60+ seconds, heartbeats unprocessed. Fixed: upgraded UDP recv thread to RT priority (all 3 lease threads now SCHED_FIFO low). Also increased SUSPECT_MISSES from 6 to 60 (180s before SUSPECT). (lease.c, lease.h)

48. **Inode cache UAF during epoch mismatch eviction** — epoch mismatch handler evicted and freed cached inodes without checking refcount. If another thread held a reference (pinned), the freed memory corrupted nextents to garbage (e.g., 1385570172), causing -ENOSPC from extent serialization. Fixed: if refcount > 0, release stale DLM lock and re-acquire at current epoch in-place, reload from disk. Only evict+free when refcount == 0. (inode_cache.c)

## Bugs 49-57 (2026-02-25/26, Dir Cache Coherency Deep Dive)

49/49b. **Dir cache stale data on lock upgrade** — inode reload on NL→EX didn't cover PR→EX. Dir cache lock_gen check only on miss, not hit. Fixed: reload inode on ANY lock upgrade (Bug 50e); lock_gen check on cache hit regardless of refcount (Bug 50g). (inode_cache.c, dir_cache.c)

50. **Flush-before-drop in membership callback** — dirty caches dropped without flushing during membership change. Multiple sub-fixes (50b-50g) explored; ultimately dir entries are eagerly flushed so the correct action is DISCARD during membership change, not flush. (mount.c, dir_cache.c, inode_cache.c)

51. **DLM dual-EX prevention (send-ordering race)** — LOCK_REQ arriving before LOCK_RELEASE caused "already granted" shortcut to grant EX while another node still held EX. Fixed: state-based detection in handle_lock_request checks for conflicting WAITING/BLOCKED entries from other nodes. (dlm.c)

52. **Direct bdev reads for directory blocks** — block cache held stale dir data blocks across lock bounces. Fixed: bypass block cache for all dir data reads, read directly from bdev. (dir_cache.c)

53. **Node-format dir writeback** — leaf dir overflow at ~502 hash entries truncated instead of growing. Fixed: proper XFS node-format writeback for directories exceeding leaf capacity. (dir_cache.c)

54. **Phantom cached EX lock (pending BAST race)** — DLM promote_waiters grants local lock, but before dlm_lock() returns and creates cache entry, another BAST arrives. bast_cb finds NOT_IN_CACHE, releases the legitimately granted lock as "residual". Node then operates with phantom EX (cached but no DLM backing). Fixed: record pending_bast_ino instead of releasing; cache_get_locked applies deferred BAST after creating the entry. (inode_cache.c, inode_cache.h) **ROOT CAUSE of persistent dual-EX.**

55. **Slab heap corruption from leaked extents/inline_data** — load_inode_from_disk() called on existing ci during lock-upgrade reload overwrote ci->extents and ci->inline_data without freeing old allocations. Leaked objects corrupted SLUB freelist. Fixed: free old allocations at top of load_inode_from_disk(). (inode_cache.c)

56. **complete_bast UAF from concurrent access** — Three sub-fixes: (a) pin ci during epoch-mismatch flush, (b) skip lock upgrade if bast_pending to avoid concurrent ci->extents access, (c) check refcount after complete_bast flush — if another thread acquired reference during I/O window, defer removal. (inode_cache.c)

57. **Remote BAST recv thread deadlock** — remote BAST message processed inline on peer recv thread called complete_bast which acquired cache->rwlock. Concurrent touch thread held rwlock waiting for DLM grant message — which arrived on the same blocked recv thread. Fixed: route remote BASTs through bast_worker_fn thread (same as local BASTs). (mount.c)

58. **Duplicate dir entries during membership change (Bug 46 root cause)** — Two-part fix: (a) Epoch mismatch handler for pinned inodes re-acquired the DLM lock at `requested_mode` (from the current caller) instead of the existing `ci->lock_mode`. When `flush_dir_immediate` (PR caller) triggered epoch mismatch on an inode held at EX by `get_dir_exclusive`, the handler silently downgraded EX→PR, breaking exclusive access. Fix: re-acquire at MAX(existing, requested) mode. (inode_cache.c) (b) `flush_dir_immediate` flushed invalidated dir cache entries (stale subset of directory) to disk, overwriting the complete on-disk directory with partial data. Fix: check `cd->invalidated` at top of flush and return -EAGAIN; existing retry logic in add/remove/rename_entry drops stale cache and reloads from disk. Also added epoch checks in flush_dir_immediate, flush_leaf_dir, flush_block_dir, and flush_shortform_dir — if DLM epoch changes during inode_cache_get[_exclusive] (from epoch mismatch handler), abort flush and return -EAGAIN. (dir_cache.c) Validated: 0 duplicates with intentional node kills. BUT: happy-path 4-node 2500/node still produces duplicates — epoch fix is necessary but not sufficient.

59. **Stale dir data blocks read beyond ci->size boundary** — flush_leaf_dir may write N data blocks but the underlying extent may be larger (allocated for a previous flush with more entries). parse_leaf_or_node_dir read ALL blocks in the extent, picking up stale entries from blocks beyond the valid range. Fix: limit data block reads to `ci->size / dir_blksize` in parse_leaf_or_node_dir. (dir_cache.c) Verified: read limiter works correctly (69/69 blocks read for 10000 entries). BUT: 2298 duplicates still appear during happy-path 4-node — the duplicates are being WRITTEN to disk, not just read from stale blocks. Root cause still open.

## Bug 93 (2026-03-05, Session 10)

93. **Module refcount leak on unmount** — `mxfs_kern_kill_sb` used `generic_shutdown_super(sb)` but the filesystem was mounted via `mount_nodev()` which allocates an anonymous bdev via `set_anon_super`. The matching cleanup is `kill_anon_super()` which calls both `generic_shutdown_super()` AND `free_anon_bdev()`. Without the anon bdev cleanup, the VFS module refcount tracking left refcnt=1 after unmount, blocking rmmod. Fix: replaced `generic_shutdown_super(sb)` with `kill_anon_super(sb)` in `mxfs_kern_kill_sb`. (frontend/linux/mxfs_super.c) Verified: 2 full mount/unmount/rmmod cycles, refcount correctly drops to 0.

## Bug 103 (2026-03-09, Session 29)

103. **VFS dentry type staleness on cross-node inode number reuse** — When node A deletes a regular file and creates a directory reusing the same inode number, nodes B/C get ENOTDIR when traversing the directory (e.g., `ls dir/`, `cd dir/`). `stat` shows correct directory type. Root cause: `iget_locked` returns cached VFS inode with old S_IFREG mode. `mxfs_kern_fill_inode` updates `i_mode` to S_IFDIR and sets dir ops. But `d_splice_alias` finds existing dentry alias of the old inode with stale `DCACHE_REGULAR_TYPE` flags. `d_move` does NOT update dentry type flags. Result: dentry with DCACHE_REGULAR_TYPE pointing to S_IFDIR inode → ENOTDIR on path traversal. Fix: In `mxfs_kern_iget`, get on-disk state via `mxfs_stat` BEFORE `iget_locked`. For existing (non-I_NEW) inodes with type change, call `d_prune_aliases(inode)` + `remove_inode_hash(inode)` + `iput(inode)` to evict the stale VFS inode, then retry `iget_locked` to get a fresh I_NEW inode with correct type. Workaround: `echo 2 > /proc/sys/vm/drop_caches` clears stale dentries. (frontend/linux/mxfs_super.c) Verified: 3-node physical test — file→directory with same name works correctly across all nodes.

## Bug 104 (2026-03-10, Session 30)

104. **DLM transport auto-detection + SCSI PR reservation conflict on TCP DLM** — Two related problems: (a) Joining a TCP DLM cluster with default CAW transport caused 30s DLM lock timeout on root inode because QNAP doesn't support SCSI Compare-And-Write. (b) SCSI PR registration on QNAP NAS caused reservation conflicts (-52 EBADE) that blocked ALL disk I/O (heartbeat writes, dir cache flushes, inode flushes) from other nodes, crashing the entire cluster. Root cause: QNAP's SCSI PR type 5 (WRITE EXCLUSIVE - REGISTRANTS ONLY) implementation is broken — it rejects writes from registered initiators that aren't the reservation holder. Fix: (1) Added `MXFS_DLM_TRANSPORT_AUTO` as new default. On mount, listens for peer discovery announces for 3s. If peers found, adopts their `dlm_transport` field from the announce packet. If no peers, probes device with a SCSI CAW operation — success/MISCOMPARE means device supports CAW, any other error falls back to TCP. (2) Skip SCSI PR entirely for TCP DLM — TCP uses network-based fencing (connections + leases), not hardware fencing. (3) Added `dlm_transport` field to discovery announce packet (replaces 1 byte of pad, wire-compatible). Files changed: mxfs.h, mxfs_common.h, discovery.h/c, mount.c, mxfs_super.c. Verified: 2-node cluster (clyde kernel 6.8 + z440 kernel 5.10) auto-detects TCP, cross-node read/write PASS, 100 concurrent metadata ops PASS, zero heartbeat failures.

## Bug 129 (2026-03-12, Session 53)

129. **Negative df / free_blocks counter drift** — `df` showed -1064% usage on pve2. Root cause: the allocator initialized `ctx->free_blocks` from the XFS superblock `sb->fdblocks`, but the superblock was never written back on sync/unmount. After remount, the stale fdblocks caused the live counter to diverge from the AGF ground truth. Freeing blocks allocated in a prior mount session incremented the counter past `dblocks`. Observed: sb fdblocks=13,075,974, AGF sum=13,077,295, in-memory=13,351,803 (drift=+274,508). Fix (3 parts): (1) `mxfs_alloc_create()` sums `agf_freeblks` across all AGs as initial `free_blocks` instead of trusting stale `sb->fdblocks`. (2) `mxfs_free_blocks()` caps `ctx->free_blocks` at `sb->dblocks` with warning log. (3) New `flush_superblock_counters()` writes fdblocks/icount/ifree back to XFS superblock (with V5 CRC) during `sync_fs`. Files changed: alloc.c, mount.c, mxfs_common.h, VERSION. Verified: pve2 mount shows correct 1% used, on-disk fdblocks matches AGF truth after sync.

## Bug 133 (2026-03-13, Session 57, FIXED in v0.9.23)

133. **Superblock flush clobbers AG 0 headers** — `flush_superblock_counters()` wrote the full 4K block 0 via `mxfs_block_cache_write()`, clobbering AGF (sector 1) and AGI (sector 2) of AG 0. Fix: Use `mxfs_block_cache_write_range()` to write only the SB sector (offset 0, 512 bytes). Files changed: mount.c.

## Bug 134 (2026-03-13, Session 57, FIXED in v0.9.24)

134. **df divergence across cluster nodes** — 4-node cluster showed different df values on each node (clyde 634M, serv 798M, pve1 3.3G, pve2 1.2G used). Root cause: `ctx->free_blocks` is a per-node in-memory counter initialized from AGF sum at mount time, only updated by LOCAL alloc/free operations. Other nodes' allocations update AGF on disk (under DLM AG lock) but no mechanism existed to propagate changes to other nodes' in-memory counters. Also, `flush_superblock_counters()` wrote the LOCAL stale counter to the on-disk superblock on sync — last node to sync wins, corrupting the SB. Fix: New `mxfs_alloc_recount_counters()` reads AGF.freeblks, AGI.count, AGI.freecount directly from disk (bypassing stale block cache), flushes cached AG dirty blocks first. Called by `mxfs_statfs()` and `flush_superblock_counters()`. `MXFS_LTYPE_SUPER` was dead code (defined in enum but never used). Files changed: alloc.c, alloc.h, mount.c, mxfs_common.h, VERSION.

## Bug 132 (2026-03-13, Session 58, FIXED in v0.9.25)

135. **Double block allocation on DLM membership change race** — Guard map detected agbno 1061 in AG 43 being allocated repeatedly on pve1, and agbno 126158 in AG 18 on clyde. No data corruption observed (sha256 matches) but the allocator was handing out the same blocks twice. Root cause: `mxfs_dlm_update_active_nodes()` purges the entire DLM lock table synchronously (all lock entries destroyed), then `dlm_membership_cb()` signals the cache flush worker thread asynchronously. Between the synchronous purge and the async `mxfs_alloc_release_cached_ag()`, `lock_ag()` gets a false cache hit on the stale `cached_ag` field (DLM lock entry is gone but `cached_ag >= 0`). Meanwhile another node retries its pending lock request and gets immediate EX grant from the now-empty lock table. Both nodes hold "EX" on the same AG and modify bnobt/cntbt simultaneously. Fix: `lock_ag()` now stores the DLM epoch in `cached_ag_epoch` when caching an AG lock. On cache hit, verifies `mxfs_dlm_get_epoch(ctx->dlm) == ctx->cached_ag_epoch`. Epoch advances on every membership change, so a mismatch means the lock table was purged — flush dirty blocks and re-acquire from DLM. Cannot call `mxfs_alloc_release_cached_ag()` synchronously from the DLM callback because lock ordering (alloc->lock → dlm->mutex in normal path) would deadlock. Files changed: alloc.h, alloc.c, VERSION.
