<!-- sess413 RULE-5 ruling D-512: shape (c) — DONTCACHE+never-return-shell(ESTALE), full data-path gate set w/ drain sync, mmap zap+pagecache invalidate a… -->
# sess413 GPT ruling: D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512 fix design

Invariant: after MXFS_IF_INCARN_STALE publishes, NO operation may obtain data, submit IO, dirty/fault a page, or successfully return that inode as current. Retirement = liveness; gates = safety; BOTH required. Lookup must NEVER fall through to the poisoned shell — blocked retirement returns -ESTALE (remove the 4-retry-then-fallthrough).

## Components (all mandatory)
1. (a) I_DONTCACHE on the poisoned inode (whole inode, not one alias) + prune aliases + retry-iget only after actual reclaim; references blocked -> -ESTALE, no spin.
2. (b) Gate set (NOT just open+iomap_begin — misses cached reads/resident PTEs/writeback): ->open, ->read_iter, ->write_iter, ->mmap, ->fault, ->page_mkwrite, ->fsync(-ESTALE, never stale durability), splice_read, direct-IO + iomap mapping paths, buffered/readahead mapping, WRITEBACK (no dirty-G1 submission post-poison), fallocate/punch/zero/copy_file_range/reflink/FIEMAP/ioctls/io_uring. vm_fault -> VM_FAULT_SIGBUS after revocation. Plain test_bit races — need shared/exclusive incarnation-transition sync (per-inode rwsem or XFS io/mmap/layout-lock integration): ops hold shared + test; poison takes exclusive, publishes, drains, revokes.
3. Poison-time revocation: block new ops -> publish -> unmap_mapping_range ALL mappings (incl. writable) + TLB -> drain in-flight -> invalidate_inode_pages2 G1 pagecache -> later faults SIGBUS. Both PTE-zap AND pagecache-invalidate needed (either alone insufficient).
4. Dirty-G1 hazard: generic eviction/writeback must NEVER flush G1 into G2 blocks. Ordering: ref-hold -> exclusive lock + XFS exclusion -> validate mismatch -> publish poison -> DONTCACHE -> block new IO -> drain gated ops -> unmap -> cancel/discard queued G1 writeback (wait only for pre-reuse lease-valid IO) -> invalidate -> prune -> drop ref -> reclaim.
5. Recycle-only clear: MXFS_IF_INCARN_STALE cleared ONLY in the serialized IRECLAIM/fresh-init path with full state reset before I_NEW release; false-positive recovery = retire+reconstruct, never re-enable in place.
6. CLUSTER REUSE BARRIER: no ino/extent reuse until every node holding the old incarnation is revoked and G1 IO drained; if reuse discovered with unrevoked G1 writeback possibly outstanding -> quarantine/fence/shutdown, never continue silently. (Interacts with the existing publication-durability gate F1-F4 machinery.)

## Verification (beyond zsl x2 + inew=1/ESTALE + md5 32/32)
Long-lived-ref matrix (open r/w fd, dio fd, ro/rw mmap, resident+dirty pages, in-flight buffered/dio, queued writeback held ACROSS reuse): all old-ref uses fail safely, reclaim after close, later iget=G2 inew=1. Path coverage incl. resident-PTE access during poison, page_mkwrite, splice, io_uring. Page assertions: PTEs zapped, faults SIGBUS, no G1 page visible via G2, dirty tags cleared only via stale teardown. Storage: no G1 bio after the reuse barrier, G2 unmodified via old fds, chk clean. Races: poison between gate-check and submit / during fault / during writeback; elevated i_count forever; crash during revocation.

Ledgered in D-512 next; large campaign — schedule after the current closure wave.
