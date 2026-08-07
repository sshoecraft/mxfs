---
name: ccloop-c7ee71c6-sess24-bast-writeback-abba-deadlock-CAPTURED
description: CRITICAL: both stacks captured of an ABBA deadlock - bast_process waits on a folio lock holding the ILOCK vs writeback holding folio waiting ILOCK
metadata:
  type: project
tags: [deadlock, bast, writeback, ilock, folio, critical, board-lie]
---

# D-BAST-WRITEBACK-ABBA-DEADLOCK - both sides captured

Build C786A05FF756A6C1C6FF797 (0.11.201), node test27, 32/caw.

## The cycle (from /proc/PID/stack, live)

**A) kworker/u9:29+mxfs-ino-bast/dm-1**, wchan=folio_wait_bit_common

    folio_wait_bit_common <- __folio_lock <- write_cache_pages
      <- iomap_writepages <- xfs_vm_writepages <- do_writepages
      <- filemap_fdatawrite_wbc <- __filemap_fdatawrite_range
      <- filemap_write_and_wait_range
      <- mxfs_dlm_bast_process+0x5d5 <- mxfs_dlm_bast_work_fn+0x13a

Holds the inode DLM/ILOCK context. **Blocked on a FOLIO LOCK.**

**B) kworker/u12:30+flush-252:1**, wchan=mxfs_dlm_ilock_begin

    mxfs_dlm_ilock_begin <- xfs_ilock <- xfs_map_blocks
      <- iomap_writepage_map <- iomap_do_writepage <- write_cache_pages
      <- iomap_writepages <- xfs_vm_writepages <- do_writepages
      <- __writeback_single_inode <- writeback_sb_inodes
      <- __writeback_inodes_wb <- wb_writeback

Holds the folio lock (write_cache_pages locks folios before
iomap_writepage_map). **Blocked on the INODE LOCK.**

Pile-up: 4+ `sync` in D at wb_wait_for_completion / sync_inodes_sb, plus
kworker inode_switch_wbs. loadavg 20.02 vs 0.00 on a healthy peer; a
single 1-file write took 69ms vs 11ms.

## The invariant violated

Upstream XFS/iomap writeback order is FOLIO LOCK then xfs_ilock. So any
path already holding the inode lock must NEVER wait on a folio lock.
mxfs_dlm_bast_process calls filemap_write_and_wait_range while holding
it. Same family as CLAUDE.md's "ILOCK held across CAW poll" tension, but
a distinct, concretely captured instance.

## Why it presented as something else entirely - READ THIS FIRST

The wedged node passes every liveness check: mxfs still mounted, `ls`
answers, no BUG/WARNING, no filesystem shutdown. But it can never
complete a `sync`, so it never reaches a barrier.

Barrier criteria need all N ranks, so ONE wedged node makes the whole
board read:

    FAIL nodes_pass=0/32 states:NO_TERMINAL_RECORD=32

which is indistinguishable from a totally broken filesystem. Observed
for cache_coherency, strong_consistency, posix_multi, mmap_coherency,
zero_silent_loss, dlm_fairness, dlm_membership - all with 31 of 32 nodes
perfectly healthy.

**How to name the straggler:** run the criterion OUTSIDE run.sh with a
generous timeout so the barrier can report. Under run.sh the outer
`timeout $tt` kills the script before coord_barrier's own COORD_TIMEOUT
fires, so the node files hold only blank preamble and nothing says which
node was late. With headroom, 31 of 32 nodes reported and their reasons
named it outright: `sc node27 last counter(exp=node27_seq20
got=node27_seq1)` on 16 nodes, `sc barrier write-done` on 15.

**Discriminator that the filesystem is NOT slower:** dir_reuse_coherency
was unaffected throughout (10 rounds in 110s, same as before). It is not
gated on the wedged node's writeback.

## Blocking fix

mxfs_dlm_bast_process must not do folio-lock-taking writeback while
holding the inode DLM lock. Preference order:

1. flush data BEFORE acquiring the inode lock for the BAST, then
   re-validate under the lock
2. drop the inode lock across the flush, re-acquire and re-check epoch -
   the shape already used for dp ILOCK in xfs_create (v0.3.148)
3. non-blocking writeback + bounded retry

Architectural invariant 1 still applies: the drain must complete before
any on-disk unlock, so a bounded RETRY is required, never a skip.

## Detection gap to close

No criterion detects a D-state mxfs kworker. precond_readiness checks
mount + readability, which a deadlocked node passes. Needs a per-node
D-state / sync-liveness precondition so this reports as a NODE FAULT
instead of manufacturing 32 correctness reds.
