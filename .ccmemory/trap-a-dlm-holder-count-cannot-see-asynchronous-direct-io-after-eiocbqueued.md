---
name: trap-a-dlm-holder-count-cannot-see-asynchronous-direct-io-after-eiocbqueued
description: TRAP (D-0971, 0.87.7): an async direct I/O drops its IOLOCK ride (the DLM holder) at -EIOCBQUEUED with bios still in flight; a release gated on holde…
metadata:
  type: feedback
tags: [dlm, direct-io, release-pipeline, io_uring, D-0971]
---

# A holder count is not an I/O count

**What bit us (D-0971, 2-node TCP, sess43-45):** the inode release pipeline in
`mxfs_dlm_bast_process` decided nobody was using an inode from its DLM holder
counts (`i_dlm_ex_holders`/`i_dlm_pr_holders`).  Those count IOLOCK/ILOCK
rides.  An asynchronous direct read or write (io_uring, AIO) returns
`-EIOCBQUEUED` from `iomap_dio_rw` and `xfs_iunlock`s the IOLOCK while its
bios are still outstanding; only `i_dio_count` still says the inode is busy.
Measured: 11-16 releases per lap committed with `i_dio_count=1` under peer
conflicts (`P-REL-DIO-INFLIGHT`), i.e. the peer's tenure started while this
node's bios were still landing.

**The shape that fixes it (Astra ruling, sess44):**
- wait for `i_dio_count` (`inode_dio_wait`) ONLY from a quiescent entry (no
  holder present) — a holder still admitted may be mid-submission and about to
  park on its own nested ILOCK, so waiting on it deadlocks; let the holders
  gate abort and re-arm instead.
- the wait goes BEFORE the log force/AIL drain: a completion's transaction may
  still be in the CIL when the wait returns; `inode_dio_wait` is a completion
  barrier, not a durability one.
- terminal guard under the spinlock BEFORE the NL store (defer, keep grant);
  never store NL then try to defer.
- polled direct I/O (IOCB_HIPRI / IORING_SETUP_IOPOLL) must be refused on a
  clustered mount: `inode_dio_wait` drives no polling and the polling ring can
  be parked behind the release.
- O_DSYNC's `generic_write_sync` tail runs AFTER `inode_dio_end` in iomap
  (`fs/iomap/direct-io.c`), so it acquires fresh; no admission needed.

**How the completion gets its ILOCK while the pipeline waits for it — measured,
not what I first assumed:** iomap runs any completion that needs fs work
(unwritten conversion, size update) on the direct-I/O completion workqueue,
i.e. a KERNEL THREAD (deferred/caller completion is cleared for those).  The
cached-grant fast path in `mxfs_dlm_ilock_begin` admits a kernel thread under
the still-EX mode (`mxfs_file_yield_gate` exempts PF_KTHREAD) as a counted
holder, and the P15-REL-ABORT holders gate before the NL store covers it.
`dioend_kthread` counted every completion, `dioend_task=0`, `dioend_admit=0`.
The per-task registry (`xfs_diotask_enter/exit` + `xfs_task_in_dio_end` in
`mxfs_ilock_admit_ioend`) is the backstop for a task-context completion iomap
does not produce today.  Lesson: before claiming a path admits X, count where
X actually runs; "the admission counter is zero" was the tell.

**io_uring driver trap:** on an IOPOLL ring, `io_uring_enter(GETEVENTS)`
returns with NO event when the request was punted to a worker before the app
polled (`io_iopoll_check` breaks on an empty iopoll list), and MXFS punts every
first attempt (no FMODE_NOWAIT).  A raw-ring driver must re-enter until the
CQE appears; treating "enter returned, no CQE" as an I/O error produced 47
phantom errors per 500 ops.

**General form:** any "nobody is using X" predicate built from lock holders
misses work that outlives its lock.  Before releasing ownership of anything
to a peer, enumerate the counters that outlive the lock (`i_dio_count`,
writeback in flight, pinned buffers, pending ioends) and gate on each.
