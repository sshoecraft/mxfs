---
name: trap-clearing-m-mxfs-dlm-does-not-stop-a-worker-already-inside-an-acquire
description: TRAP (0.90.106): put_super NULLed m_mxfs_dlm + synchronize_rcu, then freed the ctx; the log worker inside a 20 s acquire kept it -> Oops. Stop worker…
metadata:
  type: feedback
---

xfs_log_worker -> mxfs_sb_runtime_cover -> mxfs_sb_summary_lock reads mp->m_mxfs_dlm once and holds that context for the whole acquire (20 s measured on DRBD, ending in EIO). xfs_fs_put_super cleared the pointer, called synchronize_rcu() (the worker is not an RCU reader across a blocking acquire) and freed the context in mxfs_v5_dlm_shutdown_defer_release; the worker was cancelled only in xfs_log_quiesce, i.e. inside the final summary sync's LOCKED branch or in xfs_unmountfs after the free. A shut-down or log-unwritable mount skips that branch, so the worker faulted on the freed context (DRBD rig Oops in mxfs_tauth_page_write; reproduced as an Oops in mxfs_v5_dlm_inode_lock with tests/rig_unmount_cover_race.sh).

Lesson: "NULL the pointer, then free" only protects code that re-reads the pointer. Any worker that can be INSIDE a call holding the context must be stopped (cancel_*_sync) before the free, on every teardown path including the error/skip ones. When auditing a teardown, list every workqueue item that reaches the DLM context and find its cancel ABOVE the free, not below it. Fix landed in 0.90.106 (cancel_delayed_work_sync(&m_log->l_work) before the context is freed in put_super and the mount-failure unwind).

A directed reproduction must park AFTER the pointer read: a park placed before it resumed into a NULL pointer and failed gracefully, which looked like "no bug".
