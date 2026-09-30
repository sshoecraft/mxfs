---
name: trap-a-retry-armed-on-a-worker-that-takes-locks-waits-behind-the-thing-the-retry-would-unblock
description: TRAP (0.90.34, 8/tcp): replay retry armed on the reap delayed work; the worker sat in a grant wait on the dead node, retry never ran, slice unreplaye…
metadata:
  type: feedback
tags: [recovery, workqueue, replay, deadlock]
---

**What bit us.** The retry of a refused foreign-slice replay was scheduled on `m_mxfs_reap_work`
(`mxfs_reap_sched`), and the reap worker was the only thing that queued the replay work again. The
reap worker's other duties (bucket sweep, bucket scans, entry retries) take inode/AG grants. When a
second node died while the worker was inside one of them, the worker waited on that node's grant,
which only that node's replay ends. A delayed work armed while its function is running runs again
only after the function returns, so the retry waited for the replay it was meant to start. Six
survivors hung, none could unmount.

**Rule.** A retry or re-drive that some lock-holder's progress depends on must live on a work item
that takes no lock of its own. Before arming a retry on an existing worker, list what that worker
can block on; if any of it is released by the thing being retried, give the retry its own work.

**How it was proven.** `work_busy()` printed at the arm (`P89-REAP-SCHED busy=RUNNING in_duty=...`)
plus a line before each duty names the duty the worker is inside. A test parameter that parks the
worker until a dead slot is recovered (`dbg_reap_wait_dead_ms`) makes the case on every lap; the
natural case depends on what the dying node mastered and was met once in about ten laps.

**Also learned.** The refusal itself (replayer asks while the prover is between certificate and
manifest) is common: 3 of 4 plain-load laps met it with no test wait. It was harmless only because
the worker was usually free.
