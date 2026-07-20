---
name: wedge-root-has-moved-to-scsi-layer-2026-07-11
description: dir_reuse_coherency@32/caw hang signature has changed: no longer xfs_buf_iowait (wedge#2), now stuck in scsi_execute_cmd/__timer_delete_sync — likely…
metadata:
  type: project
tags: [dir_reuse_coherency, wedge, scsi, block-layer, root-cause-update, gpt-consult-followup]
---

## Context

Built a small, safe diagnostic addition to the v0.10.61 wr_inflight fix
(`mxfs_dir_wr_inflight_dec()` in pal/linux/xfs_buf.c, wraps both decrement
sites, logs a new `P-WRCNT-UNDERFLOW` probe if a decrement would go
negative — GPT consult item #1, testing the specific "leaked completion
recovered by a later distinct write's completion, then both eventually
fire" double-retirement race). Built clean (`make modules`, no new
warnings), deployed cluster-wide, ran a bounded 5-round
`dir_reuse_coherency@32/caw` smoke test (build `1BAFC14435BA2FFEBEF0742`).

## Result 1 — new diagnostic did NOT fire

`grep -c P-WRCNT-UNDERFLOW` on the full captured dmesg from the hung
node: **0**. Also zero `P-WRCNT-RESUBMIT` and zero `P40-WRBARRIER-LONG`
fires this run. This specific double-retirement race is not what's
happening in this instance — rules it out as the proximate cause here
(doesn't rule it out as a real but rarer defect; the diagnostic stays in
the tree for future runs).

## Result 2 — the harness fix (same session, earlier) validated perfectly live

`RESULT: SYSCALL_HANG` on test1 (rank1, `op=rm-rf round=1`), `RESULT:
ABORTED_BY_PEER` on all 31 other nodes, each correctly citing
`peer_reason=[SYSCALL_HANG rank=1 op=rm-rf round=1]`. Aggregator reported
`nodes_pass=0/32 states:ABORTED_BY_PEER=31,SYSCALL_HANG=1`. The whole run
concluded in roughly a couple of minutes instead of the ~2-hour cascade
the old harness produced on the same class of failure. See
`.claude/awareness/subsystems/tests.md` "Harness failure-state protocol"
section for the mechanism.

## Result 3 — THE IMPORTANT ONE: the hang signature itself has changed

Captured via the new `run_bounded` hang-detector's `/proc/$pid/stack`
dump (`mxfs-HANGSTACK`, reassembled from interleaved dmesg — the lines
land in the kernel ring mixed with other concurrent mxfs probe output
since each stack line is written via a separate kmsg write; reconstructed
in order below):

```
xfs_vn_unlink+0x53/0xb0 [mxfs]
... (xfs_inode_unlock-ish frame, name truncated in capture)
xfs_inactive+0x669/0xae0 [mxfs]
... (gap)
mxfs_dir_data_owner_scan+0x39d/0x530 [mxfs]
... (an mxfs frame, name truncated, offset 0x31/0x2a0)
scsi_execute_cmd+0x114/0x2f0
__timer_delete_sync+0x31/0x50            <-- stuck here (pid 1491, comm=rm)
```

**This is NOT the `xfs_buf_iowait` signature every prior wedge#2 session
in this project chased** (sess5/6/8/9 of ccloopa864, the
`b_mxfs_sync_wait` → `b_mxfs_force_sync` → event-ring → wr_inflight-leak
chain — see `AAA-ccloopa864-sess*` and
`gpt-consult-dir_reuse32-architectural-review`). The call chain up to
`mxfs_dir_data_owner_scan` matches that history exactly (same entry
point: `xfs_remove` → `xfs_inactive` → `mxfs_dir_data_owner_scan`, the
per-unlink durable-signal flush), but instead of stalling at the
xfs_buf-level completion wait, it now goes one layer deeper and stalls
inside **actual SCSI command dispatch** (`scsi_execute_cmd`) at a timer
teardown (`__timer_delete_sync` — synchronously waiting for a
concurrently-running timer callback to finish, i.e. this thread is
blocked because some OTHER context is mid-way through that timer's
callback and hasn't released it).

## Why this matters — likely the SAME mechanism as the mass-unmount wedge

Compare directly to `NEW-BUG-mass-unmount-blk_execute_rq-wedge-2026-07-11`
(found earlier today, unrelated trigger — a coordinated clean unmount of
all 32 idle nodes wedged 21/32 in `blk_execute_rq`, both the `umount`
process and an `mxfs-worker` kernel thread). `scsi_execute_cmd` and
`blk_execute_rq` are adjacent layers of the same synchronous-command-
dispatch machinery. Two different trigger conditions (active create/rm
churn vs. idle mass unmount) landing in the same block/SCSI dispatch
neighborhood is a strong signal these are ONE bug, not two — possibly the
actual current bottleneck behind the whole "wedge#2" family, now that the
xfs_buf-level completion-routing bugs (sync_wait/force_sync/wr_inflight)
appear to have been closed by the v0.10.61 lineage.

## Recommendation for whoever continues this

1. **Stop chasing the xfs_buf-level completion machinery for now** — it
   looks closed (zero P-WRCNT-RESUBMIT/UNDERFLOW/WRBARRIER-LONG fires this
   run). The live bottleneck has moved down a layer.
2. Get a CLEAN (non-interleaved) stack trace — the current capture method
   (line-by-line kmsg writes racing concurrent probe output) is legible
   enough to identify the function chain but loses some frame names.
   Better: `cat /proc/$pid/stack` to a FILE in one shot instead of piping
   line-by-line through kmsg, or a kprobe/kretprobe directly on
   `scsi_execute_cmd`/`__timer_delete_sync` entry to capture full
   backtraces without the interleaving problem.
3. Treat this as the same investigation as the mass-unmount wedge — a
   kprobe on `blk_execute_rq`/`scsi_execute_cmd` callers, fired under BOTH
   trigger conditions (mass idle unmount AND active rm-during-churn),
   would settle whether they're really one mechanism.
4. Given this is now block/SCSI-layer, not filesystem-layer, consider
   whether it's CAW-specific (a CAW compare-and-write command, or the
   disklock heartbeat's own SCSI I/O, stuck) vs. a generic multipath/LIO
   target-side issue exposed by concurrent load — the `__timer_delete_sync`
   frame suggests a genuine kernel synchronization wait on a live timer
   callback elsewhere, which is a different debugging surface (timer/
   workqueue callsites) than anything the dir_reuse investigation has
   instrumented so far.

## Housekeeping

test1 is wedged again from this run (same recovery as before: D-state,
needs `virsh destroy`+`start`, not yet done as of this note — RULE 2
permits it for test VMs). The other 31 nodes are clean (ABORTED_BY_PEER
path exits normally). Full artifact at
`/tmp/run_dir_reuse_coherency_20260711T193236Z/` on the dev host (not
committed anywhere, local scratch — pull the daddr=33493720-related P50-RD/
P9-LFREE/P-DIRWR lines around dmesg timestamp 140.6-140.7s for the full
in-flight context if picking this back up).
