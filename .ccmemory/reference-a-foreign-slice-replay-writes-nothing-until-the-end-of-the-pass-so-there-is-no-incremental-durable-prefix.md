---
name: reference-a-foreign-slice-replay-writes-nothing-until-the-end-of-the-pass-so-there-is-no-incremental-durable-prefix
description: REFERENCE (s85): MXFS foreign replay defers every buffer submit to one end-of-pass xfs_buf_delwri_submit, and there is NO durable progress cursor any…
metadata:
  type: reference
---

# A foreign-slice replay applies its effects all at once

Two facts that govern any work on replay crash-consistency, both established
by reading the tree in s85:

## 1. No incremental writes

`xfs/xfs_log_recover.c`: on an MXFS untrusted/foreign replay the mid-pass
`xfs_buf_delwri_submit(buffer_list)` is **skipped**; the code does
`log->l_mxfs_drain_deferred++` instead, and every replayed image stays in core
until ONE submit at the end of the pass (in `xlog_do_recovery_pass`, the
`else` arm beside the `xfs_buf_delwri_fail` unwind).

The reason is in the comment there and it is not incidental: a mid-pass write
can put an INTERMEDIATE image of a block on the platter — the tail
transaction's chunks over a block the victim last flushed at the head
transaction — and that intermediate fails the write verifier, which refuses
the whole slice. Keeping the queue means every image lands in core in LSN
order first.

The module prints the queue at the end of the pass:

```
MXFS: P-DRAIN-PEAK deferred=%u queued_buffers=%u queued_bytes=%llu
```

That line is the only measurement of how much metadata a replay pins, and the
comment beside it calls the pin unbounded except by the slice's
distinct-buffer count.

**Consequence for testing:** "a durable prefix with an unissued suffix" is not
reachable by cutting between transactions — there is nothing durable between
them. The only place it exists is INSIDE the end-of-pass submission, which is
also where a real crash leaves it, since that submission is many separate
writes and nothing makes them atomic.

## 2. No durable progress cursor

Searched under `dlm/` and `xfs/` for `replay_cursor`, `recov_progress`,
`replay_progress`, `resume_lsn`, `replayed_to`, `progress_seq`,
`last_replayed` — **zero matches for all seven**. Replay has no persisted
resume point. It is LSN-gated and idempotent instead (comment in
`dlm/v5_mount.c`: "replay is LSN-gated and idempotent"), so a successor
re-runs the pass and the gating decides what still applies.

So a successor meeting a half-applied replay must recover by REDOING, not by
resuming from a cursor — and the property that has to hold is that repeating
an already-applied prefix performs no destructive effect twice.

## Where completion actually becomes durable

Not the `P163-RECOVERY-COMPLETE` log line. That is printed at the end of
`v5_recovery_complete_ladder` (`dlm/v5_mount.c`) and is informational. The
durable act is `mxfs_disklock_purge_node(ctx->disklock, dead_node)`, which
zeroes the dead node's lock records and heartbeat sector, and it is preceded
by an irreversible CAW-authority purge and a `mxfs_pal_bdev_flush(ctx->dev)`
— the comment marks that flush "the purge must be durable before the
broadcast". On failure the caller must not treat recovery as published.
