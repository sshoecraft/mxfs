---
name: trap-a-relogged-buffer-item-is-reformatted-so-only-the-last-format-before-the-checkpoint-reaches-the-log
description: TRAP (s115): a log-image injector fired, the survivor replayed that very block, and the value was the TRUE one — every later relog re-formats and rep…
metadata:
  type: feedback
---

## The trap

An injector that substitutes a value into the LOG COPY of a buffer image
(`xfs_buf_item_format_segment`, after `xlog_format_copy` / the iovec copy)
writes into the log vector that format built. **A buffer log item is
re-formatted on every relog, and each format replaces the previous log
vector.** Only the LAST format before the CIL checkpoint is written to the
log. Every transaction that re-dirties that buffer after the substitution
therefore erases it, silently and completely.

Measured s115b, 0.89.43, 2-node TCP: `P-INJ-LOGGED-AGINO daddr=4370536
inode=14 di_next_unlinked 0x94a1 -> 0x7ffffffe` fired on the victim; the
survivor's foreign replay read that exact block (`P-FR-DINO-BUF
blkno=4370536 ... verdict=APPLY`, one image, `n=1`) and applied the true
value. Nothing refused, nothing complained. The evidence looks like "the
guard is broken" and it is not — there was never a corrupt byte in the log.

**Fix: arm the knob between the last two transactions that touch the
buffer, and force the log immediately after the final one.** The dirty map
is cumulative across relogs, so that last image still covers everything the
whole run dirtied — you lose no coverage by arming late.

## Two other things stood in front of the same arm, in this order

1. **No image to substitute into.** An unlink-while-open workload that
   closes each fd before the next unlink frees every inode at once, so the
   AGI bucket is empty at every insert and upstream logs no dinode at all.
   Hold every fd open. (Its own memory:
   `trap-an-unlink-workload-whose-fds-close-between-unlinks-logs-no-dinode-image-at-all`.)
2. **The image is carried past the replay window.** Under an fsync-per-file
   writer, xfsaild keeps the log tail within ~2 checkpoints of the head; a
   few seconds between the injection and the kill is enough for the buffer
   to be flushed and the record dropped from the recovery span. Measured:
   the whole foreign replay covered 2 checkpoints / 19 images. Pin the tail
   first — `dbg_ail_pin_ino` names one inode item xfsaild must never flush;
   with it, 53 checkpoints / 411 images and the injected block present.

## The general lesson

Each of the three failed in a way that looked like the LAST one's symptom:
"the guard did not fire". They are only distinguishable by asking, in
order: did an image of the right kind get logged at all; was it inside the
replayed span; did the value survive to the log. Ask them in that order and
each lap answers one. Guessing between them costs a lap each time.

Corollary, and it is why 0.89.42 exists: an injector whose decline path
returns silently makes the first question unanswerable. Every rejection
path must name itself and print what it judged.
