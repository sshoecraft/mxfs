---
name: sess35-ROOT-round1-format-transition-block-vs-data-divergence
description: sess35 ROOT (dirwr trace PROVEN): round-1 loss = xfsaild ABA reflush of a lagging-tenure in-AIL block-0 buffer (block-fmt, 24ent) over a newer-tenure…
metadata:
  type: project
---

## sess35 ROOT (PROVEN, dirwr=1 write-trace, build 4703FA18). Trace saved: /src/mxfs/tests/tcp/drc_cap/SESS35_daddr120_trace.txt

### Mechanism (iter4-round1, victim node7_f1, dir ino131, block0 daddr=120):
- node7 (tenure 4) adds node7_f1 → daddr=120 off=3768 at uptime 202.764, writes it xfs_dir3_DATA (leaf-fmt, block0 is pure data).
- node6 (buffer stamped tenure 3, BLOCK-fmt) has an in-AIL block-0 BLI = whole-dir image 24 entries [.,..,node1_f1..node1_f22] WITHOUT node7_f1. node6's xfsaild flushes it at uptime 203.08-203.35 — AFTER node7's add — as xfs_dir3_BLOCK → durably CLOBBERS node7_f1. r5/r2/r1 similarly re-flush block-fmt block0 at 204-205.
- = the sess11 "logged-then-vanish" ABA reflush, now NAILED: a LAGGING-TENURE in-AIL dir-block buffer (from before the block→leaf conversion) is xfsaild-flushed over a newer-tenure post-conversion add.

### WHY gen-blind / all guards missed it: ALL writes show bgen=2 dgen=2 lgen=2 (MATCH), mode=5(EX), would_skip=0, aba=0, tmism=0. The block→leaf conversion + the adds do NOT bump i_dlm_dir_gen, so the lagging block-fmt buffer looks "current" to every gen-based predicate (staleprt=0, P37=0, ex_write_guard/subset_guard don't fire). The ONLY visible discriminator is bp->b_ops: xfs_dir3_block (stale pre-conversion) vs xfs_dir3_data (current post-conversion) for the SAME daddr.

### FIX DIRECTION (next session — NOT yet implemented):
A. **dir_gen bump on format conversion**: in xfs_dir2_block_to_leaf (and sf_to_block / leaf_to_node), bump i_dlm_dir_gen + stamp the converted block so a lagging cross-tenure block-fmt buffer is detected stale (bgen<dgen) by the EXISTING evict + write-chokepoint guards → they'd then fire. Lowest-risk: reuses validated machinery, just feeds it the signal it currently lacks. CONFIRM conversion sites bump gen.
B. **format-mismatch write-suppress** at P16-DIRBLK-SUBMIT (pal/linux/xfs_buf.c): if bp->b_ops==xfs_dir3_block but the dir's current durable format is leaf/node (dir grew past one block), this write is a stale pre-conversion image → retire BLI + skip (xfs_buf_ioend DONE). Precise (only wrong-format writes), unlike the refuted blanket subset_guard/reflush_skip. RISK: must not skip a legit block-fmt write when the dir genuinely IS block format (check disk/current fmt, not just b_ops).
C. Coherent conversion drain: xfs_dir2_block_to_leaf must invalidate the pre-conversion block-fmt buffer cluster-wide.
Prefer A (feed dir_gen the conversion signal) — it's the missing input to already-working guards.

### REFUTED this session (do NOT retry as-is): epoch-never-0 (readdir=0), addname_epoch_refresh (readdir=0), subset_guard (wedge), reflush_skip (readdir=0/2). All blind to format; all either over-fire or wedge.

### Keeper = 4703FA18 (==2EAA0090, 4/5). dirwr=1 reproduces+traces. Repro: tests/tcp/drc_repro_loop.sh 15 "dirwr=1" 2 (~1/4 round-1 HIT). Criteria runner: tests/run_criteria_tcp.sh "1 2 4 8".
See [[sess35-HEAD-handoff]] [[sess11run-SMOKINGGUN-datalog-entry-bytes-logged-then-vanish-no-evict-no-reload]].
</body>
