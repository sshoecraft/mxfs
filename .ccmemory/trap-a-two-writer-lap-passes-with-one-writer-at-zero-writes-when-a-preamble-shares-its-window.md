---
name: trap-a-two-writer-lap-passes-with-one-writer-at-zero-writes-when-a-preamble-shares-its-window
description: TRAP (sess44, D-0973/0974 laps): dwcd's per-node preamble cat ran inside the writer's timed window; on a 4 GiB span test1 wrote 0 in 90 s and the lap…
metadata:
  type: feedback
tags: [harness, verdict, dio, dwcd, pace]
---

# A two-writer lap that passes with one writer at zero writes measured nothing

## What happened
`tests/dio_write_conversion_deadlock.sh` set each writer's deadline (`end=$((SECONDS+S))`) *before* the preamble `cat $F > /dev/null`. On the 65536-block and the 4 GiB (1 Mi-block, 20000-extent) spans the cat on test1 re-acquired the grant per mapping against test2's writes and did not finish inside the 90 s window, so test1's loop never ran: `test1: WRITER ok=0 failed=0`. The verdict only required `failed=0`, identical images and a clean EXTCHK, all of which test2's writes alone satisfy, so the lap reported PASS (`tests/evidence/20260918T035930Z_dwcd_fin_deep`, `…040220Z_dwcd_fin_huge`). The `NOCAT=1` arm was the only lap in which both nodes wrote on that span.

## Rule
A lap with N writers has measured its claim only if every writer wrote. `ok=0` on any node now fails the lap (sess44 harness change). More generally: any per-node counter the verdict relies on must be checked for being non-zero on every node that was supposed to produce it, not only for the absence of failures.

## Also
The slow preamble is itself a pace observation, recorded as D-TWO-NODES-ALTERNATING-ALIGNED-4-KIB-O-DIRECT-WRITES (noblock): every handoff of a btree-format file cold-reads the whole tree, and a buffered reader under a peer writer re-acquires per mapping.
