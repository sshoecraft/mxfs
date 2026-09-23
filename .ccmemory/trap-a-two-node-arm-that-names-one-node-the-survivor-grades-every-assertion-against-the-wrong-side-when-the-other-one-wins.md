---
name: trap-a-two-node-arm-that-names-one-node-the-survivor-grades-every-assertion-against-the-wrong-side-when-the-other-one-wins
description: TRAP (s125): the DLM-partition arm hard-coded A as the fencer; test2 won the race and all six FAILs were attribution errors, not MXFS defects.
metadata:
  type: feedback
---

## What happened

`tests/fence_partition_reconnect.sh ARM=network` (lap s125a) cut only the DLM TCP
port on B. Both nodes kept the LUN and both kept heartbeating on disk, so either
side could win the race. **B — the partitioned node — fenced A.**

The arm names its two nodes `A(survivor)` and `B(partitioned)` in its own banner
and then grades every assertion on that naming. Result: `fails=6`, and every one
of the six was an attribution error against a textbook-correct resolution.

- `A1's key stays registered got=0` — A was the one fenced, so its key was
  correctly preempted. The assertion sits OUTSIDE the `fen_a`/`fen_b` branch.
- `B was fenced: no write from B COMPLETED after the partition ended got=123` —
  B was the winner; its writes were legitimate.
- `B was fenced: B contained itself got=0` — A contained itself, not B.
- `every file B fsynced is back byte-identical got=0` — read from A, which was
  unmounted because it had been fenced. The durability check never ran.
- `no shutdown, BUG or Oops on test1 got=1` — the one line was
  `Metadata I/O Error ... at mxfs_dlm_fence_notify ... Shutting down filesystem`,
  which IS the fence containment. There was no BUG and no Oops anywhere.
- `test1 is still mounted got=mounted=0` — the arm prints an INFO of its own
  saying a fenced node leaving its mount is the containment it requires, and
  counts the FAIL regardless.

The MXFS-side facts the same lap PASSed: exactly one certificate (no split
brain), the fence started only past the declared `tcp_death_grace_ms`, the
certificate became durable (`kind=LU_RESET_WITNESSED_V1`), and the reservation
was unchanged across the heal (`WEAR -> WEAR`).

## The rule

In a symmetric fault — a link cut, a DLM-only partition, anything where both
sides keep the arbiter — **derive the winner and the loser from the evidence
before grading anything**, and grade roles, never hostnames. Here: `fen_a`/`fen_b`
(the `P236-FENCE-CERTIFIED` counts) name the winner; everything else follows.

A symmetric fault also needs SYMMETRIC INSTRUMENTS. This arm ran its write
oracle on B alone, so when B won there was no instrument on the loser at all and
the silence a fenced node owes could not be measured in either direction.

## Two smaller traps inside it

- `bad_lines()` exists in two harnesses with DIFFERENT bodies.
  `fence_partition_reconnect.sh:250` counts every `hutting down filesystem`;
  `admitted_write_parked_across_fence.sh:131` excludes the ones naming
  `mxfs_dlm_fence_notify`. A cluster fence is what the machinery is FOR — on the
  loser it is the expected containment, and only on the winner is it a failure.
  A `BUG:`/`Oops` is never acceptable on either.
- A harness that prints an `INFO` explaining why an outcome is legitimate and
  then still counts it as a FAIL has two graders disagreeing. The prose is
  usually the one that is right; the assertion was written first.
