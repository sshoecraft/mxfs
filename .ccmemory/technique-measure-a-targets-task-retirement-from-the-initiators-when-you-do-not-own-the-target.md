---
name: technique-measure-a-targets-task-retirement-from-the-initiators-when-you-do-not-own-the-target
description: TECHNIQUE (0.89.12): power-cut a node writing rising O_DIRECT counters and watch the platter from the survivor. Quiescence is derived from the observ…
metadata:
  type: feedback
tags: [measurement, scsi-pr, harness, qnap]
---

# Measuring a closed-source target's task retirement, from the initiators only

The question — *after the target loses a node's I_T nexus, can a write it
already accepted from that nexus still land?* — is what every recovery across a
boot boundary depends on. On an appliance you cannot read the source, you
cannot put `dm-delay` under its backing store, and you cannot trace inside it,
so `tests/fence_inflight/inflight_ab.sh` does not apply.

`tests/pr_retirement_probe.sh` is the shape that works:

- the victim runs N O_DIRECT threads writing a **rising 64-bit counter** into N
  distinct blocks, continuously;
- the survivor reads that whole window O_DIRECT in a tight loop and emits a row
  **every time any counter changes**;
- the victim is **power-cut** (`virsh destroy`), never shut down — a clean
  shutdown lets its own stack finish or cancel the outstanding writes, which is
  the opposite of the state under test;
- the survivor keeps reading.

**The key property: no cross-host clock is needed.** The counters stopping *is*
the victim's death, seen in the observer's own data, and any change after a
quiescent gap is a write from the dead nexus landing late. Two guests' clock
skew cannot move the verdict. The host's destroy timestamp is recorded as
context only.

## Things that have to be right

- **O_DIRECT needs the transfer BUFFER block-aligned**, not just the offset. A
  Python `bytes`/`bytearray` is whatever pymalloc hands out and gets EINVAL —
  which a probe reads as "the write was refused". Use `mmap.mmap(-1, n)`, which
  is page-aligned, with `os.preadv`/`os.pwritev`.
- **Rate-limit the change rows** (one per 50 ms) or the evidence file explodes.
  It never hides the row that matters: a change after a quiescent gap is by
  definition more than the limit after the previous row.
- **Quiescence at the END of the observation is not a gap between two rows.**
  A verdict that only looks at row-to-row gaps reports the clean run as "never
  went quiet". The gap may run to `READER_DONE wall=`.
- **A positive control is mandatory**: assert the survivor saw the window
  advancing while the victim was alive, or the whole observation is about a
  device nothing was writing.
- State the **resolution**: the rate limit bounds how soon after the cut a late
  landing is still distinguishable.

## What a clean result is worth

A qualified contract for that target, firmware, backend and session topology —
never a property of SPC targets in general. Declare it beside the rig
(`data/rigs.json`) with its evidence, read it fail-closed from the harness, and
re-measure when any of those change.
