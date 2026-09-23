---
name: trap-a-synced-dirty-death-oracle-is-not-a-replay-workload-and-leaves-the-cut-one-buffer-to-divide
description: TRAP (s86): fence_crash_cuts' 64 oracle files are sync -f'd, so the replay owed nothing for them; the whole foreign replay queued ONE buffer.
metadata:
  type: feedback
tags: [replay, crash-cuts, oracle, workload]
---

# A `sync -f`'d oracle is not a replay workload

**Where it bit.** `tests/fence_crash_cuts.sh` cut 7 (partial replay), lap
s86a, 0.89.18 build `7E3B0EE2D9043BB34320E38`. The lap reached the cut in
137 s and the module declined it:

```
P-DRAIN-PEAK deferred=4 queued_buffers=1 queued_bytes=16384
P-DBG-REPLAY-CUT-VACUOUS slot=1 want=8 queued=1 — a prefix of 8 over 1 queued
buffer(s) leaves no nonempty suffix
```

**Why.** The harness's dirty-death oracle creates NFILES files and then runs
`sync -f $MNT`. That is exactly right for an oracle — it makes the expected
content unambiguous — and exactly wrong as the thing the replay is supposed to
apply, because after the sync every one of those effects is already on home
storage. The only live workload in the silent-victim arm was a writer
appending one fsynced line to one file every 500 ms, which is one dirty inode.
So the entire foreign replay had a single buffer to divide into a prefix and a
suffix, and any prefix >= 1 leaves nothing behind.

**The general shape.** What a replay owes is the victim's *committed but not
yet checkpointed* work at the instant it is fenced. Anything the victim
already flushed is invisible to the measurement, and a data append touches one
inode however long it runs. A partial-replay cut therefore needs continuous
METADATA churn — creates, renames, unlinks, with the directory fsynced per
batch — running right up to the fence, so the log tail is genuinely behind
home state when the fence lands.

**And it gives you the oracle for free.** A batch acknowledged only after its
directory fsync returns is a result the filesystem promised; the set of
acknowledged batches is exactly what recovery owes back, and the suffix the
cut withheld is inside it. That is a much stronger post-recovery check than
re-reading files that were already durable before the crash — those cannot
tell a completed recovery from a skipped one.

**Cheap to detect.** The module prints `P-DRAIN-PEAK ... queued_buffers=N` on
every foreign replay. Read it before choosing a prefix, and treat
`queued_buffers` small (single digits) as evidence the workload is wrong, not
as a reason to lower the prefix to 1.
