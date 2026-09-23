---
name: trap-never-write-a-second-parser-for-a-format-the-producer-already-parses
description: TRAP (sess483): a re-written parser for create_scale_curve's OP lines took the op INDEX as the duration — caught only because the numbers happened to…
metadata:
  type: feedback
tags: [sess483, measurement, harness, parser, chain132]
---

# Never write a second parser for a format the producer already parses

`tests/create_scale_curve.sh` writes per-operation samples as:

```
OP <op index> <duration ms>
```

and parses them, three lines from where it writes them, as:

```python
if len(f) == 3 and f[0] == 'OP':   ops.append(int(f[2]))
```

Writing a new analysis chain, I did not look, and wrote a "tolerant" parser
that took the **first numeric field after `OP`** — the op index. It ran, it
produced clean-looking statistics, and it reported:

```
fwd F=8 shared per-create ms: n=256 p50=5 p90=8 p99=8 max=8 mean=4
      under 30 ms (a retained grant): 100.0%
```

Against chain 129's measured **193 ms** mean for the same arm at the same F.

**It was caught by luck.** At F=8 the op index runs 1..8, so `max=8` was
exactly F and the coincidence was visible. At F=128 the same bug would have
reported plausible three-digit "milliseconds" and I would have concluded the
cost had vanished.

## The rules

- **If the producer parses its own format, copy that parse verbatim.** Not
  "equivalent", verbatim. It is authoritative and it is usually three lines.
- **A tolerant parser is worse than a strict one here.** "First field that
  converts to a number" silently accepts the wrong field. `len(f)==3 and
  f[0]=='OP'` then `f[2]` fails loudly if the format ever changes, which is the
  behaviour you want from an instrument.
- **Sanity-check a new parser against a number you already have** before
  reading anything else from it. One prior measurement at one point would have
  caught this immediately — chain 129's 193 ms at F=8 was sitting in the
  ledger.
- Watch for output that equals a **parameter of the experiment**. `max=8` at
  F=8, `n=32` at 32 nodes, a p50 that equals the loop bound — those are the
  fingerprints of reading a counter instead of a measurement.

## Cost

Third relaunch of the same chain in one session; each earlier one was for a
real reason (a gate keyed on a failure artefact, a missing confound control),
this one was avoidable. The fix is in the chain along with the comment
explaining it, so the next author sees why the strict form is there.
