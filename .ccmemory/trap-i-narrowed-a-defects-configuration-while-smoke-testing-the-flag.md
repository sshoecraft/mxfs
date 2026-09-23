---
name: trap-i-narrowed-a-defects-configuration-while-smoke-testing-the-flag
description: TRAP (sess575): I set a defect's nodes/dlm to 2/caw to exercise the update flag; its evidence said MEASURED 32/caw. A test keystroke became a release…
metadata:
  type: feedback
tags: [defects, release-gate, tcp-2node, trap]
---

# Narrowing a defect's configuration is a claim, even when you are only testing the CLI

sess575, caught by the user.

`tools/defects.py` gained `nodes`/`dlm` fields saying the smallest cluster + transport a defect was
observed on. `--at 2/tcp` then filters the queue to what blocks that release.

While smoke-testing that the `update` subcommand's `-N`/`-D` flags worked, I ran:

    tools/defects.py update D-READDIR-PEER-CACHED-DIR-PACE -N 2 -D caw

purely to see the flags take. That record's own evidence field reads **"MEASURED 32/caw, build
0.11.243 ... 32 empty directories in one shared parent"**. There is no 2-node measurement in it at
all. The correct value was `32/caw`.

## Why it matters more than it looks

The value did not change the 2/tcp count — `2/caw` and `32/caw` are both excluded from a 2/tcp
gate — so nothing visibly broke. It would have silently dropped the defect out of a **2/caw**
release gate, on no evidence, from a keystroke whose only purpose was exercising argparse.

That is the exact failure the fail-closed default (`1/any`, blocks everything) exists to prevent,
and I defeated it by hand on the second record I touched.

## The rule

**Never write `-N`/`-D` on a real record to test the tool.** Add a throwaway record, exercise the
flags on that, remove it. A configuration field is a reach claim that a release gate reads; there
is no such thing as setting it "just to see if the flag works".

**Every narrowing is preceded by reading that record's own `evidence` field** and taking the
smallest cluster/transport it actually states. Not the id (`D-32NODE-…` is a hint, not a
measurement), not the summary prose, not a keyword sweep.

## The related number confusion this produced

A subagent keyword sweep estimated 40 of 95 open defects were 2-node-TCP-reachable. The gate then
read 93. Those are not in conflict and neither is broken: 40 was a heuristic **estimate of the
destination**, 93 is **today** — 95 minus the 2 records actually narrowed, everything else sitting
at the fail-closed default. Do not present a heuristic bucket count anywhere it can be mistaken for
a gate reading.
