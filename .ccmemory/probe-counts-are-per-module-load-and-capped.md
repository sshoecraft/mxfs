---
name: probe-counts-are-per-module-load-and-capped
description: METHOD: pr_warn probe counters are per-module-load and capped, so comparing one node's probe counts ACROSS runs of differing module age measures cap…
metadata:
  type: reference
tags: [method, measurement, probes, false-lead, differential, caps]
---

# Probe counts are per-module-load and CAPPED — what you may and may not compare

Nearly every MXFS probe is `if (atomic_inc_return(&n) <= CAP) pr_warn(...)`.
The counter is a `static atomic_t`, so it is **per module load**, monotonic, and
never resets between runs on the same mount. Once the cap is reached the probe
goes silent forever until the module is reloaded (which a fresh
`prep_cluster` does).

The tree already knew this in one place — `pal/linux/xfs_buf.c` ~3747:

    "the capped always-on traces (P170-CLWR cap 800, P3W cap 6000) exhaust
     during prep/storm long before the clobber"

## What this invalidates

| comparison | valid? |
|---|---|
| node A vs node B **within one run** | **YES** — same module age on every node |
| same node, run k vs run k, **different preps** | **YES** — same module age |
| same node, **early run vs late run on one mount** | **NO** — measures cap exhaustion |
| aged-mount run vs fresh-prep run | **NO** — worst case; aged mount == aged module |

## How it bit me (sess26)

Trying the "compare rank1-failing vs rank1-passing" method I had just
recommended, I diffed rank1's window-scoped census on a 240s FAILING run (late
in a mount's life) against a PASSING run right after a fresh prep. Top rows:

    PROBE                   pass    fail   ratio
    P170-CLWR                800       0    x0.0
    P25-INSTR                600       0    x0.0
    P141-UNLK-EXCLR          500       0    x0.0
    P78-FMT-TORN-FIX         389       0    x0.0
    P-DE-ENTER               335       0    x0.0
    P82-ADD / P19-B3DEC /
      P140-RECLAIM-COMMIT    300       0    x0.0
    P204-YT-DEFER            200       0    x0.0

Round numbers going to exactly zero. `P170-CLWR`'s documented cap is **800** and
it read exactly 800. These are saturation artifacts end to end — the passing run
was the FIRST after a module reload (caps fresh), the failing run was several
runs later (caps spent). Nothing behavioural was measured.

## The correct design when you must compare across runs

Match the ORDINAL position after a fresh prep. If a mount fails at iteration k:
prep, run k iterations (fails at k); fresh prep, run k iterations again (passes
at k); diff the two iteration-k censuses. Same node, same role, same module age.

Cheaper alternative when it works: get the failure to occur on the FIRST run
after a prep, then any fresh-prep passing run is a like-for-like control.

## Also beware, same family

- A separate hazard is `pr_warn_ratelimited` vs counted `pr_warn`: the tree notes
  P65 read 0-1 per storm run purely as a ratelimit artifact while the same
  decision point was reached ~68x. **Check which form a probe uses before
  reasoning about its frequency.**
- Findings that remain sound because they were within-run node-vs-node: the
  P6-MIDTENURE lead for D-SILENT-MKDIR-LOSS (loser test4 vs 31 peers, one run,
  one window), and the rank1 role-asymmetry measurement (rank1 vs 31 peers, one
  run).
