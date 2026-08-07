---
name: ccloop-c7ee71c6-sess21-criteria-board-must-show-open-defects
description: sess21 user directive: showstat IS the production-readiness gate - if a defect is open it must show RED. Five criteria added; plus 4 harness traps (c…
metadata:
  type: project
---

# sess21 — the criteria board must SHOW open defects (user directive)

## The directive
> "showstat was supposed to show where we are in the implementation and whether
> we are production ready. If showstat is not showing that then we need to add
> entries to the criteria."
> "If you're working on something, something better not be all green."

Every defect found in sess21 was found OUTSIDE showstat while the board read
20/20 green. A board that cannot show a known-open defect is not a gate.

## What was added
Registered in **`criteria.json`** (the AUTHORITATIVE registry — run.sh and
showstat read it; `tests/suite/manifest` is documentation/budgets only), with
node-side scripts in **`tests/suite/`** (NOT `tests/criteria/`, which run.sh
does not dispatch):

| criterion | catches |
|---|---|
| `kernel_health` | BUG/Oops/soft lockup/scheduling-while-atomic/rcu stall/WARNING on ANY node |
| `node_responsive` | node that pings but cannot fork/statfs/mkdir; D-state tasks |
| `dirent_durability` | mkdir(2)==0 with the entry durably absent (the silent loss) |
| `dirent_publish_integrity` | the DETERMINISTIC precursor: P195 / P188 |
| `sustained_load` | mount degrading with use (RULE 0) |

## Why TWO dirent criteria (the key design point)
`dirent_durability` measures the SYMPTOM and is intermittent (~1 run in 10), so
green there means "this run got lucky", not "fixed". A board that flips green on
a coin toss is worse than none.

`dirent_publish_integrity` measures the DETERMINISTIC state — did any node
mutate an epoch-stale base (`P195-STALE-BASE-ALREADY-DIRTY`) or hand off a grant
with an unlanded committed change (`P188`). It fires reliably.
**It is RED and must stay RED until the freshness gate at EX acquire exists.**
Do not silence the probe, widen the threshold, or delete the criterion.

## FOUR harness traps, each cost a full run to find

1. **`coord: "none"` runs the script on NODE1 ONLY.** `run_none()` ssh's to
   `$NODE1`; only `coord != "none"` goes through `run_coord()` which dispatches
   to every node. All three whole-cluster checks were initially `none` and
   silently passed — `dirent_publish_integrity` read green while test30 held the
   only P195 hit, and `kernel_health` would have missed the sess21 soft lockup
   because it was on test31. **Anything that must see every node needs
   `coord: "barrier"`.**

2. **A space-separated pending list splits silently.** `MISSING` held
   "node5 node7"; `for ent in $pending` then treated "node7" as a round id that
   could never verify, so the list grew without bound and every later round
   re-checked garbage. Symptom: `late_ok=1195` for THREE rounds and a blown
   240 s budget. Join with commas.

3. **Barriers are the wrong synchroniser for a concurrency test.** One barrier
   per round costs a broker round-trip per node per round (30 rounds x 32 nodes
   blew the budget) AND serialises the tenures, destroying the race under test —
   measured `late_ok=0`, i.e. zero propagation pressure. Use the storm's
   WALL-CLOCK SLOT model: ONE barrier to agree a start epoch, then fire round K
   at `START + (K-1)*SLOT`. Node clocks are UTC-synced.

4. **Never `rm -rf` a leftover tree inline before a rendezvous.** It runs before
   the barrier, so if slow every peer waits out COORD_TIMEOUT — 2 barriers x
   120 s == exactly a 240 s budget, on all 32 nodes, looking exactly like a
   hang. Detaching it instead leaves N concurrent `rm -rf`s degrading the mount
   for the next run. Use a per-run dir keyed off `MXFS_COORD_PREFIX`; let
   prep_cluster wipe.

## Calibrated walls (32/caw)
dirent_durability 124 s / 240 s budget; kernel_health 2 s; node_responsive 3 s;
sustained_load 4 s; dirent_publish_integrity 3 s.

## Board after the rework
32/caw: **24 PASS, 1 FAIL** — `dirent_publish_integrity` red, which is correct
and intended while the defect is open.
