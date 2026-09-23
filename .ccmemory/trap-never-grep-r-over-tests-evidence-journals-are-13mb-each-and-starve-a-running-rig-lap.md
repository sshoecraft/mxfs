---
name: trap-never-grep-r-over-tests-evidence-journals-are-13mb-each-and-starve-a-running-rig-lap
description: TRAP (sess562): `grep -r ... tests/` scans tests/evidence — 13 MB journals x 200+ dirs. It ran past 120 s and competes for host I/O with a live rig l…
metadata:
  type: feedback
tags: [trap, harness, rule0, host-safety]
---

# TRAP (sess562, 2026-09-09) — `grep -r` over `tests/` is not a cheap search

`grep -rn 'coord_barrier_or_abort()' tests/` blew through the 120 s Bash timeout
and had to be killed with TaskStop.

**Why.** `tests/evidence/` holds one directory per run — 204 of them dated a
single day in this checkout — and a ghost/authcap run's `A_journal.txt` /
`B_journal.txt` are **13 MB each**. A recursive grep over `tests/` therefore
reads gigabytes of captured kernel log to find a shell function.

**Why it is worse than slow.** It was launched while a 6-lap
`tests/sess570_chain_ghost.sh` was running on the rig. Every lap of that chain
is measured against a RULE 0 budget, and clyde's disk is also the host for the
LUN, the guest images and the journal. A background gigabyte-scale read
competes with the thing being measured, so the cost is not just the wasted
call — it can invalidate the lap.

**Do this instead**, always scoping the search to source:

    grep -rn PATTERN tests/suite tests/lib tests/*.sh
    grep -rn --include='*.sh' PATTERN tests/

Same rule for any sweep over the repo root: `tests/evidence/` is the landmine,
and it grows every run.

**Related, already known:** never `grep -r /` or `find /` on this box at all.
This is the in-repo version of the same mistake.
